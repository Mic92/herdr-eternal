//! herdr-eternal-server: accepts exec channels over WebSocket (behind nginx)
//! and runs commands through the user's shell. See PLAN.md.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::process::ExitCode;

use herdr_eternal_server::{Auth, OidcConfig, Server};

fn usage() -> ExitCode {
    eprintln!(
        "usage: herdr-eternal-server [--listen <addr:port>] [--token-file <path>]\n\
         \x20                          [--oidc-issuer <url> --oidc-client-id <id> --oidc-allowed-sub <sub>]\n\
         \x20                          [--session-timeout-secs <secs>]\n\
         \x20                          [--quic-listen <addr:port> --quic-cert <pem> --quic-key <pem>]\n\
         The token file contains the pre-shared token clients may present.\n\
         With --oidc-* set, OIDC bearer tokens from that issuer are also accepted.\n\
         Without --listen, a listener from systemd socket activation is expected.\n\
         With --quic-cert/--quic-key set, direct QUIC connections are also accepted,\n\
         on --quic-listen or on a datagram socket from socket activation.\n\
         Disconnected sessions are killed after the session timeout (default 7 days)."
    );
    ExitCode::FAILURE
}

/// Fds passed in by systemd: the listening sockets from socket activation
/// (TCP for WebSocket, UDP for QUIC) and any session fds a previous instance
/// pushed into the fd store (named `<token>.<role>`).
fn activation_fds() -> (
    Option<std::net::TcpListener>,
    Option<std::net::UdpSocket>,
    Vec<(String, OwnedFd)>,
) {
    let mut listener = None;
    let mut quic_socket = None;
    let mut sessions = Vec::new();
    let Ok(fds) = sd_notify::listen_fds_with_names(true) else {
        return (listener, quic_socket, sessions);
    };
    const SESSION_ROLES: [&str; 4] = [".stdin", ".stdout", ".stderr", ".exit"];
    for (fd, name) in fds {
        // SAFETY: the fd comes from LISTEN_FDS; systemd owns no other
        // reference and the environment is cleared so it is claimed only once.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if SESSION_ROLES.iter().any(|role| name.ends_with(role)) {
            sessions.push((name, fd));
        } else if is_datagram(&fd) {
            quic_socket.get_or_insert(std::net::UdpSocket::from(fd));
        } else if listener.is_none() {
            listener = Some(std::net::TcpListener::from(fd));
        }
    }
    (listener, quic_socket, sessions)
}

fn is_datagram(fd: &OwnedFd) -> bool {
    nix::sys::socket::getsockopt(fd, nix::sys::socket::sockopt::SockType)
        .is_ok_and(|kind| kind == nix::sys::socket::SockType::Datagram)
}

/// The user's login shell from the passwd database, like sshd uses.
fn login_shell() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|user| user.shell.to_string_lossy().into_owned())
        .filter(|shell| !shell.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut listen = None;
    let mut token_file = None;
    let mut oidc_issuer = None;
    let mut oidc_client_id = None;
    let mut oidc_allowed_sub = None;
    let mut session_timeout_secs = None;
    let mut quic_listen = None;
    let mut quic_cert = None;
    let mut quic_key = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--quic-listen" => quic_listen = args.next(),
            "--quic-cert" => quic_cert = args.next(),
            "--quic-key" => quic_key = args.next(),
            "--token-file" => token_file = args.next(),
            "--oidc-issuer" => oidc_issuer = args.next(),
            "--oidc-client-id" => oidc_client_id = args.next(),
            "--oidc-allowed-sub" => oidc_allowed_sub = args.next(),
            "--session-timeout-secs" => session_timeout_secs = args.next(),
            _ => return usage(),
        }
    }
    let quic = match (&quic_listen, quic_cert, quic_key) {
        (_, Some(cert), Some(key)) => Some((cert, key)),
        (None, None, None) => None,
        _ => return usage(),
    };
    let (activation, quic_socket, session_fds) = activation_fds();
    if listen.is_none() && activation.is_none() {
        return usage();
    }
    if quic.is_some() && quic_listen.is_none() && quic_socket.is_none() {
        return usage();
    }
    let static_token = match token_file {
        Some(token_file) => match std::fs::read_to_string(&token_file) {
            Ok(token) => Some(token.trim().to_string()),
            Err(err) => {
                eprintln!("herdr-eternal-server: cannot read token file {token_file}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    let oidc = match (oidc_issuer, oidc_client_id, oidc_allowed_sub) {
        (Some(issuer), Some(client_id), Some(allowed_sub)) => Some(OidcConfig {
            issuer,
            client_id,
            allowed_sub,
        }),
        (None, None, None) => None,
        _ => return usage(),
    };
    if static_token.is_none() && oidc.is_none() {
        return usage();
    }
    let session_timeout = match session_timeout_secs.as_deref().map(str::parse::<u64>) {
        Some(Ok(secs)) => Some(std::time::Duration::from_secs(secs)),
        Some(Err(_)) => return usage(),
        None => None,
    };
    let shell = login_shell();

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = runtime.block_on(async {
        let auth = Auth::new(static_token, oidc);
        let mut server = match (activation, listen) {
            (Some(listener), _) => Server::from_std_listener(listener, auth, shell)?,
            (None, Some(listen)) => Server::bind(&listen, auth, shell).await?,
            (None, None) => unreachable!("checked above"),
        };
        if let Some(timeout) = session_timeout {
            server.set_session_timeout(timeout);
        }
        if let Some((cert, key)) = &quic {
            let (cert, key) = (Path::new(cert), Path::new(key));
            match (quic_socket, &quic_listen) {
                (Some(socket), _) => server.enable_quic_from_socket(socket, cert, key)?,
                (None, Some(addr)) => {
                    let addr = addr.parse().map_err(std::io::Error::other)?;
                    server.enable_quic(addr, cert, key)?;
                }
                (None, None) => unreachable!("checked above"),
            }
        }
        // Set by systemd for RuntimeDirectory=; gives forwarded agent sockets
        // a stable path that survives daemon restarts and holds the state of
        // sessions handed over across a restart.
        if let Some(dir) = std::env::var_os("RUNTIME_DIRECTORY") {
            server.set_agent_runtime_dir(dir.clone().into());
            server.restore_sessions(Path::new(&dir), session_fds)?;
        }
        // Under Type=notify systemd (and anything ordered after the unit,
        // like nginx) only proceeds once the listener is ready.
        sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).ok();
        server.run().await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err}");
            ExitCode::FAILURE
        }
    }
}
