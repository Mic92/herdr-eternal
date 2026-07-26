//! herdr-eternal-server: accepts exec channels over WebSocket (behind nginx)
//! and runs commands through the user's shell. See PLAN.md.

use std::process::ExitCode;

use herdr_eternal_server::{Auth, OidcConfig, Server};

fn usage() -> ExitCode {
    eprintln!(
        "usage: herdr-eternal-server --listen <addr:port> [--token-file <path>]\n\
         \x20                          [--oidc-issuer <url> --oidc-client-id <id> --oidc-allowed-sub <sub>]\n\
         \x20                          [--session-timeout-secs <secs>]\n\
         The token file contains the pre-shared token clients may present.\n\
         With --oidc-* set, OIDC bearer tokens from that issuer are also accepted.\n\
         Disconnected sessions are killed after the session timeout (default 7 days)."
    );
    ExitCode::FAILURE
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
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--token-file" => token_file = args.next(),
            "--oidc-issuer" => oidc_issuer = args.next(),
            "--oidc-client-id" => oidc_client_id = args.next(),
            "--oidc-allowed-sub" => oidc_allowed_sub = args.next(),
            "--session-timeout-secs" => session_timeout_secs = args.next(),
            _ => return usage(),
        }
    }
    let Some(listen) = listen else {
        return usage();
    };
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
        let mut server = Server::bind(&listen, Auth::new(static_token, oidc), shell).await?;
        if let Some(timeout) = session_timeout {
            server.set_session_timeout(timeout);
        }
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
