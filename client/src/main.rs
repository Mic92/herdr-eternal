//! herdr-eternal-ssh: OpenSSH-argument-compatible client used via herdr's
//! `remote.ssh_command`. Parses `[-F cfg] [-S ctl] [-o k=v]... -T <target>
//! [command]`, connects to the herdr-eternal server, and relays
//! stdin/stdout/stderr. See PLAN.md.

use std::process::ExitCode;

use herdr_eternal_ssh::{ClientError, default_config_path, load_target, oidc, run_exec};

/// The subset of ssh's command line that herdr emits.
#[derive(Debug, PartialEq, Eq)]
struct SshArgs {
    target: String,
    command: Option<String>,
}

fn parse_ssh_args<I: IntoIterator<Item = String>>(args: I) -> Option<SshArgs> {
    let mut args = args.into_iter();
    let mut target = None;
    let mut command_parts = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-F" | "-S" | "-o" => {
                // Managed ssh options herdr may pass; irrelevant for this transport.
                let _ = args.next();
            }
            "-T" => {}
            _ if target.is_none() => target = Some(arg),
            _ => command_parts.push(arg),
        }
    }

    Some(SshArgs {
        target: target?,
        command: if command_parts.is_empty() {
            None
        } else {
            Some(command_parts.join(" "))
        },
    })
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // quinn_udp warns on transient sendmsg failures (e.g. network
                // unreachable while roaming); the reconnect/resume logic already
                // handles those, so don't leak them into the terminal.
                .unwrap_or_else(|_| "warn,quinn_udp=error".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut raw_args = std::env::args().skip(1).peekable();
    if raw_args.peek().map(String::as_str) == Some("login") {
        raw_args.next();
        let Some(target) = raw_args.next() else {
            eprintln!("usage: herdr-eternal-ssh login <target>");
            return ExitCode::FAILURE;
        };
        return match login(&target) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("herdr-eternal-ssh: {err}");
                ExitCode::FAILURE
            }
        };
    }

    let Some(args) = parse_ssh_args(raw_args) else {
        eprintln!("usage: herdr-eternal-ssh [ssh options] -T <target> <command>");
        eprintln!("       herdr-eternal-ssh login <target>");
        return ExitCode::FAILURE;
    };
    let Some(command) = args.command else {
        eprintln!("herdr-eternal-ssh: interactive shells are not supported, pass a command");
        return ExitCode::FAILURE;
    };

    match run(&args.target, &command) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(err) => {
            eprintln!("herdr-eternal-ssh: {err}");
            ExitCode::FAILURE
        }
    }
}

fn login(name: &str) -> Result<(), ClientError> {
    let config = load_target(&default_config_path(), name)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(oidc::login(name, &config))
}

fn run(name: &str, command: &str) -> Result<i32, ClientError> {
    let config = load_target(&default_config_path(), name)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let target = match config.resolve(name).await {
            Ok(target) => target,
            Err(ClientError::NotLoggedIn(_)) => {
                oidc::login_on_tty(name, &config).await?;
                config.resolve(name).await?
            }
            Err(err) => return Err(err),
        };
        run_exec(
            &target,
            command,
            tokio::io::stdin(),
            tokio::io::stdout(),
            tokio::io::stderr(),
        )
        .await
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_herdr_bootstrap_invocation() {
        let parsed = parse_ssh_args(args(&[
            "-F",
            "/tmp/cfg",
            "-S",
            "/tmp/ctl",
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPersist=yes",
            "-T",
            "example",
            "/bin/sh -s",
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            SshArgs {
                target: "example".to_string(),
                command: Some("/bin/sh -s".to_string()),
            }
        );
    }

    #[test]
    fn parses_target_without_command() {
        let parsed = parse_ssh_args(args(&["-T", "user@host"])).unwrap();
        assert_eq!(parsed.target, "user@host");
        assert_eq!(parsed.command, None);
    }

    #[test]
    fn missing_target_is_rejected() {
        assert_eq!(parse_ssh_args(args(&["-T"])), None);
    }
}
