//! herdr-eternal-ssh: OpenSSH-argument-compatible client used via herdr's
//! `remote.ssh_command`. Parses `[-F cfg] [-S ctl] [-o k=v]... -T <target>
//! [command]`, connects to the herdr-eternal server, and relays
//! stdin/stdout/stderr. See PLAN.md.

use std::process::ExitCode;

use herdr_eternal_ssh::{default_config_path, load_target, run_exec, ClientError};

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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let Some(args) = parse_ssh_args(std::env::args().skip(1)) else {
        eprintln!("usage: herdr-eternal-ssh [ssh options] -T <target> <command>");
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

fn run(target: &str, command: &str) -> Result<i32, ClientError> {
    let target = load_target(&default_config_path(), target)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_exec(
        &target,
        command,
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
    ))
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
