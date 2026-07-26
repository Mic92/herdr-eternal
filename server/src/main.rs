//! herdr-eternal-server: accepts exec channels over WebSocket (behind nginx)
//! and runs commands through the user's shell. See PLAN.md.

use std::process::ExitCode;

use herdr_eternal_server::{Auth, OidcConfig, Server};

fn usage() -> ExitCode {
    eprintln!(
        "usage: herdr-eternal-server --listen <addr:port> [--token-file <path>]\n\
         \x20                          [--oidc-issuer <url> --oidc-client-id <id> --oidc-allowed-sub <sub>]\n\
         The token file contains the pre-shared token clients may present.\n\
         With --oidc-* set, OIDC bearer tokens from that issuer are also accepted."
    );
    ExitCode::FAILURE
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
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--token-file" => token_file = args.next(),
            "--oidc-issuer" => oidc_issuer = args.next(),
            "--oidc-client-id" => oidc_client_id = args.next(),
            "--oidc-allowed-sub" => oidc_allowed_sub = args.next(),
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
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = runtime.block_on(async {
        let server = Server::bind(&listen, Auth::new(static_token, oidc), shell).await?;
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
