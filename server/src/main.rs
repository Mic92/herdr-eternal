//! herdr-eternal-server: accepts exec channels over WebSocket (behind nginx)
//! and runs commands through the user's shell. See PLAN.md.

use std::process::ExitCode;

use herdr_eternal_server::Server;

fn usage() -> ExitCode {
    eprintln!(
        "usage: herdr-eternal-server --listen <addr:port> --token-file <path>\n\
         The token file contains the pre-shared token clients must present."
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
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--token-file" => token_file = args.next(),
            _ => return usage(),
        }
    }
    let (Some(listen), Some(token_file)) = (listen, token_file) else {
        return usage();
    };
    let token = match std::fs::read_to_string(&token_file) {
        Ok(token) => token.trim().to_string(),
        Err(err) => {
            eprintln!("herdr-eternal-server: cannot read token file {token_file}: {err}");
            return ExitCode::FAILURE;
        }
    };
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = runtime.block_on(async {
        let server = Server::bind(&listen, token, shell).await?;
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
