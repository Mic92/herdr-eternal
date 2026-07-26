//! herdr-eternal-server: accepts exec channels over WebSocket (behind nginx)
//! and runs commands through the user's login shell. See PLAN.md.

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    todo!("M1: WebSocket exec listener");
}
