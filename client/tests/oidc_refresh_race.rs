//! Concurrent clients must not race on single-use refresh tokens.

use herdr_eternal_server::test_oidc::FakeIssuer;
use herdr_eternal_ssh::{TargetConfig, oidc};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_refreshes_share_one_grant() {
    let state_dir = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_STATE_HOME", state_dir.path());

    let issuer = FakeIssuer::start().await;
    issuer.rotate_refresh_tokens();
    issuer.grant_device_flow("joerg", 0);

    let config = TargetConfig {
        url: "ws://127.0.0.1:1".into(),
        token: None,
        issuer: Some(issuer.issuer_url()),
        client_id: Some("herdr-eternal".into()),
        forward_agent: false,
        quic_addr: None,
        quic_ca: None,
    };
    oidc::login("testbox", &config).await.unwrap();

    let cache = state_dir.path().join("herdr-eternal/tokens/testbox.json");
    let mut cached: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    cached["expires_at"] = 0.into();
    std::fs::write(&cache, serde_json::to_vec(&cached).unwrap()).unwrap();

    let config = std::sync::Arc::new(config);
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let config = std::sync::Arc::clone(&config);
            tokio::spawn(async move { oidc::access_token("testbox", &config).await })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(issuer.refresh_count(), 1);
}
