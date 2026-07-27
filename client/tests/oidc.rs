//! Device-code login against a fake issuer, followed by an exec on a server
//! that only accepts OIDC bearer tokens.

use herdr_eternal_server::test_oidc::FakeIssuer;
use herdr_eternal_server::{Auth, OidcConfig, Server};
use herdr_eternal_ssh::{TargetConfig, oidc, run_exec};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_and_exec_with_oidc() {
    // Token cache must not touch the developer's real state directory.
    let state_dir = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_STATE_HOME", state_dir.path());

    let issuer = FakeIssuer::start().await;
    // First poll is answered with authorization_pending to exercise polling.
    issuer.grant_device_flow("joerg", 1);

    let auth = Auth::new(
        None,
        Some(OidcConfig {
            issuer: issuer.issuer_url(),
            client_id: "herdr-eternal".into(),
            allowed_sub: "joerg".into(),
        }),
    );
    let server = Server::bind("127.0.0.1:0", auth, "/bin/sh".into())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let config = TargetConfig {
        url: format!("ws://{addr}"),
        token: None,
        issuer: Some(issuer.issuer_url()),
        client_id: Some("herdr-eternal".into()),
        forward_agent: false,
        quic_addr: None,
        quic_ca: None,
    };

    oidc::login("testbox", &config).await.unwrap();

    let target = config.resolve("testbox").await.unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_exec(
        &target,
        "echo authenticated",
        &b""[..],
        &mut stdout,
        &mut stderr,
    )
    .await
    .unwrap();
    assert_eq!(String::from_utf8(stdout).unwrap(), "authenticated\n");
    assert_eq!(code, 0);

    // Expired access token: resolve() must refresh it via the refresh token.
    let cache = state_dir.path().join("herdr-eternal/tokens/testbox.json");
    let mut cached: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    cached["expires_at"] = 0.into();
    std::fs::write(&cache, serde_json::to_vec(&cached).unwrap()).unwrap();
    let refreshed = config.resolve("testbox").await.unwrap();
    let mut stdout = Vec::new();
    let code = run_exec(
        &refreshed,
        "echo refreshed",
        &b""[..],
        &mut stdout,
        &mut Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(String::from_utf8(stdout).unwrap(), "refreshed\n");
    assert_eq!(code, 0);

    // Regression: the access token must be re-resolved on every connect, not
    // frozen at resolve() time. Simulate an access token that expired after
    // resolve(): the cache holds an already-expired JWT, marked as valid so
    // resolve() does not refresh it, then flip expires_at so the connect path
    // has to refresh via the refresh token to succeed.
    cached["access_token"] = issuer.token("joerg", "herdr-eternal", -300).into();
    cached["expires_at"] = (u64::MAX).into();
    cached["refresh_token"] = "test-refresh-token".into();
    std::fs::write(&cache, serde_json::to_vec(&cached).unwrap()).unwrap();
    let stale = config.resolve("testbox").await.unwrap();
    cached["expires_at"] = 0.into();
    std::fs::write(&cache, serde_json::to_vec(&cached).unwrap()).unwrap();
    let mut stdout = Vec::new();
    let code = run_exec(
        &stale,
        "echo reconnected",
        &b""[..],
        &mut stdout,
        &mut Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(String::from_utf8(stdout).unwrap(), "reconnected\n");
    assert_eq!(code, 0);

    // The refresh response carried no new refresh token (no rotation); the
    // old one must survive so the next expiry does not log the target out.
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    assert_eq!(after["refresh_token"], "test-refresh-token");

    // A target that never logged in gets a helpful error instead of a
    // rejected connection.
    let err = config.resolve("otherbox").await.unwrap_err();
    assert!(matches!(
        err,
        herdr_eternal_ssh::ClientError::NotLoggedIn(name) if name == "otherbox"
    ));
}
