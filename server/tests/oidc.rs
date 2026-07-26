//! OIDC bearer authentication against a fake issuer: valid tokens are
//! accepted, wrong subject/audience/expired tokens and garbage are rejected.

use herdr_eternal_server::test_oidc::FakeIssuer;
use herdr_eternal_server::{Auth, OidcConfig, Server};

const CLIENT_ID: &str = "herdr-eternal";
const ALLOWED_SUB: &str = "joerg";

async fn start_server(issuer: &FakeIssuer, allowed_sub: &str) -> std::net::SocketAddr {
    let auth = Auth::new(
        Some("static-secret".into()),
        Some(OidcConfig {
            issuer: issuer.issuer_url(),
            client_id: CLIENT_ID.into(),
            allowed_sub: allowed_sub.into(),
        }),
    );
    let server = Server::bind("127.0.0.1:0", auth, "/bin/sh".into())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    addr
}

/// Runs the handshake with the given token and reports whether the server
/// accepted it (answered with Welcome).
async fn handshake_accepted(addr: std::net::SocketAddr, token: &str) -> bool {
    use futures_util::{SinkExt, StreamExt};
    use herdr_eternal_proto as proto;
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
        .await
        .unwrap();
    let hello = proto::Hello {
        token: token.into(),
        client_name: "test".into(),
        client_version: "0".into(),
    };
    ws.send(Message::Binary(proto::encode(&hello).unwrap()))
        .await
        .unwrap();
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                return proto::decode::<proto::Welcome>(&bytes).is_ok();
            }
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return false,
            Some(Ok(_)) => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_bearer_tokens_are_validated() {
    let issuer = FakeIssuer::start().await;
    let addr = start_server(&issuer, ALLOWED_SUB).await;

    // The static token keeps working alongside OIDC.
    assert!(handshake_accepted(addr, "static-secret").await);

    let valid = issuer.token(ALLOWED_SUB, CLIENT_ID, 300);
    assert!(handshake_accepted(addr, &valid).await);

    let wrong_sub = issuer.token("mallory", CLIENT_ID, 300);
    assert!(!handshake_accepted(addr, &wrong_sub).await);

    let wrong_audience = issuer.token(ALLOWED_SUB, "other-app", 300);
    assert!(!handshake_accepted(addr, &wrong_audience).await);

    let expired = issuer.token(ALLOWED_SUB, CLIENT_ID, -300);
    assert!(!handshake_accepted(addr, &expired).await);

    assert!(!handshake_accepted(addr, "not-a-jwt").await);

    // client_credentials tokens carry no sub, only client_id; they only
    // authenticate a server whose allowed sub is that client id.
    let machine_token = issuer.client_credentials_token(CLIENT_ID);
    assert!(!handshake_accepted(addr, &machine_token).await);
    let machine_addr = start_server(&issuer, CLIENT_ID).await;
    assert!(handshake_accepted(machine_addr, &machine_token).await);

    // Tokens signed by a different issuer (unknown key) are rejected.
    let other_issuer = FakeIssuer::start().await;
    let forged = other_issuer.token(ALLOWED_SUB, CLIENT_ID, 300);
    assert!(!handshake_accepted(addr, &forged).await);
}
