//! Exec over the direct QUIC path, and fallback to WebSocket when QUIC is
//! unreachable.

use herdr_eternal_server::{Auth, Server};
use herdr_eternal_ssh::{Target, run_exec};

/// Self-signed server cert for 127.0.0.1 written to `dir`; returns
/// (cert_path, key_path).
fn write_test_cert(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
        .expect("generate cert");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

async fn quic_server(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> (Server, std::net::SocketAddr) {
    let mut server = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
    .await
    .unwrap();
    server
        .enable_quic("127.0.0.1:0".parse().unwrap(), cert, key)
        .unwrap();
    let quic_addr = server.quic_addr().unwrap();
    (server, quic_addr)
}

#[tokio::test]
async fn exec_runs_over_quic() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_test_cert(dir.path());
    let (server, quic_addr) = quic_server(&cert, &key).await;
    tokio::spawn(server.run());

    // The WebSocket URL points nowhere: only the QUIC path can succeed.
    let mut target = Target::new("ws://127.0.0.1:9".to_string(), "secret".into());
    target.quic_addr = Some(quic_addr.to_string());
    target.quic_ca = Some(cert.clone());

    let stdin: &[u8] = b"echo over-quic\nexit 3\n";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_exec(&target, "/bin/sh -s", stdin, &mut stdout, &mut stderr)
        .await
        .unwrap();

    assert_eq!(String::from_utf8(stdout).unwrap(), "over-quic\n");
    assert_eq!(String::from_utf8(stderr).unwrap(), "");
    assert_eq!(code, 3);
}

#[tokio::test]
async fn falls_back_to_websocket_when_quic_is_unreachable() {
    let server = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
    .await
    .unwrap();
    let ws_addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let mut target = Target::new(format!("ws://{ws_addr}"), "secret".into());
    // No QUIC listener there; the client must fall back to the WebSocket URL.
    target.quic_addr = Some("127.0.0.1:9".to_string());

    let stdin: &[u8] = b"echo over-websocket\n";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_exec(&target, "/bin/sh -s", stdin, &mut stdout, &mut stderr)
        .await
        .unwrap();

    assert_eq!(String::from_utf8(stdout).unwrap(), "over-websocket\n");
    assert_eq!(code, 0);
}
