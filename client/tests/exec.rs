//! End-to-end test: client library against the real server.

use herdr_eternal_server::Server;
use herdr_eternal_ssh::{Target, run_exec};

#[tokio::test]
async fn exec_roundtrip_through_client_and_server() {
    let server = Server::bind("127.0.0.1:0", "secret".into(), "/bin/sh".into())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let target = Target {
        url: format!("ws://{addr}"),
        token: "secret".into(),
    };
    let stdin: &[u8] = b"echo from-stdin-script\necho on-stderr >&2\nexit 7\n";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    // Mirrors herdr's bootstrap: pipe a script into `/bin/sh -s`.
    let code = run_exec(&target, "/bin/sh -s", stdin, &mut stdout, &mut stderr)
        .await
        .unwrap();

    assert_eq!(String::from_utf8(stdout).unwrap(), "from-stdin-script\n");
    assert_eq!(String::from_utf8(stderr).unwrap(), "on-stderr\n");
    assert_eq!(code, 7);
}
