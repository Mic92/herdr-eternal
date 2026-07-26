//! M3: the exec channel must survive a netsplit between client and server
//! without losing or duplicating bytes (see PLAN.md, application-level resume).
//!

mod support;

use std::time::Duration;

use herdr_eternal_server::Server;
use herdr_eternal_ssh::{Target, run_exec};
use support::proxy::FlakyProxy;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_survives_severed_connection() {
    let server = Server::bind("127.0.0.1:0", "secret".into(), "/bin/sh".into())
        .await
        .unwrap();
    let upstream = server.local_addr().unwrap();
    tokio::spawn(server.run());
    let proxy = FlakyProxy::start(upstream).await.unwrap();

    let target = Target {
        url: format!("ws://{}", proxy.local_addr()),
        token: "secret".into(),
    };
    // Slow, deterministic output so the netsplit hits mid-stream.
    let stdin: &[u8] = b"for i in $(seq 1 20); do echo $i; sleep 0.05; done\n";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exec = tokio::spawn(async move {
        let code = run_exec(&target, "/bin/sh -s", stdin, &mut stdout, &mut stderr)
            .await
            .unwrap();
        (code, stdout, stderr)
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    proxy.sever();

    let (code, stdout, stderr) = exec.await.unwrap();
    let expected: String = (1..=20).map(|i| format!("{i}\n")).collect();
    assert_eq!(String::from_utf8(stdout).unwrap(), expected);
    assert_eq!(String::from_utf8(stderr).unwrap(), "");
    assert_eq!(code, 0);
}
