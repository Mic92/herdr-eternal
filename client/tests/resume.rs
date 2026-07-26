//! M3: the exec channel must survive a netsplit between client and server
//! without losing or duplicating bytes (see PLAN.md, application-level resume).
//!

mod support;

use std::time::Duration;

use herdr_eternal_server::{Auth, Server};
use herdr_eternal_ssh::{Target, run_exec};
use support::proxy::FlakyProxy;

async fn start_server_behind_proxy() -> FlakyProxy {
    let server = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
    .await
    .unwrap();
    let upstream = server.local_addr().unwrap();
    tokio::spawn(server.run());
    FlakyProxy::start(upstream).await.unwrap()
}

/// Runs the slow counting script against `target`; returns (code, stdout, stderr).
fn spawn_counting_exec(target: Target) -> tokio::task::JoinHandle<(i32, Vec<u8>, Vec<u8>)> {
    tokio::spawn(async move {
        // Slow, deterministic output so the netsplit hits mid-stream.
        let stdin: &[u8] = b"for i in $(seq 1 20); do echo $i; sleep 0.05; done\n";
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_exec(&target, "/bin/sh -s", stdin, &mut stdout, &mut stderr)
            .await
            .unwrap();
        (code, stdout, stderr)
    })
}

fn assert_counting_output(result: (i32, Vec<u8>, Vec<u8>)) {
    let (code, stdout, stderr) = result;
    let expected: String = (1..=20).map(|i| format!("{i}\n")).collect();
    assert_eq!(String::from_utf8(stdout).unwrap(), expected);
    assert_eq!(String::from_utf8(stderr).unwrap(), "");
    assert_eq!(code, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_survives_severed_connection() {
    let proxy = start_server_behind_proxy().await;
    let target = Target::new(format!("ws://{}", proxy.local_addr()), "secret".into());
    let exec = spawn_counting_exec(target);

    tokio::time::sleep(Duration::from_millis(300)).await;
    proxy.sever();

    assert_counting_output(exec.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_survives_blackholed_connection() {
    let proxy = start_server_behind_proxy().await;
    // Aggressive keepalive so the silent drop is detected quickly in the test.
    let mut target = Target::new(format!("ws://{}", proxy.local_addr()), "secret".into());
    target.keepalive_interval = Duration::from_millis(100);
    target.keepalive_timeout = Duration::from_millis(500);
    // Reconnect attempts hitting the still-blackholed proxy must fail fast.
    target.connect_timeout = Duration::from_millis(300);
    let exec = spawn_counting_exec(target);

    // Silently stop forwarding (NAT timeout / suspend): no error is reported
    // to either side, only the keepalive can notice.
    tokio::time::sleep(Duration::from_millis(300)).await;
    proxy.blackhole();
    tokio::time::sleep(Duration::from_millis(800)).await;
    proxy.restore();

    assert_counting_output(exec.await.unwrap());
}
