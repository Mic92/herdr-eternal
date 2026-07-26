//! M3: the exec channel must survive a netsplit between client and server
//! without losing or duplicating bytes (see PLAN.md, application-level resume).
//!

mod support;

use std::time::Duration;

use herdr_eternal_server::{Auth, Server};
use herdr_eternal_ssh::Target;
use support::proxy::FlakyProxy;
use support::{assert_counting_output, spawn_counting_exec};

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
