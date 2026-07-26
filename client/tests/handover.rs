//! A daemon restart must not lose running resumable sessions: the old
//! instance hands their state and pipe fds over (in production via the
//! systemd fd store), the new instance restores them and clients resume
//! byte-exactly (see PLAN.md).

mod support;

use std::sync::Arc;
use std::time::Duration;

use herdr_eternal_server::{Auth, Server};
use herdr_eternal_ssh::Target;
use support::proxy::FlakyProxy;
use support::{assert_counting_output, spawn_counting_exec};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_survives_daemon_handover() {
    let runtime_dir = tempfile::tempdir().unwrap();
    let old = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
    .await
    .unwrap();
    let addr = old.local_addr().unwrap();
    let old = Arc::new(old);
    let serving = tokio::spawn(Arc::clone(&old).serve());
    // The proxy lets the test cut the client's connection the way a real
    // daemon restart would (the old process exits, dropping all connections).
    let proxy = FlakyProxy::start(addr).await.unwrap();

    let mut target = Target::new(format!("ws://{}", proxy.local_addr()), "secret".into());
    target.keepalive_interval = Duration::from_millis(100);
    target.keepalive_timeout = Duration::from_millis(500);
    target.connect_timeout = Duration::from_millis(300);
    let exec = spawn_counting_exec(target);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Restart mid-stream: hand the sessions over, tear the old daemon down
    // (cutting the client's connection), and bring a new one up on the same
    // address with the handed-over state.
    let fds = old.handover_sessions(runtime_dir.path()).await.unwrap();
    assert!(
        !fds.is_empty(),
        "expected the session's fds to be handed over"
    );
    serving.abort();
    drop(old);
    proxy.sever();
    let new = loop {
        // The old listener closes asynchronously; retry until the port is free.
        match Server::bind(
            &addr.to_string(),
            Auth::static_token("secret".into()),
            "/bin/sh".into(),
        )
        .await
        {
            Ok(server) => break server,
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    new.restore_sessions(runtime_dir.path(), fds).unwrap();
    tokio::spawn(new.run());

    assert_counting_output(exec.await.unwrap());
}
