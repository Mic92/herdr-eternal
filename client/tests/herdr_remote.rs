//! Full-flow test: a real (patched) `herdr --remote` drives the transport via
//! `remote.ssh_command` = herdr-eternal-ssh, against the in-process server.
//!
//! Requires `herdr` in PATH (provided by the dev shell); skips otherwise.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use herdr_eternal_server::Server;

fn herdr_available() -> bool {
    Command::new("herdr")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// Reports whether the herdr server that the bootstrap started over our
/// transport is up. `herdr status server --json` exits 0 either way, so the
/// JSON output has to be inspected.
fn herdr_server_running() -> bool {
    Command::new("herdr")
        .args(["status", "server", "--json"])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("\"running\":true"))
}

// Multi-threaded runtime: the test blocks on process polling while the
// in-process exec server must keep serving herdr's bootstrap connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn herdr_remote_bootstraps_over_the_transport() {
    if !herdr_available() {
        eprintln!("skipping: herdr not found in PATH (enter the dev shell)");
        return;
    }

    // Isolate everything (local herdr client, the "remote" herdr server our
    // exec server spawns, and both configs) in a scratch HOME. The exec
    // server's children inherit this process environment, so set it globally.
    //
    // Drop any HERDR_* variables first: when the test runs inside a herdr
    // pane, HERDR_SOCKET_PATH would otherwise point every herdr invocation
    // (and the spawned "remote" server) at the developer's live session.
    let herdr_vars: Vec<String> = std::env::vars()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with("HERDR_"))
        .collect();
    for key in herdr_vars {
        std::env::remove_var(key);
    }

    let home_dir = tempfile::tempdir().unwrap();
    let home = home_dir.path().to_path_buf();
    let config = home.join(".config");
    for (key, value) in [
        ("HOME", home.clone()),
        ("XDG_CONFIG_HOME", config.clone()),
        ("XDG_DATA_HOME", home.join(".local/share")),
        ("XDG_STATE_HOME", home.join(".local/state")),
        ("XDG_CACHE_HOME", home.join(".cache")),
        ("XDG_RUNTIME_DIR", home.join("run")),
    ] {
        std::fs::create_dir_all(&value).unwrap();
        std::env::set_var(key, value);
    }

    let server = Server::bind("127.0.0.1:0", "test-token".into(), "/bin/sh".into())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    write(
        &config.join("herdr-eternal/config.toml"),
        &format!("[targets.testbox]\nurl = \"ws://{addr}\"\ntoken = \"test-token\"\n"),
    );
    write(
        &config.join("herdr/config.toml"),
        &format!(
            "[remote]\nssh_command = \"{}\"\nmanage_ssh_config = false\n",
            env!("CARGO_BIN_EXE_herdr-eternal-ssh")
        ),
    );

    // The bootstrap (platform detection, binary discovery, server start,
    // stdio bridge) all runs before the TUI needs a terminal, so a piped
    // stdout/stderr is fine for what this test asserts.
    let mut herdr = Command::new("herdr")
        .args(["--remote", "testbox"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut started = false;
    while Instant::now() < deadline {
        if herdr_server_running() {
            started = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    herdr.kill().ok();
    let output = herdr.wait_with_output().unwrap();
    Command::new("herdr").args(["server", "stop"]).status().ok();

    assert!(
        started,
        "herdr --remote did not start the remote server over the transport.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
