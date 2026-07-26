//! Shared test helpers.

pub mod proxy;

use herdr_eternal_ssh::{Target, run_exec};

/// Runs a slow counting script against `target` (deterministic output, so a
/// mid-stream disruption is guaranteed to hit it); returns (code, stdout, stderr).
pub fn spawn_counting_exec(target: Target) -> tokio::task::JoinHandle<(i32, Vec<u8>, Vec<u8>)> {
    tokio::spawn(async move {
        let stdin: &[u8] = b"for i in $(seq 1 20); do echo $i; sleep 0.05; done\n";
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_exec(&target, "/bin/sh -s", stdin, &mut stdout, &mut stderr)
            .await
            .unwrap();
        (code, stdout, stderr)
    })
}

pub fn assert_counting_output(result: (i32, Vec<u8>, Vec<u8>)) {
    let (code, stdout, stderr) = result;
    let expected: String = (1..=20).map(|i| format!("{i}\n")).collect();
    assert_eq!(String::from_utf8(stdout).unwrap(), expected);
    assert_eq!(String::from_utf8(stderr).unwrap(), "");
    assert_eq!(code, 0);
}
