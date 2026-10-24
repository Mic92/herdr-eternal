//! Latency benchmark: in-process server plus client over loopback. Run it
//! under `nix/bench-netem.sh` to add realistic delay/loss to `lo`.
//!
//! usage: latency [ws|quic] [iterations]
//!        latency ssh [iterations] <ssh argv...>

use std::process::Stdio;
use std::time::{Duration, Instant};

use herdr_eternal_server::{Auth, Server};
use herdr_eternal_ssh::{Target, run_exec};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone)]
enum Backend {
    Eternal(Target),
    Ssh(Vec<String>),
}

impl Backend {
    async fn exec(
        &self,
        cmd: &str,
        mut stdin: impl AsyncRead + Unpin + Send + 'static,
        mut stdout: impl AsyncWrite + Unpin + Send + 'static,
    ) -> i32 {
        match self {
            Backend::Eternal(target) => run_exec(target, cmd, stdin, stdout, tokio::io::sink())
                .await
                .unwrap(),
            Backend::Ssh(argv) => {
                let mut child = tokio::process::Command::new(&argv[0])
                    .args(&argv[1..])
                    .arg(cmd)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut child_in = child.stdin.take().unwrap();
                let mut child_out = child.stdout.take().unwrap();
                let input = tokio::spawn(async move {
                    // Byte-wise so each keystroke is flushed immediately.
                    let mut b = [0_u8; 1];
                    while stdin.read(&mut b).await.unwrap_or(0) == 1 {
                        if child_in.write_all(&b).await.is_err() {
                            break;
                        }
                    }
                });
                tokio::io::copy(&mut child_out, &mut stdout).await.unwrap();
                drop(stdout);
                let status = child.wait().await.unwrap();
                input.abort();
                status.code().unwrap_or(-1)
            }
        }
    }
}

fn report(name: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let pct = |p: usize| samples[(samples.len() - 1) * p / 100].as_secs_f64() * 1000.0;
    println!(
        "{name:<10} n={:<4} p50={:>8.2}ms p90={:>8.2}ms p99={:>8.2}ms",
        samples.len(),
        pct(50),
        pct(90),
        pct(99)
    );
}

async fn connect(backend: &Backend, n: usize) {
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        let code = backend
            .exec("true", tokio::io::empty(), tokio::io::sink())
            .await;
        assert_eq!(code, 0);
        samples.push(start.elapsed());
    }
    report("connect", samples);
}

/// Keystroke round trip: one byte to a remote `cat` and back.
async fn echo(backend: &Backend, n: usize) {
    let (mut input, stdin) = tokio::io::duplex(64);
    let (stdout, mut output) = tokio::io::duplex(64);
    let backend = backend.clone();
    let exec = tokio::spawn(async move { backend.exec("cat", stdin, stdout).await });

    let mut byte = [0_u8; 1];
    // Warm-up: the first echo also pays for connection setup.
    input.write_all(b"x").await.unwrap();
    output.read_exact(&mut byte).await.unwrap();

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        input.write_all(b"x").await.unwrap();
        output.read_exact(&mut byte).await.unwrap();
        samples.push(start.elapsed());
    }
    report("echo", samples);
    drop(input);
    exec.await.unwrap();
}

async fn bulk(backend: &Backend) {
    let (stdout, mut output) = tokio::io::duplex(64 * 1024);
    let backend = backend.clone();
    let exec = tokio::spawn(async move {
        backend
            .exec("seq 2000000", tokio::io::empty(), stdout)
            .await
    });
    let start = Instant::now();
    let mut total = 0;
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let n = output.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    let elapsed = start.elapsed();
    exec.await.unwrap();
    println!(
        "bulk       {:.1} MiB in {:.2}s = {:.1} MiB/s",
        total as f64 / 1048576.0,
        elapsed.as_secs_f64(),
        total as f64 / 1048576.0 / elapsed.as_secs_f64()
    );
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let mut args = std::env::args().skip(1);
    let transport = args.next().unwrap_or_else(|| "quic".into());
    let n: usize = args.next().map_or(50, |n| n.parse().expect("iterations"));

    if transport == "ssh" {
        let backend = Backend::Ssh(args.collect());
        println!("transport=ssh");
        connect(&backend, n).await;
        echo(&backend, n).await;
        bulk(&backend).await;
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let mut server = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
    .await
    .unwrap();
    server
        .enable_quic("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
        .unwrap();
    let ws_addr = server.local_addr().unwrap();
    let quic_addr = server.quic_addr().unwrap();
    tokio::spawn(server.run());

    let mut target = Target::new(format!("ws://{ws_addr}"), "secret".into());
    match transport.as_str() {
        "ws" => {}
        "quic" => {
            target.quic_addr = Some(quic_addr.to_string());
            target.quic_ca = Some(cert_path.clone());
        }
        other => panic!("unknown transport {other}, expected ws, quic or ssh"),
    }

    let backend = Backend::Eternal(target);
    println!("transport={transport}");
    connect(&backend, n).await;
    echo(&backend, n).await;
    bulk(&backend).await;
}
