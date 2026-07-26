//! TCP proxy that simulates network failures (netsplits) between the client
//! and the server: severed connections and silent blackholes. New inbound
//! connections are always forwarded again, so reconnect/resume paths can be
//! exercised.

// Every test binary compiles this shared helper but uses only a subset of it.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Forward,
    /// Keep connections open but stop forwarding (NAT timeout / suspend).
    Blackhole,
}

pub struct FlakyProxy {
    local_addr: SocketAddr,
    mode: watch::Sender<Mode>,
    /// Bumping this generation aborts all currently proxied connections.
    generation: Arc<watch::Sender<u64>>,
}

impl FlakyProxy {
    /// Starts a proxy on an ephemeral port forwarding to `upstream`.
    pub async fn start(upstream: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let (mode_tx, mode_rx) = watch::channel(Mode::Forward);
        let (generation_tx, generation_rx) = watch::channel(0_u64);
        let generation_tx = Arc::new(generation_tx);

        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                let mode_rx = mode_rx.clone();
                let generation_rx = generation_rx.clone();
                tokio::spawn(async move {
                    let Ok(server) = TcpStream::connect(upstream).await else {
                        return;
                    };
                    forward(client, server, mode_rx, generation_rx).await;
                });
            }
        });

        Ok(Self {
            local_addr,
            mode: mode_tx,
            generation: generation_tx,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Drops all currently proxied connections (both sides see EOF/reset).
    pub fn sever(&self) {
        self.generation.send_modify(|generation| *generation += 1);
    }

    /// Silently stops forwarding on existing connections without closing them.
    #[allow(dead_code)]
    pub fn blackhole(&self) {
        self.mode.send_replace(Mode::Blackhole);
    }

    /// Resumes forwarding for existing and new connections.
    #[allow(dead_code)]
    pub fn restore(&self) {
        self.mode.send_replace(Mode::Forward);
    }
}

async fn forward(
    client: TcpStream,
    server: TcpStream,
    mode: watch::Receiver<Mode>,
    mut generation: watch::Receiver<u64>,
) {
    // Only future sever() calls concern this connection; past ones are stale.
    generation.borrow_and_update();
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();
    let upload = tokio::spawn(pump(client_read, server_write, mode.clone()));
    let download = tokio::spawn(pump(server_read, client_write, mode));

    let abort_upload = upload.abort_handle();
    let abort_download = download.abort_handle();
    tokio::select! {
        _ = generation.changed() => {
            abort_upload.abort();
            abort_download.abort();
        }
        _ = async { upload.await.ok(); download.await.ok(); } => {}
    }
}

async fn pump(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut mode: watch::Receiver<Mode>,
) {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if *mode.borrow() == Mode::Blackhole {
            if mode.changed().await.is_err() {
                return;
            }
            continue;
        }
        let n = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if *mode.borrow() == Mode::Blackhole {
            // Drop the data that raced with the mode switch.
            continue;
        }
        if writer.write_all(&buffer[..n]).await.is_err() {
            return;
        }
    }
}
