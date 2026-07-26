//! WebSocket exec listener: accepts authenticated connections and runs one
//! command per connection through the user's shell, relaying framed stdio
//! (see PLAN.md).

use std::process::Stdio;

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("websocket error: {0}")]
    WebSocket(#[from] Box<tokio_tungstenite::tungstenite::Error>),
    #[error("protocol error: {0}")]
    Protocol(#[from] proto::ProtocolError),
    #[error("client closed the connection during handshake")]
    HandshakeClosed,
    #[error("invalid authentication token")]
    InvalidToken,
    #[error("expected an Exec request")]
    ExpectedExec,
}

pub struct Server {
    listener: TcpListener,
    token: String,
    shell: String,
}

impl Server {
    pub async fn bind(addr: &str, token: String, shell: String) -> Result<Self, ServerError> {
        let listener = TcpListener::bind(addr).await?;
        info!(addr = %listener.local_addr()?, "listening");
        Ok(Self {
            listener,
            token,
            shell,
        })
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn run(self) -> Result<(), ServerError> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let token = self.token.clone();
            let shell = self.shell.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, &token, &shell).await {
                    warn!(%peer, "connection failed: {err}");
                }
            });
        }
    }
}

async fn handle_connection(stream: TcpStream, token: &str, shell: &str) -> Result<(), ServerError> {
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(Box::new)?;

    let hello: proto::Hello = recv(&mut ws).await?;
    if hello.token != token {
        ws.close(None).await.ok();
        return Err(ServerError::InvalidToken);
    }
    send(
        &mut ws,
        &proto::Welcome {
            user: std::env::var("USER").unwrap_or_default(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;

    let request: proto::ExecRequest = recv(&mut ws).await?;
    let proto::ExecRequest::Exec { command, .. } = request else {
        return Err(ServerError::ExpectedExec);
    };
    debug!(%command, "exec");
    run_command(ws, shell, &command).await
}

/// Runs `command` through the user's shell (`shell -c`, matching how sshd
/// executes remote commands) and relays framed stdio until exit.
async fn run_command(
    mut ws: WebSocketStream<TcpStream>,
    shell: &str,
    command: &str,
) -> Result<(), ServerError> {
    let mut child = tokio::process::Command::new(shell)
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Kept in an Option so StdinEof can drop it: dropping closes the pipe and
    // is the only way the child sees EOF (AsyncWrite::shutdown does not).
    let mut child_stdin = child.stdin.take();
    let mut child_stdout = child.stdout.take().expect("piped stdout");
    let mut child_stderr = child.stderr.take().expect("piped stderr");

    send(
        &mut ws,
        &proto::ChannelMessage::Started { resume_token: None },
    )
    .await?;

    let mut seq: u64 = 0;
    let mut stdout_buf = [0_u8; 16 * 1024];
    let mut stderr_buf = [0_u8; 16 * 1024];
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut exit_code = None;

    loop {
        tokio::select! {
            read = child_stdout.read(&mut stdout_buf), if stdout_open => {
                let n = read?;
                if n == 0 {
                    stdout_open = false;
                } else {
                    seq += 1;
                    send(&mut ws, &proto::ChannelMessage::Stdout { seq, data: stdout_buf[..n].to_vec() }).await?;
                }
            }
            read = child_stderr.read(&mut stderr_buf), if stderr_open => {
                let n = read?;
                if n == 0 {
                    stderr_open = false;
                } else {
                    seq += 1;
                    send(&mut ws, &proto::ChannelMessage::Stderr { seq, data: stderr_buf[..n].to_vec() }).await?;
                }
            }
            status = child.wait(), if exit_code.is_none() => {
                exit_code = Some(status?.code().unwrap_or(255));
            }
            message = ws.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => match proto::decode(&bytes)? {
                        proto::ChannelMessage::Stdin { data, .. } => {
                            if let Some(stdin) = child_stdin.as_mut() {
                                stdin.write_all(&data).await?;
                                stdin.flush().await?;
                            }
                        }
                        proto::ChannelMessage::StdinEof { .. } => {
                            child_stdin = None;
                        }
                        proto::ChannelMessage::Ack { .. } => {}
                        other => {
                            debug!(?other, "ignoring unexpected channel message");
                        }
                    },
                    Some(Ok(Message::Close(_))) | None => {
                        // Client is gone; stop the command (M1: no resume).
                        child.start_kill().ok();
                        return Ok(());
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(Box::new(err).into()),
                }
            }
        }

        if let Some(code) = exit_code {
            if !stdout_open && !stderr_open {
                seq += 1;
                send(&mut ws, &proto::ChannelMessage::Exit { seq, code }).await?;
                ws.close(None).await.ok();
                return Ok(());
            }
        }
    }
}

async fn send<T: serde::Serialize>(
    ws: &mut WebSocketStream<TcpStream>,
    msg: &T,
) -> Result<(), ServerError> {
    ws.send(Message::Binary(proto::encode(msg)?))
        .await
        .map_err(Box::new)?;
    Ok(())
}

async fn recv<T: serde::de::DeserializeOwned>(
    ws: &mut WebSocketStream<TcpStream>,
) -> Result<T, ServerError> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => return Ok(proto::decode(&bytes)?),
            Some(Ok(Message::Close(_))) | None => return Err(ServerError::HandshakeClosed),
            Some(Ok(_)) => continue,
            Some(Err(err)) => return Err(Box::new(err).into()),
        }
    }
}
