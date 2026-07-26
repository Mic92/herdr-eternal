//! Client side of the herdr-eternal transport: connect to the server over
//! WebSocket, run one command, and relay stdio (see PLAN.md).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub mod oidc;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot read config {path}: {source}")]
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse config {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("target {0:?} is not configured; add a [targets.{0:?}] section")]
    UnknownTarget(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("websocket error: {0}")]
    WebSocket(#[from] Box<tokio_tungstenite::tungstenite::Error>),
    #[error("protocol error: {0}")]
    Protocol(#[from] proto::ProtocolError),
    #[error("server closed the connection unexpectedly")]
    ConnectionClosed,
    #[error("timed out connecting to the server")]
    ConnectTimeout,
    #[error("cannot fetch {url}: {source}")]
    Http {
        url: String,
        source: Box<reqwest::Error>,
    },
    #[error("oidc error: {0}")]
    Oidc(String),
    #[error("not logged in to {0}; run: herdr-eternal-ssh login {0}")]
    NotLoggedIn(String),
    #[error("target has neither a token nor issuer/client_id configured")]
    NoAuthConfigured,
}

/// Per-target connection settings, `[targets.<name>]` in the config file.
#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    /// WebSocket endpoint, e.g. `wss://host/herdr-eternal` or `ws://127.0.0.1:8422`.
    pub url: String,
    /// Pre-shared token; alternative to OIDC.
    pub token: Option<String>,
    /// OIDC issuer URL; enables `herdr-eternal-ssh login <target>`.
    pub issuer: Option<String>,
    /// OAuth client id used for the device-code flow.
    pub client_id: Option<String>,
}

impl TargetConfig {
    /// Resolves the token to present: the static token if configured,
    /// otherwise a cached/refreshed OIDC access token.
    pub async fn resolve(&self, name: &str) -> Result<Target, ClientError> {
        let token = match &self.token {
            Some(token) => token.clone(),
            None => oidc::access_token(name, self).await?,
        };
        Ok(Target::new(self.url.clone(), token))
    }
}

/// Connection parameters with a resolved authentication token.
#[derive(Debug, Clone)]
pub struct Target {
    pub url: String,
    pub token: String,
    /// How often to send a WebSocket ping while attached.
    pub keepalive_interval: std::time::Duration,
    /// Treat the connection as dead when nothing (not even a pong) arrived
    /// for this long; a silent drop then triggers the resume path.
    pub keepalive_timeout: std::time::Duration,
    /// Give up on a single connect/handshake attempt after this long, so a
    /// blackholed reconnect does not eat the whole resume window.
    pub connect_timeout: std::time::Duration,
}

impl Target {
    pub fn new(url: String, token: String) -> Self {
        Self {
            url,
            token,
            keepalive_interval: std::time::Duration::from_secs(10),
            keepalive_timeout: std::time::Duration::from_secs(30),
            connect_timeout: std::time::Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Config {
    targets: HashMap<String, TargetConfig>,
}

/// Looks up `target` in the TOML config file.
pub fn load_target(path: &Path, target: &str) -> Result<TargetConfig, ClientError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ClientError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let config: Config = toml::from_str(&contents).map_err(|source| ClientError::ParseConfig {
        path: path.to_path_buf(),
        source,
    })?;
    config
        .targets
        .get(target)
        .cloned()
        .ok_or_else(|| ClientError::UnknownTarget(target.to_string()))
}

pub fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        });
    base.join("herdr-eternal").join("config.toml")
}

/// How long a disconnected exec keeps trying to resume before giving up.
const RESUME_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const RESUME_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// Runs `command` on the target and relays stdio; returns the remote exit code.
///
/// The exec is resumable: if the connection drops, the client reconnects and
/// resumes the same session with `Resume { last_seq_seen }`. Sent stdin is
/// kept for resend (the server deduplicates by sequence number), so the
/// stream stays byte-exact in both directions across reconnects.
pub async fn run_exec(
    target: &Target,
    command: &str,
    stdin: impl AsyncRead + Unpin,
    mut stdout: impl AsyncWrite + Unpin,
    mut stderr: impl AsyncWrite + Unpin,
) -> Result<i32, ClientError> {
    let mut stdin = Some(stdin);
    let mut stdin_buf = [0_u8; 16 * 1024];
    // Stdin the server has not acknowledged yet; resent verbatim on resume.
    let mut sent_stdin: Vec<proto::ChannelMessage> = Vec::new();
    let mut client_seq: u64 = 0;
    let mut last_server_seq: u64 = 0;
    let mut resume_token: Option<String> = None;
    // Set on disconnect; bounds how long we keep trying to resume afterwards.
    let mut resume_deadline: Option<tokio::time::Instant> = None;

    loop {
        let connect = tokio::time::timeout(
            target.connect_timeout,
            connect_and_start(target, command, &resume_token, last_server_seq),
        );
        let mut ws = match connect.await.unwrap_or(Err(ClientError::ConnectTimeout)) {
            Ok((ws, token)) => {
                if resume_token.is_none() {
                    resume_token = token;
                }
                ws
            }
            Err(err) => {
                // resume_deadline is only set after a resumable session dropped.
                match resume_deadline {
                    Some(deadline) if tokio::time::Instant::now() < deadline => {
                        tokio::time::sleep(RESUME_RETRY_DELAY).await;
                        continue;
                    }
                    _ => return Err(err),
                }
            }
        };

        let attached = async {
            // Resend stdin the server may not have seen; it deduplicates by seq.
            // Send failures are disconnects and handled by the resume loop.
            for message in &sent_stdin {
                if send(&mut ws, message).await.is_err() {
                    return Ok(None);
                }
            }

            let mut keepalive = tokio::time::interval(target.keepalive_interval);
            keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_activity = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    _ = keepalive.tick() => {
                        // A blackholed connection never errors; the missing
                        // pong (or any other traffic) is what gives it away.
                        if last_activity.elapsed() >= target.keepalive_timeout {
                            return Ok(None);
                        }
                        if ws.send(Message::Ping(Vec::new())).await.is_err() {
                            return Ok(None);
                        }
                    }
                    read = async { stdin.as_mut().unwrap().read(&mut stdin_buf).await }, if stdin.is_some() => {
                        let n = read?;
                        client_seq += 1;
                        let message = if n == 0 {
                            stdin = None;
                            proto::ChannelMessage::StdinEof { seq: client_seq }
                        } else {
                            proto::ChannelMessage::Stdin { seq: client_seq, data: stdin_buf[..n].to_vec() }
                        };
                        sent_stdin.push(message.clone());
                        if send(&mut ws, &message).await.is_err() {
                            return Ok(None);
                        }
                    }
                    message = ws.next() => {
                        last_activity = tokio::time::Instant::now();
                        match message {
                            Some(Ok(Message::Binary(bytes))) => match proto::decode(&bytes)? {
                                proto::ChannelMessage::Stdout { seq, data } if seq > last_server_seq => {
                                    last_server_seq = seq;
                                    stdout.write_all(&data).await?;
                                    stdout.flush().await?;
                                    ack(&mut ws, last_server_seq).await;
                                }
                                proto::ChannelMessage::Stderr { seq, data } if seq > last_server_seq => {
                                    last_server_seq = seq;
                                    stderr.write_all(&data).await?;
                                    stderr.flush().await?;
                                    ack(&mut ws, last_server_seq).await;
                                }
                                proto::ChannelMessage::Exit { seq, code } => {
                                    // Confirm delivery so the server can drop the session.
                                    ack(&mut ws, seq).await;
                                    return Ok(Some(code));
                                }
                                proto::ChannelMessage::Ack { seq: acked } => {
                                    sent_stdin.retain(|message| match message {
                                        proto::ChannelMessage::Stdin { seq, .. }
                                        | proto::ChannelMessage::StdinEof { seq } => *seq > acked,
                                        _ => true,
                                    });
                                }
                                _ => {}
                            },
                            Some(Ok(Message::Close(_))) | None => return Ok(None),
                            Some(Ok(_)) => {}
                            Some(Err(_)) => return Ok(None),
                        }
                    }
                }
            }
        };

        match attached.await {
            Ok(Some(code)) => return Ok(code),
            // Disconnected mid-exec: resume if the server handed out a token.
            Ok(None) if resume_token.is_some() => {
                resume_deadline = Some(tokio::time::Instant::now() + RESUME_WINDOW);
                tokio::time::sleep(RESUME_RETRY_DELAY).await;
            }
            Ok(None) => return Err(ClientError::ConnectionClosed),
            Err(err) => return Err(err),
        }
    }
}

/// Tells the server which of its messages we have persisted, so it can trim
/// its replay buffer. Failures surface on the next send/receive.
async fn ack(ws: &mut Ws, seq: u64) {
    if let Ok(bytes) = proto::encode(&proto::ChannelMessage::Ack { seq }) {
        ws.send(Message::Binary(bytes)).await.ok();
    }
}

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Connects, authenticates, and starts or resumes the exec session.
async fn connect_and_start(
    target: &Target,
    command: &str,
    resume_token: &Option<String>,
    last_server_seq: u64,
) -> Result<(Ws, Option<String>), ClientError> {
    let (mut ws, _) = tokio_tungstenite::connect_async(&target.url)
        .await
        .map_err(Box::new)?;

    send(
        &mut ws,
        &proto::Hello {
            token: target.token.clone(),
            client_name: "herdr-eternal-ssh".to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;
    let _welcome: proto::Welcome = recv(&mut ws).await?;

    let request = match resume_token {
        Some(resume_token) => proto::ExecRequest::Resume {
            resume_token: resume_token.clone(),
            last_seq_seen: last_server_seq,
        },
        None => proto::ExecRequest::Exec {
            command: command.to_string(),
            resumable: true,
        },
    };
    send(&mut ws, &request).await?;

    let proto::ChannelMessage::Started { resume_token } = recv(&mut ws).await? else {
        return Err(ClientError::ConnectionClosed);
    };
    Ok((ws, resume_token))
}

async fn send<S, T>(ws: &mut S, msg: &T) -> Result<(), ClientError>
where
    S: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    T: serde::Serialize,
{
    ws.send(Message::Binary(proto::encode(msg)?))
        .await
        .map_err(Box::new)?;
    Ok(())
}

async fn recv<S, T>(ws: &mut S) -> Result<T, ClientError>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    T: serde::de::DeserializeOwned,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => return Ok(proto::decode(&bytes)?),
            Some(Ok(Message::Close(_))) | None => return Err(ClientError::ConnectionClosed),
            Some(Ok(_)) => continue,
            Some(Err(err)) => return Err(Box::new(err).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_target_finds_configured_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[targets.workbox]\nurl = \"ws://127.0.0.1:8422\"\ntoken = \"secret\"\n",
        )
        .unwrap();

        let target = load_target(&path, "workbox").unwrap();
        assert_eq!(target.url, "ws://127.0.0.1:8422");
        assert_eq!(target.token.as_deref(), Some("secret"));
        assert_eq!(target.issuer, None);

        assert!(matches!(
            load_target(&path, "other"),
            Err(ClientError::UnknownTarget(name)) if name == "other"
        ));
    }
}
