//! Client side of the herdr-eternal transport: connect to the server (QUIC
//! when configured, WebSocket otherwise), run one command, and relay stdio
//! (see PLAN.md).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use herdr_eternal_proto as proto;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod agent;
mod channel;
pub mod oidc;
use channel::{Conn, Event};

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
    #[error("server rejected the session: {0}")]
    Denied(String),
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
    /// Forward the local SSH agent (`SSH_AUTH_SOCK`) into the session.
    #[serde(default)]
    pub forward_agent: bool,
    /// Direct QUIC endpoint (`host:port`); tried first, with the WebSocket
    /// URL as fallback. Roaming benefits from QUIC connection migration.
    pub quic_addr: Option<String>,
    /// Extra trusted CA certificate (PEM) for the QUIC endpoint, on top of
    /// the system trust store.
    pub quic_ca: Option<PathBuf>,
}

impl TargetConfig {
    /// Resolves the token to present: the static token if configured,
    /// otherwise a cached/refreshed OIDC access token.
    pub async fn resolve(&self, name: &str) -> Result<Target, ClientError> {
        let token = match &self.token {
            Some(token) => token.clone(),
            None => oidc::access_token(name, self).await?,
        };
        let mut target = Target::new(self.url.clone(), token);
        target.quic_addr = self.quic_addr.clone();
        target.quic_ca = self.quic_ca.clone();
        if self.forward_agent {
            // Without a local agent there is nothing to forward, like ssh -A.
            target.agent_socket = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
        }
        Ok(target)
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
    /// Local SSH agent socket to forward into the session, if any.
    pub agent_socket: Option<PathBuf>,
    /// Direct QUIC endpoint (`host:port`), preferred over the WebSocket URL.
    pub quic_addr: Option<String>,
    /// Extra trusted CA certificate (PEM) for the QUIC endpoint.
    pub quic_ca: Option<PathBuf>,
}

impl Target {
    pub fn new(url: String, token: String) -> Self {
        Self {
            url,
            token,
            keepalive_interval: std::time::Duration::from_secs(10),
            keepalive_timeout: std::time::Duration::from_secs(30),
            connect_timeout: std::time::Duration::from_secs(10),
            agent_socket: None,
            quic_addr: None,
            quic_ca: None,
        }
    }
}

/// Aborts a background task when the owning scope ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
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

/// Reconnect backoff after a disconnect. The server alone decides how long a
/// session stays resumable, so the client retries until it gets an answer.
const RESUME_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(300);
const RESUME_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(2);

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
    let mut retry_delay = RESUME_RETRY_DELAY;
    // Runs the agent channel alongside the exec; aborted when we return.
    let mut agent_channel: Option<AbortOnDrop> = None;

    loop {
        let connect = tokio::time::timeout(
            target.connect_timeout,
            connect_and_start(target, command, &resume_token, last_server_seq),
        );
        let mut conn = match connect.await.unwrap_or(Err(ClientError::ConnectTimeout)) {
            Ok((conn, token)) => {
                if resume_token.is_none() {
                    resume_token = token;
                }
                if agent_channel.is_none() {
                    if let (Some(socket), Some(token)) = (&target.agent_socket, &resume_token) {
                        agent_channel = Some(AbortOnDrop(tokio::spawn(agent::forward_agent(
                            target.clone(),
                            token.clone(),
                            socket.clone(),
                        ))));
                    }
                }
                conn
            }
            Err(err) if resume_token.is_some() && !matches!(err, ClientError::Denied(_)) => {
                tokio::time::sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(RESUME_RETRY_MAX);
                continue;
            }
            Err(err) => return Err(err),
        };
        retry_delay = RESUME_RETRY_DELAY;

        let attached = async {
            // Resend stdin the server may not have seen; it deduplicates by seq.
            // Send failures are disconnects and handled by the resume loop.
            for message in &sent_stdin {
                if conn.send(message).await.is_err() {
                    return Ok(None);
                }
            }

            let mut keepalive = tokio::time::interval(target.keepalive_interval);
            keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_activity = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    // QUIC has its own keepalive and idle timeout; only the
                    // WebSocket path needs application-level pings.
                    _ = keepalive.tick(), if conn.needs_ping() => {
                        // A blackholed connection never errors; the missing
                        // pong (or any other traffic) is what gives it away.
                        if last_activity.elapsed() >= target.keepalive_timeout {
                            return Ok(None);
                        }
                        if conn.ping().await.is_err() {
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
                        if conn.send(&message).await.is_err() {
                            return Ok(None);
                        }
                    }
                    event = conn.next() => {
                        last_activity = tokio::time::Instant::now();
                        match event? {
                            Event::Frame(bytes) => match proto::decode(&bytes)? {
                                proto::ChannelMessage::Stdout { seq, data } if seq > last_server_seq => {
                                    last_server_seq = seq;
                                    stdout.write_all(&data).await?;
                                    stdout.flush().await?;
                                    ack(&mut conn, last_server_seq).await;
                                }
                                proto::ChannelMessage::Stderr { seq, data } if seq > last_server_seq => {
                                    last_server_seq = seq;
                                    stderr.write_all(&data).await?;
                                    stderr.flush().await?;
                                    ack(&mut conn, last_server_seq).await;
                                }
                                proto::ChannelMessage::Exit { seq, code } => {
                                    // Confirm delivery so the server can drop the session.
                                    ack(&mut conn, seq).await;
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
                            Event::Disconnected => return Ok(None),
                        }
                    }
                }
            }
        };

        match attached.await {
            Ok(Some(code)) => return Ok(code),
            // Disconnected mid-exec: resume if the server handed out a token.
            Ok(None) if resume_token.is_some() => {
                tokio::time::sleep(RESUME_RETRY_DELAY).await;
            }
            Ok(None) => return Err(ClientError::ConnectionClosed),
            Err(err) => return Err(err),
        }
    }
}

/// Tells the server which of its messages we have persisted, so it can trim
/// its replay buffer. Failures surface on the next send/receive.
async fn ack(conn: &mut Conn, seq: u64) {
    conn.send(&proto::ChannelMessage::Ack { seq }).await.ok();
}

/// Connects, authenticates, and starts or resumes the exec session.
async fn connect_and_start(
    target: &Target,
    command: &str,
    resume_token: &Option<String>,
    last_server_seq: u64,
) -> Result<(Conn, Option<String>), ClientError> {
    let mut conn = Conn::connect(target).await?;

    conn.send(&proto::Hello {
        token: target.token.clone(),
        client_name: "herdr-eternal-ssh".to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    })
    .await?;
    let _welcome: proto::Welcome = conn.recv().await?;

    let request = match resume_token {
        Some(resume_token) => proto::ExecRequest::Resume {
            resume_token: resume_token.clone(),
            last_seq_seen: last_server_seq,
        },
        None => proto::ExecRequest::Exec {
            command: command.to_string(),
            resumable: true,
            forward_agent: target.agent_socket.is_some(),
        },
    };
    conn.send(&request).await?;

    match conn.recv().await? {
        proto::ChannelMessage::Started { resume_token } => Ok((conn, resume_token)),
        proto::ChannelMessage::Denied { reason } => Err(ClientError::Denied(reason)),
        _ => Err(ClientError::ConnectionClosed),
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
