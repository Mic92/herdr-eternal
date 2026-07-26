//! Client side of the herdr-eternal transport: connect to the server over
//! WebSocket, run one command, and relay stdio (see PLAN.md).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

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
}

/// Per-target connection settings, `[targets.<name>]` in the config file.
#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    /// WebSocket endpoint, e.g. `wss://host/herdr-eternal` or `ws://127.0.0.1:8422`.
    pub url: String,
    /// Pre-shared token (M1; replaced by OIDC in M2).
    pub token: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    targets: HashMap<String, Target>,
}

/// Looks up `target` in the TOML config file.
pub fn load_target(path: &Path, target: &str) -> Result<Target, ClientError> {
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

/// Runs `command` on the target and relays stdio; returns the remote exit code.
pub async fn run_exec(
    target: &Target,
    command: &str,
    stdin: impl AsyncRead + Unpin,
    mut stdout: impl AsyncWrite + Unpin,
    mut stderr: impl AsyncWrite + Unpin,
) -> Result<i32, ClientError> {
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

    send(
        &mut ws,
        &proto::ExecRequest::Exec {
            command: command.to_string(),
            resumable: false,
        },
    )
    .await?;
    let proto::ChannelMessage::Started { .. } = recv(&mut ws).await? else {
        return Err(ClientError::ConnectionClosed);
    };

    let mut stdin = Some(stdin);
    let mut stdin_buf = [0_u8; 16 * 1024];
    let mut seq: u64 = 0;

    loop {
        tokio::select! {
            read = async { stdin.as_mut().unwrap().read(&mut stdin_buf).await }, if stdin.is_some() => {
                let n = read?;
                seq += 1;
                if n == 0 {
                    stdin = None;
                    send(&mut ws, &proto::ChannelMessage::StdinEof { seq }).await?;
                } else {
                    send(&mut ws, &proto::ChannelMessage::Stdin { seq, data: stdin_buf[..n].to_vec() }).await?;
                }
            }
            message = ws.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => match proto::decode(&bytes)? {
                        proto::ChannelMessage::Stdout { data, .. } => {
                            stdout.write_all(&data).await?;
                            stdout.flush().await?;
                        }
                        proto::ChannelMessage::Stderr { data, .. } => {
                            stderr.write_all(&data).await?;
                            stderr.flush().await?;
                        }
                        proto::ChannelMessage::Exit { code, .. } => return Ok(code),
                        _ => {}
                    },
                    Some(Ok(Message::Close(_))) | None => return Err(ClientError::ConnectionClosed),
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(Box::new(err).into()),
                }
            }
        }
    }
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
        let dir = std::env::temp_dir().join(format!("herdr-eternal-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[targets.workbox]\nurl = \"ws://127.0.0.1:8422\"\ntoken = \"secret\"\n",
        )
        .unwrap();

        let target = load_target(&path, "workbox").unwrap();
        assert_eq!(target.url, "ws://127.0.0.1:8422");
        assert_eq!(target.token, "secret");

        assert!(matches!(
            load_target(&path, "other"),
            Err(ClientError::UnknownTarget(name)) if name == "other"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
