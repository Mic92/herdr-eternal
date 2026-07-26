//! Server side of opt-in SSH agent forwarding.
//!
//! A session started with `forward_agent` gets a unix socket exported as
//! `SSH_AUTH_SOCK` to its child. Each connection accepted on that socket is
//! relayed as `AgentOpen`/`AgentData`/`AgentClose` messages over a dedicated
//! agent channel (a separate WebSocket connection the client attaches with
//! `ExecRequest::AgentChannel`), where the client dials its local agent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::debug;

use crate::ServerError;

type ChannelSender = mpsc::UnboundedSender<proto::ChannelMessage>;

/// How long an agent connection waits for an agent channel to attach. Right
/// after the exec starts, programs like ssh-add race the client's separate
/// agent-channel connection.
const CHANNEL_WAIT: Duration = Duration::from_secs(5);

/// Relays connections to the session's forwarded agent socket to whichever
/// agent channel is currently attached.
pub(crate) struct AgentHub {
    socket_path: PathBuf,
    /// Keeps the private (0700) socket directory alive as long as the hub.
    _dir: tempfile::TempDir,
    /// Sender towards the currently attached agent channel, if any.
    channel: watch::Sender<Option<ChannelSender>>,
    /// Write halves of open agent connections, by stream id.
    streams: Mutex<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>,
    next_id: AtomicU64,
}

impl AgentHub {
    /// Creates the agent socket and starts accepting connections on it.
    pub(crate) fn start() -> Result<Arc<Self>, ServerError> {
        let dir = tempfile::Builder::new()
            .prefix("herdr-eternal-agent")
            .tempdir()?;
        let socket_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let hub = Arc::new(Self {
            socket_path,
            _dir: dir,
            channel: watch::Sender::new(None),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        });
        tokio::spawn(accept_agent_connections(Arc::clone(&hub), listener));
        Ok(hub)
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn send_to_channel(&self, message: proto::ChannelMessage) -> bool {
        match self.channel.borrow().as_ref() {
            Some(channel) => channel.send(message).is_ok(),
            None => false,
        }
    }

    /// Waits (bounded) until an agent channel is attached.
    async fn channel_attached(&self) -> bool {
        let mut channel = self.channel.subscribe();
        tokio::time::timeout(CHANNEL_WAIT, channel.wait_for(Option::is_some))
            .await
            .is_ok_and(|attached| attached.is_ok())
    }
}

async fn accept_agent_connections(hub: Arc<AgentHub>, listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(relay_agent_stream(Arc::clone(&hub), stream));
    }
}

/// Pumps one accepted agent connection: local reads become `AgentData`
/// towards the client, and `AgentData` from the client is written back.
async fn relay_agent_stream(hub: Arc<AgentHub>, stream: UnixStream) {
    // Without an attached client there is nobody to answer; give a fresh
    // reconnect a moment, then fail the connection like ssh does when the
    // agent is gone.
    if !hub.channel_attached().await {
        return;
    }
    let id = hub.next_id.fetch_add(1, Ordering::Relaxed);
    let (write_tx, mut write_rx) = mpsc::unbounded_channel();
    hub.streams.lock().unwrap().insert(id, write_tx);
    if !hub.send_to_channel(proto::ChannelMessage::AgentOpen { id }) {
        hub.streams.lock().unwrap().remove(&id);
        return;
    }

    let (mut reader, mut writer) = stream.into_split();
    let mut buffer = [0_u8; 4096];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = buffer[..n].to_vec();
                        if !hub.send_to_channel(proto::ChannelMessage::AgentData { id, data }) {
                            break;
                        }
                    }
                }
            }
            data = write_rx.recv() => {
                match data {
                    Some(data) => {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    // The client closed its side of this stream.
                    None => break,
                }
            }
        }
    }
    hub.streams.lock().unwrap().remove(&id);
    hub.send_to_channel(proto::ChannelMessage::AgentClose { id });
}

/// Runs a connection that became the session's agent channel.
pub(crate) async fn handle_agent_channel(
    mut ws: WebSocketStream<TcpStream>,
    hub: Arc<AgentHub>,
) -> Result<(), ServerError> {
    let (channel_tx, mut channel_rx) = mpsc::unbounded_channel();
    hub.channel.send_replace(Some(channel_tx.clone()));

    let result: Result<(), ServerError> = async {
        loop {
            tokio::select! {
                outbound = channel_rx.recv() => {
                    // The hub holds a sender, so recv() cannot return None here.
                    let Some(message) = outbound else { return Ok(()) };
                    ws.send(Message::Binary(proto::encode(&message)?)).await.map_err(Box::new)?;
                }
                message = ws.next() => {
                    match message {
                        Some(Ok(Message::Binary(bytes))) => match proto::decode(&bytes)? {
                            proto::ChannelMessage::AgentData { id, data } => {
                                if let Some(stream) = hub.streams.lock().unwrap().get(&id) {
                                    stream.send(data).ok();
                                }
                            }
                            proto::ChannelMessage::AgentClose { id } => {
                                hub.streams.lock().unwrap().remove(&id);
                            }
                            other => debug!(?other, "ignoring message on agent channel"),
                        },
                        Some(Ok(Message::Close(_))) | None => return Ok(()),
                        Some(Ok(_)) => {}
                        Some(Err(err)) => return Err(ServerError::WebSocket(Box::new(err))),
                    }
                }
            }
        }
    }
    .await;

    // Only detach if a reconnected agent channel has not replaced us already.
    hub.channel.send_if_modified(|channel| {
        let ours = channel
            .as_ref()
            .is_some_and(|current| current.same_channel(&channel_tx));
        if ours {
            *channel = None;
        }
        ours
    });
    result
}
