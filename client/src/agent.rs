//! Client side of opt-in SSH agent forwarding.
//!
//! Attaches a dedicated agent channel (`ExecRequest::AgentChannel`) to the
//! running exec session. Every `AgentOpen` from the server becomes a
//! connection to the local agent socket, and bytes flow both ways as
//! `AgentData` until either side closes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use herdr_eternal_proto as proto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::channel::{Conn, Event};
use crate::{ClientError, Target};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Keeps an agent channel attached to the session for as long as the caller
/// lets this future run; reconnects after connection drops.
pub(crate) async fn forward_agent(target: Target, resume_token: String, agent_socket: PathBuf) {
    loop {
        if let Ok(conn) = connect_agent_channel(&target, &resume_token).await {
            relay_agent_channel(conn, &agent_socket).await;
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn connect_agent_channel(target: &Target, resume_token: &str) -> Result<Conn, ClientError> {
    let mut conn = Conn::connect(target).await?;
    conn.send(&proto::Hello {
        token: target.token.clone(),
        client_name: "herdr-eternal-ssh (agent)".to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    })
    .await?;
    let _welcome: proto::Welcome = conn.recv().await?;
    conn.send(&proto::ExecRequest::AgentChannel {
        resume_token: resume_token.to_string(),
    })
    .await?;
    Ok(conn)
}

/// Serves one agent channel connection until it drops.
async fn relay_agent_channel(mut conn: Conn, agent_socket: &Path) {
    // Local reads from all agent connections funnel through one queue so a
    // single task owns the connection's writer.
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<proto::ChannelMessage>();
    let mut streams: HashMap<u64, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();

    loop {
        tokio::select! {
            outbound = outbound_rx.recv() => {
                // outbound_tx lives in this scope, so recv() cannot return None.
                let Some(message) = outbound else { return };
                if conn.send(&message).await.is_err() {
                    return;
                }
            }
            event = conn.next() => {
                match event {
                    Ok(Event::Frame(bytes)) => {
                        let Ok(message) = proto::decode(&bytes) else { return };
                        match message {
                            proto::ChannelMessage::AgentOpen { id } => {
                                let (write_tx, write_rx) = mpsc::unbounded_channel();
                                streams.insert(id, write_tx);
                                tokio::spawn(relay_agent_stream(
                                    id,
                                    agent_socket.to_path_buf(),
                                    outbound_tx.clone(),
                                    write_rx,
                                ));
                            }
                            proto::ChannelMessage::AgentData { id, data } => {
                                if let Some(stream) = streams.get(&id) {
                                    stream.send(data).ok();
                                }
                            }
                            proto::ChannelMessage::AgentClose { id } => {
                                streams.remove(&id);
                            }
                            _ => {}
                        }
                    }
                    Ok(Event::Disconnected) | Err(_) => return,
                }
            }
        }
    }
}

/// Connects one forwarded agent request to the local agent socket.
async fn relay_agent_stream(
    id: u64,
    agent_socket: PathBuf,
    outbound: mpsc::UnboundedSender<proto::ChannelMessage>,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let Ok(stream) = UnixStream::connect(&agent_socket).await else {
        outbound.send(proto::ChannelMessage::AgentClose { id }).ok();
        return;
    };
    let (mut reader, mut writer) = stream.into_split();
    let mut buffer = [0_u8; 4096];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = buffer[..n].to_vec();
                        if outbound.send(proto::ChannelMessage::AgentData { id, data }).is_err() {
                            return;
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
                    // The server closed this stream.
                    None => return,
                }
            }
        }
    }
    outbound.send(proto::ChannelMessage::AgentClose { id }).ok();
}
