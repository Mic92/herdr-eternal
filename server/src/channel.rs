//! Transport abstraction for exec channels: WebSocket (behind nginx) or a
//! direct QUIC bidirectional stream. Both carry the same postcard frames;
//! on QUIC each frame is length-prefixed on the stream.

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::ServerError;

/// Upper bound for a single QUIC frame; stdio chunks are 16 KiB.
const MAX_FRAME: u32 = 1024 * 1024;

pub(crate) enum Channel {
    Ws(Box<WebSocketStream<TcpStream>>),
    Quic {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
}

/// What a connection produced next, uniform across transports.
pub(crate) enum Event {
    Frame(Vec<u8>),
    /// Peer closed the connection in an orderly way.
    Closed,
    Failed(ServerError),
}

impl Channel {
    pub(crate) async fn send<T: serde::Serialize>(&mut self, msg: &T) -> Result<(), ServerError> {
        let bytes = proto::encode(msg)?;
        match self {
            Channel::Ws(ws) => ws.send(Message::Binary(bytes)).await.map_err(Box::new)?,
            Channel::Quic { send, .. } => {
                send.write_all(&(bytes.len() as u32).to_be_bytes())
                    .await
                    .map_err(std::io::Error::other)?;
                send.write_all(&bytes)
                    .await
                    .map_err(std::io::Error::other)?;
            }
        }
        Ok(())
    }

    /// Receives one message during the handshake; a closed connection is an
    /// error at that stage.
    pub(crate) async fn recv<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, ServerError> {
        match self.next().await {
            Event::Frame(bytes) => Ok(proto::decode(&bytes)?),
            Event::Closed => Err(ServerError::HandshakeClosed),
            Event::Failed(err) => Err(err),
        }
    }

    /// Waits for the next protocol frame, skipping transport-internal
    /// messages (WebSocket ping/pong/text).
    pub(crate) async fn next(&mut self) -> Event {
        match self {
            Channel::Ws(ws) => loop {
                match ws.next().await {
                    Some(Ok(Message::Binary(bytes))) => return Event::Frame(bytes),
                    Some(Ok(Message::Close(_))) | None => return Event::Closed,
                    Some(Ok(_)) => continue,
                    Some(Err(err)) => return Event::Failed(Box::new(err).into()),
                }
            },
            Channel::Quic { recv, .. } => {
                let mut len = [0_u8; 4];
                match recv.read_exact(&mut len).await {
                    Ok(()) => {}
                    Err(quinn::ReadExactError::FinishedEarly(_)) => return Event::Closed,
                    Err(err) => return Event::Failed(std::io::Error::other(err).into()),
                }
                let len = u32::from_be_bytes(len);
                if len > MAX_FRAME {
                    return Event::Failed(
                        std::io::Error::other(format!("oversized frame: {len} bytes")).into(),
                    );
                }
                let mut bytes = vec![0; len as usize];
                match recv.read_exact(&mut bytes).await {
                    Ok(()) => Event::Frame(bytes),
                    Err(quinn::ReadExactError::FinishedEarly(_)) => Event::Closed,
                    Err(err) => Event::Failed(std::io::Error::other(err).into()),
                }
            }
        }
    }

    /// Whether the server has to probe liveness itself. QUIC connections
    /// carry their own keepalive and idle timeout.
    pub(crate) fn needs_ping(&self) -> bool {
        matches!(self, Channel::Ws(_))
    }

    pub(crate) async fn ping(&mut self) -> Result<(), ServerError> {
        if let Channel::Ws(ws) = self {
            ws.send(Message::Ping(Vec::new())).await.map_err(Box::new)?;
        }
        Ok(())
    }

    pub(crate) async fn close(&mut self) {
        match self {
            Channel::Ws(ws) => {
                ws.close(None).await.ok();
            }
            Channel::Quic { send, .. } => {
                send.finish().ok();
            }
        }
    }
}
