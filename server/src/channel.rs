//! Transport abstraction for exec channels: WebSocket (behind nginx) or a
//! direct QUIC bidirectional stream. Both carry the same postcard frames;
//! on QUIC each frame is length-prefixed on the stream.

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::ServerError;

pub(crate) enum Channel {
    Ws(Box<WebSocketStream<TcpStream>>),
    Quic {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        /// Holds partially received frames across cancelled `next()` calls.
        decoder: proto::FrameDecoder,
        connection: quinn::Connection,
    },
}

/// What a connection produced next, uniform across transports.
pub(crate) enum Event {
    Frame(Vec<u8>),
    /// Unreliable copy of a message, see [`proto::worth_duplicating`].
    Datagram(Vec<u8>),
    /// Peer closed the connection in an orderly way.
    Closed,
    Failed(ServerError),
}

impl Channel {
    pub(crate) async fn send<T: serde::Serialize>(&mut self, msg: &T) -> Result<(), ServerError> {
        match self {
            Channel::Ws(ws) => ws
                .send(Message::Binary(proto::encode(msg)?))
                .await
                .map_err(Box::new)?,
            Channel::Quic { send, .. } => {
                send.write_all(&proto::encode_frame(msg)?)
                    .await
                    .map_err(std::io::Error::other)?;
            }
        }
        Ok(())
    }

    /// Sends an unreliable QUIC datagram copy of small stdio messages.
    pub(crate) fn send_duplicate(&self, msg: &proto::ChannelMessage) {
        let Channel::Quic { connection, .. } = self else {
            return;
        };
        if !proto::worth_duplicating(msg) {
            return;
        }
        let Ok(bytes) = proto::encode(msg) else {
            return;
        };
        let connection = connection.clone();
        tokio::spawn(async move {
            tokio::time::sleep(proto::DUPLICATE_DELAY).await;
            connection.send_datagram(bytes.into()).ok();
        });
    }

    /// Receives one message during the handshake; a closed connection is an
    /// error at that stage.
    pub(crate) async fn recv<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, ServerError> {
        loop {
            match self.next().await {
                Event::Frame(bytes) => return Ok(proto::decode(&bytes)?),
                Event::Datagram(_) => {}
                Event::Closed => return Err(ServerError::HandshakeClosed),
                Event::Failed(err) => return Err(err),
            }
        }
    }

    /// Waits for the next protocol frame, skipping transport-internal
    /// messages (WebSocket ping/pong/text).
    ///
    /// Cancel-safe: the attach loops poll this inside `tokio::select!`.
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
            Channel::Quic {
                recv,
                decoder,
                connection,
                ..
            } => loop {
                match decoder.next_frame() {
                    Ok(Some(frame)) => return Event::Frame(frame),
                    Ok(None) => {}
                    Err(err) => return Event::Failed(std::io::Error::other(err).into()),
                }
                tokio::select! {
                    chunk = recv.read_chunk(64 * 1024, true) => match chunk {
                        Ok(Some(chunk)) => decoder.push(&chunk.bytes),
                        Ok(None) => return Event::Closed,
                        Err(err) => return Event::Failed(std::io::Error::other(err).into()),
                    },
                    datagram = connection.read_datagram() => match datagram {
                        Ok(datagram) => return Event::Datagram(datagram.to_vec()),
                        Err(err) => return Event::Failed(std::io::Error::other(err).into()),
                    },
                }
            },
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
