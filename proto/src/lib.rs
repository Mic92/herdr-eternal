//! Wire protocol for the herdr-eternal transport.
//!
//! Transport-agnostic framed messages (`herdr-eternal/2`), carried over a
//! WebSocket connection or a QUIC bidi stream. Every data-bearing message
//! carries a sequence number so a broken connection can be resumed
//! byte-exactly in both directions.

use serde::{Deserialize, Serialize};

/// Protocol identifier used for ALPN / WebSocket subprotocol negotiation.
pub const PROTOCOL: &str = "herdr-eternal/2";

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("failed to encode message: {0}")]
    Encode(#[source] postcard::Error),
    #[error("failed to decode message: {0}")]
    Decode(#[source] postcard::Error),
    #[error("failed to decompress message: {0}")]
    Decompress(#[source] std::io::Error),
    #[error("unknown message encoding {0}")]
    UnknownEncoding(u8),
}

const ENC_RAW: u8 = 0;
const ENC_ZSTD: u8 = 1;
/// Smaller messages (keystrokes, acks) don't benefit from compression.
const COMPRESS_MIN: usize = 64;

/// First message sent by the client after the transport is established.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// OIDC access token (or pre-shared token during M1).
    pub token: String,
    pub client_name: String,
    pub client_version: String,
}

/// Server reply to a successful [`Hello`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    pub user: String,
    pub server_version: String,
}

/// Client request to start a command or resume an existing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecRequest {
    /// Run `command` through the user's login shell.
    Exec {
        command: String,
        /// Ask the server to keep the session resumable after disconnects.
        resumable: bool,
        /// Ask the server to expose an SSH agent socket (`SSH_AUTH_SOCK`) to
        /// the command; agent requests are relayed back over an agent channel.
        forward_agent: bool,
    },
    /// Re-attach to a resumable session and replay output past `last_seq_seen`.
    Resume {
        resume_token: String,
        last_seq_seen: u64,
    },
    /// Become the agent-forwarding channel of an existing session: the server
    /// relays connections to the session's agent socket as Agent* messages.
    AgentChannel { resume_token: String },
}

/// Messages flowing on an established exec channel (both directions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelMessage {
    /// Server -> client: session accepted; token present when resumable.
    Started { resume_token: Option<String> },
    /// Server -> client: request rejected (e.g. unknown resume token); do not retry.
    Denied { reason: String },
    /// Client -> server.
    Stdin { seq: u64, data: Vec<u8> },
    /// Client -> server: no more stdin.
    StdinEof { seq: u64 },
    /// Server -> client.
    Stdout { seq: u64, data: Vec<u8> },
    /// Server -> client.
    Stderr { seq: u64, data: Vec<u8> },
    /// Server -> client: process finished.
    Exit { seq: u64, code: i32 },
    /// Either direction: "I have seen everything up to `seq` from you", so
    /// the peer can drop those messages from its replay buffer.
    Ack { seq: u64 },
    /// Agent channel, server -> client: a program on the server connected to
    /// the forwarded agent socket; the client dials its local agent.
    AgentOpen { id: u64 },
    /// Agent channel, both directions: bytes of one agent connection.
    AgentData { id: u64, data: Vec<u8> },
    /// Agent channel, both directions: one side of the agent connection closed.
    AgentClose { id: u64 },
}

/// Messages are compressed independently so replay after resume needs no
/// shared compressor state.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let body = postcard::to_stdvec(msg).map_err(ProtocolError::Encode)?;
    let (tag, payload) = if body.len() >= COMPRESS_MIN
        && let Ok(compressed) = zstd::bulk::compress(&body, 3)
        && compressed.len() < body.len()
    {
        (ENC_ZSTD, compressed)
    } else {
        (ENC_RAW, body)
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(tag);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    match bytes.split_first() {
        Some((&ENC_RAW, body)) => postcard::from_bytes(body).map_err(ProtocolError::Decode),
        Some((&ENC_ZSTD, body)) => {
            let body =
                zstd::bulk::decompress(body, MAX_FRAME).map_err(ProtocolError::Decompress)?;
            postcard::from_bytes(&body).map_err(ProtocolError::Decode)
        }
        Some((&other, _)) => Err(ProtocolError::UnknownEncoding(other)),
        None => Err(ProtocolError::Decode(
            postcard::Error::DeserializeUnexpectedEnd,
        )),
    }
}

/// Keystrokes and their echo are usually the only packet in flight, so a
/// lost one waits for QUIC's probe timeout (2-3 RTT). Such small messages are
/// additionally sent as unreliable datagrams; receivers use whichever copy
/// arrives first and must only apply a datagram if it is the next `seq`.
pub fn worth_duplicating(msg: &ChannelMessage) -> bool {
    matches!(
        msg,
        ChannelMessage::Stdin { data, .. }
            | ChannelMessage::Stdout { data, .. }
            | ChannelMessage::Stderr { data, .. }
            if data.len() <= 512
    )
}

/// Delay before the datagram copy so it does not share a packet (and thus
/// its loss) with the stream copy.
pub const DUPLICATE_DELAY: std::time::Duration = std::time::Duration::from_millis(3);

/// Upper bound for a single stream frame; stdio chunks are 16 KiB.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Length-prefixes `msg` for a byte-stream transport (QUIC).
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let body = encode(msg)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

#[derive(Debug, thiserror::Error)]
#[error("oversized frame: {0} bytes")]
pub struct OversizedFrame(pub usize);

/// Reassembles length-prefixed frames from a byte stream.
///
/// All partial state lives in the decoder, so a reader built on it stays
/// cancel-safe inside `tokio::select!`: dropping a pending read never loses
/// bytes that were already taken off the stream.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pops the next complete frame, if buffered.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, OversizedFrame> {
        let Some(len) = self.buf.first_chunk::<4>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*len) as usize;
        if len > MAX_FRAME {
            return Err(OversizedFrame(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let rest = self.buf.split_off(4 + len);
        let frame = std::mem::replace(&mut self.buf, rest).split_off(4);
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_message_roundtrip() {
        let msg = ChannelMessage::Stdout {
            seq: 42,
            data: b"hello".to_vec(),
        };
        let bytes = encode(&msg).unwrap();
        let decoded: ChannelMessage = decode(&bytes).unwrap();
        match decoded {
            ChannelMessage::Stdout { seq, data } => {
                assert_eq!(seq, 42);
                assert_eq!(data, b"hello");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn frame_decoder_reassembles_split_and_coalesced_frames() {
        let a = encode_frame(&ChannelMessage::Ack { seq: 1 }).unwrap();
        let b = encode_frame(&ChannelMessage::Stdout {
            seq: 2,
            data: vec![7; 30_000],
        })
        .unwrap();
        let mut wire = a.clone();
        wire.extend_from_slice(&b);

        let mut decoder = FrameDecoder::new();
        let mut frames = Vec::new();
        // Feed in odd-sized pieces so both the length prefix and bodies get split.
        for chunk in wire.chunks(1337) {
            decoder.push(chunk);
            while let Some(frame) = decoder.next_frame().unwrap() {
                frames.push(frame);
            }
        }
        assert_eq!(frames, vec![a[4..].to_vec(), b[4..].to_vec()]);
        assert!(decoder.next_frame().unwrap().is_none());
    }

    #[test]
    fn frame_decoder_rejects_oversized_frames() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert!(decoder.next_frame().is_err());
    }

    #[test]
    fn large_output_is_compressed_and_roundtrips() {
        let data = b"drwxr-xr-x 2 joerg users 4096 ".repeat(500);
        let msg = ChannelMessage::Stdout {
            seq: 9,
            data: data.clone(),
        };
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes[0], ENC_ZSTD);
        assert!(bytes.len() < data.len() / 10);
        match decode(&bytes).unwrap() {
            ChannelMessage::Stdout { seq, data: got } => {
                assert_eq!(seq, 9);
                assert_eq!(got, data);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn exec_request_roundtrip() {
        let req = ExecRequest::Exec {
            command: "/bin/sh -s".to_string(),
            resumable: false,
            forward_agent: false,
        };
        let bytes = encode(&req).unwrap();
        let decoded: ExecRequest = decode(&bytes).unwrap();
        match decoded {
            ExecRequest::Exec {
                command,
                resumable,
                forward_agent,
            } => {
                assert_eq!(command, "/bin/sh -s");
                assert!(!resumable);
                assert!(!forward_agent);
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }
}
