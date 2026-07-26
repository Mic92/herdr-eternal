//! Wire protocol for the herdr-eternal transport.
//!
//! Transport-agnostic framed messages (`herdr-eternal/1`), carried over a
//! WebSocket connection or a QUIC bidi stream. Every data-bearing message
//! carries a sequence number so a broken connection can be resumed
//! byte-exactly in both directions.

use serde::{Deserialize, Serialize};

/// Protocol identifier used for ALPN / WebSocket subprotocol negotiation.
pub const PROTOCOL: &str = "herdr-eternal/1";

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("failed to encode message: {0}")]
    Encode(#[source] postcard::Error),
    #[error("failed to decode message: {0}")]
    Decode(#[source] postcard::Error),
}

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
    },
    /// Re-attach to a resumable session and replay output past `last_seq_seen`.
    Resume {
        resume_token: String,
        last_seq_seen: u64,
    },
}

/// Messages flowing on an established exec channel (both directions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelMessage {
    /// Server -> client: session accepted; token present when resumable.
    Started { resume_token: Option<String> },
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
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    postcard::to_stdvec(msg).map_err(ProtocolError::Encode)
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, ProtocolError> {
    postcard::from_bytes(bytes).map_err(ProtocolError::Decode)
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
    fn exec_request_roundtrip() {
        let req = ExecRequest::Exec {
            command: "/bin/sh -s".to_string(),
            resumable: false,
        };
        let bytes = encode(&req).unwrap();
        let decoded: ExecRequest = decode(&bytes).unwrap();
        match decoded {
            ExecRequest::Exec { command, resumable } => {
                assert_eq!(command, "/bin/sh -s");
                assert!(!resumable);
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }
}
