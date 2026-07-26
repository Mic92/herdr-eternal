//! End-to-end test of the exec listener with a raw WebSocket client.

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use herdr_eternal_server::Server;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start_server() -> Ws {
    let server = Server::bind("127.0.0.1:0", "secret".into(), "/bin/sh".into())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
        .await
        .unwrap();
    ws
}

async fn send<T: serde::Serialize>(ws: &mut Ws, msg: &T) {
    ws.send(Message::Binary(proto::encode(msg).unwrap()))
        .await
        .unwrap();
}

async fn recv<T: serde::de::DeserializeOwned>(ws: &mut Ws) -> T {
    loop {
        match ws.next().await.expect("stream open").expect("no ws error") {
            Message::Binary(bytes) => return proto::decode(&bytes).unwrap(),
            Message::Close(_) => panic!("connection closed unexpectedly"),
            _ => continue,
        }
    }
}

fn hello(token: &str) -> proto::Hello {
    proto::Hello {
        token: token.into(),
        client_name: "test".into(),
        client_version: "0".into(),
    }
}

#[tokio::test]
async fn exec_relays_stdio_and_exit_code() {
    let mut ws = start_server().await;

    send(&mut ws, &hello("secret")).await;
    let welcome: proto::Welcome = recv(&mut ws).await;
    assert!(!welcome.server_version.is_empty());

    send(
        &mut ws,
        &proto::ExecRequest::Exec {
            command: "cat; echo err >&2; exit 3".into(),
            resumable: false,
        },
    )
    .await;
    let started: proto::ChannelMessage = recv(&mut ws).await;
    assert!(matches!(
        started,
        proto::ChannelMessage::Started { resume_token: None }
    ));

    send(
        &mut ws,
        &proto::ChannelMessage::Stdin {
            seq: 1,
            data: b"hello over stdin\n".to_vec(),
        },
    )
    .await;
    send(&mut ws, &proto::ChannelMessage::StdinEof { seq: 2 }).await;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit_code = loop {
        match recv::<proto::ChannelMessage>(&mut ws).await {
            proto::ChannelMessage::Stdout { data, .. } => stdout.extend(data),
            proto::ChannelMessage::Stderr { data, .. } => stderr.extend(data),
            proto::ChannelMessage::Exit { code, .. } => break code,
            other => panic!("unexpected message: {other:?}"),
        }
    };

    assert_eq!(String::from_utf8(stdout).unwrap(), "hello over stdin\n");
    assert_eq!(String::from_utf8(stderr).unwrap(), "err\n");
    assert_eq!(exit_code, 3);
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let mut ws = start_server().await;

    send(&mut ws, &hello("wrong")).await;
    // The server closes the connection without sending Welcome.
    loop {
        match ws.next().await {
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(Message::Binary(_))) => panic!("server replied despite bad token"),
            Some(Ok(_)) => continue,
            Some(Err(_)) => break,
        }
    }
}
