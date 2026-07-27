//! End-to-end test of the exec listener with a raw WebSocket client.

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use herdr_eternal_server::{Auth, Server};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start_server() -> Ws {
    let server = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
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
            forward_agent: false,
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
            // Acknowledgement of applied stdin; irrelevant for this test.
            proto::ChannelMessage::Ack { .. } => {}
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

/// A resumable session whose client crashed and never comes back must not
/// keep its child process forever: after the session timeout the server
/// forgets the resume token.
#[tokio::test]
async fn disconnected_session_expires_after_timeout() {
    let mut server = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
    .await
    .unwrap();
    server.set_session_timeout(std::time::Duration::from_millis(200));
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let connect = || async {
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        send(&mut ws, &hello("secret")).await;
        let _welcome: proto::Welcome = recv(&mut ws).await;
        ws
    };

    // Start a long-running resumable exec, then vanish without closing.
    let mut ws = connect().await;
    send(
        &mut ws,
        &proto::ExecRequest::Exec {
            command: "sleep 60".into(),
            resumable: true,
            forward_agent: false,
        },
    )
    .await;
    let proto::ChannelMessage::Started {
        resume_token: Some(resume_token),
    } = recv(&mut ws).await
    else {
        panic!("expected a resumable session");
    };
    drop(ws);

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // The expired session cannot be resumed; the server denies the request.
    let mut ws = connect().await;
    send(
        &mut ws,
        &proto::ExecRequest::Resume {
            resume_token,
            last_seq_seen: 0,
        },
    )
    .await;
    let proto::ChannelMessage::Denied { .. } = recv(&mut ws).await else {
        panic!("server resumed an expired session");
    };
}
