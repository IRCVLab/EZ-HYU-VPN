use std::sync::Arc;

use async_trait::async_trait;
use hyu_vpn_daemon::ipc::{IpcError, RequestHandler, serve_connection};
use hyu_vpn_protocol::{RequestEnvelope, Response, ResponseEnvelope};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct AckHandler;

#[async_trait]
impl RequestHandler for AckHandler {
    async fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope {
        ResponseEnvelope::new(request.request_id, Response::Ack)
    }
}

#[tokio::test]
async fn serves_one_length_bounded_request_and_response() {
    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_connection(server, Arc::new(AckHandler)));
    let payload = br#"{"schema_version":1,"request_id":"tray-1","command":"status"}"#;
    client.write_u32(payload.len() as u32).await.unwrap();
    client.write_all(payload).await.unwrap();

    let response_len = client.read_u32().await.unwrap() as usize;
    let mut response = vec![0; response_len];
    client.read_exact(&mut response).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["request_id"], "tray-1");
    assert_eq!(value["result"], "ack");
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn rejects_oversized_frame_before_allocating_or_calling_handler() {
    let (mut client, server) = tokio::io::duplex(64);
    let task = tokio::spawn(serve_connection(server, Arc::new(AckHandler)));
    client.write_u32(65_537).await.unwrap();
    assert_eq!(task.await.unwrap().unwrap_err(), IpcError::FrameTooLarge);
}
