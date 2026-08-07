use std::sync::Arc;

use async_trait::async_trait;
use hyu_vpn_daemon::ipc::{RequestHandler, serve_connection};
use hyu_vpn_gtk::UnixIpcClient;
use hyu_vpn_protocol::{Request, RequestEnvelope, Response, ResponseEnvelope};
use tempfile::tempdir;

struct Ack;

#[async_trait]
impl RequestHandler for Ack {
    async fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope {
        ResponseEnvelope::new(request.request_id, Response::Ack)
    }
}

#[tokio::test]
async fn unix_client_uses_one_bounded_request_per_connection() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_connection(stream, Arc::new(Ack)).await.unwrap();
    });
    let client = UnixIpcClient::new(&path);
    assert_eq!(
        client.request(Request::Status).await.unwrap(),
        Response::Ack
    );
    server.await.unwrap();
}
