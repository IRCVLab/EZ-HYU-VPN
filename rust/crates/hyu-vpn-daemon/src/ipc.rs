use std::sync::Arc;

use async_trait::async_trait;
use hyu_vpn_protocol::{
    MAX_FRAME_BYTES, RequestEnvelope, ResponseEnvelope, decode_request, encode_response,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    #[error("IPC frame is too large")]
    FrameTooLarge,
    #[error("IPC transport failed")]
    Transport,
    #[error("IPC protocol failed")]
    Protocol,
}

#[async_trait]
pub trait RequestHandler: Send + Sync {
    async fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope;
}

pub async fn serve_connection<S, H>(mut stream: S, handler: Arc<H>) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: RequestHandler + ?Sized + 'static,
{
    let frame_length = stream.read_u32().await.map_err(|_| IpcError::Transport)? as usize;
    if frame_length > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge);
    }
    let mut frame = vec![0_u8; frame_length];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|_| IpcError::Transport)?;
    let request = decode_request(&frame).map_err(|_| IpcError::Protocol)?;
    let response =
        encode_response(&handler.handle(request).await).map_err(|_| IpcError::Protocol)?;
    stream
        .write_u32(u32::try_from(response.len()).map_err(|_| IpcError::FrameTooLarge)?)
        .await
        .map_err(|_| IpcError::Transport)?;
    stream
        .write_all(&response)
        .await
        .map_err(|_| IpcError::Transport)?;
    stream.flush().await.map_err(|_| IpcError::Transport)?;
    stream.shutdown().await.map_err(|_| IpcError::Transport)
}
