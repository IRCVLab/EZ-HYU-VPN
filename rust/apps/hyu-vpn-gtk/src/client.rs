use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hyu_vpn_protocol::{
    MAX_FRAME_BYTES, Request, RequestEnvelope, Response, decode_response, encode_request,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IpcClientError {
    #[error("HYU VPN service is unavailable")]
    Unavailable,
    #[error("HYU VPN service protocol failed")]
    Protocol,
}

pub struct UnixIpcClient {
    socket: PathBuf,
    sequence: AtomicU64,
}

impl UnixIpcClient {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            socket: path.as_ref().to_path_buf(),
            sequence: AtomicU64::new(1),
        }
    }

    pub async fn request(&self, request: Request) -> Result<Response, IpcClientError> {
        let id = format!(
            "gtk-{}-{}",
            std::process::id(),
            self.sequence.fetch_add(1, Ordering::Relaxed)
        );
        let envelope = RequestEnvelope::new(&id, request);
        let payload = encode_request(&envelope).map_err(|_| IpcClientError::Protocol)?;
        let mut stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|_| IpcClientError::Unavailable)?;
        stream
            .write_u32(u32::try_from(payload.len()).map_err(|_| IpcClientError::Protocol)?)
            .await
            .map_err(|_| IpcClientError::Unavailable)?;
        stream
            .write_all(&payload)
            .await
            .map_err(|_| IpcClientError::Unavailable)?;
        stream
            .flush()
            .await
            .map_err(|_| IpcClientError::Unavailable)?;
        let length = stream
            .read_u32()
            .await
            .map_err(|_| IpcClientError::Unavailable)? as usize;
        if length > MAX_FRAME_BYTES {
            return Err(IpcClientError::Protocol);
        }
        let mut frame = vec![0_u8; length];
        stream
            .read_exact(&mut frame)
            .await
            .map_err(|_| IpcClientError::Unavailable)?;
        let response = decode_response(&frame).map_err(|_| IpcClientError::Protocol)?;
        if response.request_id() != id {
            return Err(IpcClientError::Protocol);
        }
        Ok(response.into_response())
    }
}
