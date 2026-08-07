use std::sync::atomic::{AtomicU64, Ordering};

use hyu_vpn_protocol::{
    MAX_FRAME_BYTES, Request, RequestEnvelope, Response, decode_response, encode_request,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    #[error("HYU VPN service is unavailable")]
    Unavailable,
    #[error("HYU VPN service protocol failed")]
    Protocol,
}

pub struct WindowsPipeClient {
    pipe: String,
    sequence: AtomicU64,
}

impl WindowsPipeClient {
    pub fn production() -> Self {
        Self::new(r"\\.\pipe\hyu-vpn-v1")
    }

    pub fn new(pipe: impl Into<String>) -> Self {
        Self {
            pipe: pipe.into(),
            sequence: AtomicU64::new(1),
        }
    }

    pub fn request(&self, request: Request) -> Result<Response, ClientError> {
        let id = format!(
            "tray-{}-{}",
            std::process::id(),
            self.sequence.fetch_add(1, Ordering::Relaxed)
        );
        let frame = encode_framed_request(&id, request)?;
        request_pipe(&self.pipe, &frame).and_then(|response| decode_framed_response(&id, &response))
    }
}

pub fn encode_framed_request(id: &str, request: Request) -> Result<Vec<u8>, ClientError> {
    let payload =
        encode_request(&RequestEnvelope::new(id, request)).map_err(|_| ClientError::Protocol)?;
    let length = u32::try_from(payload.len()).map_err(|_| ClientError::Protocol)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_framed_response(id: &str, frame: &[u8]) -> Result<Response, ClientError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .and_then(|value| value.try_into().ok())
        .ok_or(ClientError::Protocol)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES || frame.len() != length + 4 {
        return Err(ClientError::Protocol);
    }
    let response = decode_response(&frame[4..]).map_err(|_| ClientError::Protocol)?;
    if response.request_id() != id {
        return Err(ClientError::Protocol);
    }
    Ok(response.into_response())
}

#[cfg(windows)]
fn request_pipe(pipe: &str, frame: &[u8]) -> Result<Vec<u8>, ClientError> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    use hyu_vpn_platform_windows::authorize_pipe_server_system;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    let pipe_wide: Vec<u16> = pipe.encode_utf16().chain(std::iter::once(0)).collect();
    let ready = unsafe { WaitNamedPipeW(pipe_wide.as_ptr(), 500) };
    if ready == 0 {
        return Err(ClientError::Unavailable);
    }
    let mut stream = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_WRITE_THROUGH)
        .open(pipe)
        .map_err(|_| ClientError::Unavailable)?;
    let raw = stream.as_raw_handle().cast();
    unsafe { authorize_pipe_server_system(raw) }.map_err(|_| ClientError::Unavailable)?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|_| ClientError::Unavailable)?;
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| ClientError::Unavailable)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ClientError::Protocol);
    }
    let mut response = Vec::with_capacity(length + 4);
    response.extend_from_slice(&prefix);
    response.resize(length + 4, 0);
    stream
        .read_exact(&mut response[4..])
        .map_err(|_| ClientError::Unavailable)?;
    Ok(response)
}

#[cfg(not(windows))]
fn request_pipe(_pipe: &str, _frame: &[u8]) -> Result<Vec<u8>, ClientError> {
    Err(ClientError::Unavailable)
}
