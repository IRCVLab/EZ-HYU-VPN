use std::os::fd::AsRawFd;

use thiserror::Error;
use tokio::net::UnixStream;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PeerAuthorizationError {
    #[error("unable to authenticate local IPC peer")]
    QueryFailed,
}

pub fn peer_uid(stream: &UnixStream) -> Result<u32, PeerAuthorizationError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(PeerAuthorizationError::QueryFailed);
    }
    Ok(credentials.uid)
}

pub fn authorize_peer_uid(
    stream: &UnixStream,
    expected_uid: u32,
) -> Result<bool, PeerAuthorizationError> {
    Ok(peer_uid(stream)? == expected_uid)
}
