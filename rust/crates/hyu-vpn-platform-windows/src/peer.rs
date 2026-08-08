use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PeerAuthorizationError {
    #[error("named pipe peer is not authorized")]
    Unauthorized,
}

pub fn authorize_pipe_client_sid(
    expected: &str,
    actual: &str,
) -> Result<(), PeerAuthorizationError> {
    if !valid_sid(expected) || !valid_sid(actual) || expected != actual {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    Ok(())
}

fn valid_sid(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() <= 184
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
        && value.bytes().filter(|byte| *byte == b'-').count() >= 3
}

#[cfg(windows)]
unsafe fn token_user_buffer(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<Vec<usize>, PeerAuthorizationError> {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser};

    let mut required = 0_u32;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
    }
    if required == 0 || required > 64 * 1024 {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    let word = std::mem::size_of::<usize>();
    let words = (required as usize).div_ceil(word);
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    Ok(buffer)
}

#[cfg(windows)]
unsafe fn open_process_token_for_pid(
    process_id: u32,
) -> Result<
    (
        windows_sys::Win32::Foundation::HANDLE,
        windows_sys::Win32::Foundation::HANDLE,
    ),
    PeerAuthorizationError,
> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(process) };
        return Err(PeerAuthorizationError::Unauthorized);
    }
    Ok((process, token))
}

#[cfg(windows)]
unsafe fn token_user_sid(buffer: &[usize]) -> windows_sys::Win32::Security::PSID {
    let user = unsafe {
        &*buffer
            .as_ptr()
            .cast::<windows_sys::Win32::Security::TOKEN_USER>()
    };
    user.User.Sid
}

#[cfg(windows)]
/// Authorizes a connected client as the user logged into that client's own
/// console or Remote Desktop session.
///
/// # Safety
/// `pipe` must be a valid connected named-pipe server handle owned by the caller.
pub unsafe fn authorize_active_pipe_client(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), PeerAuthorizationError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::EqualSid;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSQueryUserToken};

    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    let mut client_session = u32::MAX;
    if unsafe { ProcessIdToSessionId(process_id, &mut client_session) } == 0
        || client_session == u32::MAX
    {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    let mut session_token = std::ptr::null_mut();
    if unsafe { WTSQueryUserToken(client_session, &mut session_token) } == 0
        || session_token.is_null()
    {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    let (client_process, client_token) = match unsafe { open_process_token_for_pid(process_id) } {
        Ok(value) => value,
        Err(error) => {
            unsafe { CloseHandle(session_token) };
            return Err(error);
        }
    };
    let result = (|| {
        let session_user = unsafe { token_user_buffer(session_token) }?;
        let client_user = unsafe { token_user_buffer(client_token) }?;
        let session_sid = unsafe { token_user_sid(&session_user) };
        let client_sid = unsafe { token_user_sid(&client_user) };
        if session_sid.is_null()
            || client_sid.is_null()
            || unsafe { EqualSid(session_sid, client_sid) } == 0
        {
            return Err(PeerAuthorizationError::Unauthorized);
        }
        Ok(())
    })();
    unsafe {
        CloseHandle(client_token);
        CloseHandle(client_process);
        CloseHandle(session_token);
    }
    result
}

#[cfg(windows)]
/// Verifies that a connected pipe client is talking to a LocalSystem server
/// before any credential-bearing bytes are written.
///
/// # Safety
/// `pipe` must be a valid connected named-pipe client handle owned by the caller.
pub unsafe fn authorize_pipe_server_system(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), PeerAuthorizationError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{IsWellKnownSid, WinLocalSystemSid};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        return Err(PeerAuthorizationError::Unauthorized);
    }
    let (process, token) = unsafe { open_process_token_for_pid(process_id) }?;
    let result = (|| {
        let user = unsafe { token_user_buffer(token) }?;
        let sid = unsafe { token_user_sid(&user) };
        if sid.is_null() || unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } == 0 {
            return Err(PeerAuthorizationError::Unauthorized);
        }
        Ok(())
    })();
    unsafe {
        CloseHandle(token);
        CloseHandle(process);
    }
    result
}
