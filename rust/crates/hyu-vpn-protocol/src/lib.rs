use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_USERNAME_BYTES: usize = 256;
const MAX_PASSWORD_BYTES: usize = 4096;
const MAX_TOTP_SEED_BYTES: usize = 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("protocol frame is too large")]
    FrameTooLarge,
    #[error("invalid protocol document")]
    InvalidDocument,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("invalid request")]
    InvalidRequest,
    #[error("invalid credentials")]
    InvalidCredentials,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    schema_version: u16,
    request_id: String,
    command: String,
    #[serde(default)]
    credentials: Option<Credentials>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RequestEnvelope {
    pub schema_version: u16,
    pub request_id: String,
    pub request: Request,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Status,
    Connect,
    Disconnect,
    Reconnect,
    AutomaticOn,
    AutomaticOff,
    CredentialsPresent,
    ReplaceCredentials { credentials: Credentials },
    CurrentOtp,
}

pub fn decode_request(frame: &[u8]) -> Result<RequestEnvelope, ProtocolError> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let wire: WireRequest =
        serde_json::from_slice(frame).map_err(|_| ProtocolError::InvalidDocument)?;
    if wire.schema_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if !valid_request_id(&wire.request_id) {
        return Err(ProtocolError::InvalidRequest);
    }
    let request = match (wire.command.as_str(), wire.credentials) {
        ("status", None) => Request::Status,
        ("connect", None) => Request::Connect,
        ("disconnect", None) => Request::Disconnect,
        ("reconnect", None) => Request::Reconnect,
        ("automatic_on", None) => Request::AutomaticOn,
        ("automatic_off", None) => Request::AutomaticOff,
        ("credentials_present", None) => Request::CredentialsPresent,
        ("replace_credentials", Some(credentials)) => Request::ReplaceCredentials { credentials },
        ("current_otp", None) => Request::CurrentOtp,
        _ => return Err(ProtocolError::InvalidRequest),
    };
    Ok(RequestEnvelope {
        schema_version: wire.schema_version,
        request_id: wire.request_id,
        request,
    })
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    username: String,
    password: String,
    totp_seed: String,
}

impl Credentials {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        totp_seed: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            username: username.into(),
            password: password.into(),
            totp_seed: totp_seed.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn totp_seed(&self) -> &str {
        &self.totp_seed
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if !bounded_nonempty(&self.username, MAX_USERNAME_BYTES)
            || !bounded_nonempty(&self.password, MAX_PASSWORD_BYTES)
            || !bounded_nonempty(&self.totp_seed, MAX_TOTP_SEED_BYTES)
            || self.username.chars().any(char::is_control)
            || self.password.contains('\0')
            || self.totp_seed.chars().any(char::is_control)
        {
            return Err(ProtocolError::InvalidCredentials);
        }
        Ok(())
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Credentials([REDACTED])")
    }
}

fn bounded_nonempty(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VpnState {
    Disabled,
    WaitingForNetwork,
    Connecting,
    Connected,
    Disconnecting,
    Backoff,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    AuthenticationFailed,
    PortalUnreachable,
    ConnectTimeoutNoTunnel,
    NetworkScriptFailed,
    RepairRequired,
    ServiceUnavailable,
    ProtocolMismatch,
    CredentialStoreFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VpnStatus {
    pub state: VpnState,
    pub automatic_reconnect_enabled: bool,
    pub connected_at: Option<String>,
    pub session_expires_at: Option<String>,
    pub last_successful_hip_at: Option<String>,
    pub tunnel_interface: Option<String>,
    pub next_retry_at: Option<String>,
    pub error_code: Option<ErrorCode>,
    pub backend_build_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResponseEnvelope {
    schema_version: u16,
    request_id: String,
    #[serde(flatten)]
    response: Response,
}

impl ResponseEnvelope {
    pub fn new(request_id: impl Into<String>, response: Response) -> Self {
        Self {
            schema_version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            response,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ack,
    Status { status: VpnStatus },
    CredentialsPresent { present: bool },
    CurrentOtp { code: String, remaining_seconds: u8 },
    Error { error_code: ErrorCode },
}

pub fn encode_response(response: &ResponseEnvelope) -> Result<Vec<u8>, ProtocolError> {
    let encoded = serde_json::to_vec(response).map_err(|_| ProtocolError::InvalidDocument)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(encoded)
}
