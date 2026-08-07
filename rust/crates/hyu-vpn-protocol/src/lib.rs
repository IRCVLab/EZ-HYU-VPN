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

impl RequestEnvelope {
    pub fn new(request_id: impl Into<String>, request: Request) -> Self {
        Self {
            schema_version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            request,
        }
    }
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

#[derive(Serialize)]
struct WireRequestRef<'a> {
    schema_version: u16,
    request_id: &'a str,
    command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<&'a Credentials>,
}

pub fn encode_request(request: &RequestEnvelope) -> Result<Vec<u8>, ProtocolError> {
    if request.schema_version != PROTOCOL_VERSION || !valid_request_id(&request.request_id) {
        return Err(ProtocolError::InvalidRequest);
    }
    let (command, credentials) = match &request.request {
        Request::Status => ("status", None),
        Request::Connect => ("connect", None),
        Request::Disconnect => ("disconnect", None),
        Request::Reconnect => ("reconnect", None),
        Request::AutomaticOn => ("automatic_on", None),
        Request::AutomaticOff => ("automatic_off", None),
        Request::CredentialsPresent => ("credentials_present", None),
        Request::ReplaceCredentials { credentials } => ("replace_credentials", Some(credentials)),
        Request::CurrentOtp => ("current_otp", None),
    };
    let encoded = serde_json::to_vec(&WireRequestRef {
        schema_version: request.schema_version,
        request_id: &request.request_id,
        command,
        credentials,
    })
    .map_err(|_| ProtocolError::InvalidDocument)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(encoded)
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
#[serde(try_from = "WireVpnStatus", deny_unknown_fields)]
pub struct VpnStatus {
    pub schema_version: u16,
    pub state: VpnState,
    pub automatic_reconnect_enabled: bool,
    pub connected_at: Option<String>,
    pub session_expires_at: Option<String>,
    pub last_successful_hip_at: Option<String>,
    pub tunnel_interface: Option<String>,
    pub next_retry_at: Option<String>,
    pub error_code: Option<ErrorCode>,
    pub last_transition_at: String,
    pub backend_build_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVpnStatus {
    schema_version: u16,
    state: VpnState,
    automatic_reconnect_enabled: bool,
    connected_at: Option<String>,
    session_expires_at: Option<String>,
    last_successful_hip_at: Option<String>,
    tunnel_interface: Option<String>,
    next_retry_at: Option<String>,
    error_code: Option<ErrorCode>,
    last_transition_at: String,
    backend_build_version: Option<String>,
}

impl TryFrom<WireVpnStatus> for VpnStatus {
    type Error = &'static str;

    fn try_from(value: WireVpnStatus) -> Result<Self, Self::Error> {
        if value.schema_version != PROTOCOL_VERSION {
            return Err("unsupported status version");
        }
        for timestamp in [
            value.connected_at.as_deref(),
            value.session_expires_at.as_deref(),
            value.last_successful_hip_at.as_deref(),
            value.next_retry_at.as_deref(),
            Some(value.last_transition_at.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
                .map_err(|_| "invalid status timestamp")?;
        }
        if let Some(interface) = value.tunnel_interface.as_deref() {
            let mut bytes = interface.bytes();
            if interface.len() > 64
                || !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
                || !bytes
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err("invalid tunnel interface");
            }
        }
        if let Some(version) = value.backend_build_version.as_deref() {
            let mut bytes = version.bytes();
            if version.len() > 128
                || !bytes
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !bytes.all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
                })
            {
                return Err("invalid backend build version");
            }
        }
        Ok(Self {
            schema_version: value.schema_version,
            state: value.state,
            automatic_reconnect_enabled: value.automatic_reconnect_enabled,
            connected_at: value.connected_at,
            session_expires_at: value.session_expires_at,
            last_successful_hip_at: value.last_successful_hip_at,
            tunnel_interface: value.tunnel_interface,
            next_retry_at: value.next_retry_at,
            error_code: value.error_code,
            last_transition_at: value.last_transition_at,
            backend_build_version: value.backend_build_version,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn response(&self) -> &Response {
        &self.response
    }

    pub fn into_response(self) -> Response {
        self.response
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

pub fn decode_response(frame: &[u8]) -> Result<ResponseEnvelope, ProtocolError> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let response: ResponseEnvelope =
        serde_json::from_slice(frame).map_err(|_| ProtocolError::InvalidDocument)?;
    if response.schema_version != PROTOCOL_VERSION || !valid_request_id(&response.request_id) {
        return Err(ProtocolError::InvalidDocument);
    }
    Ok(response)
}
