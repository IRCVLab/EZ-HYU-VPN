use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCode {
    AuthenticationFailed,
    PortalUnreachable,
    ConnectTimeout,
    CredentialStoreFailure,
    UnsafeNetworkState,
    ServiceUnavailable,
    ProtocolMismatch,
}

impl DiagnosticCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::PortalUnreachable => "PORTAL_UNREACHABLE",
            Self::ConnectTimeout => "CONNECT_TIMEOUT",
            Self::CredentialStoreFailure => "CREDENTIAL_STORE_FAILURE",
            Self::UnsafeNetworkState => "UNSAFE_NETWORK_STATE",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::ProtocolMismatch => "PROTOCOL_MISMATCH",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RedactedError {
    code: DiagnosticCode,
}

impl RedactedError {
    pub fn from_source(code: DiagnosticCode, _untrusted_source: &str) -> Self {
        Self { code }
    }

    pub const fn code(self) -> &'static str {
        self.code.as_str()
    }
}

impl Display for RedactedError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Debug for RedactedError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedactedError")
            .field("code", &self.code.as_str())
            .finish()
    }
}

impl std::error::Error for RedactedError {}
