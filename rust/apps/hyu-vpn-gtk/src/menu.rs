use hyu_vpn_protocol::{VpnState, VpnStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuCommand {
    Connect,
    Disconnect,
    Reconnect,
    CopyOtp,
    ChangeCredentials,
    ToggleAutostart,
    Quit,
}

impl MenuCommand {
    pub fn protocol_commands(self) -> &'static [&'static str] {
        match self {
            Self::Connect => &["connect"],
            Self::Disconnect => &["disconnect"],
            Self::Reconnect => &["reconnect"],
            Self::CopyOtp => &["current_otp"],
            Self::ChangeCredentials => &["replace_credentials"],
            Self::ToggleAutostart | Self::Quit => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuModel {
    pub status_label: String,
    pub otp_label: Option<String>,
    pub connect_enabled: bool,
    pub disconnect_enabled: bool,
    pub reconnect_enabled: bool,
    pub launch_at_login: bool,
}

impl MenuModel {
    pub fn project(status: &VpnStatus, otp: Option<(&str, u8)>, launch_at_login: bool) -> Self {
        let automatic = status.automatic_reconnect_enabled;
        let connect_enabled = matches!(status.state, VpnState::Disabled | VpnState::Error);
        Self {
            status_label: status_label(status.state).into(),
            otp_label: otp.map(|(code, seconds)| format!("OTP {code} · {seconds}s")),
            connect_enabled,
            disconnect_enabled: automatic,
            reconnect_enabled: automatic && status.state != VpnState::Disconnecting,
            launch_at_login,
        }
    }
}

fn status_label(state: VpnState) -> &'static str {
    match state {
        VpnState::Disabled => "Disconnected",
        VpnState::WaitingForNetwork => "Waiting for network",
        VpnState::Connecting => "Connecting…",
        VpnState::Connected => "Connected",
        VpnState::Disconnecting => "Disconnecting…",
        VpnState::Backoff => "Reconnecting…",
        VpnState::Error => "Connection error",
    }
}
