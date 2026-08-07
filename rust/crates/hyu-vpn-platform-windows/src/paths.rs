use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPaths {
    pub install_dir: PathBuf,
    pub state_dir: PathBuf,
    pub credentials: PathBuf,
    pub protected_key: PathBuf,
    pub automatic_reconnect: PathBuf,
    pub openconnect: PathBuf,
    pub vpnc_script: PathBuf,
    pub hip_wrapper: PathBuf,
    pub pipe_name: String,
}

impl WindowsPaths {
    pub fn production() -> Self {
        #[cfg(windows)]
        let root = PathBuf::from(
            std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into()),
        );
        #[cfg(not(windows))]
        let root = PathBuf::from("/ProgramData");
        Self::from_program_data(root)
    }

    pub fn under(root: impl AsRef<Path>) -> Self {
        Self::from_program_data(root.as_ref().join("ProgramData"))
    }

    fn from_program_data(program_data: PathBuf) -> Self {
        let state_dir = program_data.join("HYUVPN");
        #[cfg(windows)]
        let install_dir = PathBuf::from(
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into()),
        )
        .join("HYU VPN");
        #[cfg(not(windows))]
        let install_dir = PathBuf::from("/Program Files/HYU VPN");
        Self {
            install_dir: install_dir.clone(),
            credentials: state_dir.join("credentials.enc"),
            protected_key: state_dir.join("credentials.dpapi"),
            automatic_reconnect: state_dir.join("automatic-reconnect"),
            openconnect: install_dir.join("runtime").join("openconnect.exe"),
            vpnc_script: install_dir.join("runtime").join("vpnc-script-win.js"),
            hip_wrapper: install_dir.join("hyu-vpn-hip.exe"),
            state_dir,
            pipe_name: r"\\.\pipe\hyu-vpn-v1".to_owned(),
        }
    }
}
