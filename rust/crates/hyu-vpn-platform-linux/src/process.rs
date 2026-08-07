use std::path::PathBuf;

use hyu_vpn_core::openconnect::{ConnectorConfig, ConnectorConfigError, build_openconnect_args};
use hyu_vpn_protocol::Credentials;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    #[error("invalid OpenConnect launch configuration")]
    InvalidConfiguration,
}

impl From<ConnectorConfigError> for LaunchError {
    fn from(_: ConnectorConfigError) -> Self {
        Self::InvalidConfiguration
    }
}

pub struct OpenConnectLaunch {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub environment: Vec<(String, String)>,
    stdin: Zeroizing<Vec<u8>>,
}

impl OpenConnectLaunch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executable: &str,
        portal: &str,
        authgroup: &str,
        vpnc_script: &str,
        hip_wrapper: &str,
        credentials: &Credentials,
        otp: &str,
    ) -> Result<Self, LaunchError> {
        if otp.len() != 6 || !otp.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(LaunchError::InvalidConfiguration);
        }
        let config = ConnectorConfig {
            executable: executable.into(),
            portal: portal.to_owned(),
            authgroup: authgroup.to_owned(),
            vpnc_script: vpnc_script.into(),
            hip_wrapper: hip_wrapper.into(),
        };
        let argv = build_openconnect_args(&config)?;
        let stdin = Zeroizing::new(
            format!(
                "{}\n{}\n{}\n",
                credentials.username(),
                credentials.password(),
                otp
            )
            .into_bytes(),
        );
        Ok(Self {
            executable: config.executable,
            argv,
            environment: Vec::new(),
            stdin,
        })
    }

    pub fn stdin_payload(&self) -> &[u8] {
        self.stdin.as_slice()
    }
}

pub struct ManagedChild {
    child: tokio::process::Child,
    pid: u32,
}

impl ManagedChild {
    pub async fn spawn(
        executable: &str,
        argv: &[&str],
        stdin_payload: &[u8],
    ) -> Result<Self, LaunchError> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;

        if !executable.starts_with('/') || executable.chars().any(char::is_control) {
            return Err(LaunchError::InvalidConfiguration);
        }
        let mut command = tokio::process::Command::new(executable);
        command
            .args(argv)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| LaunchError::InvalidConfiguration)?;
        let pid = child.id().ok_or(LaunchError::InvalidConfiguration)?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_payload)
                .await
                .map_err(|_| LaunchError::InvalidConfiguration)?;
            stdin
                .shutdown()
                .await
                .map_err(|_| LaunchError::InvalidConfiguration)?;
        }
        Ok(Self { child, pid })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub async fn terminate(mut self, timeout: std::time::Duration) -> Result<(), LaunchError> {
        let process_group = -(self.pid as i32);
        unsafe {
            libc::kill(process_group, libc::SIGTERM);
        }
        if tokio::time::timeout(timeout, self.child.wait())
            .await
            .is_err()
        {
            unsafe {
                libc::kill(process_group, libc::SIGKILL);
            }
            self.child
                .wait()
                .await
                .map_err(|_| LaunchError::InvalidConfiguration)?;
        }
        Ok(())
    }
}
