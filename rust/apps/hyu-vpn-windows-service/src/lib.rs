#[cfg(windows)]
mod runtime;
#[cfg(windows)]
pub use runtime::run_daemon;

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

pub const SERVICE_NAME: &str = "HYUVPN";
pub const SERVICE_DISPLAY_NAME: &str = "HYU VPN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsServiceConfig {
    pub pipe_name: String,
    pub maximum_frame_bytes: usize,
    pub reject_remote_clients: bool,
    pub require_active_interactive_session: bool,
}

impl WindowsServiceConfig {
    pub fn production() -> Self {
        Self {
            pipe_name: r"\\.\pipe\hyu-vpn-v1".to_owned(),
            maximum_frame_bytes: 64 * 1024,
            reject_remote_clients: true,
            require_active_interactive_session: true,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStateError {
    #[error("service state is invalid")]
    InvalidState,
}

#[derive(Debug, Clone)]
pub struct AutomaticPreference {
    path: PathBuf,
}

impl AutomaticPreference {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn load(&self) -> Result<bool, ServiceStateError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(_) => return Err(ServiceStateError::InvalidState),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8 {
            return Err(ServiceStateError::InvalidState);
        }
        let mut value = String::new();
        OpenOptions::new()
            .read(true)
            .open(&self.path)
            .and_then(|file| file.take(9).read_to_string(&mut value))
            .map_err(|_| ServiceStateError::InvalidState)?;
        match value.as_str() {
            "true\n" => Ok(true),
            "false\n" => Ok(false),
            _ => Err(ServiceStateError::InvalidState),
        }
    }

    pub fn store(&self, enabled: bool) -> Result<(), ServiceStateError> {
        let parent = self.path.parent().ok_or(ServiceStateError::InvalidState)?;
        fs::create_dir_all(parent).map_err(|_| ServiceStateError::InvalidState)?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| ServiceStateError::InvalidState)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ServiceStateError::InvalidState);
        }
        let temporary = parent.join(format!(
            ".{}.tmp-{}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ServiceStateError::InvalidState)?,
            std::process::id()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| ServiceStateError::InvalidState)?;
            file.write_all(if enabled { b"true\n" } else { b"false\n" })
                .and_then(|()| file.sync_all())
                .map_err(|_| ServiceStateError::InvalidState)?;
            if self.path.exists() {
                let metadata = fs::symlink_metadata(&self.path)
                    .map_err(|_| ServiceStateError::InvalidState)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(ServiceStateError::InvalidState);
                }
                fs::remove_file(&self.path).map_err(|_| ServiceStateError::InvalidState)?;
            }
            fs::rename(&temporary, &self.path).map_err(|_| ServiceStateError::InvalidState)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[derive(Default)]
pub struct NetworkReadinessTracker {
    candidate: Option<hyu_vpn_core::state::NetworkIdentity>,
    stable_samples: u8,
    published: Option<hyu_vpn_core::state::NetworkIdentity>,
}

impl NetworkReadinessTracker {
    pub fn portal_probe_required(
        &self,
        sample: Option<&hyu_vpn_core::state::NetworkIdentity>,
    ) -> bool {
        sample.is_some() && sample != self.published.as_ref()
    }

    pub fn observe(
        &mut self,
        sample: Option<hyu_vpn_core::state::NetworkIdentity>,
        portal_reachable: bool,
    ) -> Option<hyu_vpn_core::state::EngineEvent> {
        use hyu_vpn_core::state::EngineEvent;
        let ready = match sample {
            Some(identity) if self.published.as_ref() == Some(&identity) || portal_reachable => {
                Some(identity)
            }
            _ => None,
        };
        if ready == self.candidate {
            self.stable_samples = self.stable_samples.saturating_add(1);
        } else {
            self.candidate = ready.clone();
            self.stable_samples = 1;
        }
        if self.stable_samples < 2 || ready == self.published {
            return None;
        }
        self.published = ready.clone();
        Some(match ready {
            Some(identity) => EngineEvent::NetworkReady(identity),
            None => EngineEvent::NetworkUnavailable,
        })
    }
}
