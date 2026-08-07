use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AutostartError {
    #[error("unable to update launch-at-login")]
    UpdateFailed,
}

pub struct AutostartManager {
    path: PathBuf,
    executable: String,
}

impl AutostartManager {
    pub fn new(path: impl AsRef<Path>, executable: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            executable: executable.into(),
        }
    }

    pub fn is_enabled(&self) -> Result<bool, AutostartError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
            Ok(_) => Err(AutostartError::UpdateFailed),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(AutostartError::UpdateFailed),
        }
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), AutostartError> {
        if enabled {
            self.enable()
        } else {
            self.disable()
        }
    }

    fn enable(&self) -> Result<(), AutostartError> {
        if self.executable.is_empty()
            || !self.executable.starts_with('/')
            || self.executable.chars().any(char::is_control)
        {
            return Err(AutostartError::UpdateFailed);
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AutostartError::UpdateFailed);
            }
        }
        let parent = self.path.parent().ok_or(AutostartError::UpdateFailed)?;
        fs::create_dir_all(parent).map_err(|_| AutostartError::UpdateFailed)?;
        let temporary = parent.join(format!(".hyu-vpn.{}.tmp", std::process::id()));
        let document = format!(
            "[Desktop Entry]\nType=Application\nName=HYU VPN\nExec={}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            self.executable
        );
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| AutostartError::UpdateFailed)?;
            file.write_all(document.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| AutostartError::UpdateFailed)?;
            fs::rename(&temporary, &self.path).map_err(|_| AutostartError::UpdateFailed)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|_| AutostartError::UpdateFailed)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn disable(&self) -> Result<(), AutostartError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(&self.path).map_err(|_| AutostartError::UpdateFailed)
            }
            Ok(_) => Err(AutostartError::UpdateFailed),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AutostartError::UpdateFailed),
        }
    }
}
