use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    #[error("invalid platform path")]
    InvalidPath,
    #[error("insecure state directory")]
    InsecureStateDirectory,
    #[error("invalid network evidence")]
    InvalidNetworkEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacPaths {
    pub state_dir: PathBuf,
    pub credential_key: PathBuf,
    pub credentials: PathBuf,
    pub socket: PathBuf,
    pub status: PathBuf,
    pub automatic_reconnect: PathBuf,
    pub totp_counter: PathBuf,
    pub helper: PathBuf,
}

impl MacPaths {
    pub fn production(home: &Path) -> Result<Self, PlatformError> {
        validate_absolute_bounded(home)?;
        let state_dir = home
            .join("Library")
            .join("Application Support")
            .join("hyu-openconnect");
        match fs::symlink_metadata(&state_dir) {
            Ok(_) => {
                let uid = fs::symlink_metadata(home)
                    .map(|metadata| metadata.uid())
                    .or_else(|_| fs::symlink_metadata(&state_dir).map(|metadata| metadata.uid()))
                    .map_err(|_| PlatformError::InsecureStateDirectory)?;
                Self::validate_state_dir_for_owner(&state_dir, uid)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PlatformError::InsecureStateDirectory),
        }
        Ok(Self::from_state_and_helper(
            state_dir,
            PathBuf::from("/Library/PrivilegedHelperTools/com.hyu.vpn.helper"),
        ))
    }

    pub fn under(root: &Path, uid: u32) -> Self {
        assert!(
            validate_absolute_bounded(root).is_ok(),
            "MacPaths::under root must be absolute and normalized"
        );
        let state_dir = root
            .join(uid.to_string())
            .join("Library")
            .join("Application Support")
            .join("hyu-openconnect");
        Self::from_state_and_helper(
            state_dir,
            root.join("Library/PrivilegedHelperTools/com.hyu.vpn.helper"),
        )
    }

    pub fn validate_state_dir_for_owner(
        path: &Path,
        required_uid: u32,
    ) -> Result<(), PlatformError> {
        validate_state_directory(path, required_uid)
    }

    fn from_state_and_helper(state_dir: PathBuf, helper: PathBuf) -> Self {
        Self {
            credential_key: state_dir.join("credentials.key"),
            credentials: state_dir.join("credentials.enc"),
            socket: state_dir.join("daemon.sock"),
            status: state_dir.join("status.json"),
            automatic_reconnect: state_dir.join("automatic-reconnect"),
            totp_counter: state_dir.join("totp-counter"),
            state_dir,
            helper,
        }
    }
}

pub(crate) fn validate_state_directory(
    path: &Path,
    required_uid: u32,
) -> Result<(), PlatformError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PlatformError::InsecureStateDirectory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(PlatformError::InsecureStateDirectory);
    }
    Ok(())
}

fn validate_absolute_bounded(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(PlatformError::InvalidPath);
    }
    Ok(())
}
