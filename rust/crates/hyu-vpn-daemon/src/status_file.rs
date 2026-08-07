use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hyu_vpn_protocol::VpnStatus;
use thiserror::Error;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StatusFileError {
    #[error("status file operation failed")]
    WriteFailed,
}

pub struct AtomicStatusFile {
    path: PathBuf,
}

impl AtomicStatusFile {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn write(&self, status: &VpnStatus) -> Result<(), StatusFileError> {
        let payload = serde_json::to_vec(status).map_err(|_| StatusFileError::WriteFailed)?;
        if payload.len() > 64 * 1024 {
            return Err(StatusFileError::WriteFailed);
        }
        let parent = self.path.parent().ok_or(StatusFileError::WriteFailed)?;
        fs::create_dir_all(parent).map_err(|_| StatusFileError::WriteFailed)?;
        let temporary = self.path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| StatusFileError::WriteFailed)?;
            set_owner_only_permissions(&temporary)?;
            file.write_all(&payload)
                .and_then(|()| file.sync_all())
                .map_err(|_| StatusFileError::WriteFailed)?;
            fs::rename(&temporary, &self.path).map_err(|_| StatusFileError::WriteFailed)?;
            set_owner_only_permissions(&self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), StatusFileError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| StatusFileError::WriteFailed)
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), StatusFileError> {
    Ok(())
}
