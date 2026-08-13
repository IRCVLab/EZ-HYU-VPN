use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use hyu_vpn_core::credentials::CredentialEnvelope;
use hyu_vpn_daemon::runtime::{CredentialRepository, RepositoryError};
use hyu_vpn_protocol::Credentials;
use zeroize::Zeroizing;

use crate::paths::validate_state_directory;
use crate::{MacPaths, PlatformError};

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const KEY_BYTES: usize = 32;

pub struct MacCredentialRepository {
    paths: MacPaths,
    required_uid: u32,
}

impl MacCredentialRepository {
    pub fn new(paths: MacPaths, required_uid: u32) -> Self {
        Self {
            paths,
            required_uid,
        }
    }

    pub fn production(home: &Path) -> Result<Self, PlatformError> {
        let paths = MacPaths::production(home)?;
        let uid = fs::symlink_metadata(home)
            .or_else(|_| fs::symlink_metadata(&paths.state_dir))
            .map_err(|_| PlatformError::InvalidPath)?
            .uid();
        Ok(Self::new(paths, uid))
    }

    fn prepare_directory(&self) -> Result<(), RepositoryError> {
        if self.paths.state_dir.exists() {
            validate_state_directory(&self.paths.state_dir, self.required_uid)
                .map_err(|_| RepositoryError::Storage)?;
        } else {
            fs::create_dir_all(&self.paths.state_dir).map_err(|_| RepositoryError::Storage)?;
            fs::set_permissions(&self.paths.state_dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| RepositoryError::Storage)?;
            validate_state_directory(&self.paths.state_dir, self.required_uid)
                .map_err(|_| RepositoryError::Storage)?;
        }
        Ok(())
    }

    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, RepositoryError> {
        let key = read_private_file(&self.paths.credential_key, self.required_uid, KEY_BYTES)?;
        if key.len() != KEY_BYTES {
            return Err(RepositoryError::Corrupt);
        }
        Ok(Zeroizing::new(key))
    }

    fn load_or_create_key(&self) -> Result<Zeroizing<Vec<u8>>, RepositoryError> {
        if self.paths.credential_key.exists() {
            return self.load_key();
        }
        let mut key = Zeroizing::new(vec![0_u8; KEY_BYTES]);
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut key))
            .map_err(|_| RepositoryError::Storage)?;
        atomic_private_write(&self.paths.credential_key, &key)?;
        self.load_key()
    }
}

impl CredentialRepository for MacCredentialRepository {
    fn present(&self) -> Result<bool, RepositoryError> {
        self.prepare_directory()?;
        match (
            self.paths.credential_key.try_exists(),
            self.paths.credentials.try_exists(),
        ) {
            (Ok(false), Ok(false)) => Ok(false),
            (Ok(true), Ok(true)) => self.load().map(|_| true),
            _ => Err(RepositoryError::Corrupt),
        }
    }

    fn load(&self) -> Result<Credentials, RepositoryError> {
        self.prepare_directory()?;
        let key = self.load_key()?;
        let envelope = read_private_file(
            &self.paths.credentials,
            self.required_uid,
            MAX_CREDENTIAL_BYTES,
        )?;
        CredentialEnvelope::open(&key, &envelope).map_err(|_| RepositoryError::Corrupt)
    }

    fn replace(&self, credentials: Credentials) -> Result<(), RepositoryError> {
        self.prepare_directory()?;
        let key = self.load_or_create_key()?;
        let envelope =
            CredentialEnvelope::seal(&key, &credentials).map_err(|_| RepositoryError::Storage)?;
        atomic_private_write(&self.paths.credentials, &envelope)
    }
}

fn read_private_file(
    path: &Path,
    required_uid: u32,
    maximum: usize,
) -> Result<Vec<u8>, RepositoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryError::Missing)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(RepositoryError::Corrupt);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| RepositoryError::Storage)?;
    let mut value = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut value)
        .map_err(|_| RepositoryError::Storage)?;
    if value.len() > maximum {
        return Err(RepositoryError::Corrupt);
    }
    Ok(value)
}

fn atomic_private_write(path: &Path, value: &[u8]) -> Result<(), RepositoryError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES {
        return Err(RepositoryError::Storage);
    }
    let parent = path.parent().ok_or(RepositoryError::Storage)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(RepositoryError::Storage)?,
        std::process::id()
    ));
    let result = (|| {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                let parent_uid = fs::symlink_metadata(parent)
                    .map_err(|_| RepositoryError::Storage)?
                    .uid();
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != parent_uid
                    || metadata.permissions().mode() & 0o777 != 0o600
                {
                    return Err(RepositoryError::Storage);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RepositoryError::Storage),
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| RepositoryError::Storage)?;
        file.write_all(value)
            .and_then(|()| file.sync_all())
            .map_err(|_| RepositoryError::Storage)?;
        fs::rename(&temporary, path).map_err(|_| RepositoryError::Storage)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RepositoryError::Storage)?;
        fsync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn fsync_parent(parent: &Path) -> Result<(), RepositoryError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RepositoryError::Storage)
}
