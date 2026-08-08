use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use hyu_vpn_core::credentials::CredentialEnvelope;
use hyu_vpn_daemon::runtime::{CredentialRepository, RepositoryError};
use hyu_vpn_protocol::Credentials;

const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct LinuxPaths {
    pub state_dir: PathBuf,
    pub credential_key: PathBuf,
    pub credentials: PathBuf,
    pub runtime_dir: PathBuf,
    pub socket: PathBuf,
}

impl LinuxPaths {
    pub fn production() -> Self {
        Self {
            state_dir: "/var/lib/hyu-vpn".into(),
            credential_key: "/var/lib/hyu-vpn/credentials.key".into(),
            credentials: "/var/lib/hyu-vpn/credentials.enc".into(),
            runtime_dir: "/run/hyu-vpn".into(),
            socket: "/run/hyu-vpn/daemon.sock".into(),
        }
    }

    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            state_dir: root.join("var/lib/hyu-vpn"),
            credential_key: root.join("var/lib/hyu-vpn/credentials.key"),
            credentials: root.join("var/lib/hyu-vpn/credentials.enc"),
            runtime_dir: root.join("run/hyu-vpn"),
            socket: root.join("run/hyu-vpn/daemon.sock"),
        }
    }
}

pub struct LinuxCredentialRepository {
    paths: LinuxPaths,
    required_uid: u32,
}

impl LinuxCredentialRepository {
    pub fn new(paths: LinuxPaths, required_uid: u32) -> Self {
        Self {
            paths,
            required_uid,
        }
    }

    fn prepare_directory(&self) -> Result<(), RepositoryError> {
        if self.paths.state_dir.exists() {
            validate_directory(&self.paths.state_dir, self.required_uid)?;
        } else {
            fs::create_dir_all(&self.paths.state_dir).map_err(|_| RepositoryError::Storage)?;
            fs::set_permissions(&self.paths.state_dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| RepositoryError::Storage)?;
            validate_directory(&self.paths.state_dir, self.required_uid)?;
        }
        Ok(())
    }

    fn load_key(&self) -> Result<Vec<u8>, RepositoryError> {
        read_private_file(&self.paths.credential_key, self.required_uid, 32)
    }

    fn load_or_create_key(&self) -> Result<Vec<u8>, RepositoryError> {
        if self.paths.credential_key.exists() {
            return self.load_key();
        }
        let mut key = vec![0_u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut key))
            .map_err(|_| RepositoryError::Storage)?;
        atomic_private_write(&self.paths.credential_key, &key)?;
        self.load_key()
    }
}

impl CredentialRepository for LinuxCredentialRepository {
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
            MAX_CREDENTIAL_BYTES as usize,
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

fn validate_directory(path: &Path, required_uid: u32) -> Result<(), RepositoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryError::Storage)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(RepositoryError::Storage);
    }
    Ok(())
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
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES as usize {
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
            .map_err(|_| RepositoryError::Storage)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
