use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hyu_vpn_core::credentials::CredentialEnvelope;
use hyu_vpn_daemon::runtime::{CredentialRepository, RepositoryError};
use hyu_vpn_protocol::Credentials;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::WindowsPaths;

pub const DPAPI_DOCUMENT_VERSION: u8 = 1;
pub const PRIVATE_STATE_SDDL: &str = r"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const MAX_DOCUMENT_BYTES: usize = 4096;
const MAX_PROTECTED_KEY_BYTES: usize = 2048;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedKeyError {
    #[error("invalid protected key document")]
    InvalidDocument,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtectionError {
    #[error("key protection failed")]
    ProtectionFailed,
}

pub trait KeyProtector: Clone + Send + Sync + 'static {
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>, KeyProtectionError>;
    fn unprotect(&self, protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyProtectionError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DpapiMachineProtector;

impl KeyProtector for DpapiMachineProtector {
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>, KeyProtectionError> {
        protect_machine_key(key)
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyProtectionError> {
        unprotect_machine_key(protected)
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct WireDocument {
    version: u8,
    protected_key: Vec<u8>,
}

pub struct ProtectedKeyDocument {
    wire: WireDocument,
}

impl ProtectedKeyDocument {
    pub fn new(protected_key: Vec<u8>) -> Result<Self, ProtectedKeyError> {
        let document = Self {
            wire: WireDocument {
                version: DPAPI_DOCUMENT_VERSION,
                protected_key,
            },
        };
        document.validate()?;
        Ok(document)
    }

    pub fn version(&self) -> u8 {
        self.wire.version
    }

    pub fn protected_key(&self) -> &[u8] {
        &self.wire.protected_key
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtectedKeyError> {
        self.validate()?;
        let encoded =
            serde_json::to_vec(&self.wire).map_err(|_| ProtectedKeyError::InvalidDocument)?;
        if encoded.len() > MAX_DOCUMENT_BYTES {
            return Err(ProtectedKeyError::InvalidDocument);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtectedKeyError> {
        if encoded.is_empty() || encoded.len() > MAX_DOCUMENT_BYTES {
            return Err(ProtectedKeyError::InvalidDocument);
        }
        let wire: WireDocument =
            serde_json::from_slice(encoded).map_err(|_| ProtectedKeyError::InvalidDocument)?;
        let document = Self { wire };
        document.validate()?;
        Ok(document)
    }

    fn validate(&self) -> Result<(), ProtectedKeyError> {
        if self.wire.version != DPAPI_DOCUMENT_VERSION
            || self.wire.protected_key.len() < 32
            || self.wire.protected_key.len() > MAX_PROTECTED_KEY_BYTES
        {
            return Err(ProtectedKeyError::InvalidDocument);
        }
        Ok(())
    }
}

pub struct WindowsCredentialRepository<P = DpapiMachineProtector> {
    paths: WindowsPaths,
    protector: P,
}

impl WindowsCredentialRepository<DpapiMachineProtector> {
    pub fn production() -> Self {
        Self::new(WindowsPaths::production(), DpapiMachineProtector)
    }
}

impl<P> WindowsCredentialRepository<P>
where
    P: KeyProtector,
{
    pub fn new(paths: WindowsPaths, protector: P) -> Self {
        Self { paths, protector }
    }

    fn prepare_directory(&self) -> Result<(), RepositoryError> {
        fs::create_dir_all(&self.paths.state_dir).map_err(|_| RepositoryError::Storage)?;
        let metadata =
            fs::symlink_metadata(&self.paths.state_dir).map_err(|_| RepositoryError::Storage)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(RepositoryError::Storage);
        }
        secure_state_directory(&self.paths.state_dir)?;
        Ok(())
    }

    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, RepositoryError> {
        let encoded = read_bounded(&self.paths.protected_key, MAX_DOCUMENT_BYTES)?;
        let document =
            ProtectedKeyDocument::decode(&encoded).map_err(|_| RepositoryError::Corrupt)?;
        let key = self
            .protector
            .unprotect(document.protected_key())
            .map_err(|_| RepositoryError::Corrupt)?;
        if key.len() != 32 {
            return Err(RepositoryError::Corrupt);
        }
        Ok(key)
    }

    fn load_or_create_key(&self) -> Result<Zeroizing<Vec<u8>>, RepositoryError> {
        if self.paths.protected_key.exists() {
            return self.load_key();
        }
        let mut key = Zeroizing::new(vec![0_u8; 32]);
        fill_random(&mut key).map_err(|_| RepositoryError::Storage)?;
        let protected = self
            .protector
            .protect(&key)
            .map_err(|_| RepositoryError::Storage)?;
        let document =
            ProtectedKeyDocument::new(protected).map_err(|_| RepositoryError::Storage)?;
        atomic_write(
            &self.paths.protected_key,
            &document.encode().map_err(|_| RepositoryError::Storage)?,
        )?;
        Ok(key)
    }
}

impl<P> CredentialRepository for WindowsCredentialRepository<P>
where
    P: KeyProtector,
{
    fn present(&self) -> Result<bool, RepositoryError> {
        self.prepare_directory()?;
        match (
            self.paths.protected_key.try_exists(),
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
        let envelope = read_bounded(&self.paths.credentials, MAX_CREDENTIAL_BYTES)?;
        CredentialEnvelope::open(&key, &envelope).map_err(|_| RepositoryError::Corrupt)
    }

    fn replace(&self, credentials: Credentials) -> Result<(), RepositoryError> {
        self.prepare_directory()?;
        let key = self.load_or_create_key()?;
        let envelope =
            CredentialEnvelope::seal(&key, &credentials).map_err(|_| RepositoryError::Storage)?;
        atomic_write(&self.paths.credentials, &envelope)
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, RepositoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryError::Missing)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(RepositoryError::Corrupt);
    }
    let file = File::open(path).map_err(|_| RepositoryError::Storage)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RepositoryError::Storage)?;
    if bytes.len() > maximum {
        return Err(RepositoryError::Corrupt);
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RepositoryError> {
    let parent = path.parent().ok_or(RepositoryError::Storage)?;
    let temporary: PathBuf = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .ok_or(RepositoryError::Storage)?,
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| RepositoryError::Storage)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| RepositoryError::Storage)?;
        if path.exists() {
            let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryError::Storage)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(RepositoryError::Storage);
            }
        }
        replace_file_atomic(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(windows)]
fn replace_file_atomic(temporary: &Path, destination: &Path) -> Result<(), RepositoryError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temporary: Vec<u16> = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let moved = unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    (moved != 0).then_some(()).ok_or(RepositoryError::Storage)
}

#[cfg(not(windows))]
fn replace_file_atomic(temporary: &Path, destination: &Path) -> Result<(), RepositoryError> {
    if destination.exists() {
        fs::remove_file(destination).map_err(|_| RepositoryError::Storage)?;
    }
    fs::rename(temporary, destination).map_err(|_| RepositoryError::Storage)
}

#[cfg(windows)]
fn secure_state_directory(path: &Path) -> Result<(), RepositoryError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };

    let sddl: Vec<u16> = PRIVATE_STATE_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        return Err(RepositoryError::Storage);
    }
    let path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let secured = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    unsafe { LocalFree(descriptor) };
    (secured != 0).then_some(()).ok_or(RepositoryError::Storage)
}

#[cfg(not(windows))]
fn secure_state_directory(_path: &Path) -> Result<(), RepositoryError> {
    Ok(())
}

#[cfg(unix)]
fn fill_random(bytes: &mut [u8]) -> Result<(), KeyProtectionError> {
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(bytes))
        .map_err(|_| KeyProtectionError::ProtectionFailed)
}

#[cfg(windows)]
fn fill_random(bytes: &mut [u8]) -> Result<(), KeyProtectionError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            u32::try_from(bytes.len()).map_err(|_| KeyProtectionError::ProtectionFailed)?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(KeyProtectionError::ProtectionFailed)
    }
}

#[cfg(not(any(unix, windows)))]
fn fill_random(_bytes: &mut [u8]) -> Result<(), KeyProtectionError> {
    Err(KeyProtectionError::ProtectionFailed)
}

#[cfg(windows)]
fn protect_machine_key(key: &[u8]) -> Result<Vec<u8>, KeyProtectionError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    if key.len() != 32 {
        return Err(KeyProtectionError::ProtectionFailed);
    }
    let mut key_copy = Zeroizing::new(key.to_vec());
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(key_copy.len()).map_err(|_| KeyProtectionError::ProtectionFailed)?,
        pbData: key_copy.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() || output.cbData == 0 {
        return Err(KeyProtectionError::ProtectionFailed);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    if bytes.len() > MAX_PROTECTED_KEY_BYTES {
        return Err(KeyProtectionError::ProtectionFailed);
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn protect_machine_key(_key: &[u8]) -> Result<Vec<u8>, KeyProtectionError> {
    Err(KeyProtectionError::ProtectionFailed)
}

#[cfg(windows)]
fn unprotect_machine_key(protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyProtectionError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    if protected.is_empty() || protected.len() > MAX_PROTECTED_KEY_BYTES {
        return Err(KeyProtectionError::ProtectionFailed);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).map_err(|_| KeyProtectionError::ProtectionFailed)?,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() || output.cbData != 32 {
        if !output.pbData.is_null() {
            unsafe {
                LocalFree(output.pbData.cast());
            }
        }
        return Err(KeyProtectionError::ProtectionFailed);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(not(windows))]
fn unprotect_machine_key(_protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyProtectionError> {
    Err(KeyProtectionError::ProtectionFailed)
}
