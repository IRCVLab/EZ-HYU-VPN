use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha1 = Hmac<Sha1>;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    #[error("invalid TOTP setup secret")]
    InvalidSecret,
    #[error("invalid system time")]
    TimeBeforeEpoch,
    #[error("TOTP counter was already used")]
    CounterAlreadyUsed,
    #[error("TOTP state operation failed")]
    StateFailure,
    #[error("TOTP generation failed")]
    GenerationFailure,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret {
    normalized: String,
    decoded: Vec<u8>,
}

impl TotpSecret {
    pub fn parse(value: &str) -> Result<Self, TotpError> {
        let normalized: String = value
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != '-')
            .flat_map(char::to_uppercase)
            .collect();
        if normalized.len() == 6 && normalized.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(TotpError::InvalidSecret);
        }
        if !(16..=256).contains(&normalized.len()) || !valid_base32_shape(&normalized) {
            return Err(TotpError::InvalidSecret);
        }
        let unpadded = normalized.trim_end_matches('=');
        let decoded = BASE32_NOPAD
            .decode(unpadded.as_bytes())
            .map_err(|_| TotpError::InvalidSecret)?;
        if decoded.is_empty() {
            return Err(TotpError::InvalidSecret);
        }
        Ok(Self {
            normalized,
            decoded,
        })
    }

    pub fn normalized(&self) -> &str {
        &self.normalized
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TotpSecret([REDACTED])")
    }
}

fn valid_base32_shape(value: &str) -> bool {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte) || byte == b'=')
    {
        return false;
    }
    let Some(first_padding) = value.find('=') else {
        return matches!(value.len() % 8, 0 | 2 | 4 | 5 | 7);
    };
    if !value[first_padding..].bytes().all(|byte| byte == b'=') || value.len() % 8 != 0 {
        return false;
    }
    let padding = value.len() - first_padding;
    matches!(
        (padding, first_padding % 8),
        (6, 2) | (4, 4) | (3, 5) | (1, 7)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpCode {
    pub value: String,
    pub remaining_seconds: u8,
    pub counter: u64,
}

pub struct TotpGenerator {
    secret: TotpSecret,
}

impl TotpGenerator {
    pub fn new(secret: TotpSecret) -> Self {
        Self { secret }
    }

    pub fn code_at(&self, time: SystemTime) -> Result<OtpCode, TotpError> {
        let seconds = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TotpError::TimeBeforeEpoch)?
            .as_secs();
        let counter = seconds / 30;
        let mut mac = HmacSha1::new_from_slice(&self.secret.decoded)
            .map_err(|_| TotpError::GenerationFailure)?;
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        let binary = (u32::from(digest[offset] & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        Ok(OtpCode {
            value: format!("{:06}", binary % 1_000_000),
            remaining_seconds: (30 - (seconds % 30)) as u8,
            counter,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CounterDocument {
    last_counter: u64,
}

pub struct CounterGuard {
    state_path: PathBuf,
    lock_path: PathBuf,
}

impl CounterGuard {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let state_path = path.as_ref().to_path_buf();
        let lock_name = format!(
            "{}.lock",
            state_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("totp-counter.json")
        );
        let lock_path = state_path.with_file_name(lock_name);
        Self {
            state_path,
            lock_path,
        }
    }

    pub fn reserve(&self, counter: u64) -> Result<(), TotpError> {
        let lock = self.open_lock()?;
        lock.lock_exclusive().map_err(|_| TotpError::StateFailure)?;
        let last = self.read_document()?;
        if last.is_some_and(|value| counter <= value) {
            return Err(TotpError::CounterAlreadyUsed);
        }
        self.write_document(counter)
    }

    pub fn last_reserved(&self) -> Result<Option<u64>, TotpError> {
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock).map_err(|_| TotpError::StateFailure)?;
        self.read_document()
    }

    fn open_lock(&self) -> Result<File, TotpError> {
        let parent = self.state_path.parent().ok_or(TotpError::StateFailure)?;
        fs::create_dir_all(parent).map_err(|_| TotpError::StateFailure)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|_| TotpError::StateFailure)?;
        set_owner_only_permissions(&self.lock_path)?;
        Ok(file)
    }

    fn read_document(&self) -> Result<Option<u64>, TotpError> {
        let file = match OpenOptions::new().read(true).open(&self.state_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(TotpError::StateFailure),
        };
        let mut data = Vec::new();
        file.take(4097)
            .read_to_end(&mut data)
            .map_err(|_| TotpError::StateFailure)?;
        if data.len() > 4096 {
            return Err(TotpError::StateFailure);
        }
        let document: CounterDocument =
            serde_json::from_slice(&data).map_err(|_| TotpError::StateFailure)?;
        Ok(Some(document.last_counter))
    }

    fn write_document(&self, counter: u64) -> Result<(), TotpError> {
        let payload = serde_json::to_vec(&CounterDocument {
            last_counter: counter,
        })
        .map_err(|_| TotpError::StateFailure)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .state_path
            .with_extension(format!("tmp-{}-{sequence}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| TotpError::StateFailure)?;
            set_owner_only_permissions(&temporary)?;
            file.write_all(&payload)
                .and_then(|()| file.sync_all())
                .map_err(|_| TotpError::StateFailure)?;
            fs::rename(&temporary, &self.state_path).map_err(|_| TotpError::StateFailure)?;
            set_owner_only_permissions(&self.state_path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), TotpError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| TotpError::StateFailure)
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), TotpError> {
    Ok(())
}
