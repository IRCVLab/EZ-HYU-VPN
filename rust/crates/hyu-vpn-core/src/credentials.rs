use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hyu_vpn_protocol::Credentials;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"HYUVPNC1";
const MAGIC_FAMILY: &[u8; 7] = b"HYUVPNC";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CredentialEnvelopeError {
    #[error("invalid credential encryption key")]
    InvalidKey,
    #[error("unsupported credential envelope version")]
    UnsupportedVersion,
    #[error("credential envelope is too large")]
    EnvelopeTooLarge,
    #[error("credential envelope is malformed")]
    InvalidEnvelope,
    #[error("credential envelope authentication failed")]
    AuthenticationFailed,
    #[error("credential document is invalid")]
    InvalidDocument,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct CredentialDocument {
    schema_version: u8,
    values: CredentialValues,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct CredentialValues {
    username: String,
    password: String,
    #[serde(rename = "totpSeed")]
    totp_seed: String,
}

pub struct CredentialEnvelope;

impl CredentialEnvelope {
    pub fn seal(key: &[u8], credentials: &Credentials) -> Result<Vec<u8>, CredentialEnvelopeError> {
        let cipher = cipher(key)?;
        let mut document = CredentialDocument {
            schema_version: 1,
            values: CredentialValues {
                username: credentials.username().to_owned(),
                password: credentials.password().to_owned(),
                totp_seed: credentials.totp_seed().to_owned(),
            },
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&document).map_err(|_| CredentialEnvelopeError::InvalidDocument)?,
        );
        document.zeroize();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: MAGIC,
                },
            )
            .map_err(|_| CredentialEnvelopeError::AuthenticationFailed)?;
        let capacity = MAGIC.len() + nonce.len() + ciphertext.len();
        if capacity > MAX_ENVELOPE_BYTES {
            return Err(CredentialEnvelopeError::EnvelopeTooLarge);
        }
        let mut envelope = Vec::with_capacity(capacity);
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub fn open(key: &[u8], envelope: &[u8]) -> Result<Credentials, CredentialEnvelopeError> {
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(CredentialEnvelopeError::EnvelopeTooLarge);
        }
        let cipher = cipher(key)?;
        let (nonce_bytes, ciphertext, aad) = if envelope.starts_with(MAGIC) {
            if envelope.len() < MAGIC.len() + NONCE_BYTES + TAG_BYTES {
                return Err(CredentialEnvelopeError::InvalidEnvelope);
            }
            (
                &envelope[MAGIC.len()..MAGIC.len() + NONCE_BYTES],
                &envelope[MAGIC.len() + NONCE_BYTES..],
                MAGIC.as_slice(),
            )
        } else if envelope.starts_with(MAGIC_FAMILY) {
            return Err(CredentialEnvelopeError::UnsupportedVersion);
        } else {
            if envelope.len() < NONCE_BYTES + TAG_BYTES {
                return Err(CredentialEnvelopeError::InvalidEnvelope);
            }
            (
                &envelope[..NONCE_BYTES],
                &envelope[NONCE_BYTES..],
                &[] as &[u8],
            )
        };
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CredentialEnvelopeError::AuthenticationFailed)?,
        );
        let mut document: CredentialDocument = serde_json::from_slice(plaintext.as_slice())
            .map_err(|_| CredentialEnvelopeError::InvalidDocument)?;
        if document.schema_version != 1 {
            document.zeroize();
            return Err(CredentialEnvelopeError::InvalidDocument);
        }
        let credentials = Credentials::new(
            document.values.username.as_str(),
            document.values.password.as_str(),
            document.values.totp_seed.as_str(),
        )
        .map_err(|_| CredentialEnvelopeError::InvalidDocument);
        document.zeroize();
        credentials
    }
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm, CredentialEnvelopeError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| CredentialEnvelopeError::InvalidKey)
}
