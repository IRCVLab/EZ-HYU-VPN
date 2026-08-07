use hyu_vpn_core::credentials::{CredentialEnvelope, CredentialEnvelopeError};
use hyu_vpn_protocol::Credentials;
use serde::Deserialize;

fn key() -> [u8; 32] {
    [7_u8; 32]
}

fn credentials() -> Credentials {
    Credentials::new("test-user", "PASSWORD-CANARY", "JBSWY3DPEHPK3PXP").unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn versioned_envelope_round_trips_without_plaintext_and_uses_unique_nonces() {
    let first = CredentialEnvelope::seal(&key(), &credentials()).unwrap();
    let second = CredentialEnvelope::seal(&key(), &credentials()).unwrap();
    assert_ne!(first, second);
    assert!(!String::from_utf8_lossy(&first).contains("PASSWORD-CANARY"));

    let opened = CredentialEnvelope::open(&key(), &first).unwrap();
    assert_eq!(opened.username(), "test-user");
    assert_eq!(opened.password(), "PASSWORD-CANARY");
    assert_eq!(opened.totp_seed(), "JBSWY3DPEHPK3PXP");
}

#[test]
fn rejects_wrong_key_tampering_truncation_version_and_oversize() {
    let envelope = CredentialEnvelope::seal(&key(), &credentials()).unwrap();
    assert_eq!(
        CredentialEnvelope::open(&[8_u8; 32], &envelope).unwrap_err(),
        CredentialEnvelopeError::AuthenticationFailed
    );
    let mut tampered = envelope.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        CredentialEnvelope::open(&key(), &tampered).unwrap_err(),
        CredentialEnvelopeError::AuthenticationFailed
    );
    assert!(CredentialEnvelope::open(&key(), &envelope[..15]).is_err());
    let mut wrong_version = envelope.clone();
    wrong_version[7] = b'9';
    assert_eq!(
        CredentialEnvelope::open(&key(), &wrong_version).unwrap_err(),
        CredentialEnvelopeError::UnsupportedVersion
    );
    assert_eq!(
        CredentialEnvelope::open(&key(), &vec![0; 65_537]).unwrap_err(),
        CredentialEnvelopeError::EnvelopeTooLarge
    );
}

#[derive(Deserialize)]
struct MacVector {
    key_hex: String,
    combined_hex: String,
    username: String,
    password: String,
    totp_seed: String,
}

#[test]
fn opens_existing_cryptokit_combined_envelope() {
    let vector: MacVector = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/macos-credential-vector.json"
    ))
    .unwrap();
    let key = decode_hex(&vector.key_hex);
    let opened = CredentialEnvelope::open(&key, &decode_hex(&vector.combined_hex)).unwrap();
    assert_eq!(opened.username(), vector.username);
    assert_eq!(opened.password(), vector.password);
    assert_eq!(opened.totp_seed(), vector.totp_seed);
}
