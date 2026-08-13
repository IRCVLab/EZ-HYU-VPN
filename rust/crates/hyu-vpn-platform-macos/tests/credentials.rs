use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::Path;

use hyu_vpn_core::credentials::CredentialEnvelope;
use hyu_vpn_daemon::runtime::{CredentialRepository, RepositoryError};
use hyu_vpn_platform_macos::{MacCredentialRepository, MacPaths};
use hyu_vpn_protocol::Credentials;
use serde::Deserialize;
use tempfile::TempDir;

fn uid() -> u32 {
    fs::metadata(".").unwrap().uid()
}

fn credentials() -> Credentials {
    Credentials::new("test-user", "PASSWORD-CANARY", "JBSWY3DPEHPK3PXP").unwrap()
}

fn repository(root: &TempDir) -> (MacCredentialRepository, MacPaths) {
    let paths = MacPaths::under(root.path(), uid());
    let repo = MacCredentialRepository::new(paths.clone(), uid());
    (repo, paths)
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn make_private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
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
fn loads_existing_raw_cryptokit_combined_envelope_without_rewriting() {
    let temp = TempDir::new().unwrap();
    let (repo, paths) = repository(&temp);
    make_private_dir(&paths.state_dir);
    let vector: MacVector = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/macos-credential-vector.json"
    ))
    .unwrap();
    let key = decode_hex(&vector.key_hex);
    let envelope = decode_hex(&vector.combined_hex);
    write_private(&paths.credential_key, &key);
    write_private(&paths.credentials, &envelope);
    let before = fs::read(&paths.credentials).unwrap();

    let opened = repo.load().unwrap();

    assert_eq!(opened.username(), vector.username);
    assert_eq!(opened.password(), vector.password);
    assert_eq!(opened.totp_seed(), vector.totp_seed);
    assert_eq!(fs::read(&paths.credentials).unwrap(), before);
}

#[test]
fn replaces_with_versioned_envelope_that_round_trips_and_hides_plaintext() {
    let temp = TempDir::new().unwrap();
    let (repo, paths) = repository(&temp);

    repo.replace(credentials()).unwrap();

    let key = fs::read(&paths.credential_key).unwrap();
    let stored = fs::read(&paths.credentials).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(
        fs::symlink_metadata(&paths.credential_key)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::symlink_metadata(&paths.credentials)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(stored.starts_with(b"HYUVPNC1"));
    assert!(!String::from_utf8_lossy(&stored).contains("PASSWORD-CANARY"));
    let loaded = repo.load().unwrap();
    assert_eq!(loaded.username(), "test-user");
    assert_eq!(loaded.password(), "PASSWORD-CANARY");
    assert!(!format!("{loaded:?}").contains("PASSWORD-CANARY"));
}

#[test]
fn rejects_wrong_key_truncated_envelope_symlinks_bad_mode_wrong_owner_and_oversize() {
    let temp = TempDir::new().unwrap();
    let (repo, paths) = repository(&temp);
    repo.replace(credentials()).unwrap();

    let mut key = fs::read(&paths.credential_key).unwrap();
    key[0] ^= 1;
    fs::write(&paths.credential_key, &key).unwrap();
    fs::set_permissions(&paths.credential_key, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(repo.load().unwrap_err(), RepositoryError::Corrupt);

    repo.replace(credentials()).unwrap();
    let envelope = fs::read(&paths.credentials).unwrap();
    fs::write(&paths.credentials, &envelope[..15]).unwrap();
    fs::set_permissions(&paths.credentials, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(repo.load().unwrap_err(), RepositoryError::Corrupt);

    repo.replace(credentials()).unwrap();
    fs::set_permissions(&paths.credentials, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(repo.load().unwrap_err(), RepositoryError::Corrupt);

    fs::set_permissions(&paths.credentials, fs::Permissions::from_mode(0o600)).unwrap();
    let real = paths.state_dir.join("real-credentials.enc");
    fs::rename(&paths.credentials, &real).unwrap();
    symlink(&real, &paths.credentials).unwrap();
    assert_eq!(repo.load().unwrap_err(), RepositoryError::Corrupt);

    fs::remove_file(&paths.credentials).unwrap();
    write_private(&paths.credentials, &vec![1_u8; 65_537]);
    assert_eq!(repo.load().unwrap_err(), RepositoryError::Corrupt);

    assert_eq!(
        MacCredentialRepository::new(paths.clone(), uid().saturating_add(1))
            .present()
            .unwrap_err(),
        RepositoryError::Storage
    );
}

#[test]
fn replacement_is_atomic_reuses_key_and_generates_unique_nonces() {
    let temp = TempDir::new().unwrap();
    let (repo, paths) = repository(&temp);

    repo.replace(credentials()).unwrap();
    let key_before = fs::read(&paths.credential_key).unwrap();
    let first = fs::read(&paths.credentials).unwrap();
    repo.replace(credentials()).unwrap();
    let key_after = fs::read(&paths.credential_key).unwrap();
    let second = fs::read(&paths.credentials).unwrap();

    assert_eq!(key_before, key_after);
    assert_ne!(first, second);
    assert_eq!(
        CredentialEnvelope::open(&key_after, &second)
            .unwrap()
            .password(),
        "PASSWORD-CANARY"
    );
    let leftovers: Vec<_> = fs::read_dir(&paths.state_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| name.to_string_lossy().contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary files left behind: {leftovers:?}"
    );
}

#[test]
fn present_distinguishes_absent_valid_and_partial_storage() {
    let temp = TempDir::new().unwrap();
    let (repo, paths) = repository(&temp);
    assert!(!repo.present().unwrap());

    repo.replace(credentials()).unwrap();
    assert!(repo.present().unwrap());

    fs::remove_file(&paths.credentials).unwrap();
    assert_eq!(repo.present().unwrap_err(), RepositoryError::Corrupt);
}

#[test]
fn create_new_writes_do_not_follow_preexisting_temporary_symlink() {
    let temp = TempDir::new().unwrap();
    let (repo, paths) = repository(&temp);
    make_private_dir(&paths.state_dir);
    let predictable_temp = paths.state_dir.join(format!(
        ".{}.{}.tmp",
        paths.credential_key.file_name().unwrap().to_str().unwrap(),
        std::process::id()
    ));
    let outside = temp.path().join("outside");
    File::create(&outside).unwrap();
    symlink(&outside, &predictable_temp).unwrap();

    assert_eq!(
        repo.replace(credentials()).unwrap_err(),
        RepositoryError::Storage
    );
    assert_eq!(fs::read(&outside).unwrap(), Vec::<u8>::new());
}
