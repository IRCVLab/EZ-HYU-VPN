use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use hyu_vpn_linux_service::{AutomaticPreference, read_owner_uid};
use tempfile::tempdir;

#[test]
fn automatic_preference_is_private_atomic_and_persists_explicit_false() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state/automatic-reconnect");
    let preference = AutomaticPreference::new(&path);
    assert!(preference.load().unwrap());
    preference.store(false).unwrap();
    assert!(!AutomaticPreference::new(&path).load().unwrap());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn automatic_preference_rejects_symlink_destination() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    let path = dir.path().join("automatic-reconnect");
    fs::write(&target, "true\n").unwrap();
    symlink(&target, &path).unwrap();
    assert!(AutomaticPreference::new(path).load().is_err());
}

#[test]
fn owner_uid_file_is_strict_bounded_and_rejects_root() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("owner.uid");
    fs::write(&path, "1000\n").unwrap();
    assert_eq!(read_owner_uid(&path).unwrap(), 1000);
    for invalid in ["0\n", "-1\n", "1000 trailing\n", "4294967296\n"] {
        fs::write(&path, invalid).unwrap();
        assert!(read_owner_uid(&path).is_err());
    }
}
