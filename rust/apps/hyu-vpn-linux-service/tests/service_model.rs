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

#[test]
fn established_physical_identity_is_not_invalidated_by_tunnel_routed_portal_probe() {
    use hyu_vpn_core::state::{EngineEvent, NetworkIdentity};
    use hyu_vpn_linux_service::NetworkReadinessTracker;
    let identity = NetworkIdentity::new("eth0", "192.0.2.1");
    let mut tracker = NetworkReadinessTracker::default();
    assert!(tracker.observe(Some(identity.clone()), true).is_none());
    assert_eq!(
        tracker.observe(Some(identity.clone()), true),
        Some(EngineEvent::NetworkReady(identity.clone()))
    );
    assert!(!tracker.portal_probe_required(Some(&identity)));
    assert!(tracker.observe(Some(identity), false).is_none());
    assert!(tracker.observe(None, false).is_none());
    assert_eq!(
        tracker.observe(None, false),
        Some(EngineEvent::NetworkUnavailable)
    );
}
