use std::fs;

use hyu_vpn_windows_service::{
    AutomaticPreference, NetworkReadinessTracker, SERVICE_DISPLAY_NAME, SERVICE_NAME,
    WindowsServiceConfig,
};
use tempfile::tempdir;

#[test]
fn service_identity_and_pipe_contract_are_fixed() {
    assert_eq!(SERVICE_NAME, "HYUVPN");
    assert_eq!(SERVICE_DISPLAY_NAME, "HYU VPN");
    let config = WindowsServiceConfig::production();
    assert_eq!(config.pipe_name, r"\\.\pipe\hyu-vpn-v1");
    assert_eq!(config.maximum_frame_bytes, 64 * 1024);
    assert!(config.reject_remote_clients);
    assert!(config.require_active_interactive_session);
}

#[test]
fn automatic_preference_defaults_on_and_persists_exact_values() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("automatic-reconnect");
    let preference = AutomaticPreference::new(&path);
    assert!(preference.load().unwrap());
    preference.store(false).unwrap();
    assert!(!preference.load().unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"false\n");
    preference.store(true).unwrap();
    assert!(preference.load().unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"true\n");
}

#[test]
fn automatic_preference_rejects_symlink_and_malformed_state() {
    let temp = tempdir().unwrap();
    let target = temp.path().join("target");
    let path = temp.path().join("automatic-reconnect");
    fs::write(&target, b"true\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, &path).unwrap();
    let preference = AutomaticPreference::new(&path);
    assert!(preference.load().is_err());

    let malformed = temp.path().join("malformed");
    fs::write(&malformed, b"TRUE\n").unwrap();
    assert!(AutomaticPreference::new(malformed).load().is_err());
}

#[test]
fn network_tracker_publishes_loss_and_recovery_after_stable_samples() {
    use hyu_vpn_core::state::{EngineEvent, NetworkIdentity};

    let wifi = NetworkIdentity::new("luid-7", "192.168.0.1");
    let mut tracker = NetworkReadinessTracker::default();
    assert!(tracker.portal_probe_required(Some(&wifi)));
    assert_eq!(tracker.observe(Some(wifi.clone()), true), None);
    assert!(matches!(
        tracker.observe(Some(wifi.clone()), true),
        Some(EngineEvent::NetworkReady(identity)) if identity == wifi
    ));
    assert!(!tracker.portal_probe_required(Some(&wifi)));
    assert_eq!(tracker.observe(None, false), None);
    assert_eq!(
        tracker.observe(None, false),
        Some(EngineEvent::NetworkUnavailable)
    );
    assert!(tracker.portal_probe_required(Some(&wifi)));
    assert_eq!(tracker.observe(Some(wifi.clone()), false), None);
    assert_eq!(tracker.observe(Some(wifi.clone()), true), None);
    assert!(matches!(
        tracker.observe(Some(wifi.clone()), true),
        Some(EngineEvent::NetworkReady(identity)) if identity == wifi
    ));
}
