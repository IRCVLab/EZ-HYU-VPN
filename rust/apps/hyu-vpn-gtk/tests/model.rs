use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use hyu_vpn_gtk::{
    AutostartManager, CredentialForm, FormField, MenuCommand, MenuModel, ValidationError,
};
use hyu_vpn_protocol::{VpnState, VpnStatus};
use tempfile::tempdir;

fn status(state: VpnState, automatic: bool) -> VpnStatus {
    VpnStatus {
        schema_version: 1,
        state,
        automatic_reconnect_enabled: automatic,
        connected_at: None,
        session_expires_at: None,
        last_successful_hip_at: None,
        tunnel_interface: None,
        next_retry_at: None,
        error_code: None,
        last_transition_at: "2026-08-04T12:00:00Z".into(),
        backend_build_version: Some("0.2.0".into()),
    }
}

#[test]
fn menu_projection_covers_every_daemon_state_and_otp_countdown() {
    for state in [
        VpnState::Disabled,
        VpnState::WaitingForNetwork,
        VpnState::Connecting,
        VpnState::Connected,
        VpnState::Disconnecting,
        VpnState::Backoff,
        VpnState::Error,
    ] {
        let automatic = state != VpnState::Disabled;
        let model = MenuModel::project(&status(state, automatic), Some(("123456", 17)), true);
        assert_eq!(model.otp_label.as_deref(), Some("OTP 123456 · 17s"));
        assert!(model.launch_at_login);
        assert_eq!(
            model.connect_enabled,
            state == VpnState::Disabled || state == VpnState::Error
        );
        assert_eq!(model.disconnect_enabled, automatic);
        assert_eq!(
            model.reconnect_enabled,
            automatic && state != VpnState::Disconnecting
        );
    }
}

#[test]
fn menu_commands_map_to_single_ordered_protocol_transactions() {
    assert_eq!(MenuCommand::Connect.protocol_commands(), &["connect"]);
    assert_eq!(MenuCommand::Disconnect.protocol_commands(), &["disconnect"]);
    assert_eq!(MenuCommand::Reconnect.protocol_commands(), &["reconnect"]);
    assert_eq!(MenuCommand::CopyOtp.protocol_commands(), &["current_otp"]);
}

#[test]
fn credential_form_requires_confirmed_values_and_has_stable_tab_order() {
    assert_eq!(
        CredentialForm::tab_order(),
        [
            FormField::Username,
            FormField::Password,
            FormField::PasswordConfirmation,
            FormField::TotpSeed,
            FormField::TotpSeedConfirmation,
            FormField::Save,
            FormField::Cancel,
        ]
    );
    let valid = CredentialForm {
        username: "user".into(),
        password: "correct horse".into(),
        password_confirmation: "correct horse".into(),
        totp_seed: "JBSW Y3DP EHPK 3PXP".into(),
        totp_seed_confirmation: "JBSWY3DPEHPK3PXP".into(),
    };
    let credentials = valid.validate().unwrap();
    assert_eq!(credentials.totp_seed(), "JBSWY3DPEHPK3PXP");
    let mut mismatch = valid;
    mismatch.password_confirmation = "wrong".into();
    assert_eq!(
        mismatch.validate().unwrap_err(),
        ValidationError::PasswordMismatch
    );
}

#[test]
fn autostart_is_atomic_private_and_rejects_symlink_destination() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("autostart/hyu-vpn.desktop");
    let manager = AutostartManager::new(&path, "/usr/bin/hyu-vpn");
    manager.set_enabled(true).unwrap();
    assert!(manager.is_enabled().unwrap());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let raw = fs::read_to_string(&path).unwrap();
    assert!(raw.contains("Exec=/usr/bin/hyu-vpn"));
    manager.set_enabled(false).unwrap();
    assert!(!path.exists());

    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "sentinel").unwrap();
    symlink(&target, &path).unwrap();
    assert!(manager.set_enabled(true).is_err());
    assert_eq!(fs::read_to_string(target).unwrap(), "sentinel");
}
