use hyu_vpn_protocol::{
    Credentials, Request, Response, ResponseEnvelope, VpnState, VpnStatus, encode_response,
};
use hyu_vpn_windows_tray::{
    CredentialForm, FormField, MenuModel, decode_framed_response, encode_framed_request,
};

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
        last_transition_at: "2026-08-08T00:00:00Z".into(),
        backend_build_version: Some("0.2.0".into()),
    }
}

#[test]
fn windows_menu_exposes_otp_countdown_and_correct_action_availability() {
    let model = MenuModel::project(
        &status(VpnState::Connected, true),
        Some(("123456", 17)),
        true,
    );
    assert_eq!(model.status_label, "Connected");
    assert_eq!(model.otp_label.as_deref(), Some("OTP 123456 - 17s (copy)"));
    assert!(!model.connect_enabled);
    assert!(model.disconnect_enabled);
    assert!(model.reconnect_enabled);
    assert!(model.launch_at_login);

    let disabled = MenuModel::project(&status(VpnState::Disabled, false), None, false);
    assert!(disabled.connect_enabled);
    assert!(!disabled.disconnect_enabled);
}

#[test]
fn credential_dialog_is_one_tab_navigable_three_field_form() {
    assert_eq!(
        CredentialForm::tab_order(),
        [
            FormField::Username,
            FormField::Password,
            FormField::TotpSeed,
            FormField::Save,
            FormField::Cancel,
        ]
    );
    let valid = CredentialForm {
        username: "hyu-user".into(),
        password: "secret".into(),
        totp_seed: "jbsw y3dp ehpk 3pxp".into(),
    };
    let credentials = valid.validate().unwrap();
    assert_eq!(credentials.username(), "hyu-user");
    assert_eq!(credentials.password(), "secret");
    assert_eq!(credentials.totp_seed(), "JBSWY3DPEHPK3PXP");
}

#[test]
fn windows_pipe_codec_is_bounded_big_endian_and_correlates_ids() {
    let frame = encode_framed_request("tray-1", Request::Status).unwrap();
    assert_eq!(
        u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
        frame.len() - 4
    );

    let payload = encode_response(&ResponseEnvelope::new("tray-1", Response::Ack)).unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    response.extend_from_slice(&payload);
    assert_eq!(
        decode_framed_response("tray-1", &response).unwrap(),
        Response::Ack
    );
    assert!(decode_framed_response("wrong-id", &response).is_err());
    response[0] = 0x7f;
    assert!(decode_framed_response("tray-1", &response).is_err());

    let debug = format!(
        "{:?}",
        Credentials::new("user", "password", "JBSWY3DPEHPK3PXP").unwrap()
    );
    assert_eq!(debug, "Credentials([REDACTED])");
}
