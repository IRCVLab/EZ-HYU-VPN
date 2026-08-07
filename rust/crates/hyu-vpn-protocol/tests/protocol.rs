use hyu_vpn_protocol::{
    Credentials, ErrorCode, MAX_FRAME_BYTES, Request, Response, ResponseEnvelope, VpnState,
    VpnStatus, decode_request, encode_response,
};
use zeroize::Zeroize;

#[test]
fn decodes_exact_version_one_status_request() {
    let decoded =
        decode_request(br#"{"schema_version":1,"request_id":"menu-1","command":"status"}"#)
            .expect("valid request");
    assert_eq!(decoded.schema_version, 1);
    assert_eq!(decoded.request_id, "menu-1");
    assert_eq!(decoded.request, Request::Status);
}

#[test]
fn decodes_replace_credentials_only_from_the_secret_bearing_command() {
    let decoded = decode_request(
        br#"{"schema_version":1,"request_id":"menu-2","command":"replace_credentials","credentials":{"username":"user","password":"pass","totp_seed":"JBSWY3DPEHPK3PXP"}}"#,
    )
    .expect("valid credential replacement");
    assert!(matches!(
        decoded.request,
        Request::ReplaceCredentials { .. }
    ));

    let unexpected = decode_request(
        br#"{"schema_version":1,"request_id":"menu-3","command":"status","credentials":{"username":"user","password":"pass","totp_seed":"JBSWY3DPEHPK3PXP"}}"#,
    );
    assert!(unexpected.is_err());
}

#[test]
fn rejects_unknown_versions_commands_fields_and_oversized_frames() {
    for raw in [
        br#"{"schema_version":2,"request_id":"x","command":"status"}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"x","command":"shell"}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"x","command":"status","extra":true}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"","command":"status"}"#.as_slice(),
    ] {
        assert!(
            decode_request(raw).is_err(),
            "accepted hostile request: {raw:?}"
        );
    }
    assert!(decode_request(&vec![b'x'; MAX_FRAME_BYTES + 1]).is_err());
}

#[test]
fn credentials_are_bounded_and_zeroizable() {
    let mut credentials = Credentials::new("user", "password", "JBSWY3DPEHPK3PXP").unwrap();
    credentials.zeroize();
    assert!(credentials.username().is_empty());
    assert!(credentials.password().is_empty());
    assert!(credentials.totp_seed().is_empty());

    assert!(Credentials::new("", "password", "JBSWY3DPEHPK3PXP").is_err());
    assert!(Credentials::new("user", "", "JBSWY3DPEHPK3PXP").is_err());
    assert!(Credentials::new("user", "password", "x".repeat(1025)).is_err());
}

#[test]
fn status_response_is_secret_free_and_uses_compatible_state_values() {
    let status = VpnStatus {
        state: VpnState::WaitingForNetwork,
        automatic_reconnect_enabled: true,
        connected_at: None,
        session_expires_at: None,
        last_successful_hip_at: None,
        tunnel_interface: None,
        next_retry_at: None,
        error_code: Some(ErrorCode::PortalUnreachable),
        backend_build_version: Some("0.2.0".into()),
    };
    let encoded = encode_response(&ResponseEnvelope::new(
        "menu-4",
        Response::Status { status },
    ))
    .expect("encode response");
    let text = String::from_utf8(encoded).unwrap();
    assert!(text.contains("\"state\":\"waiting-for-network\""));
    for forbidden in [
        "\"password\":",
        "\"totp_seed\":",
        "\"cookie\":",
        "\"username\":",
        "\"portal\":",
    ] {
        assert!(!text.to_ascii_lowercase().contains(forbidden));
    }
}
