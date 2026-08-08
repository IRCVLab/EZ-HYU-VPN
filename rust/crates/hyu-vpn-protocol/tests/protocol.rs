use hyu_vpn_protocol::{
    Credentials, ErrorCode, MAX_FRAME_BYTES, Request, RequestEnvelope, Response, ResponseEnvelope,
    VpnState, VpnStatus, decode_request, decode_response, encode_request, encode_response,
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
fn decode_rejects_credential_payloads_that_bypass_constructor_invariants() {
    for raw in [
        br#"{"schema_version":1,"request_id":"bad-empty","command":"replace_credentials","credentials":{"username":"","password":"pass","totp_seed":"JBSWY3DPEHPK3PXP"}}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"bad-control","command":"replace_credentials","credentials":{"username":"user\nname","password":"pass","totp_seed":"JBSWY3DPEHPK3PXP"}}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"bad-nul","command":"replace_credentials","credentials":{"username":"user","password":"bad\u0000pass","totp_seed":"JBSWY3DPEHPK3PXP"}}"#.as_slice(),
    ] {
        assert!(decode_request(raw).is_err(), "accepted invalid credentials: {raw:?}");
    }
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
        schema_version: 1,
        state: VpnState::WaitingForNetwork,
        automatic_reconnect_enabled: true,
        connected_at: None,
        session_expires_at: None,
        last_successful_hip_at: None,
        tunnel_interface: None,
        next_retry_at: None,
        error_code: Some(ErrorCode::PortalUnreachable),
        last_transition_at: "1970-01-01T00:00:00Z".into(),
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

#[test]
fn shared_status_fixture_round_trips_exact_python_schema() {
    let raw = include_str!("../../../../tests/fixtures/vpn-status-v1.json");
    let status: VpnStatus = serde_json::from_str(raw).expect("shared status fixture");
    assert_eq!(status.schema_version, 1);
    assert_eq!(status.last_transition_at, "2026-08-04T12:00:01Z");
    let original: serde_json::Value = serde_json::from_str(raw).unwrap();
    let encoded = serde_json::to_value(status).unwrap();
    assert_eq!(encoded, original);
}

#[test]
fn rejects_invalid_status_version_timestamps_interface_and_build() {
    let raw = include_str!("../../../../tests/fixtures/vpn-status-v1.json");
    let valid: serde_json::Value = serde_json::from_str(raw).unwrap();
    for (field, invalid) in [
        ("schema_version", serde_json::json!(2)),
        (
            "last_transition_at",
            serde_json::json!("2026-08-04T12:00:01"),
        ),
        ("connected_at", serde_json::json!("not-a-date")),
        ("tunnel_interface", serde_json::json!("utun7;rm")),
        ("backend_build_version", serde_json::json!("bad version!")),
    ] {
        let mut candidate = valid.clone();
        candidate[field] = invalid;
        assert!(
            serde_json::from_value::<VpnStatus>(candidate).is_err(),
            "accepted invalid {field}"
        );
    }
}

#[test]
fn request_and_response_codecs_round_trip_for_native_clients() {
    let request = RequestEnvelope {
        schema_version: 1,
        request_id: "tray-codec".into(),
        request: Request::Status,
    };
    let encoded = encode_request(&request).unwrap();
    assert_eq!(decode_request(&encoded).unwrap(), request);

    let response = ResponseEnvelope::new("tray-codec", Response::Ack);
    let encoded = encode_response(&response).unwrap();
    assert_eq!(decode_response(&encoded).unwrap(), response);
}
