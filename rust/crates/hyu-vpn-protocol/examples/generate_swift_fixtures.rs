use std::fs;
use std::path::{Path, PathBuf};

use hyu_vpn_protocol::{
    Credentials, ErrorCode, Request, RequestEnvelope, Response, ResponseEnvelope, VpnStatus,
    encode_request, encode_response,
};

fn main() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root");
    let fixture_dir = repo.join("tests/fixtures/protocol");
    fs::create_dir_all(&fixture_dir).expect("fixture dir");

    let status_fixture = repo.join("tests/fixtures/vpn-status-v1.json");
    let status: VpnStatus =
        serde_json::from_slice(&fs::read(&status_fixture).expect("status fixture"))
            .expect("decode shared status fixture");

    write_request(
        &fixture_dir,
        "status-request-v1",
        "swift-status-1",
        Request::Status,
    );
    write_request(
        &fixture_dir,
        "connect-request-v1",
        "swift-connect-1",
        Request::Connect,
    );
    write_request(
        &fixture_dir,
        "disconnect-request-v1",
        "swift-disconnect-1",
        Request::Disconnect,
    );
    write_request(
        &fixture_dir,
        "reconnect-request-v1",
        "swift-reconnect-1",
        Request::Reconnect,
    );
    write_request(
        &fixture_dir,
        "current-otp-request-v1",
        "swift-current-otp-1",
        Request::CurrentOtp,
    );
    write_request(
        &fixture_dir,
        "automatic-on-request-v1",
        "swift-automatic-on-1",
        Request::AutomaticOn,
    );
    write_request(
        &fixture_dir,
        "automatic-off-request-v1",
        "swift-automatic-off-1",
        Request::AutomaticOff,
    );
    write_request(
        &fixture_dir,
        "replace-credentials-request-v1",
        "swift-replace-credentials-1",
        Request::ReplaceCredentials {
            credentials: Credentials::new("swift-user", "swift-pass", "JBSWY3DPEHPK3PXP")
                .expect("credentials"),
        },
    );

    write_response(
        &fixture_dir,
        "ack-response-v1",
        "swift-ack-1",
        Response::Ack,
    );
    write_response(
        &fixture_dir,
        "connect-ack-response-v1",
        "swift-connect-1",
        Response::Ack,
    );
    write_response(
        &fixture_dir,
        "disconnect-ack-response-v1",
        "swift-disconnect-1",
        Response::Ack,
    );
    write_response(
        &fixture_dir,
        "reconnect-ack-response-v1",
        "swift-reconnect-1",
        Response::Ack,
    );
    write_response(
        &fixture_dir,
        "automatic-on-ack-response-v1",
        "swift-automatic-on-1",
        Response::Ack,
    );
    write_response(
        &fixture_dir,
        "automatic-off-ack-response-v1",
        "swift-automatic-off-1",
        Response::Ack,
    );
    write_response(
        &fixture_dir,
        "replace-credentials-ack-response-v1",
        "swift-replace-credentials-1",
        Response::Ack,
    );
    write_response(
        &fixture_dir,
        "status-response-v1",
        "swift-status-1",
        Response::Status { status },
    );
    write_response(
        &fixture_dir,
        "current-otp-response-v1",
        "swift-current-otp-1",
        Response::CurrentOtp {
            code: "123456".into(),
            remaining_seconds: 17,
        },
    );
    write_response(
        &fixture_dir,
        "error-protocol-mismatch-v1",
        "swift-error-protocol-mismatch-1",
        Response::Error {
            error_code: ErrorCode::ProtocolMismatch,
        },
    );
}

fn write_request(dir: &Path, stem: &str, request_id: &str, request: Request) {
    let payload =
        encode_request(&RequestEnvelope::new(request_id, request)).expect("encode request");
    write_payload_and_frame(dir, stem, &payload);
}

fn write_response(dir: &Path, stem: &str, request_id: &str, response: Response) {
    let payload =
        encode_response(&ResponseEnvelope::new(request_id, response)).expect("encode response");
    write_payload_and_frame(dir, stem, &payload);
}

fn write_payload_and_frame(dir: &Path, stem: &str, payload: &[u8]) {
    let json_path = dir.join(format!("{stem}.json"));
    fs::write(&json_path, payload)
        .unwrap_or_else(|error| panic!("write {}: {error}", json_path.display()));

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    let frame_path = dir.join(format!("{stem}.frame"));
    fs::write(&frame_path, frame)
        .unwrap_or_else(|error| panic!("write {}: {error}", frame_path.display()));
}
