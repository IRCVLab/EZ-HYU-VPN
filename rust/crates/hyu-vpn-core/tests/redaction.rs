use hyu_vpn_core::redaction::{DiagnosticCode, RedactedError};

#[test]
fn formatted_diagnostics_never_include_untrusted_source_text() {
    let source = "username=CANARY-USER password=CANARY-PASS totp=JBSWY3DPEHPK3PXP";
    let error = RedactedError::from_source(DiagnosticCode::CredentialStoreFailure, source);
    let rendered = format!("{error:?} {error}");
    assert_eq!(error.code(), "CREDENTIAL_STORE_FAILURE");
    for forbidden in ["CANARY-USER", "CANARY-PASS", "JBSWY3DPEHPK3PXP"] {
        assert!(!rendered.contains(forbidden));
    }
}
