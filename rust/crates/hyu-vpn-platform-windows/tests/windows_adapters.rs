use hyu_vpn_platform_windows::{
    DPAPI_DOCUMENT_VERSION, HiddenProcessSpec, NetworkSnapshot, ProtectedKeyDocument, WindowsPaths,
    authorize_pipe_client_sid,
};

#[test]
fn production_paths_and_named_pipe_are_fixed_machine_locations() {
    let paths = WindowsPaths::production();
    assert_eq!(paths.pipe_name, r"\\.\pipe\hyu-vpn-v1");
    assert!(paths.state_dir.is_absolute());
    assert_eq!(paths.state_dir.file_name().unwrap(), "HYUVPN");
    let root = std::env::temp_dir().join("hyu-windows-root");
    let rooted = WindowsPaths::under(&root);
    assert_eq!(
        rooted.credentials,
        root.join("ProgramData")
            .join("HYUVPN")
            .join("credentials.enc")
    );
}

#[test]
fn protected_key_document_is_versioned_bounded_and_rejects_corruption() {
    let document = ProtectedKeyDocument::new(vec![7; 96]).unwrap();
    let bytes = document.encode().unwrap();
    assert!(bytes.len() < 4096);
    let opened = ProtectedKeyDocument::decode(&bytes).unwrap();
    assert_eq!(opened.version(), DPAPI_DOCUMENT_VERSION);
    assert_eq!(opened.protected_key(), &[7; 96]);
    for hostile in [
        Vec::new(),
        b"{}".to_vec(),
        br#"{"version":2,"protected_key":[1,2,3]}"#.to_vec(),
        vec![0; 4097],
    ] {
        assert!(ProtectedKeyDocument::decode(&hostile).is_err());
    }
}

#[test]
fn pipe_peer_authorization_accepts_only_exact_bounded_windows_sid() {
    assert!(authorize_pipe_client_sid("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001").is_ok());
    for actual in [
        "",
        "S-1-5-18",
        "s-1-5-21-1-2-3-1001",
        "S-1-5-21-1-2-3-1001\n",
        "S-1-5-21-1-2-3-1001-extra",
    ] {
        assert!(authorize_pipe_client_sid("S-1-5-21-1-2-3-1001", actual).is_err());
    }
}

#[test]
fn network_snapshot_uses_stable_luid_and_rejects_tunnel_defaults() {
    let physical = NetworkSnapshot::new(44, "192.168.1.1", "Ethernet");
    let identity = physical.identity().unwrap();
    assert_eq!(identity.interface, "luid-44");
    assert_eq!(identity.gateway, "192.168.1.1");
    assert!(!identity.is_tunnel);

    for name in [
        "Wintun Userspace Tunnel",
        "TAP-Windows Adapter V9",
        "OpenConnect virtual adapter",
        "WireGuard Tunnel",
        "HYU VPN",
    ] {
        assert!(
            NetworkSnapshot::new(55, "10.0.0.1", name)
                .identity()
                .is_none()
        );
    }
    assert_ne!(
        NetworkSnapshot::new(44, "192.168.1.1", "Ethernet").identity(),
        NetworkSnapshot::new(45, "192.168.1.1", "Wi-Fi").identity()
    );
}

#[test]
fn hidden_process_spec_contains_no_credentials_and_uses_no_console() {
    let spec = HiddenProcessSpec::production().unwrap();
    assert!(spec.executable.is_absolute());
    assert!(spec.argv.iter().any(|arg| arg == "--protocol=gp"));
    assert!(spec.argv.iter().any(|arg| arg == "--no-dtls"));
    assert!(spec.create_no_window);
    assert!(spec.kill_job_on_close);
    let flattened = format!("{spec:?}").to_ascii_lowercase();
    for forbidden in ["password", "totp", "cookie", "credential"] {
        assert!(!flattened.contains(forbidden));
    }
}

#[derive(Clone)]
struct FakeProtector;

impl hyu_vpn_platform_windows::KeyProtector for FakeProtector {
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>, hyu_vpn_platform_windows::KeyProtectionError> {
        let mut protected = b"DPAPI-TEST".to_vec();
        protected.extend(key.iter().rev());
        Ok(protected)
    }

    fn unprotect(
        &self,
        protected: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, hyu_vpn_platform_windows::KeyProtectionError> {
        let body = protected
            .strip_prefix(b"DPAPI-TEST")
            .ok_or(hyu_vpn_platform_windows::KeyProtectionError::ProtectionFailed)?;
        Ok(zeroize::Zeroizing::new(
            body.iter().rev().copied().collect(),
        ))
    }
}

#[test]
fn credential_repository_never_stores_plaintext_and_round_trips() {
    use hyu_vpn_daemon::runtime::CredentialRepository;
    use hyu_vpn_platform_windows::WindowsCredentialRepository;
    use hyu_vpn_protocol::Credentials;

    let temp = tempfile::tempdir().unwrap();
    let paths = WindowsPaths::under(temp.path());
    let repository = WindowsCredentialRepository::new(paths.clone(), FakeProtector);
    let credentials = Credentials::new("ID-CANARY", "PASSWORD-CANARY", "SEED-CANARY").unwrap();
    repository.replace(credentials).unwrap();
    assert!(repository.present().unwrap());
    let loaded = repository.load().unwrap();
    assert_eq!(loaded.username(), "ID-CANARY");
    assert_eq!(loaded.password(), "PASSWORD-CANARY");
    assert_eq!(loaded.totp_seed(), "SEED-CANARY");
    let on_disk = [
        std::fs::read(paths.protected_key).unwrap(),
        std::fs::read(paths.credentials).unwrap(),
    ]
    .concat();
    for forbidden in [b"ID-CANARY".as_slice(), b"PASSWORD-CANARY", b"SEED-CANARY"] {
        assert!(
            !on_disk
                .windows(forbidden.len())
                .any(|part| part == forbidden)
        );
    }
}

#[test]
fn prompt_detector_handles_fragmented_hyu_prompts_without_retaining_output() {
    use hyu_vpn_platform_windows::{PromptDetector, PromptKind};

    let mut detector = PromptDetector::default();
    assert_eq!(detector.feed(b"User"), None);
    assert_eq!(detector.feed(b"name:"), Some(PromptKind::Username));
    assert_eq!(detector.feed(b"Pass"), None);
    assert_eq!(detector.feed(b"word:"), Some(PromptKind::Password));
    assert_eq!(detector.feed(b"Chal"), None);
    assert_eq!(detector.feed(b"lenge:"), Some(PromptKind::Challenge));
    assert_eq!(detector.buffered_bytes(), 0);
}

#[test]
fn private_state_acl_excludes_ordinary_users_and_grants_only_system_admins() {
    let sddl = hyu_vpn_platform_windows::PRIVATE_STATE_SDDL;
    assert!(sddl.starts_with("D:P"));
    assert!(sddl.contains(";;;SY)"));
    assert!(sddl.contains(";;;BA)"));
    for forbidden in [";;;WD)", ";;;AU)", ";;;BU)", ";;;IU)"] {
        assert!(!sddl.contains(forbidden));
    }
}
