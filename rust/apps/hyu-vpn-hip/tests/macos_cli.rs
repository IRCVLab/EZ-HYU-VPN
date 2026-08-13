#![cfg(target_os = "macos")]

use hyu_vpn_hip::{
    Drive, HostInfo, MacPosture, NetworkInterface, Patch, Product,
    build_macos_hip_with_posture_from_args,
};

fn args(cookie: &str, md5: &str, ip: &str, ipv6: &str, version: &str) -> Vec<String> {
    vec![
        "--cookie".to_owned(),
        cookie.to_owned(),
        format!("--client-ip={ip}"),
        format!("--client-ipv6={ipv6}"),
        format!("--md5={md5}"),
        format!("--app-version={version}"),
    ]
}

#[test]
fn macos_hip_cli_generates_full_native_shape_and_escapes_without_cookie_leakage() {
    let cookie = "user=alice%2Dvpn&domain=HYU&computer=mac%3Clab%3E";
    let invocation = args(
        cookie,
        "0123456789abcdef0123456789abcdef",
        "192.0.2.10",
        "2001:db8::1",
        "OpenConnect-9.12",
    );
    let posture = MacPosture {
        host_info: HostInfo {
            os: Some("Apple Mac OS X 15.6".to_owned()),
            os_vendor: Some("Apple".to_owned()),
            host_id: Some("aa:bb:cc:dd:ee:ff".to_owned()),
            interfaces: vec![NetworkInterface {
                name: "en0".to_owned(),
                description: Some("Wi-Fi".to_owned()),
                mac_address: Some("aa:bb:cc:dd:ee:ff".to_owned()),
                ..NetworkInterface::default()
            }],
            ..HostInfo::default()
        },
        ..MacPosture::default()
    };

    let xml =
        build_macos_hip_with_posture_from_args(&invocation, &posture, "2026-08-08T00:00:00Z", None)
            .unwrap();

    assert!(xml.contains("<hip-report name=\"hip-report\">"));
    assert!(xml.contains("<host-id>aa:bb:cc:dd:ee:ff</host-id>"));
    assert!(xml.contains("<os-vendor>Apple</os-vendor>"));
    assert!(xml.contains("<os>Apple Mac OS X 15.6</os>"));
    assert!(xml.contains("<user-name>alice-vpn</user-name>"));
    assert!(xml.contains("<domain>HYU</domain>"));
    assert!(xml.contains("<host-name>mac&lt;lab&gt;</host-name>"));
    assert!(xml.contains("<ip-address>192.0.2.10</ip-address>"));
    assert!(xml.contains("<ipv6-address>2001:db8::1</ipv6-address>"));
    assert!(xml.contains("<generate-time>08/08/2026 00:00:00</generate-time>"));
    assert!(xml.contains("<network-interface>"));
    for category in [
        "host-info",
        "anti-malware",
        "disk-backup",
        "disk-encryption",
        "firewall",
        "patch-management",
        "data-loss-prevention",
    ] {
        assert!(xml.contains(&format!("<entry name=\"{category}\">")));
    }
    assert!(!xml.contains(cookie));
    assert!(!xml.contains("mac<lab>"));
}

#[test]
fn macos_rust_hip_matches_the_sanitized_python_native_fixture() {
    let invocation = args(
        "user=TEST-USER&domain=&computer=TEST-HOST",
        "00000000000000000000000000000000",
        "192.0.2.10",
        "2001:db8::10",
        "OpenConnect TEST",
    );
    let posture = MacPosture {
        host_info: HostInfo {
            host_name: Some("TEST-HOST".to_owned()),
            os: Some("Apple Mac OS X 14.0".to_owned()),
            os_version: Some("14.0".to_owned()),
            client_version: Some("OpenConnect TEST".to_owned()),
            os_vendor: Some("Apple".to_owned()),
            domain: Some(String::new()),
            host_id: Some("TEST-HOST-ID".to_owned()),
            interfaces: vec![NetworkInterface {
                name: "en0".to_owned(),
                description: Some("Wi-Fi".to_owned()),
                mac_address: Some("00:00:00:00:00:00".to_owned()),
                ipv4_addresses: vec!["192.0.2.10".to_owned()],
                ipv6_addresses: vec!["2001:db8::10".to_owned()],
            }],
        },
        anti_malware: vec![
            Product {
                vendor: Some("Apple Inc.".to_owned()),
                name: "Xprotect".to_owned(),
                version: Some("TEST-XPROTECT".to_owned()),
                defver: Some("TEST-DEFVER".to_owned()),
                engver: Some(String::new()),
                datemon: Some("08".to_owned()),
                dateday: Some("01".to_owned()),
                dateyear: Some("2026".to_owned()),
                prod_type: Some("3".to_owned()),
                os_type: Some("4".to_owned()),
                real_time_protection: Some("yes".to_owned()),
                last_full_scan_time: Some("n/a".to_owned()),
                ..Product::default()
            },
            Product {
                vendor: Some("Apple Inc.".to_owned()),
                name: "Gatekeeper".to_owned(),
                version: Some("14.0".to_owned()),
                defver: Some(String::new()),
                engver: Some(String::new()),
                datemon: Some("08".to_owned()),
                dateday: Some("04".to_owned()),
                dateyear: Some("2026".to_owned()),
                prod_type: Some("3".to_owned()),
                os_type: Some("4".to_owned()),
                real_time_protection: Some("yes".to_owned()),
                last_full_scan_time: Some("n/a".to_owned()),
                ..Product::default()
            },
        ],
        disk_backup: vec![Product {
            vendor: Some("Apple Inc.".to_owned()),
            name: "Time Machine".to_owned(),
            version: Some("1.3".to_owned()),
            last_backup_time: Some("n/a".to_owned()),
            ..Product::default()
        }],
        disk_encryption: vec![Drive {
            drive_name: "All".to_owned(),
            enc_state: Some("encrypted".to_owned()),
            product_version: Some("14.0".to_owned()),
        }],
        firewall: vec![
            Product {
                vendor: Some("Apple Inc.".to_owned()),
                name: "Mac OS X Builtin Firewall".to_owned(),
                version: Some("14.0".to_owned()),
                is_enabled: Some("yes".to_owned()),
                ..Product::default()
            },
            Product {
                vendor: Some("OpenBSD".to_owned()),
                name: "Packet Filter".to_owned(),
                version: Some("14.0".to_owned()),
                is_enabled: Some("no".to_owned()),
                ..Product::default()
            },
        ],
        patch_management_product: Product {
            vendor: Some("Apple Inc.".to_owned()),
            name: "Software Update".to_owned(),
            version: Some("3.0".to_owned()),
            is_enabled: Some("yes".to_owned()),
            ..Product::default()
        },
        patches: vec![Patch {
            title: "TEST-UPDATE-001".to_owned(),
            description: Some("TEST-UPDATE-001".to_owned()),
            product: Some("macOS".to_owned()),
            vendor: Some("Apple Inc.".to_owned()),
            severity: Some("2".to_owned()),
            category: Some("update".to_owned()),
            is_installed: Some("no".to_owned()),
            ..Patch::default()
        }],
    };

    let generated =
        build_macos_hip_with_posture_from_args(&invocation, &posture, "2026-08-04T01:02:03Z", None)
            .unwrap();
    let expected = include_str!("../../../../tests/fixtures/native_hip_sanitized.xml");

    assert_eq!(generated, expected);
}
