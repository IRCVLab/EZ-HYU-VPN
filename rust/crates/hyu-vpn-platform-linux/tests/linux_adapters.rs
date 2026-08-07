use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;
use std::time::Duration;

use hyu_vpn_core::ports::NetworkMonitor;
use hyu_vpn_daemon::runtime::CredentialRepository;
use hyu_vpn_platform_linux::{
    LinuxCredentialRepository, LinuxPaths, LinuxRouteMonitor, ManagedChild, OpenConnectLaunch,
    authorize_peer_uid, parse_proc_net_route,
};
use hyu_vpn_protocol::Credentials;
use tempfile::tempdir;
use tokio::net::UnixStream;

const ROUTE_A: &str = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\n";
const ROUTE_B: &str = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nwlan0\t00000000\t0101A8C0\t0003\t0\t0\t50\t00000000\n";

#[test]
fn route_parser_selects_non_tunnel_default_and_decodes_gateway() {
    let input = format!("{ROUTE_A}tun0\t00000000\t020200C0\t0003\t0\t0\t1\t00000000\n");
    let identity = parse_proc_net_route(&input).unwrap();
    assert_eq!(identity.interface, "eth0");
    assert_eq!(identity.gateway, "192.0.2.1");
    assert!(!identity.is_tunnel);
}

#[tokio::test]
async fn route_monitor_wakes_when_identity_changes() {
    let dir = tempdir().unwrap();
    let route = dir.path().join("route");
    fs::write(&route, ROUTE_A).unwrap();
    let monitor = Arc::new(LinuxRouteMonitor::new(&route, Duration::from_millis(10)));
    assert_eq!(
        monitor.current_identity().await.unwrap().unwrap().interface,
        "eth0"
    );
    let waiting = {
        let monitor = Arc::clone(&monitor);
        tokio::spawn(async move { monitor.wait_for_change(Duration::from_secs(1)).await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    fs::write(route, ROUTE_B).unwrap();
    waiting.await.unwrap().unwrap();
}

#[tokio::test]
async fn unix_peer_uid_is_checked_against_expected_user() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let client = UnixStream::connect(&socket);
    let server = async { listener.accept().await.unwrap().0 };
    let (client, server) = tokio::join!(client, server);
    let client = client.unwrap();
    let expected = unsafe { libc::geteuid() };
    assert!(authorize_peer_uid(&client, expected).unwrap());
    assert!(!authorize_peer_uid(&server, expected.saturating_add(1)).unwrap());
}

#[test]
fn credential_repository_uses_private_regular_files_and_rejects_symlinks() {
    let dir = tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let paths = LinuxPaths::under(dir.path());
    let store = LinuxCredentialRepository::new(paths.clone(), uid);
    store
        .replace(Credentials::new("user", "PASSWORD-CANARY", "JBSWY3DPEHPK3PXP").unwrap())
        .unwrap();
    assert_eq!(
        fs::metadata(&paths.state_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&paths.credential_key)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&paths.credentials)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(store.load().unwrap().username(), "user");
    let raw = fs::read(&paths.credentials).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("PASSWORD-CANARY"));

    fs::remove_file(&paths.credentials).unwrap();
    symlink(&paths.credential_key, &paths.credentials).unwrap();
    assert!(store.load().is_err());
}

#[test]
fn openconnect_launch_keeps_credentials_out_of_argv_and_environment() {
    let credentials =
        Credentials::new("USERNAME-CANARY", "PASSWORD-CANARY", "JBSWY3DPEHPK3PXP").unwrap();
    let launch = OpenConnectLaunch::new(
        "/usr/sbin/openconnect",
        "secure.hanyang.ac.kr",
        "HYU-ExternalGW-General",
        "/usr/lib/hyu-vpn/vpnc-script",
        "/usr/lib/hyu-vpn/hip-report",
        &credentials,
        "123456",
    )
    .unwrap();
    let joined = launch.argv.join(" ");
    for secret in [
        "USERNAME-CANARY",
        "PASSWORD-CANARY",
        "JBSWY3DPEHPK3PXP",
        "123456",
    ] {
        assert!(!joined.contains(secret));
        assert!(
            !launch
                .environment
                .iter()
                .any(|(k, v)| k.contains(secret) || v.contains(secret))
        );
    }
    assert_eq!(
        launch.stdin_payload(),
        b"USERNAME-CANARY\nPASSWORD-CANARY\n123456\n"
    );
}

#[tokio::test]
async fn managed_child_terminates_its_process_group() {
    let child = ManagedChild::spawn("/bin/sh", &["-c", "sleep 30"], &[])
        .await
        .unwrap();
    let pid = child.pid();
    child.terminate(Duration::from_millis(100)).await.unwrap();
    let alive = unsafe { libc::kill(pid as i32, 0) } == 0;
    assert!(!alive, "managed process remained alive");
}
