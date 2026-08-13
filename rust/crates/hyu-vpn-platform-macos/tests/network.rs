use std::time::{Duration, Instant};

use hyu_vpn_core::ports::{NetworkMonitor, PortalProbe};
use hyu_vpn_core::state::NetworkIdentity;
use hyu_vpn_platform_macos::{
    MacNetworkMonitor, MacPortalProbe, PlatformError, parse_default_route,
};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hyu_vpn_core::ports::NetworkProbeError;
use hyu_vpn_platform_macos::{
    InterfaceConnector, InterfaceScopedResolver, socket_bind_parameters_for_test,
};

#[test]
fn socket_binding_uses_family_specific_macos_bound_interface_options() {
    // Catches: binding IPv6 sockets with IPPROTO_IP/IP_BOUND_IF instead of IPPROTO_IPV6/IPV6_BOUND_IF.
    let ipv4 =
        socket_bind_parameters_for_test(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443));
    assert_eq!(ipv4.level, libc::IPPROTO_IP);
    assert_eq!(ipv4.option, 25);

    let ipv6 =
        socket_bind_parameters_for_test(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443));
    assert_eq!(ipv6.level, libc::IPPROTO_IPV6);
    assert_eq!(ipv6.option, 125);
}

#[derive(Default)]
struct RecordingResolver {
    calls: Mutex<Vec<(String, u16, String, Duration)>>,
    addresses: Vec<SocketAddr>,
}

#[async_trait]
impl InterfaceScopedResolver for RecordingResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        interface: &str,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, NetworkProbeError> {
        self.calls
            .lock()
            .unwrap()
            .push((host.to_owned(), port, interface.to_owned(), timeout));
        Ok(self.addresses.clone())
    }
}

#[derive(Default)]
struct RecordingConnector {
    outcomes: Mutex<Vec<bool>>,
    attempts: Mutex<Vec<(SocketAddr, String, Duration)>>,
}

#[async_trait]
impl InterfaceConnector for RecordingConnector {
    async fn connect(
        &self,
        address: SocketAddr,
        interface: &str,
        timeout: Duration,
    ) -> Result<bool, NetworkProbeError> {
        self.attempts
            .lock()
            .unwrap()
            .push((address, interface.to_owned(), timeout));
        Ok(self.outcomes.lock().unwrap().remove(0))
    }
}

#[tokio::test]
async fn portal_probe_resolves_dns_on_the_observed_interface() {
    // Catches: using unscoped tokio::net::lookup_host before the physical interface is known to DNS.
    let resolver = Arc::new(RecordingResolver {
        calls: Mutex::new(Vec::new()),
        addresses: Vec::new(),
    });
    let connector = Arc::new(RecordingConnector::default());
    let probe = MacPortalProbe::with_components_for_test(
        "secure.hanyang.ac.kr",
        443,
        Duration::from_secs(2),
        resolver.clone(),
        connector,
    )
    .unwrap();

    assert!(
        !probe
            .reachable(&NetworkIdentity::new("en7", "192.0.2.1"))
            .await
            .unwrap()
    );

    assert_eq!(
        resolver.calls.lock().unwrap().as_slice(),
        &[(
            "secure.hanyang.ac.kr".to_owned(),
            443,
            "en7".to_owned(),
            Duration::from_secs(2)
        )]
    );
}

#[tokio::test]
async fn portal_probe_attempts_subsequent_resolved_addresses_after_failures() {
    // Catches: returning false/error after the first resolved address fails instead of trying bounded fallbacks.
    let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443);
    let second = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    let resolver = Arc::new(RecordingResolver {
        calls: Mutex::new(Vec::new()),
        addresses: vec![first, second],
    });
    let connector = Arc::new(RecordingConnector {
        outcomes: Mutex::new(vec![false, true]),
        attempts: Mutex::new(Vec::new()),
    });
    let probe = MacPortalProbe::with_components_for_test(
        "secure.hanyang.ac.kr",
        443,
        Duration::from_secs(2),
        resolver,
        connector.clone(),
    )
    .unwrap();

    assert!(
        probe
            .reachable(&NetworkIdentity::new("en0", "192.0.2.1"))
            .await
            .unwrap()
    );

    let attempts = connector.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts[0],
        (first, "en0".to_owned(), Duration::from_secs(2))
    );
    assert_eq!(
        attempts[1],
        (second, "en0".to_owned(), Duration::from_secs(2))
    );
}

fn route(interface: &str, gateway: &str) -> Vec<u8> {
    format!(
        "   route to: default\n destination: default\n       mask: default\n    gateway: {gateway}\n  interface: {interface}\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0\n"
    )
    .into_bytes()
}

#[test]
fn parse_default_route_selects_physical_default_route() {
    // Catches: treating any default route as unavailable or failing to read route(8)'s interface/gateway fields.
    let identity = parse_default_route(&route("en0", "192.168.1.1")).unwrap();

    assert_eq!(identity, Some(NetworkIdentity::new("en0", "192.168.1.1")));
}

#[test]
fn parse_default_route_excludes_tunnel_default_routes() {
    // Catches: readiness being satisfied by VPN/tunnel interfaces instead of physical network interfaces.
    for tunnel in ["utun5", "tap0", "tun1", "ppp0", "wg0", "vpn0"] {
        assert_eq!(
            parse_default_route(&route(tunnel, "10.0.0.1")).unwrap(),
            None,
            "{tunnel} should not be a physical default route"
        );
    }
}

#[test]
fn parse_default_route_requires_bounded_safe_interface_and_gateway() {
    // Catches: accepting malformed command output that could create unstable or unsafe network identities.
    for invalid_interface in ["", "en0123456789abcdef", "en0\u{7f}"] {
        assert!(matches!(
            parse_default_route(&route(invalid_interface, "192.168.1.1")),
            Err(PlatformError::InvalidNetworkEvidence)
        ));
    }
    for invalid_gateway in [
        "",
        "192.168.1.1\u{7f}",
        "gateway-name-that-is-far-too-long-for-a-route-and-must-be-rejected-by-parser",
    ] {
        assert!(matches!(
            parse_default_route(&route("en0", invalid_gateway)),
            Err(PlatformError::InvalidNetworkEvidence)
        ));
    }
}

#[test]
fn parse_default_route_maps_offline_evidence_to_none() {
    // Catches: mapping absent physical route evidence to ProbeFailed instead of offline/unavailable.
    let offline = b"route: writing to routing socket: not in table\n";

    assert_eq!(parse_default_route(offline).unwrap(), None);
}

#[tokio::test]
async fn monitor_reports_stable_identity_changes_without_live_route_mutation() {
    // Catches: monitor implementations that mutate routes/DNS or do not observe changed snapshots.
    let monitor = MacNetworkMonitor::from_route_snapshots_for_test(
        vec![route("en0", "192.168.1.1"), route("en1", "192.168.1.254")],
        Duration::from_millis(1),
    );

    assert_eq!(
        monitor.current_identity().await.unwrap(),
        Some(NetworkIdentity::new("en0", "192.168.1.1"))
    );
    let started = Instant::now();
    monitor
        .wait_for_change(Duration::from_secs(1))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(
        monitor.current_identity().await.unwrap(),
        Some(NetworkIdentity::new("en1", "192.168.1.254"))
    );
}

#[tokio::test]
async fn monitor_wait_for_change_wakes_on_resume_notification() {
    // Catches: sleep/resume handling that waits for the full poll timeout before rechecking readiness.
    let monitor = MacNetworkMonitor::from_route_snapshots_for_test(
        vec![route("en0", "192.168.1.1")],
        Duration::from_secs(60),
    );

    let resumed = monitor.resume_notifier_for_test();
    let waiter = tokio::spawn(async move {
        let started = Instant::now();
        monitor
            .wait_for_change(Duration::from_secs(5))
            .await
            .unwrap();
        started.elapsed()
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    resumed.notify_resume();

    assert!(waiter.await.unwrap() < Duration::from_millis(250));
}

#[tokio::test]
async fn portal_probe_rejects_tunnel_identity_before_dns_or_tcp() {
    // Catches: probing captive portal reachability through a VPN/tunnel identity.
    let probe = MacPortalProbe::new("127.0.0.1", 443, Duration::from_millis(1)).unwrap();

    assert!(
        !probe
            .reachable(&NetworkIdentity::tunnel("utun5", "10.0.0.1"))
            .await
            .unwrap()
    );
}
