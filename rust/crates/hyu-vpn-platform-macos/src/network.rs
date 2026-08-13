use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_int, c_void};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, NetworkProbeError, PortalProbe};
use hyu_vpn_core::state::NetworkIdentity;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::Notify;

use crate::PlatformError;

const ROUTE_EXECUTABLE: &str = "/sbin/route";
const ROUTE_ARGS: [&str; 3] = ["-n", "get", "default"];
const MAX_ROUTE_OUTPUT: usize = 16 * 1024;
const MAX_INTERFACE_LEN: usize = 15;
const MAX_GATEWAY_LEN: usize = 64;
const MAX_HOST_LEN: usize = 253;
const MAX_ADDRESSES: usize = 8;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_PORTAL_TIMEOUT: Duration = Duration::from_secs(3);
const IPV6_BOUND_IF_OPTION: c_int = 125;
const DNS_SERVICE_FLAGS_TIMEOUT: u32 = 0x10000;
const DNS_SERVICE_FLAGS_MORE_COMING: u32 = 0x1;
const DNS_SERVICE_FLAGS_ADD: u32 = 0x2;
const DNS_SERVICE_PROTOCOL_IPV4: u32 = 0x01;
const DNS_SERVICE_PROTOCOL_IPV6: u32 = 0x02;
const DNS_SERVICE_ERR_NO_ERROR: i32 = 0;

pub fn parse_default_route(bytes: &[u8]) -> Result<Option<NetworkIdentity>, PlatformError> {
    if bytes.len() > MAX_ROUTE_OUTPUT {
        return Err(PlatformError::InvalidNetworkEvidence);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| PlatformError::InvalidNetworkEvidence)?;
    let mut interface = None;
    let mut gateway = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "interface" => interface = Some(value.trim()),
            "gateway" => gateway = Some(value.trim()),
            _ => {}
        }
    }
    match (interface, gateway) {
        (None, None) | (None, Some(_)) | (Some(_), None) => Ok(None),
        (Some(interface), Some(gateway)) => {
            validate_interface(interface)?;
            validate_gateway(gateway)?;
            if is_tunnel_interface(interface) {
                return Ok(None);
            }
            Ok(Some(NetworkIdentity::new(interface, gateway)))
        }
    }
}

fn validate_interface(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > MAX_INTERFACE_LEN
        || value.chars().any(|character| {
            character.is_control()
                || !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
        })
    {
        return Err(PlatformError::InvalidNetworkEvidence);
    }
    Ok(())
}

fn validate_gateway(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > MAX_GATEWAY_LEN
        || value.chars().any(|character| {
            character.is_control()
                || !(character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '-'))
        })
    {
        return Err(PlatformError::InvalidNetworkEvidence);
    }
    Ok(())
}

fn is_tunnel_interface(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["utun", "tap", "tun", "ppp", "wg", "vpn"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

#[derive(Clone, Debug)]
pub struct ResumeNotifier {
    notify: Arc<Notify>,
}

impl ResumeNotifier {
    pub fn notify_resume(&self) {
        self.notify.notify_waiters();
    }
}

#[derive(Debug)]
pub struct MacNetworkMonitor {
    source: RouteSource,
    poll_interval: Duration,
    command_timeout: Duration,
    last_snapshot: Mutex<Option<Vec<u8>>>,
    resume: ResumeNotifier,
}

#[derive(Debug)]
enum RouteSource {
    Command,
    Snapshots(Mutex<SnapshotState>),
}

#[derive(Debug)]
struct SnapshotState {
    snapshots: Vec<Vec<u8>>,
    index: usize,
}

impl MacNetworkMonitor {
    pub fn production() -> Self {
        Self::new(DEFAULT_POLL_INTERVAL, DEFAULT_COMMAND_TIMEOUT)
    }

    pub fn new(poll_interval: Duration, command_timeout: Duration) -> Self {
        Self {
            source: RouteSource::Command,
            poll_interval: poll_interval.max(Duration::from_millis(10)),
            command_timeout: command_timeout
                .clamp(Duration::from_millis(100), Duration::from_secs(10)),
            last_snapshot: Mutex::new(None),
            resume: ResumeNotifier {
                notify: Arc::new(Notify::new()),
            },
        }
    }

    pub fn from_route_snapshots_for_test(snapshots: Vec<Vec<u8>>, poll_interval: Duration) -> Self {
        assert!(!snapshots.is_empty(), "test snapshots must not be empty");
        Self {
            source: RouteSource::Snapshots(Mutex::new(SnapshotState {
                snapshots,
                index: 0,
            })),
            poll_interval: poll_interval.max(Duration::from_millis(1)),
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
            last_snapshot: Mutex::new(None),
            resume: ResumeNotifier {
                notify: Arc::new(Notify::new()),
            },
        }
    }

    pub fn resume_notifier_for_test(&self) -> ResumeNotifier {
        self.resume.clone()
    }

    async fn snapshot(&self) -> Result<Vec<u8>, NetworkProbeError> {
        match &self.source {
            RouteSource::Command => route_command_output(self.command_timeout).await,
            RouteSource::Snapshots(state) => {
                let state = state.lock().map_err(|_| NetworkProbeError::ProbeFailed)?;
                Ok(state.snapshots[state.index].clone())
            }
        }
    }

    fn advance_test_snapshot_if_possible(&self) -> Result<(), NetworkProbeError> {
        if let RouteSource::Snapshots(state) = &self.source {
            let mut state = state.lock().map_err(|_| NetworkProbeError::ProbeFailed)?;
            if state.index + 1 < state.snapshots.len() {
                state.index += 1;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl NetworkMonitor for MacNetworkMonitor {
    async fn current_identity(&self) -> Result<Option<NetworkIdentity>, NetworkProbeError> {
        let snapshot = self.snapshot().await?;
        let identity =
            parse_default_route(&snapshot).map_err(|_| NetworkProbeError::ProbeFailed)?;
        *self
            .last_snapshot
            .lock()
            .map_err(|_| NetworkProbeError::ProbeFailed)? = Some(snapshot);
        Ok(identity)
    }

    async fn wait_for_change(&self, timeout: Duration) -> Result<(), NetworkProbeError> {
        let cached = self
            .last_snapshot
            .lock()
            .map_err(|_| NetworkProbeError::ProbeFailed)?
            .clone();
        let baseline = match cached {
            Some(value) => value,
            None => self.snapshot().await?,
        };
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Ok(());
            }
            let sleep_for = self
                .poll_interval
                .min(deadline.saturating_duration_since(Instant::now()));
            tokio::select! {
                _ = tokio::time::sleep(sleep_for) => {},
                _ = self.resume.notify.notified() => return Ok(()),
            }
            self.advance_test_snapshot_if_possible()?;
            let current = self.snapshot().await?;
            if current != baseline {
                *self
                    .last_snapshot
                    .lock()
                    .map_err(|_| NetworkProbeError::ProbeFailed)? = Some(current);
                return Ok(());
            }
        }
    }
}

async fn route_command_output(timeout: Duration) -> Result<Vec<u8>, NetworkProbeError> {
    let mut child = Command::new(ROUTE_EXECUTABLE);
    child
        .args(ROUTE_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = child.spawn().map_err(|_| NetworkProbeError::ProbeFailed)?;
    let mut stdout = child.stdout.take().ok_or(NetworkProbeError::ProbeFailed)?;
    let mut stderr = child.stderr.take().ok_or(NetworkProbeError::ProbeFailed)?;
    let output = async move {
        let (stdout_result, stderr_result, status_result) = tokio::join!(
            read_bounded(&mut stdout),
            read_bounded(&mut stderr),
            child.wait(),
        );
        let status = status_result.map_err(|_| NetworkProbeError::ProbeFailed)?;
        let stdout_bytes = stdout_result?;
        let stderr_bytes = stderr_result?;
        if status.success() {
            Ok(stdout_bytes)
        } else if stdout_bytes.is_empty() && !stderr_bytes.is_empty() {
            Ok(stderr_bytes)
        } else {
            Ok(stdout_bytes)
        }
    };
    tokio::time::timeout(timeout, output)
        .await
        .map_err(|_| NetworkProbeError::ProbeFailed)?
}

async fn read_bounded<R>(reader: &mut R) -> Result<Vec<u8>, NetworkProbeError>
where
    R: AsyncReadExt + Unpin,
{
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|_| NetworkProbeError::ProbeFailed)?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(read) > MAX_ROUTE_OUTPUT {
            return Err(NetworkProbeError::ProbeFailed);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

#[async_trait]
pub trait InterfaceScopedResolver: Send + Sync {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        interface: &str,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, NetworkProbeError>;
}

#[async_trait]
pub trait InterfaceConnector: Send + Sync {
    async fn connect(
        &self,
        address: SocketAddr,
        interface: &str,
        timeout: Duration,
    ) -> Result<bool, NetworkProbeError>;
}

#[derive(Clone)]
pub struct MacPortalProbe {
    host: String,
    port: u16,
    timeout: Duration,
    resolver: Arc<dyn InterfaceScopedResolver>,
    connector: Arc<dyn InterfaceConnector>,
}

impl MacPortalProbe {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        timeout: Duration,
    ) -> Result<Self, NetworkProbeError> {
        Self::with_components(
            host,
            port,
            timeout,
            Arc::new(DnsSdResolver),
            Arc::new(BoundTcpConnector),
        )
    }

    pub fn with_components_for_test(
        host: impl Into<String>,
        port: u16,
        timeout: Duration,
        resolver: Arc<dyn InterfaceScopedResolver>,
        connector: Arc<dyn InterfaceConnector>,
    ) -> Result<Self, NetworkProbeError> {
        Self::with_components(host, port, timeout, resolver, connector)
    }

    fn with_components(
        host: impl Into<String>,
        port: u16,
        timeout: Duration,
        resolver: Arc<dyn InterfaceScopedResolver>,
        connector: Arc<dyn InterfaceConnector>,
    ) -> Result<Self, NetworkProbeError> {
        let host = host.into();
        if host.is_empty()
            || host.len() > MAX_HOST_LEN
            || host.chars().any(char::is_control)
            || port == 0
            || timeout.is_zero()
        {
            return Err(NetworkProbeError::ProbeFailed);
        }
        Ok(Self {
            host,
            port,
            timeout: timeout.min(Duration::from_secs(10)),
            resolver,
            connector,
        })
    }

    pub fn production() -> Self {
        Self::new("secure.hanyang.ac.kr", 443, DEFAULT_PORTAL_TIMEOUT)
            .expect("fixed portal probe configuration must be valid")
    }
}

#[async_trait]
impl PortalProbe for MacPortalProbe {
    async fn reachable(&self, identity: &NetworkIdentity) -> Result<bool, NetworkProbeError> {
        if identity.is_tunnel || validate_interface(&identity.interface).is_err() {
            return Ok(false);
        }
        let addresses = self
            .resolver
            .resolve(&self.host, self.port, &identity.interface, self.timeout)
            .await?
            .into_iter()
            .take(MAX_ADDRESSES);
        for address in addresses {
            if self
                .connector
                .connect(address, &identity.interface, self.timeout)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Debug)]
struct DnsSdResolver;

#[async_trait]
impl InterfaceScopedResolver for DnsSdResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        interface: &str,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, NetworkProbeError> {
        let host = host.to_owned();
        let interface = interface.to_owned();
        tokio::task::spawn_blocking(move || resolve_with_dns_sd(&host, port, &interface, timeout))
            .await
            .map_err(|_| NetworkProbeError::ProbeFailed)?
    }
}

#[derive(Debug)]
struct BoundTcpConnector;

#[async_trait]
impl InterfaceConnector for BoundTcpConnector {
    async fn connect(
        &self,
        address: SocketAddr,
        interface: &str,
        timeout: Duration,
    ) -> Result<bool, NetworkProbeError> {
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        }
        .map_err(|_| NetworkProbeError::ProbeFailed)?;
        bind_socket_to_interface(&socket, address, interface)
            .map_err(|_| NetworkProbeError::ProbeFailed)?;
        Ok(matches!(
            tokio::time::timeout(timeout, socket.connect(address)).await,
            Ok(Ok(_))
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketBindParameters {
    pub level: c_int,
    pub option: c_int,
}

pub fn socket_bind_parameters_for_test(address: SocketAddr) -> SocketBindParameters {
    bind_parameters(address)
}

fn bind_parameters(address: SocketAddr) -> SocketBindParameters {
    if address.is_ipv4() {
        SocketBindParameters {
            level: libc::IPPROTO_IP,
            option: libc::IP_BOUND_IF,
        }
    } else {
        SocketBindParameters {
            level: libc::IPPROTO_IPV6,
            option: IPV6_BOUND_IF_OPTION,
        }
    }
}

#[cfg(target_os = "macos")]
fn bind_socket_to_interface(
    socket: &tokio::net::TcpSocket,
    address: SocketAddr,
    interface: &str,
) -> io::Result<()> {
    let index = interface_index(interface)?;
    let parameters = bind_parameters(address);
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            parameters.level,
            parameters.option,
            (&index as *const libc::c_uint).cast(),
            std::mem::size_of_val(&index) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn bind_socket_to_interface(
    _socket: &tokio::net::TcpSocket,
    _address: SocketAddr,
    interface: &str,
) -> io::Result<()> {
    validate_interface(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))
}

fn interface_index(interface: &str) -> io::Result<u32> {
    validate_interface(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
    let c_name = CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

#[cfg(target_os = "macos")]
type DnsServiceRef = *mut c_void;
#[cfg(target_os = "macos")]
type DnsServiceFlags = u32;
#[cfg(target_os = "macos")]
type DnsServiceProtocol = u32;
#[cfg(target_os = "macos")]
type DnsServiceErrorType = i32;

#[cfg(target_os = "macos")]
#[link(name = "System")]
unsafe extern "C" {
    fn DNSServiceGetAddrInfo(
        sd_ref: *mut DnsServiceRef,
        flags: DnsServiceFlags,
        interface_index: u32,
        protocol: DnsServiceProtocol,
        hostname: *const c_char,
        callback: DnsServiceGetAddrInfoReply,
        context: *mut c_void,
    ) -> DnsServiceErrorType;
    fn DNSServiceRefSockFD(sd_ref: DnsServiceRef) -> c_int;
    fn DNSServiceProcessResult(sd_ref: DnsServiceRef) -> DnsServiceErrorType;
    fn DNSServiceRefDeallocate(sd_ref: DnsServiceRef);
}

#[cfg(target_os = "macos")]
type DnsServiceGetAddrInfoReply = unsafe extern "C" fn(
    sd_ref: DnsServiceRef,
    flags: DnsServiceFlags,
    interface_index: u32,
    error_code: DnsServiceErrorType,
    hostname: *const c_char,
    address: *const libc::sockaddr,
    ttl: u32,
    context: *mut c_void,
);

#[cfg(target_os = "macos")]
struct DnsServiceRefGuard(DnsServiceRef);

#[cfg(target_os = "macos")]
impl Drop for DnsServiceRefGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { DNSServiceRefDeallocate(self.0) };
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct DnsResults {
    addresses: Vec<SocketAddr>,
    done: bool,
    error: bool,
}

#[cfg(target_os = "macos")]
fn resolve_with_dns_sd(
    host: &str,
    port: u16,
    interface: &str,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, NetworkProbeError> {
    let interface_index = interface_index(interface).map_err(|_| NetworkProbeError::ProbeFailed)?;
    let hostname = CString::new(host).map_err(|_| NetworkProbeError::ProbeFailed)?;
    let mut service_ref = std::ptr::null_mut();
    let mut results = DnsResults::default();
    let code = unsafe {
        DNSServiceGetAddrInfo(
            &mut service_ref,
            DNS_SERVICE_FLAGS_TIMEOUT,
            interface_index,
            DNS_SERVICE_PROTOCOL_IPV4 | DNS_SERVICE_PROTOCOL_IPV6,
            hostname.as_ptr(),
            dns_service_getaddrinfo_reply,
            (&mut results as *mut DnsResults).cast(),
        )
    };
    if code != DNS_SERVICE_ERR_NO_ERROR || service_ref.is_null() {
        return Err(NetworkProbeError::ProbeFailed);
    }
    let guard = DnsServiceRefGuard(service_ref);
    let fd = unsafe { DNSServiceRefSockFD(guard.0) };
    if fd < 0 {
        return Err(NetworkProbeError::ProbeFailed);
    }
    let deadline = Instant::now() + timeout;
    while !results.done && !results.error && results.addresses.len() < MAX_ADDRESSES {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let timeout_ms = remaining.as_millis().min(c_int::MAX as u128) as c_int;
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if poll_result < 0 {
            return Err(NetworkProbeError::ProbeFailed);
        }
        if poll_result == 0 {
            break;
        }
        let process_result = unsafe { DNSServiceProcessResult(guard.0) };
        if process_result != DNS_SERVICE_ERR_NO_ERROR {
            return Err(NetworkProbeError::ProbeFailed);
        }
    }
    if results.error {
        return Ok(Vec::new());
    }
    for address in &mut results.addresses {
        *address = SocketAddr::new(address.ip(), port);
    }
    Ok(results.addresses)
}

#[cfg(not(target_os = "macos"))]
fn resolve_with_dns_sd(
    host: &str,
    port: u16,
    interface: &str,
    _timeout: Duration,
) -> Result<Vec<SocketAddr>, NetworkProbeError> {
    validate_interface(interface).map_err(|_| NetworkProbeError::ProbeFailed)?;
    let host = CString::new(host).map_err(|_| NetworkProbeError::ProbeFailed)?;
    let _ = host;
    let _ = port;
    Ok(Vec::new())
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn dns_service_getaddrinfo_reply(
    _sd_ref: DnsServiceRef,
    flags: DnsServiceFlags,
    _interface_index: u32,
    error_code: DnsServiceErrorType,
    _hostname: *const c_char,
    address: *const libc::sockaddr,
    _ttl: u32,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    let results = unsafe { &mut *(context.cast::<DnsResults>()) };
    if error_code != DNS_SERVICE_ERR_NO_ERROR {
        results.error = true;
        results.done = true;
        return;
    }
    if flags & DNS_SERVICE_FLAGS_ADD != 0
        && !address.is_null()
        && results.addresses.len() < MAX_ADDRESSES
    {
        if let Some(socket_addr) = unsafe { sockaddr_to_socket_addr(address) } {
            results.addresses.push(socket_addr);
        }
    }
    if flags & DNS_SERVICE_FLAGS_MORE_COMING == 0 {
        results.done = true;
    }
}

#[cfg(target_os = "macos")]
unsafe fn sockaddr_to_socket_addr(address: *const libc::sockaddr) -> Option<SocketAddr> {
    match unsafe { (*address).sa_family as c_int } {
        libc::AF_INET => {
            let address = unsafe { &*(address.cast::<libc::sockaddr_in>()) };
            let octets = address.sin_addr.s_addr.to_ne_bytes();
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let address = unsafe { &*(address.cast::<libc::sockaddr_in6>()) };
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                u16::from_be(address.sin6_port),
            ))
        }
        _ => None,
    }
}
