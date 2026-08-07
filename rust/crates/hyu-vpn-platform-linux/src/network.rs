use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, NetworkProbeError};
use hyu_vpn_core::state::NetworkIdentity;

pub fn parse_proc_net_route(input: &str) -> Option<NetworkIdentity> {
    let mut best: Option<(u32, NetworkIdentity)> = None;
    for line in input.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        let interface = fields[0];
        if is_tunnel_interface(interface) {
            continue;
        }
        let flags = u16::from_str_radix(fields[3], 16).ok()?;
        if flags & 0x3 != 0x3 {
            continue;
        }
        let metric = fields[6].parse::<u32>().ok()?;
        let gateway = decode_ipv4_gateway(fields[2])?;
        let identity = NetworkIdentity::new(interface, gateway);
        if best.as_ref().is_none_or(|(current, _)| metric < *current) {
            best = Some((metric, identity));
        }
    }
    best.map(|(_, identity)| identity)
}

fn decode_ipv4_gateway(value: &str) -> Option<String> {
    if value.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(value, 16).ok()?;
    Some(format!(
        "{}.{}.{}.{}",
        raw & 0xff,
        (raw >> 8) & 0xff,
        (raw >> 16) & 0xff,
        (raw >> 24) & 0xff
    ))
}

fn is_tunnel_interface(value: &str) -> bool {
    ["tun", "tap", "ppp", "wg", "utun", "vpn"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

pub struct LinuxRouteMonitor {
    route_path: PathBuf,
    poll_interval: Duration,
    last_snapshot: Mutex<Option<Vec<u8>>>,
}

impl LinuxRouteMonitor {
    pub fn new(route_path: impl AsRef<Path>, poll_interval: Duration) -> Self {
        Self {
            route_path: route_path.as_ref().to_path_buf(),
            poll_interval: poll_interval.max(Duration::from_millis(10)),
            last_snapshot: Mutex::new(None),
        }
    }

    pub fn production() -> Self {
        Self::new("/proc/net/route", Duration::from_secs(1))
    }

    async fn snapshot(&self) -> Result<Vec<u8>, NetworkProbeError> {
        tokio::fs::read(&self.route_path)
            .await
            .map_err(|_| NetworkProbeError::ProbeFailed)
    }
}

#[async_trait]
impl NetworkMonitor for LinuxRouteMonitor {
    async fn current_identity(&self) -> Result<Option<NetworkIdentity>, NetworkProbeError> {
        let snapshot = self.snapshot().await?;
        let text = std::str::from_utf8(&snapshot).map_err(|_| NetworkProbeError::ProbeFailed)?;
        let identity = parse_proc_net_route(text);
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
            tokio::time::sleep(
                self.poll_interval
                    .min(deadline.saturating_duration_since(Instant::now())),
            )
            .await;
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

pub struct LinuxPortalProbe {
    host: String,
    port: u16,
    timeout: Duration,
}

impl LinuxPortalProbe {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        timeout: Duration,
    ) -> Result<Self, NetworkProbeError> {
        let host = host.into();
        if host.is_empty()
            || host.len() > 253
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
        })
    }

    pub fn production() -> Self {
        Self::new("secure.hanyang.ac.kr", 443, Duration::from_secs(3))
            .expect("fixed portal probe configuration must be valid")
    }
}

#[async_trait]
impl hyu_vpn_core::ports::PortalProbe for LinuxPortalProbe {
    async fn reachable(&self, _identity: &NetworkIdentity) -> Result<bool, NetworkProbeError> {
        let addresses = match tokio::time::timeout(
            self.timeout,
            tokio::net::lookup_host((self.host.as_str(), self.port)),
        )
        .await
        {
            Ok(Ok(addresses)) => addresses.collect::<Vec<_>>(),
            _ => return Ok(false),
        };
        for address in addresses.into_iter().take(8) {
            if matches!(
                tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(address)).await,
                Ok(Ok(_))
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
