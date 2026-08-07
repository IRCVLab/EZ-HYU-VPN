use std::time::{Duration, Instant};

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, NetworkProbeError, PortalProbe};
use hyu_vpn_core::state::NetworkIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSnapshot {
    adapter_luid: u64,
    gateway: String,
    friendly_name: String,
}

impl NetworkSnapshot {
    pub fn new(
        adapter_luid: u64,
        gateway: impl Into<String>,
        friendly_name: impl Into<String>,
    ) -> Self {
        Self {
            adapter_luid,
            gateway: gateway.into(),
            friendly_name: friendly_name.into(),
        }
    }

    pub fn identity(&self) -> Option<NetworkIdentity> {
        let name = self.friendly_name.to_ascii_lowercase();
        if self.adapter_luid == 0
            || self.gateway.is_empty()
            || self.gateway.len() > 64
            || self.gateway.chars().any(char::is_control)
            || [
                "wintun",
                "tap-windows",
                "openconnect",
                "wireguard",
                "hyu vpn",
                "loopback",
                "tunnel",
            ]
            .iter()
            .any(|needle| name.contains(needle))
        {
            return None;
        }
        Some(NetworkIdentity::new(
            format!("luid-{}", self.adapter_luid),
            self.gateway.clone(),
        ))
    }
}

#[derive(Debug, Default)]
pub struct WindowsNetworkMonitor;

#[async_trait]
impl NetworkMonitor for WindowsNetworkMonitor {
    async fn current_identity(&self) -> Result<Option<NetworkIdentity>, NetworkProbeError> {
        current_default_snapshot()
            .map(|snapshot| snapshot.and_then(|value| value.identity()))
            .map_err(|_| NetworkProbeError::ProbeFailed)
    }

    async fn wait_for_change(&self, timeout: Duration) -> Result<(), NetworkProbeError> {
        let baseline = self.current_identity().await?;
        let started = Instant::now();
        while started.elapsed() < timeout {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if self.current_identity().await? != baseline {
                return Ok(());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WindowsPortalProbe {
    portal: String,
}

impl WindowsPortalProbe {
    pub fn production() -> Self {
        Self {
            portal: "secure.hanyang.ac.kr".to_owned(),
        }
    }
}

#[async_trait]
impl PortalProbe for WindowsPortalProbe {
    async fn reachable(&self, _identity: &NetworkIdentity) -> Result<bool, NetworkProbeError> {
        let addresses = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((self.portal.as_str(), 443)),
        )
        .await
        .map_err(|_| NetworkProbeError::ProbeFailed)?
        .map_err(|_| NetworkProbeError::ProbeFailed)?;
        for address in addresses.take(8) {
            if tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(address),
            )
            .await
            .is_ok_and(|result| result.is_ok())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(windows)]
pub fn active_vpn_interface() -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_OPER_STATUS_UP;

    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&mut table) } != 0 || table.is_null() {
        return None;
    }
    struct TableGuard(*mut MIB_IF_TABLE2);
    impl Drop for TableGuard {
        fn drop(&mut self) {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
    let guard = TableGuard(table);
    let count = unsafe { (*guard.0).NumEntries as usize };
    if count > 4096 {
        return None;
    }
    let rows = unsafe { std::slice::from_raw_parts((*guard.0).Table.as_ptr(), count) };
    for row in rows {
        if row.OperStatus != NET_IF_OPER_STATUS_UP {
            continue;
        }
        let alias_len = row
            .Alias
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(row.Alias.len());
        let description_len = row
            .Description
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(row.Description.len());
        let alias = String::from_utf16_lossy(&row.Alias[..alias_len]);
        let description = String::from_utf16_lossy(&row.Description[..description_len]);
        let combined = format!("{alias} {description}").to_ascii_lowercase();
        if ["wintun", "tap-windows", "openconnect", "hyu vpn"]
            .iter()
            .any(|needle| combined.contains(needle))
        {
            return Some(alias);
        }
    }
    None
}

#[cfg(not(windows))]
pub fn active_vpn_interface() -> Option<String> {
    None
}

#[cfg(windows)]
fn current_default_snapshot() -> Result<Option<NetworkSnapshot>, ()> {
    use std::net::Ipv4Addr;

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfEntry2, GetIpForwardTable2, IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK,
        IF_TYPE_TUNNEL, MIB_IF_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_OPER_STATUS_UP;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let code = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if code != 0 || table.is_null() {
        return Err(());
    }
    struct TableGuard(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for TableGuard {
        fn drop(&mut self) {
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
    let guard = TableGuard(table);
    let count = unsafe { (*guard.0).NumEntries as usize };
    if count > 65_536 {
        return Err(());
    }
    let routes = unsafe { std::slice::from_raw_parts((*guard.0).Table.as_ptr(), count) };
    let mut selected: Option<(u32, NetworkSnapshot)> = None;
    for route in routes {
        let destination_family = unsafe { route.DestinationPrefix.Prefix.si_family };
        let next_hop_family = unsafe { route.NextHop.si_family };
        if route.DestinationPrefix.PrefixLength != 0
            || destination_family != AF_INET
            || next_hop_family != AF_INET
        {
            continue;
        }
        let gateway_bytes = unsafe { route.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() };
        if gateway_bytes == [0, 0, 0, 0] {
            continue;
        }
        let mut interface = MIB_IF_ROW2 {
            InterfaceLuid: route.InterfaceLuid,
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut interface) } != 0
            || interface.OperStatus != NET_IF_OPER_STATUS_UP
            || matches!(
                interface.Type,
                IF_TYPE_PPP | IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_TUNNEL
            )
        {
            continue;
        }
        let alias = bounded_wide(&interface.Alias);
        let description = bounded_wide(&interface.Description);
        let friendly_name = format!("{alias} {description}");
        let snapshot = NetworkSnapshot::new(
            unsafe { route.InterfaceLuid.Value },
            Ipv4Addr::from(gateway_bytes).to_string(),
            friendly_name,
        );
        if snapshot.identity().is_none() {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(metric, _)| route.Metric < *metric)
        {
            selected = Some((route.Metric, snapshot));
        }
    }
    Ok(selected.map(|(_, snapshot)| snapshot))
}

#[cfg(windows)]
fn bounded_wide(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

#[cfg(not(windows))]
fn current_default_snapshot() -> Result<Option<NetworkSnapshot>, ()> {
    Ok(None)
}
