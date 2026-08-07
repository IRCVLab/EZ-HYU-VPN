use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, NetworkProbeError, PortalProbe};
use hyu_vpn_core::readiness::{ReadinessGate, ReadinessOutcome};
use hyu_vpn_core::state::NetworkIdentity;

struct FakeMonitor {
    samples: Mutex<VecDeque<Option<NetworkIdentity>>>,
    waits: Mutex<Vec<Duration>>,
}

#[async_trait]
impl NetworkMonitor for FakeMonitor {
    async fn current_identity(&self) -> Result<Option<NetworkIdentity>, NetworkProbeError> {
        Ok(self.samples.lock().unwrap().pop_front().flatten())
    }

    async fn wait_for_change(&self, timeout: Duration) -> Result<(), NetworkProbeError> {
        self.waits.lock().unwrap().push(timeout);
        Ok(())
    }
}

struct FakePortal {
    ready: Mutex<VecDeque<bool>>,
}

#[async_trait]
impl PortalProbe for FakePortal {
    async fn reachable(&self, _identity: &NetworkIdentity) -> Result<bool, NetworkProbeError> {
        Ok(self.ready.lock().unwrap().pop_front().unwrap_or(false))
    }
}

fn wifi() -> NetworkIdentity {
    NetworkIdentity::new("wlan0", "192.0.2.1")
}

#[tokio::test]
async fn requires_two_stable_non_tunnel_samples_and_portal_reachability() {
    let monitor = FakeMonitor {
        samples: Mutex::new(VecDeque::from([None, Some(wifi()), Some(wifi())])),
        waits: Mutex::new(Vec::new()),
    };
    let portal = FakePortal {
        ready: Mutex::new(VecDeque::from([true, true])),
    };
    let gate = ReadinessGate::new(2, Duration::from_secs(5));

    assert_eq!(
        gate.wait_for_stable_network(&monitor, &portal, || false)
            .await
            .unwrap(),
        ReadinessOutcome::Ready(wifi())
    );
    assert_eq!(
        *monitor.waits.lock().unwrap(),
        vec![Duration::from_secs(5), Duration::from_secs(5)]
    );
}

#[tokio::test]
async fn rejects_tunnel_default_route_and_unreachable_portal() {
    let monitor = FakeMonitor {
        samples: Mutex::new(VecDeque::from([
            Some(NetworkIdentity::tunnel("utun9", "198.51.100.1")),
            Some(wifi()),
            Some(wifi()),
            Some(wifi()),
        ])),
        waits: Mutex::new(Vec::new()),
    };
    let portal = FakePortal {
        ready: Mutex::new(VecDeque::from([false, true, true])),
    };
    let gate = ReadinessGate::new(2, Duration::from_secs(1));
    assert!(matches!(
        gate.wait_for_stable_network(&monitor, &portal, || false)
            .await
            .unwrap(),
        ReadinessOutcome::Ready(_)
    ));
    assert_eq!(monitor.waits.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn stop_request_interrupts_offline_wait() {
    let monitor = FakeMonitor {
        samples: Mutex::new(VecDeque::from([None])),
        waits: Mutex::new(Vec::new()),
    };
    let portal = FakePortal {
        ready: Mutex::new(VecDeque::new()),
    };
    assert_eq!(
        ReadinessGate::new(2, Duration::from_secs(5))
            .wait_for_stable_network(&monitor, &portal, || true)
            .await
            .unwrap(),
        ReadinessOutcome::Stopped
    );
    assert!(monitor.waits.lock().unwrap().is_empty());
}
