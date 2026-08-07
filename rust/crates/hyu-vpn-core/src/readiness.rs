use std::time::Duration;

use crate::ports::{NetworkMonitor, NetworkProbeError, PortalProbe};
use crate::state::NetworkIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessOutcome {
    Ready(NetworkIdentity),
    Stopped,
}

#[derive(Debug, Clone)]
pub struct ReadinessGate {
    stable_samples: usize,
    poll_interval: Duration,
}

impl ReadinessGate {
    pub fn new(stable_samples: usize, poll_interval: Duration) -> Self {
        Self {
            stable_samples: stable_samples.max(1),
            poll_interval,
        }
    }

    pub async fn wait_for_stable_network<M, P, S>(
        &self,
        monitor: &M,
        portal: &P,
        stop_requested: S,
    ) -> Result<ReadinessOutcome, NetworkProbeError>
    where
        M: NetworkMonitor,
        P: PortalProbe,
        S: Fn() -> bool,
    {
        let mut last_identity: Option<NetworkIdentity> = None;
        let mut stable = 0;
        loop {
            if stop_requested() {
                return Ok(ReadinessOutcome::Stopped);
            }
            let sample = monitor.current_identity().await?;
            let ready_identity = match sample {
                Some(identity) if !identity.is_tunnel && portal.reachable(&identity).await? => {
                    Some(identity)
                }
                _ => None,
            };
            match ready_identity {
                Some(identity) if last_identity.as_ref() == Some(&identity) => {
                    stable += 1;
                    if stable >= self.stable_samples {
                        return Ok(ReadinessOutcome::Ready(identity));
                    }
                }
                Some(identity) => {
                    last_identity = Some(identity.clone());
                    stable = 1;
                    if stable >= self.stable_samples {
                        return Ok(ReadinessOutcome::Ready(identity));
                    }
                }
                None => {
                    last_identity = None;
                    stable = 0;
                }
            }
            monitor.wait_for_change(self.poll_interval).await?;
        }
    }
}
