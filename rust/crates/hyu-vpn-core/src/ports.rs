use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;

use crate::state::NetworkIdentity;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProbeError {
    #[error("network probe failed")]
    ProbeFailed,
}

#[async_trait]
pub trait NetworkMonitor: Send + Sync {
    async fn current_identity(&self) -> Result<Option<NetworkIdentity>, NetworkProbeError>;
    async fn wait_for_change(&self, timeout: Duration) -> Result<(), NetworkProbeError>;
}

#[async_trait]
pub trait PortalProbe: Send + Sync {
    async fn reachable(&self, identity: &NetworkIdentity) -> Result<bool, NetworkProbeError>;
}
