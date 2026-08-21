use hyu_vpn_protocol::{ErrorCode, VpnState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionGeneration(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkIdentity {
    pub interface: String,
    pub gateway: String,
    pub is_tunnel: bool,
}

impl NetworkIdentity {
    pub fn new(interface: impl Into<String>, gateway: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            gateway: gateway.into(),
            is_tunnel: false,
        }
    }

    pub fn tunnel(interface: impl Into<String>, gateway: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            gateway: gateway.into(),
            is_tunnel: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineAction {
    PersistAutomaticReconnect(bool),
    PublishState(VpnState),
    PublishError(ErrorCode),
    StartConnection { generation: ConnectionGeneration },
    StopConnection { generation: ConnectionGeneration },
    ScheduleRetry { delay_seconds: u64 },
    CancelRetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    ConnectRequested,
    DisconnectRequested,
    ReconnectRequested,
    NetworkUnavailable,
    NetworkReady(NetworkIdentity),
    ConnectorConnected {
        generation: ConnectionGeneration,
        tunnel_interface: Option<String>,
        hip_succeeded: bool,
    },
    ConnectorExited {
        generation: ConnectionGeneration,
        return_code: i32,
        runtime_seconds: u64,
    },
    ConnectorError {
        generation: ConnectionGeneration,
        error_code: ErrorCode,
    },
    RetryElapsed,
    SessionExpired,
    SleepResumed,
    ConnectTimedOut {
        generation: ConnectionGeneration,
    },
}

#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    consecutive_failures: u32,
    reset_after_seconds: u64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            reset_after_seconds: 300,
        }
    }
}

impl ReconnectPolicy {
    pub fn record_exit(&mut self, return_code: i32, runtime_seconds: u64) -> u64 {
        if return_code == 0 || runtime_seconds >= self.reset_after_seconds {
            self.consecutive_failures = 0;
        } else {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
        self.next_delay(self.consecutive_failures.max(1))
    }

    pub fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    fn next_delay(&self, failures: u32) -> u64 {
        120_u64.min(10_u64.saturating_mul(1_u64 << failures.saturating_sub(1).min(4)))
    }
}

#[derive(Debug)]
pub struct Engine {
    state: VpnState,
    automatic_reconnect_enabled: bool,
    network: Option<NetworkIdentity>,
    active_generation: Option<ConnectionGeneration>,
    next_generation: u64,
    pending_retry_seconds: Option<u64>,
    reconnect_immediately_after_stop: bool,
    policy: ReconnectPolicy,
}

impl Engine {
    pub fn new(automatic_reconnect_enabled: bool) -> Self {
        Self {
            state: if automatic_reconnect_enabled {
                VpnState::WaitingForNetwork
            } else {
                VpnState::Disabled
            },
            automatic_reconnect_enabled,
            network: None,
            active_generation: None,
            next_generation: 1,
            pending_retry_seconds: None,
            reconnect_immediately_after_stop: false,
            policy: ReconnectPolicy::default(),
        }
    }

    pub fn state(&self) -> VpnState {
        self.state
    }

    pub fn automatic_reconnect_enabled(&self) -> bool {
        self.automatic_reconnect_enabled
    }

    pub fn pending_retry_seconds(&self) -> Option<u64> {
        self.pending_retry_seconds
    }

    pub fn handle(&mut self, event: EngineEvent) -> Vec<EngineAction> {
        match event {
            EngineEvent::ConnectRequested => self.enable_and_connect(),
            EngineEvent::DisconnectRequested => self.disconnect(),
            EngineEvent::ReconnectRequested => self.reconnect(),
            EngineEvent::NetworkUnavailable | EngineEvent::SleepResumed => {
                self.network_unavailable()
            }
            EngineEvent::NetworkReady(identity) => self.network_ready(identity),
            EngineEvent::ConnectorConnected { generation, .. } => {
                self.connector_connected(generation)
            }
            EngineEvent::ConnectorExited {
                generation,
                return_code,
                runtime_seconds,
            } => self.connector_exited(generation, return_code, runtime_seconds),
            EngineEvent::ConnectorError {
                generation,
                error_code,
            } => self.connector_error(generation, error_code),
            EngineEvent::RetryElapsed => self.retry_elapsed(),
            EngineEvent::SessionExpired => self.session_expired(),
            EngineEvent::ConnectTimedOut { generation } => self.connector_exited(generation, 1, 0),
        }
    }

    fn enable_and_connect(&mut self) -> Vec<EngineAction> {
        let mut actions = Vec::new();
        if !self.automatic_reconnect_enabled {
            self.automatic_reconnect_enabled = true;
            actions.push(EngineAction::PersistAutomaticReconnect(true));
        }
        if self.active_generation.is_none() && self.network.is_some() {
            actions.extend(self.start_connection());
        } else if self.active_generation.is_none() {
            actions.push(self.publish(VpnState::WaitingForNetwork));
        }
        actions
    }

    fn disconnect(&mut self) -> Vec<EngineAction> {
        let mut actions = Vec::new();
        if self.automatic_reconnect_enabled {
            self.automatic_reconnect_enabled = false;
            actions.push(EngineAction::PersistAutomaticReconnect(false));
        }
        self.reconnect_immediately_after_stop = false;
        if self.pending_retry_seconds.take().is_some() {
            actions.push(EngineAction::CancelRetry);
        }
        if let Some(generation) = self.active_generation {
            actions.push(self.publish(VpnState::Disconnecting));
            actions.push(EngineAction::StopConnection { generation });
        } else {
            actions.push(self.publish(VpnState::Disabled));
        }
        actions
    }

    fn reconnect(&mut self) -> Vec<EngineAction> {
        let mut actions = Vec::new();
        if !self.automatic_reconnect_enabled {
            self.automatic_reconnect_enabled = true;
            actions.push(EngineAction::PersistAutomaticReconnect(true));
        }
        if self.pending_retry_seconds.take().is_some() {
            actions.push(EngineAction::CancelRetry);
        }
        self.policy.reset();
        if let Some(generation) = self.active_generation {
            self.reconnect_immediately_after_stop = true;
            actions.push(self.publish(VpnState::Disconnecting));
            actions.push(EngineAction::StopConnection { generation });
        } else if self.network.is_some() {
            actions.extend(self.start_connection());
        } else {
            actions.push(self.publish(VpnState::WaitingForNetwork));
        }
        actions
    }

    fn network_unavailable(&mut self) -> Vec<EngineAction> {
        if self.network.is_none()
            && self.state == VpnState::WaitingForNetwork
            && self.pending_retry_seconds.is_none()
        {
            return Vec::new();
        }
        self.network = None;
        self.policy.reset();
        let mut actions = Vec::new();
        if self.pending_retry_seconds.take().is_some() {
            actions.push(EngineAction::CancelRetry);
        }
        if self.automatic_reconnect_enabled {
            actions.push(self.publish(VpnState::WaitingForNetwork));
            if let Some(generation) = self.active_generation {
                actions.push(EngineAction::StopConnection { generation });
            }
        }
        actions
    }

    fn network_ready(&mut self, identity: NetworkIdentity) -> Vec<EngineAction> {
        let changed = self.network.as_ref() != Some(&identity);
        self.network = Some(identity);
        if !self.automatic_reconnect_enabled {
            return Vec::new();
        }

        let mut actions = Vec::new();
        if changed {
            self.policy.reset();
            if self.pending_retry_seconds.take().is_some() {
                actions.push(EngineAction::CancelRetry);
            }
            if let Some(generation) = self.active_generation {
                if self.state != VpnState::Disconnecting {
                    self.reconnect_immediately_after_stop = true;
                    actions.push(self.publish(VpnState::Disconnecting));
                    actions.push(EngineAction::StopConnection { generation });
                }
                return actions;
            }
        }
        if self.active_generation.is_none()
            && (changed || self.pending_retry_seconds.is_none())
            && self.state != VpnState::Connected
        {
            actions.extend(self.start_connection());
        }
        actions
    }

    fn connector_connected(&mut self, generation: ConnectionGeneration) -> Vec<EngineAction> {
        if self.active_generation != Some(generation) {
            return Vec::new();
        }
        self.policy.reset();
        vec![self.publish(VpnState::Connected)]
    }

    fn connector_exited(
        &mut self,
        generation: ConnectionGeneration,
        return_code: i32,
        runtime_seconds: u64,
    ) -> Vec<EngineAction> {
        if self.active_generation != Some(generation) {
            return Vec::new();
        }
        self.active_generation = None;
        if !self.automatic_reconnect_enabled {
            return vec![self.publish(VpnState::Disabled)];
        }
        if self.network.is_none() {
            return vec![self.publish(VpnState::WaitingForNetwork)];
        }
        if std::mem::take(&mut self.reconnect_immediately_after_stop) {
            return self.start_connection();
        }
        let delay_seconds = self.policy.record_exit(return_code, runtime_seconds);
        self.pending_retry_seconds = Some(delay_seconds);
        vec![
            self.publish(VpnState::Backoff),
            EngineAction::ScheduleRetry { delay_seconds },
        ]
    }

    fn connector_error(
        &mut self,
        generation: ConnectionGeneration,
        error_code: ErrorCode,
    ) -> Vec<EngineAction> {
        if self.active_generation != Some(generation) {
            return Vec::new();
        }
        self.active_generation = None;
        self.pending_retry_seconds = None;
        self.reconnect_immediately_after_stop = false;
        vec![EngineAction::PublishError(error_code)]
    }

    fn retry_elapsed(&mut self) -> Vec<EngineAction> {
        if self.pending_retry_seconds.take().is_none() || !self.automatic_reconnect_enabled {
            return Vec::new();
        }
        if self.network.is_some() {
            self.start_connection()
        } else {
            vec![self.publish(VpnState::WaitingForNetwork)]
        }
    }

    fn session_expired(&mut self) -> Vec<EngineAction> {
        let Some(generation) = self.active_generation else {
            return Vec::new();
        };
        vec![
            self.publish(VpnState::Disconnecting),
            EngineAction::StopConnection { generation },
        ]
    }

    fn start_connection(&mut self) -> Vec<EngineAction> {
        let generation = ConnectionGeneration(self.next_generation);
        self.next_generation = self.next_generation.saturating_add(1);
        self.active_generation = Some(generation);
        self.pending_retry_seconds = None;
        vec![
            self.publish(VpnState::Connecting),
            EngineAction::StartConnection { generation },
        ]
    }

    fn publish(&mut self, state: VpnState) -> EngineAction {
        self.state = state;
        EngineAction::PublishState(state)
    }
}
