use hyu_vpn_core::state::{
    ConnectionGeneration, Engine, EngineAction, EngineEvent, NetworkIdentity, ReconnectPolicy,
};
use hyu_vpn_protocol::VpnState;

fn wifi(name: &str) -> NetworkIdentity {
    NetworkIdentity::new(name, "192.0.2.1")
}

#[test]
fn connect_waits_for_network_then_starts_one_generation() {
    let mut engine = Engine::new(false);
    assert_eq!(
        engine.handle(EngineEvent::ConnectRequested),
        vec![
            EngineAction::PersistAutomaticReconnect(true),
            EngineAction::PublishState(VpnState::WaitingForNetwork),
        ]
    );

    assert_eq!(
        engine.handle(EngineEvent::NetworkReady(wifi("en0"))),
        vec![
            EngineAction::PublishState(VpnState::Connecting),
            EngineAction::StartConnection {
                generation: ConnectionGeneration(1),
            },
        ]
    );
    assert!(engine.automatic_reconnect_enabled());
}

#[test]
fn explicit_disconnect_disables_automatic_reconnect() {
    let mut engine = Engine::new(false);
    engine.handle(EngineEvent::ConnectRequested);
    engine.handle(EngineEvent::NetworkReady(wifi("en0")));

    assert_eq!(
        engine.handle(EngineEvent::DisconnectRequested),
        vec![
            EngineAction::PersistAutomaticReconnect(false),
            EngineAction::PublishState(VpnState::Disconnecting),
            EngineAction::StopConnection {
                generation: ConnectionGeneration(1),
            },
        ]
    );
    assert_eq!(
        engine.handle(EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(1),
            return_code: 0,
            runtime_seconds: 10,
        }),
        vec![EngineAction::PublishState(VpnState::Disabled)]
    );
    assert!(!engine.automatic_reconnect_enabled());
}

#[test]
fn rapid_failures_back_off_and_cap_at_two_minutes() {
    let mut policy = ReconnectPolicy::default();
    let delays: Vec<u64> = (0..7).map(|_| policy.record_exit(1, 1)).collect();
    assert_eq!(delays, vec![10, 20, 40, 80, 120, 120, 120]);
    assert_eq!(policy.record_exit(0, 1), 10);
    assert_eq!(policy.record_exit(1, 300), 10);
}

#[test]
fn restored_different_network_cancels_long_backoff_and_starts_immediately() {
    let mut engine = Engine::new(false);
    engine.handle(EngineEvent::ConnectRequested);
    engine.handle(EngineEvent::NetworkReady(wifi("en0")));
    for generation in 1..=5 {
        let actions = engine.handle(EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(generation),
            return_code: 1,
            runtime_seconds: 1,
        });
        assert!(matches!(
            actions.last(),
            Some(EngineAction::ScheduleRetry { .. })
        ));
        if generation < 5 {
            engine.handle(EngineEvent::RetryElapsed);
        }
    }
    assert_eq!(engine.pending_retry_seconds(), Some(120));

    assert_eq!(
        engine.handle(EngineEvent::NetworkReady(wifi("en7"))),
        vec![
            EngineAction::CancelRetry,
            EngineAction::PublishState(VpnState::Connecting),
            EngineAction::StartConnection {
                generation: ConnectionGeneration(6),
            },
        ]
    );
    assert_eq!(engine.pending_retry_seconds(), None);
}

#[test]
fn session_expiry_stops_owned_generation_and_retries_after_exit() {
    let mut engine = Engine::new(false);
    engine.handle(EngineEvent::ConnectRequested);
    engine.handle(EngineEvent::NetworkReady(wifi("en0")));
    engine.handle(EngineEvent::ConnectorConnected {
        generation: ConnectionGeneration(1),
        tunnel_interface: None,
        hip_succeeded: false,
    });

    assert_eq!(
        engine.handle(EngineEvent::SessionExpired),
        vec![
            EngineAction::PublishState(VpnState::Disconnecting),
            EngineAction::StopConnection {
                generation: ConnectionGeneration(1),
            },
        ]
    );
    assert_eq!(
        engine.handle(EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(1),
            return_code: 0,
            runtime_seconds: 3600,
        }),
        vec![
            EngineAction::PublishState(VpnState::Backoff),
            EngineAction::ScheduleRetry { delay_seconds: 10 },
        ]
    );
}

#[test]
fn stale_generation_events_cannot_change_current_connection() {
    let mut engine = Engine::new(false);
    engine.handle(EngineEvent::ConnectRequested);
    engine.handle(EngineEvent::NetworkReady(wifi("en0")));
    engine.handle(EngineEvent::ConnectorExited {
        generation: ConnectionGeneration(1),
        return_code: 1,
        runtime_seconds: 1,
    });
    engine.handle(EngineEvent::RetryElapsed);

    assert!(
        engine
            .handle(EngineEvent::ConnectorConnected {
                generation: ConnectionGeneration(1),
                tunnel_interface: None,
                hip_succeeded: false,
            })
            .is_empty()
    );
    assert_eq!(engine.state(), VpnState::Connecting);
}

#[test]
fn changed_physical_network_restarts_an_active_generation() {
    let mut engine = Engine::new(true);
    let first = NetworkIdentity::new("wlan0", "192.0.2.1");
    let second = NetworkIdentity::new("wlan0", "192.0.2.254");
    let started = engine.handle(EngineEvent::NetworkReady(first));
    let generation = started
        .iter()
        .find_map(|action| match action {
            EngineAction::StartConnection { generation } => Some(*generation),
            _ => None,
        })
        .unwrap();
    engine.handle(EngineEvent::ConnectorConnected {
        generation,
        tunnel_interface: None,
        hip_succeeded: false,
    });

    let changed = engine.handle(EngineEvent::NetworkReady(second));
    assert_eq!(
        changed[0],
        EngineAction::PublishState(VpnState::Disconnecting)
    );
    assert_eq!(changed[1], EngineAction::StopConnection { generation });
    let restarted = engine.handle(EngineEvent::ConnectorExited {
        generation,
        return_code: 0,
        runtime_seconds: 60,
    });
    assert!(matches!(
        restarted.as_slice(),
        [
            EngineAction::PublishState(VpnState::Connecting),
            EngineAction::StartConnection { .. }
        ]
    ));
}

#[test]
fn connected_health_loss_stops_once_and_waits_for_network_without_backoff() {
    let mut engine = Engine::new(true);
    let started = engine.handle(EngineEvent::NetworkReady(wifi("en0")));
    let generation = started
        .iter()
        .find_map(|action| match action {
            EngineAction::StartConnection { generation } => Some(*generation),
            _ => None,
        })
        .unwrap();
    engine.handle(EngineEvent::ConnectorConnected {
        generation,
        tunnel_interface: Some("utun7".to_owned()),
        hip_succeeded: true,
    });

    assert_eq!(
        engine.handle(EngineEvent::NetworkUnavailable),
        vec![
            EngineAction::PublishState(VpnState::WaitingForNetwork),
            EngineAction::StopConnection { generation },
        ]
    );
    assert!(engine.handle(EngineEvent::NetworkUnavailable).is_empty());
    assert_eq!(
        engine.handle(EngineEvent::ConnectorExited {
            generation,
            return_code: 1,
            runtime_seconds: 60,
        }),
        vec![EngineAction::PublishState(VpnState::WaitingForNetwork)]
    );
    assert_eq!(engine.state(), VpnState::WaitingForNetwork);
    assert_eq!(engine.pending_retry_seconds(), None);
}

#[test]
fn connection_timeout_enters_backoff_and_schedules_retry() {
    let mut engine = Engine::new(true);
    let started = engine.handle(EngineEvent::NetworkReady(NetworkIdentity::new(
        "en0",
        "192.0.2.1",
    )));
    let generation = started
        .iter()
        .find_map(|action| match action {
            EngineAction::StartConnection { generation } => Some(*generation),
            _ => None,
        })
        .unwrap();

    assert_eq!(
        engine.handle(EngineEvent::ConnectTimedOut { generation }),
        vec![
            EngineAction::PublishState(VpnState::Backoff),
            EngineAction::ScheduleRetry { delay_seconds: 10 },
        ]
    );
}
