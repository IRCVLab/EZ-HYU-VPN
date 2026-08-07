use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyu_vpn_core::state::{EngineAction, EngineEvent, NetworkIdentity};
use hyu_vpn_daemon::runtime::{
    ActionExecutor, ControlPlane, CredentialRepository, DaemonRuntime, RepositoryError, SystemClock,
};
use hyu_vpn_daemon::status_file::AtomicStatusFile;
use hyu_vpn_protocol::{Credentials, Request, RequestEnvelope, VpnState};
use tempfile::tempdir;
use tokio::sync::watch;

#[derive(Default)]
struct MemoryCredentials {
    values: Mutex<Option<(String, String, String)>>,
}

impl CredentialRepository for MemoryCredentials {
    fn present(&self) -> Result<bool, RepositoryError> {
        Ok(self.values.lock().unwrap().is_some())
    }

    fn load(&self) -> Result<Credentials, RepositoryError> {
        let values = self.values.lock().unwrap();
        let (username, password, seed) = values.as_ref().ok_or(RepositoryError::Missing)?;
        Credentials::new(username, password, seed).map_err(|_| RepositoryError::Corrupt)
    }

    fn replace(&self, credentials: Credentials) -> Result<(), RepositoryError> {
        *self.values.lock().unwrap() = Some((
            credentials.username().to_owned(),
            credentials.password().to_owned(),
            credentials.totp_seed().to_owned(),
        ));
        Ok(())
    }
}

struct FixedClock;

impl SystemClock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(59)
    }
}

fn request(id: &str, request: Request) -> RequestEnvelope {
    RequestEnvelope {
        schema_version: 1,
        request_id: id.into(),
        request,
    }
}

#[test]
fn connect_and_network_events_publish_status_and_actions() {
    let (plane, mut actions) = ControlPlane::new(false, MemoryCredentials::default(), FixedClock);
    let response = plane.handle(request("1", Request::Connect));
    assert_eq!(serde_json::to_value(response).unwrap()["result"], "ack");
    assert_eq!(plane.status().state, VpnState::WaitingForNetwork);
    assert_eq!(
        actions.try_recv().unwrap(),
        EngineAction::PersistAutomaticReconnect(true)
    );
    assert_eq!(
        actions.try_recv().unwrap(),
        EngineAction::PublishState(VpnState::WaitingForNetwork)
    );

    plane.apply_event(EngineEvent::NetworkReady(NetworkIdentity::new(
        "wlan0",
        "192.0.2.1",
    )));
    assert_eq!(plane.status().state, VpnState::Connecting);
    assert!(matches!(
        actions.try_recv().unwrap(),
        EngineAction::PublishState(VpnState::Connecting)
    ));
    assert!(matches!(
        actions.try_recv().unwrap(),
        EngineAction::StartConnection { .. }
    ));
}

#[test]
fn credential_replacement_and_current_otp_are_served_without_status_secrets() {
    let (plane, _actions) = ControlPlane::new(false, MemoryCredentials::default(), FixedClock);
    let credentials = Credentials::new(
        "fixture-user",
        "PASSWORD-CANARY",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    )
    .unwrap();
    let replaced = plane.handle(request("2", Request::ReplaceCredentials { credentials }));
    assert_eq!(serde_json::to_value(replaced).unwrap()["result"], "ack");

    let otp = serde_json::to_value(plane.handle(request("3", Request::CurrentOtp))).unwrap();
    assert_eq!(otp["result"], "current_otp");
    assert_eq!(otp["code"], "287082");
    assert_eq!(otp["remaining_seconds"], 1);

    let status = serde_json::to_string(&plane.status()).unwrap();
    for forbidden in ["fixture-user", "PASSWORD-CANARY", "GEZDGNBV"] {
        assert!(!status.contains(forbidden));
    }
}

#[test]
fn atomic_status_file_contains_only_exact_status_document() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("status.json");
    let (plane, _actions) = ControlPlane::new(false, MemoryCredentials::default(), FixedClock);
    AtomicStatusFile::new(&path).write(&plane.status()).unwrap();
    let raw = std::fs::read_to_string(path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["state"], "disabled");
    assert_eq!(value["automatic_reconnect_enabled"], false);
    for forbidden in ["password", "username", "totp_seed", "cookie"] {
        assert!(!raw.contains(forbidden));
    }
}

#[derive(Default)]
struct FakeExecutor {
    actions: Mutex<Vec<EngineAction>>,
}

#[async_trait::async_trait]
impl ActionExecutor for FakeExecutor {
    async fn execute(&self, action: EngineAction) -> Option<EngineEvent> {
        self.actions.lock().unwrap().push(action.clone());
        match action {
            EngineAction::StartConnection { generation } => {
                Some(EngineEvent::ConnectorConnected { generation })
            }
            _ => None,
        }
    }
}

#[tokio::test]
async fn daemon_runtime_executes_actions_and_feeds_connector_events_back() {
    let (plane, actions) = ControlPlane::new(false, MemoryCredentials::default(), FixedClock);
    let plane = Arc::new(plane);
    let executor = Arc::new(FakeExecutor::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = DaemonRuntime::new(Arc::clone(&plane), actions, Arc::clone(&executor));
    let task = tokio::spawn(runtime.run(shutdown_rx));

    plane.handle(request("4", Request::Connect));
    plane.apply_event(EngineEvent::NetworkReady(NetworkIdentity::new(
        "wlan0",
        "192.0.2.1",
    )));
    tokio::time::timeout(Duration::from_secs(1), async {
        while plane.status().state != VpnState::Connected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    shutdown_tx.send(true).unwrap();
    task.await.unwrap();
    assert!(
        executor
            .actions
            .lock()
            .unwrap()
            .iter()
            .any(|action| matches!(action, EngineAction::StartConnection { .. }))
    );
}
