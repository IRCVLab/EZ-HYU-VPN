use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, NetworkProbeError, PortalProbe};
use hyu_vpn_core::state::{ConnectionGeneration, EngineEvent, NetworkIdentity};
use hyu_vpn_daemon::ipc::RequestHandler;
use hyu_vpn_daemon::runtime::{ControlPlane, CredentialRepository, RepositoryError, SystemClock};
use hyu_vpn_macos_service::{
    AutomaticPreference, MacActionExecutor, ServiceConfig, ServiceError, bind_owner_socket,
    current_otp_preview, current_otp_reserved, peer_uid_authorized_for_test,
    reconcile_helper_at_startup, run_health_check, run_health_check_socket_for_test,
    serve_owner_socket_for_test,
};
use hyu_vpn_platform_macos::{
    HelperCommand, HelperError, HelperRunner, HelperSessionEvent, HelperSessionOutcome,
    HelperSessionRunner, HelperStartInput, HelperStartSession, HelperState, HelperStdin,
    helper_start_invocation_for_test,
};
use hyu_vpn_protocol::{
    Credentials, ErrorCode, Request, RequestEnvelope, Response, ResponseEnvelope, VpnState,
};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

struct StaticStatusHandler;

#[async_trait]
impl RequestHandler for StaticStatusHandler {
    async fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope {
        let request_id = request.request_id;
        match request.request {
            Request::Status => ResponseEnvelope::new(
                request_id,
                Response::Status {
                    status: hyu_vpn_protocol::VpnStatus {
                        schema_version: hyu_vpn_protocol::PROTOCOL_VERSION,
                        state: VpnState::Disabled,
                        automatic_reconnect_enabled: false,
                        connected_at: None,
                        session_expires_at: None,
                        last_successful_hip_at: None,
                        tunnel_interface: None,
                        next_retry_at: None,
                        error_code: None,
                        last_transition_at: "1970-01-01T00:00:00Z".to_string(),
                        backend_build_version: Some("0.2.0".to_string()),
                    },
                },
            ),
            _ => ResponseEnvelope::new(
                request_id,
                Response::Error {
                    error_code: ErrorCode::ServiceUnavailable,
                },
            ),
        }
    }
}

#[derive(Clone)]
struct FixedClock(SystemTime);
impl SystemClock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

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
        let (u, p, s) = values.as_ref().ok_or(RepositoryError::Missing)?;
        Credentials::new(u, p, s).map_err(|_| RepositoryError::Corrupt)
    }
    fn replace(&self, c: Credentials) -> Result<(), RepositoryError> {
        *self.values.lock().unwrap() = Some((
            c.username().to_string(),
            c.password().to_string(),
            c.totp_seed().to_string(),
        ));
        Ok(())
    }
}

struct FakeHelper {
    calls: Mutex<Vec<String>>,
    state: Mutex<HelperState>,
    starts: Mutex<Vec<FakeStartPlan>>,
    usernames: Mutex<Vec<String>>,
    repair_response: Mutex<HelperState>,
    cancel_count: Arc<Mutex<usize>>,
    wait_count: Arc<Mutex<usize>>,
}

#[derive(Clone)]
struct FakeStartPlan {
    events: Vec<HelperSessionEvent>,
    outcome: HelperSessionOutcome,
    waits_until_cancel: bool,
    wait_never_returns: bool,
    event_delay: Option<Duration>,
}

impl FakeStartPlan {
    fn connected(tunnel: &str) -> Self {
        Self {
            events: vec![
                HelperSessionEvent::HipSubmitted,
                HelperSessionEvent::Connected {
                    tunnel: tunnel.to_string(),
                },
            ],
            outcome: HelperSessionOutcome::Cancelled,
            waits_until_cancel: true,
            wait_never_returns: false,
            event_delay: None,
        }
    }

    fn delayed_connected(tunnel: &str, delay: Duration) -> Self {
        Self {
            events: vec![
                HelperSessionEvent::HipSubmitted,
                HelperSessionEvent::Connected {
                    tunnel: tunnel.to_string(),
                },
            ],
            outcome: HelperSessionOutcome::Cancelled,
            waits_until_cancel: true,
            wait_never_returns: false,
            event_delay: Some(delay),
        }
    }

    fn connecting() -> Self {
        Self {
            events: Vec::new(),
            outcome: HelperSessionOutcome::Cancelled,
            waits_until_cancel: true,
            wait_never_returns: false,
            event_delay: None,
        }
    }

    fn connecting_cleanup_timeout() -> Self {
        Self {
            events: vec![HelperSessionEvent::HipSubmitted],
            outcome: HelperSessionOutcome::Cancelled,
            waits_until_cancel: true,
            wait_never_returns: true,
            event_delay: Some(Duration::from_secs(60)),
        }
    }

    fn tunnel_without_hip(tunnel: &str) -> Self {
        Self {
            events: vec![HelperSessionEvent::Connected {
                tunnel: tunnel.to_owned(),
            }],
            outcome: HelperSessionOutcome::Cancelled,
            waits_until_cancel: true,
            wait_never_returns: false,
            event_delay: None,
        }
    }

    fn immediate(outcome: HelperSessionOutcome) -> Self {
        Self {
            events: Vec::new(),
            outcome,
            waits_until_cancel: false,
            wait_never_returns: false,
            event_delay: None,
        }
    }

    fn cleanup_timeout() -> Self {
        Self {
            events: vec![
                HelperSessionEvent::HipSubmitted,
                HelperSessionEvent::Connected {
                    tunnel: "utun9".to_string(),
                },
            ],
            outcome: HelperSessionOutcome::Cancelled,
            waits_until_cancel: true,
            wait_never_returns: true,
            event_delay: None,
        }
    }
}

impl Default for FakeHelper {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            state: Mutex::new(HelperState::Stopped),
            starts: Mutex::new(Vec::new()),
            usernames: Mutex::new(Vec::new()),
            repair_response: Mutex::new(HelperState::Stopped),
            cancel_count: Arc::new(Mutex::new(0)),
            wait_count: Arc::new(Mutex::new(0)),
        }
    }
}
impl FakeHelper {
    fn with_connected(tunnel: &str) -> Self {
        Self {
            starts: Mutex::new(vec![FakeStartPlan::connected(tunnel)]),
            ..Self::default()
        }
    }

    fn with_connecting_session() -> Self {
        Self {
            starts: Mutex::new(vec![FakeStartPlan::connecting()]),
            ..Self::default()
        }
    }

    fn with_connecting_cleanup_timeout() -> Self {
        Self {
            starts: Mutex::new(vec![FakeStartPlan::connecting_cleanup_timeout()]),
            ..Self::default()
        }
    }

    fn with_tunnel_without_hip(tunnel: &str) -> Self {
        Self {
            starts: Mutex::new(vec![FakeStartPlan::tunnel_without_hip(tunnel)]),
            ..Self::default()
        }
    }

    fn with_delayed_connected(tunnel: &str, delay: Duration) -> Self {
        Self {
            starts: Mutex::new(vec![FakeStartPlan::delayed_connected(tunnel, delay)]),
            ..Self::default()
        }
    }

    fn with_cleanup_timeout() -> Self {
        Self {
            starts: Mutex::new(vec![FakeStartPlan::cleanup_timeout()]),
            ..Self::default()
        }
    }

    fn with_outcome(outcome: HelperSessionOutcome) -> Self {
        Self {
            starts: Mutex::new(vec![FakeStartPlan::immediate(outcome)]),
            ..Self::default()
        }
    }

    fn with_outcomes(outcomes: Vec<HelperSessionOutcome>) -> Self {
        Self {
            starts: Mutex::new(outcomes.into_iter().map(FakeStartPlan::immediate).collect()),
            ..Self::default()
        }
    }

    fn with_repair_response(response: HelperState) -> Self {
        Self {
            state: Mutex::new(HelperState::RepairRequired),
            repair_response: Mutex::new(response),
            ..Self::default()
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn start_count(&self) -> usize {
        self.usernames.lock().unwrap().len()
    }

    fn usernames(&self) -> Vec<String> {
        self.usernames.lock().unwrap().clone()
    }

    fn cancel_count(&self) -> usize {
        *self.cancel_count.lock().unwrap()
    }

    fn wait_count(&self) -> usize {
        *self.wait_count.lock().unwrap()
    }
}

#[async_trait]
impl HelperRunner for FakeHelper {
    async fn run(&self, command: HelperCommand) -> Result<HelperState, HelperError> {
        self.calls.lock().unwrap().push(format!("run:{command:?}"));
        match command {
            HelperCommand::Status => Ok(self.state.lock().unwrap().clone()),
            HelperCommand::Stop => {
                *self.state.lock().unwrap() = HelperState::Stopped;
                Ok(HelperState::Stopped)
            }
            HelperCommand::Repair => Ok(self.repair_response.lock().unwrap().clone()),
        }
    }
}
#[async_trait]
impl HelperSessionRunner for FakeHelper {
    async fn start_session(
        &self,
        input: HelperStartInput,
    ) -> Result<Box<dyn HelperStartSession>, HelperError> {
        self.calls.lock().unwrap().push("start_session".to_string());
        let invocation = helper_start_invocation_for_test(&input).unwrap();
        let HelperStdin::Interactive { initial_header } = invocation.stdin else {
            panic!("start input must use interactive header");
        };
        let header = String::from_utf8(initial_header).unwrap();
        let username = header
            .strip_prefix("HYU-Username: ")
            .and_then(|value| value.strip_suffix("\n\n"))
            .unwrap()
            .to_string();
        self.usernames.lock().unwrap().push(username);
        let plan = {
            let mut starts = self.starts.lock().unwrap();
            if starts.is_empty() {
                FakeStartPlan::connecting()
            } else {
                starts.remove(0)
            }
        };
        Ok(Box::new(FakeSession {
            events: plan.events,
            cancelled: false,
            outcome: plan.outcome,
            waits_until_cancel: plan.waits_until_cancel,
            wait_never_returns: plan.wait_never_returns,
            event_delay: plan.event_delay,
            cancel_count: Arc::clone(&self.cancel_count),
            wait_count: Arc::clone(&self.wait_count),
        }))
    }
}
struct FakeSession {
    events: Vec<HelperSessionEvent>,
    cancelled: bool,
    outcome: HelperSessionOutcome,
    waits_until_cancel: bool,
    wait_never_returns: bool,
    event_delay: Option<Duration>,
    cancel_count: Arc<Mutex<usize>>,
    wait_count: Arc<Mutex<usize>>,
}
#[async_trait]
impl HelperStartSession for FakeSession {
    async fn next_event(&mut self) -> Result<Option<HelperSessionEvent>, HelperError> {
        if let Some(delay) = self.event_delay.take() {
            tokio::time::sleep(delay).await;
        }
        Ok(if self.cancelled {
            None
        } else {
            self.events.pop()
        })
    }
    async fn wait(&mut self) -> Result<HelperSessionOutcome, HelperError> {
        if self.wait_never_returns || (self.waits_until_cancel && !self.cancelled) {
            std::future::pending().await
        } else {
            *self.wait_count.lock().unwrap() += 1;
            Ok(self.outcome.clone())
        }
    }
    async fn cancel(&mut self) -> Result<(), HelperError> {
        *self.cancel_count.lock().unwrap() += 1;
        self.cancelled = true;
        Ok(())
    }
}

#[tokio::test]
async fn owner_socket_parent_and_socket_are_private_and_owned_by_uid() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("state/daemon.sock");
    let uid = unsafe { libc::geteuid() } as u32;
    let listener = bind_owner_socket(&socket, uid).unwrap();
    drop(listener);
    let parent = fs::metadata(socket.parent().unwrap()).unwrap();
    let meta = fs::metadata(&socket).unwrap();
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(parent.uid(), uid);
    assert_eq!(meta.uid(), uid);
}

#[test]
fn owner_socket_rejects_insecure_parent_or_non_socket_destination() {
    let dir = tempdir().unwrap();
    let uid = unsafe { libc::geteuid() } as u32;
    let symlink_parent = dir.path().join("link");
    symlink(dir.path(), &symlink_parent).unwrap();
    assert!(matches!(
        bind_owner_socket(symlink_parent.join("daemon.sock"), uid),
        Err(ServiceError::Transport)
    ));
    let file = dir.path().join("file.sock");
    fs::write(&file, b"not socket").unwrap();
    assert!(matches!(
        bind_owner_socket(&file, uid),
        Err(ServiceError::Transport)
    ));
}

#[test]
fn local_peercred_same_uid_acceptance_and_rejection_is_exact() {
    let uid = unsafe { libc::geteuid() } as u32;
    assert!(peer_uid_authorized_for_test(uid, uid));
    if uid != 0 {
        assert!(!peer_uid_authorized_for_test(0, uid));
    }
    assert!(!peer_uid_authorized_for_test(uid.saturating_add(1), uid));
}

#[test]
fn automatic_preference_is_atomic_private_and_rejects_symlinks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state/automatic-reconnect");
    let pref = AutomaticPreference::new(&path);
    assert!(pref.load().unwrap());
    pref.store(false).unwrap();
    assert!(!AutomaticPreference::new(&path).load().unwrap());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let link = dir.path().join("link-pref");
    symlink(&path, &link).unwrap();
    assert!(AutomaticPreference::new(&link).load().is_err());
}

#[tokio::test]
async fn status_request_returns_schema_v1_document_over_daemon_framing() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("state/daemon.sock");
    let uid = unsafe { libc::geteuid() } as u32;
    let credentials = Arc::new(MemoryCredentials::default());
    let helper = Arc::new(FakeHelper::default());
    AutomaticPreference::new(dir.path().join("automatic"))
        .store(false)
        .unwrap();
    let config = ServiceConfig::for_test(
        socket.clone(),
        dir.path().join("status.json"),
        dir.path().join("automatic"),
        dir.path().join("counter"),
        uid,
        credentials,
        helper,
        FixedClock(UNIX_EPOCH + Duration::from_secs(59)),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(hyu_vpn_macos_service::run_service(config, shutdown_rx));
    wait_for_socket(&socket).await;
    let response = request(&socket, Request::Status).await;
    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
    match response.into_response() {
        Response::Status { status } => {
            assert_eq!(status.schema_version, 1);
            assert_eq!(status.state, VpnState::Disabled);
        }
        other => panic!("unexpected response {other:?}"),
    }
}

#[derive(Default)]
struct FakeMonitor {
    samples: Mutex<Vec<Option<NetworkIdentity>>>,
}
#[async_trait]
impl NetworkMonitor for FakeMonitor {
    async fn current_identity(&self) -> Result<Option<NetworkIdentity>, NetworkProbeError> {
        Ok(self.samples.lock().unwrap().pop().flatten())
    }
    async fn wait_for_change(&self, _timeout: Duration) -> Result<(), NetworkProbeError> {
        Ok(())
    }
}
#[allow(dead_code)]
struct FakeProbe(bool);
#[async_trait]
impl PortalProbe for FakeProbe {
    async fn reachable(&self, _identity: &NetworkIdentity) -> Result<bool, NetworkProbeError> {
        Ok(self.0)
    }
}

#[tokio::test]
async fn connect_waits_for_readiness_then_retains_exactly_one_helper_start_until_disconnect() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new(
                "fixture-user",
                "PASSWORD-CANARY",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
            .unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_connected("utun7"));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );
    let monitor = FakeMonitor {
        samples: Mutex::new(vec![
            Some(NetworkIdentity::new("en0", "192.0.2.1")),
            Some(NetworkIdentity::new("en0", "192.0.2.1")),
        ]),
    };
    let mut tracker = hyu_vpn_macos_service::NetworkReadinessTracker::default();
    assert!(
        tracker
            .observe(monitor.current_identity().await.unwrap(), true)
            .is_none()
    );
    assert_eq!(
        tracker.observe(monitor.current_identity().await.unwrap(), true),
        Some(EngineEvent::NetworkReady(NetworkIdentity::new(
            "en0",
            "192.0.2.1"
        )))
    );
    executor
        .execute_start_for_test(ConnectionGeneration(1))
        .await;
    let connected = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        connected,
        EngineEvent::ConnectorConnected {
            generation: ConnectionGeneration(1),
            tunnel_interface: Some("utun7".to_owned()),
            hip_succeeded: true,
        }
    );
    assert_eq!(helper.calls(), vec!["start_session"]);
    executor
        .execute_stop_for_test(ConnectionGeneration(1))
        .await;
    let exited = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        exited,
        EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(1),
            return_code: 0,
            runtime_seconds: 0
        }
    );
}

#[tokio::test]
async fn disconnect_and_retry_cancellation_only_affect_owned_generation() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_connected("utun7"));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );
    executor
        .execute_start_for_test(ConnectionGeneration(2))
        .await;
    let _ = events_rx.recv().await.unwrap();
    executor
        .execute_stop_for_test(ConnectionGeneration(1))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), events_rx.recv())
            .await
            .is_err()
    );
    executor
        .execute_stop_for_test(ConnectionGeneration(2))
        .await;
    assert!(matches!(
        events_rx.recv().await.unwrap(),
        EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(2),
            ..
        }
    ));
    executor.execute_schedule_retry_for_test(60).await;
    executor.execute_cancel_retry_for_test().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(80), events_rx.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn health_cli_status_only_uses_owner_socket_and_never_starts_helper() {
    let dir = tempfile::Builder::new()
        .prefix("hvc")
        .tempdir_in("/tmp")
        .unwrap();
    let home = dir.path().join("h");
    let state = home.join("Library/Application Support/hyu-openconnect");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state.join("daemon.sock");
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let listener = tokio::net::UnixListener::bind(&socket_for_server).unwrap();
        std::fs::set_permissions(&socket_for_server, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        serve_status_once(stream, "health").await;
    });

    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_hyu-vpn-macos-service"))
        .arg("health")
        .arg("--uid")
        .arg((unsafe { libc::geteuid() } as u32).to_string())
        .arg("--home")
        .arg(&home)
        .arg("--timeout-ms")
        .arg("1000")
        .output()
        .await
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).trim().is_empty());
    server.await.unwrap();
}

#[tokio::test]
async fn health_cli_rejects_bad_args_and_timeout_without_service_without_starting() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bad_relative = tokio::process::Command::new(env!("CARGO_BIN_EXE_hyu-vpn-macos-service"))
        .arg("health")
        .arg("--uid")
        .arg((unsafe { libc::geteuid() } as u32).to_string())
        .arg("--home")
        .arg("relative")
        .arg("--timeout-ms")
        .arg("100")
        .output()
        .await
        .unwrap();
    assert_eq!(bad_relative.status.code(), Some(64));
    assert!(!String::from_utf8_lossy(&bad_relative.stderr).contains("relative"));

    let timeout = tokio::process::Command::new(env!("CARGO_BIN_EXE_hyu-vpn-macos-service"))
        .arg("health")
        .arg("--uid")
        .arg((unsafe { libc::geteuid() } as u32).to_string())
        .arg("--home")
        .arg(&home)
        .arg("--timeout-ms")
        .arg("20")
        .output()
        .await
        .unwrap();
    assert_eq!(timeout.status.code(), Some(70));
    assert!(String::from_utf8_lossy(&timeout.stderr).contains("health check failed"));
}

#[tokio::test]
async fn credential_replacement_during_backoff_cancels_old_retry_and_starts_with_replacement() {
    let dir = tempdir().unwrap();
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new(
                "old-user",
                "old-password",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
            .unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_connected("utun7"));
    let config = ServiceConfig::for_test(
        dir.path().join("daemon.sock"),
        dir.path().join("status.json"),
        dir.path().join("automatic"),
        dir.path().join("counter"),
        unsafe { libc::geteuid() } as u32,
        credentials.clone(),
        helper.clone(),
        FixedClock(UNIX_EPOCH + Duration::from_secs(59)),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(hyu_vpn_macos_service::run_service(config, shutdown_rx));
    wait_for_socket(&dir.path().join("daemon.sock")).await;
    let _ = request(&dir.path().join("daemon.sock"), Request::Connect).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    credentials
        .replace(
            Credentials::new(
                "new-user",
                "new-password",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
            .unwrap(),
        )
        .unwrap();
    let _ = request(
        &dir.path().join("daemon.sock"),
        Request::ReplaceCredentials {
            credentials: Credentials::new(
                "new-user",
                "new-password",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
            .unwrap(),
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(!format!("{:?}", helper.calls()).contains("old-password"));
}

#[test]
fn current_otp_preview_repeats_same_counter_without_reserving_or_exposing_secret() {
    let dir = tempdir().unwrap();
    let credentials = Credentials::new(
        "fixture-user",
        "PASSWORD-CANARY",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    )
    .unwrap();
    let otp = current_otp_preview(
        &credentials,
        UNIX_EPOCH + Duration::from_secs(59),
        dir.path().join("counter"),
    )
    .unwrap();
    assert_eq!(otp.code, "287082");
    assert_eq!(otp.remaining_seconds, 1);
    assert!(
        current_otp_preview(
            &credentials,
            UNIX_EPOCH + Duration::from_secs(59),
            dir.path().join("counter")
        )
        .is_ok()
    );
    let debug = format!("{otp:?}");
    assert!(!debug.contains("GEZDGNBV"));
    assert!(!debug.contains("PASSWORD-CANARY"));
}

#[test]
fn current_otp_preview_does_not_block_subsequent_reservation_and_reservation_antireuse_remains() {
    let dir = tempdir().unwrap();
    let credentials = Credentials::new(
        "fixture-user",
        "PASSWORD-CANARY",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    )
    .unwrap();
    let counter = dir.path().join("counter");
    let preview =
        current_otp_preview(&credentials, UNIX_EPOCH + Duration::from_secs(59), &counter).unwrap();
    let preview_again =
        current_otp_preview(&credentials, UNIX_EPOCH + Duration::from_secs(59), &counter).unwrap();
    assert_eq!(preview.code, preview_again.code);
    assert_eq!(preview.remaining_seconds, preview_again.remaining_seconds);

    let reserved =
        current_otp_reserved(&credentials, UNIX_EPOCH + Duration::from_secs(59), &counter).unwrap();
    assert_eq!(reserved.code, preview.code);
    assert!(
        current_otp_reserved(&credentials, UNIX_EPOCH + Duration::from_secs(59), &counter).is_err()
    );
}

#[tokio::test]
async fn startup_reconciles_helper_status_without_duplicate_start() {
    let helper = Arc::new(FakeHelper::default());
    *helper.state.lock().unwrap() = HelperState::Running {
        tunnel: Some("utun4".to_string()),
    };
    reconcile_helper_at_startup(helper.clone()).await.unwrap();
    assert_eq!(helper.calls(), vec!["run:Status", "run:Stop"]);
}

#[tokio::test]
async fn repair_reconciliation_success_and_failure_are_distinguishable() {
    let success = Arc::new(FakeHelper::with_repair_response(HelperState::Stopped));
    reconcile_helper_at_startup(success.clone()).await.unwrap();
    assert_eq!(success.calls(), vec!["run:Status", "run:Repair"]);

    let failure = Arc::new(FakeHelper::with_repair_response(
        HelperState::RepairRequired,
    ));
    assert!(matches!(
        reconcile_helper_at_startup(failure.clone()).await,
        Err(ServiceError::RepairRequired)
    ));
    assert_eq!(
        failure.calls(),
        vec![
            "run:Status",
            "run:Repair",
            "run:Status",
            "run:Repair",
            "run:Status",
            "run:Repair",
            "run:Status",
            "run:Repair",
        ]
    );
}

struct RacingReconcileHelper {
    responses: Mutex<VecDeque<Result<HelperState, HelperError>>>,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl HelperRunner for RacingReconcileHelper {
    async fn run(&self, command: HelperCommand) -> Result<HelperState, HelperError> {
        self.calls.lock().unwrap().push(format!("{command:?}"));
        self.responses.lock().unwrap().pop_front().unwrap()
    }
}

#[tokio::test]
async fn startup_reconciliation_retries_stop_race_then_repairs_stale_session() {
    let helper = Arc::new(RacingReconcileHelper {
        responses: Mutex::new(VecDeque::from([
            Ok(HelperState::Running {
                tunnel: Some("utun7".to_owned()),
            }),
            Err(HelperError::InvalidResponse),
            Ok(HelperState::RepairRequired),
            Ok(HelperState::Stopped),
        ])),
        calls: Mutex::new(Vec::new()),
    });

    reconcile_helper_at_startup(helper.clone()).await.unwrap();
    assert_eq!(
        *helper.calls.lock().unwrap(),
        ["Status", "Stop", "Status", "Repair"]
    );
}

#[test]
fn production_shutdown_signal_set_includes_launchd_termination_and_hangup() {
    let names = hyu_vpn_macos_service::shutdown_signal_names_for_test();
    assert!(names.contains(&"SIGTERM"));
    assert!(names.contains(&"SIGINT"));
    assert!(names.contains(&"SIGHUP"));
}

#[tokio::test]
async fn shutdown_while_connected_cancels_and_awaits_exactly_one_session() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_connected("utun7"));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    executor
        .execute_start_for_test(ConnectionGeneration(77))
        .await;
    assert_eq!(
        events_rx.recv().await.unwrap(),
        EngineEvent::ConnectorConnected {
            generation: ConnectionGeneration(77),
            tunnel_interface: Some("utun7".to_owned()),
            hip_succeeded: true,
        }
    );
    executor
        .shutdown_sessions_for_test(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(helper.cancel_count(), 1);
    assert_eq!(helper.wait_count(), 1);
    assert_eq!(executor.active_session_count_for_test(), 0);
}

#[tokio::test]
async fn tunnel_evidence_without_hip_confirmation_never_reports_connected() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_tunnel_without_hip("utun7"));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper,
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    executor
        .execute_start_for_test(ConnectionGeneration(78))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), events_rx.recv())
            .await
            .is_err()
    );
    executor
        .shutdown_sessions_for_test(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn connection_establishment_timeout_cancels_cleans_and_emits_timeout() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_delayed_connected(
        "utun7",
        Duration::from_secs(1),
    ));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    )
    .with_connect_timeout_for_test(Duration::from_millis(20));

    executor
        .execute_start_for_test(ConnectionGeneration(79))
        .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        EngineEvent::ConnectTimedOut {
            generation: ConnectionGeneration(79),
        }
    );
    assert_eq!(helper.cancel_count(), 1);
    assert_eq!(helper.wait_count(), 1);
    assert_eq!(executor.active_session_count_for_test(), 0);
}

#[tokio::test]
async fn connection_establishment_timeout_bounds_cleanup_and_requires_repair() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_connecting_cleanup_timeout());
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    )
    .with_connect_timeout_for_test(Duration::from_secs(1));

    executor
        .execute_start_for_test(ConnectionGeneration(80))
        .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(8), events_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        EngineEvent::ConnectorError {
            generation: ConnectionGeneration(80),
            error_code: ErrorCode::RepairRequired,
        }
    );
    assert_eq!(helper.cancel_count(), 1);
    assert_eq!(executor.active_session_count_for_test(), 0);
}

#[tokio::test]
async fn shutdown_while_connecting_cancels_and_awaits_cleanup_before_returning() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_connecting_session());
    let (events_tx, _events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    executor
        .execute_start_for_test(ConnectionGeneration(78))
        .await;
    executor
        .shutdown_sessions_for_test(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(helper.cancel_count(), 1);
    assert_eq!(helper.wait_count(), 1);
    assert_eq!(executor.active_session_count_for_test(), 0);
}

#[tokio::test]
async fn shutdown_surfaces_cleanup_timeout_or_failure() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_cleanup_timeout());
    let (events_tx, _events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper,
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    executor
        .execute_start_for_test(ConnectionGeneration(79))
        .await;
    assert!(matches!(
        executor
            .shutdown_sessions_for_test(Duration::from_millis(20))
            .await,
        Err(ServiceError::Failed)
    ));
}

#[tokio::test]
async fn repair_required_outcome_publishes_error_and_does_not_retry_storm() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_outcome(
        HelperSessionOutcome::RepairRequired,
    ));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials.clone(),
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );
    let (plane, mut actions) = ControlPlane::new(true, credentials, FixedClock(UNIX_EPOCH));

    plane.apply_event(EngineEvent::NetworkReady(NetworkIdentity::new(
        "en0",
        "192.0.2.1",
    )));
    assert_eq!(
        actions.try_recv().unwrap(),
        hyu_vpn_core::state::EngineAction::PublishState(VpnState::Connecting)
    );
    let start = actions.try_recv().unwrap();
    hyu_vpn_daemon::runtime::ActionExecutor::execute(&executor, start).await;
    let event = events_rx.recv().await.unwrap();
    plane.apply_event(event);
    assert_eq!(plane.status().state, VpnState::Error);
    assert_eq!(plane.status().error_code, Some(ErrorCode::RepairRequired));
    assert_eq!(
        actions.try_recv().unwrap(),
        hyu_vpn_core::state::EngineAction::PublishError(ErrorCode::RepairRequired)
    );
    assert!(actions.try_recv().is_err());
    assert_eq!(helper.start_count(), 1);
}

#[tokio::test]
async fn completed_failed_sessions_are_evicted_and_shutdown_does_not_reawait_them() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_outcomes(vec![
        HelperSessionOutcome::Exited { status: 1 },
        HelperSessionOutcome::Exited { status: 1 },
        HelperSessionOutcome::Exited { status: 1 },
    ]));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    for generation in [1, 2, 3] {
        executor
            .execute_start_for_test(ConnectionGeneration(generation))
            .await;
        assert!(matches!(
            events_rx.recv().await.unwrap(),
            EngineEvent::ConnectorExited { .. }
        ));
        wait_for_session_count(&executor, 0).await;
    }
    assert_eq!(helper.start_count(), 3);
    executor
        .shutdown_sessions_for_test(Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(helper.cancel_count(), 0);
}

#[tokio::test]
async fn shutdown_after_handled_failure_succeeds_but_active_session_cancels_once() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper {
        starts: Mutex::new(vec![
            FakeStartPlan::immediate(HelperSessionOutcome::Exited { status: 1 }),
            FakeStartPlan::connected("utun8"),
        ]),
        ..FakeHelper::default()
    });
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    executor
        .execute_start_for_test(ConnectionGeneration(10))
        .await;
    assert!(matches!(
        events_rx.recv().await.unwrap(),
        EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(10),
            ..
        }
    ));
    wait_for_session_count(&executor, 0).await;
    executor
        .execute_start_for_test(ConnectionGeneration(11))
        .await;
    assert!(matches!(
        events_rx.recv().await.unwrap(),
        EngineEvent::ConnectorConnected {
            generation: ConnectionGeneration(11),
            tunnel_interface: Some(tunnel_interface),
            hip_succeeded: true,
        } if tunnel_interface == "utun8"
    ));
    executor
        .shutdown_sessions_for_test(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(helper.cancel_count(), 1);
    assert_eq!(helper.wait_count(), 2);
    assert_eq!(executor.active_session_count_for_test(), 0);
}

#[tokio::test]
async fn stale_completion_cannot_evict_newer_session_for_same_generation() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_delayed_connected(
        "utun7",
        Duration::from_millis(80),
    ));
    let (events_tx, _events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials,
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper,
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    executor
        .execute_start_for_test(ConnectionGeneration(42))
        .await;
    executor
        .force_replace_session_for_test(ConnectionGeneration(42))
        .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(executor.active_session_count_for_test(), 1);
    executor
        .shutdown_sessions_for_test(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn health_check_is_status_only_and_never_starts_helper() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("state/daemon.sock");
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_connected("utun7"));
    let config = ServiceConfig::for_test_with_network(
        socket,
        dir.path().join("status.json"),
        dir.path().join("automatic"),
        dir.path().join("counter"),
        unsafe { libc::geteuid() } as u32,
        credentials,
        helper.clone(),
        FixedClock(UNIX_EPOCH),
        FakeMonitor {
            samples: Mutex::new(vec![
                Some(NetworkIdentity::new("en0", "192.0.2.1")),
                Some(NetworkIdentity::new("en0", "192.0.2.1")),
            ]),
        },
        FakeProbe(true),
    );

    let result = tokio::time::timeout(
        Duration::from_millis(250),
        run_health_check(config, Duration::from_millis(80)),
    )
    .await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());
    assert_eq!(helper.start_count(), 0);
}

#[tokio::test]
async fn health_check_retries_until_delayed_status_server_is_ready() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("delayed.sock");
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        let listener =
            bind_owner_socket(&socket_for_server, unsafe { libc::geteuid() } as u32).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        serve_status_once(stream, "health").await;
    });
    run_health_check_socket_for_test(&socket, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn run_health_check_uses_delayed_existing_service_without_helper_start() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("state/daemon.sock");
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        let listener =
            bind_owner_socket(&socket_for_server, unsafe { libc::geteuid() } as u32).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        serve_status_once(stream, "health").await;
    });
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new("fixture-user", "pass", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_cleanup_timeout());
    let config = ServiceConfig::for_test_with_network(
        socket,
        dir.path().join("status.json"),
        dir.path().join("automatic"),
        dir.path().join("counter"),
        unsafe { libc::geteuid() } as u32,
        credentials,
        helper.clone(),
        FixedClock(UNIX_EPOCH),
        FakeMonitor {
            samples: Mutex::new(vec![
                Some(NetworkIdentity::new("en0", "192.0.2.1")),
                Some(NetworkIdentity::new("en0", "192.0.2.1")),
            ]),
        },
        FakeProbe(true),
    );
    run_health_check(config, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(helper.start_count(), 0);
}

#[tokio::test]
async fn health_check_requires_authenticated_schema_v1_status_response() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("missing.sock");
    assert!(
        run_health_check_socket_for_test(&socket, Duration::from_millis(20))
            .await
            .is_err()
    );

    let malformed = dir.path().join("malformed.sock");
    let listener = bind_owner_socket(&malformed, unsafe { libc::geteuid() } as u32).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_u32(4).await.unwrap();
        stream.write_all(b"nope").await.unwrap();
    });
    assert!(
        run_health_check_socket_for_test(&malformed, Duration::from_secs(1))
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn credential_replacement_in_real_backoff_cancels_retry_and_uses_replacement_marker() {
    let credentials = Arc::new(MemoryCredentials::default());
    credentials
        .replace(
            Credentials::new(
                "old-user",
                "old-password-marker",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
            .unwrap(),
        )
        .unwrap();
    let helper = Arc::new(FakeHelper::with_outcomes(vec![
        HelperSessionOutcome::Exited { status: 1 },
        HelperSessionOutcome::Stopped,
    ]));
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let executor = MacActionExecutor::new(
        credentials.clone(),
        AutomaticPreference::new(tempdir().unwrap().path().join("auto")),
        helper.clone(),
        tempdir().unwrap().path().join("counter"),
        events_tx,
    );

    executor
        .execute_start_for_test(ConnectionGeneration(1))
        .await;
    assert!(matches!(
        events_rx.recv().await.unwrap(),
        EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(1),
            return_code: 1,
            ..
        }
    ));
    executor.execute_schedule_retry_for_test(60).await;
    credentials
        .replace(
            Credentials::new(
                "new-user",
                "new-password-marker",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
            .unwrap(),
        )
        .unwrap();
    executor.execute_cancel_retry_for_test().await;
    executor
        .execute_start_for_test(ConnectionGeneration(2))
        .await;
    for _ in 0..100 {
        if helper.usernames().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        helper.usernames(),
        vec!["old-user".to_string(), "new-user".to_string()]
    );
    assert!(matches!(
        events_rx.recv().await.unwrap(),
        EngineEvent::ConnectorExited {
            generation: ConnectionGeneration(2),
            ..
        }
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(80), events_rx.recv())
            .await
            .is_err()
    );
    assert!(!format!("{:?}", helper.usernames()).contains("password-marker"));
}

#[tokio::test]
async fn owner_socket_shutdown_drains_stalled_partial_frame_client() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("state/daemon.sock");
    let listener = bind_owner_socket(&socket, unsafe { libc::geteuid() } as u32).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(serve_owner_socket_for_test(
        listener,
        unsafe { libc::geteuid() } as u32,
        Arc::new(StaticStatusHandler),
        shutdown_rx,
        Duration::from_millis(50),
    ));

    let mut stalled = UnixStream::connect(&socket).await.unwrap();
    stalled.write_u32(64).await.unwrap();
    shutdown_tx.send(true).unwrap();
    let remaining = tokio::time::timeout(Duration::from_millis(250), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn owner_socket_tracks_multiple_clients_and_registry_is_empty_after_shutdown() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("state/daemon.sock");
    let listener = bind_owner_socket(&socket, unsafe { libc::geteuid() } as u32).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(serve_owner_socket_for_test(
        listener,
        unsafe { libc::geteuid() } as u32,
        Arc::new(StaticStatusHandler),
        shutdown_rx,
        Duration::from_millis(100),
    ));

    let first = request(&socket, Request::Status).await;
    let second = request(&socket, Request::Status).await;
    assert!(matches!(first.into_response(), Response::Status { .. }));
    assert!(matches!(second.into_response(), Response::Status { .. }));
    shutdown_tx.send(true).unwrap();
    let remaining = tokio::time::timeout(Duration::from_millis(250), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(remaining, 0);
}

async fn wait_for_session_count<H: hyu_vpn_macos_service::MacHelper + ?Sized + 'static>(
    executor: &MacActionExecutor<H>,
    expected: usize,
) {
    for _ in 0..100 {
        if executor.active_session_count_for_test() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("session count did not reach {expected}");
}

async fn serve_status_once(mut stream: tokio::net::UnixStream, request_id: &str) {
    let len = stream.read_u32().await.unwrap() as usize;
    let mut frame = vec![0; len];
    stream.read_exact(&mut frame).await.unwrap();
    let request = hyu_vpn_protocol::decode_request(&frame).unwrap();
    assert_eq!(request.request_id, request_id);
    let status = hyu_vpn_protocol::VpnStatus {
        schema_version: hyu_vpn_protocol::PROTOCOL_VERSION,
        state: VpnState::Disabled,
        automatic_reconnect_enabled: false,
        connected_at: None,
        session_expires_at: None,
        last_successful_hip_at: None,
        tunnel_interface: None,
        next_retry_at: None,
        error_code: None,
        last_transition_at: "1970-01-01T00:00:00Z".to_string(),
        backend_build_version: Some("0.2.0".to_string()),
    };
    let response = hyu_vpn_protocol::encode_response(&hyu_vpn_protocol::ResponseEnvelope::new(
        request_id,
        Response::Status { status },
    ))
    .unwrap();
    stream.write_u32(response.len() as u32).await.unwrap();
    stream.write_all(&response).await.unwrap();
}

async fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("socket was not created");
}

async fn request(socket: &std::path::Path, command: Request) -> hyu_vpn_protocol::ResponseEnvelope {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    let bytes = hyu_vpn_protocol::encode_request(&RequestEnvelope::new("test", command)).unwrap();
    stream.write_u32(bytes.len() as u32).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let len = stream.read_u32().await.unwrap() as usize;
    let mut frame = vec![0; len];
    stream.read_exact(&mut frame).await.unwrap();
    hyu_vpn_protocol::decode_response(&frame).unwrap()
}
