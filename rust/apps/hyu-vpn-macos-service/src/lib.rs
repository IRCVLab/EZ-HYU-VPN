use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, PortalProbe, TunnelHealthProbe};
use hyu_vpn_core::state::{ConnectionGeneration, EngineAction, EngineEvent, NetworkIdentity};
use hyu_vpn_core::totp::{CounterGuard, TotpError, TotpGenerator, TotpSecret};
use hyu_vpn_daemon::ipc::{RequestHandler, serve_connection};
use hyu_vpn_daemon::runtime::{
    ActionExecutor, ControlPlane, CredentialRepository, DaemonRuntime, RepositoryError, SystemClock,
};
use hyu_vpn_daemon::status_file::AtomicStatusFile;
use hyu_vpn_platform_macos::{
    HelperCleanupOutcome, HelperCommand, HelperError, HelperRunner, HelperSessionEvent,
    HelperSessionOutcome, HelperSessionRunner, HelperStartInput, HelperState, HelperTotpProvider,
    InstalledHelperRunner, MacCredentialRepository, MacNetworkMonitor, MacPaths, MacPortalProbe,
    MacTunnelDnsProbe, SecretBytes,
};
use hyu_vpn_protocol::{
    Credentials, ErrorCode, Request, RequestEnvelope, Response, ResponseEnvelope, VpnState,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    #[error("service configuration is invalid")]
    InvalidConfiguration,
    #[error("service state operation failed")]
    State,
    #[error("service transport failed")]
    Transport,
    #[error("helper cleanup/repair is required")]
    RepairRequired,
    #[error("helper operation failed")]
    Failed,
}

#[derive(Clone)]
pub struct AutomaticPreference {
    path: PathBuf,
}

impl AutomaticPreference {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn load(&self) -> Result<bool, ServiceError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(_) => return Err(ServiceError::State),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() > 8
        {
            return Err(ServiceError::State);
        }
        let mut value = String::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .and_then(|file| file.take(9).read_to_string(&mut value))
            .map_err(|_| ServiceError::State)?;
        match value.as_str() {
            "true\n" => Ok(true),
            "false\n" => Ok(false),
            _ => Err(ServiceError::State),
        }
    }

    pub fn store(&self, enabled: bool) -> Result<(), ServiceError> {
        let parent = self.path.parent().ok_or(ServiceError::State)?;
        prepare_owner_dir(parent, unsafe { libc::geteuid() } as u32)?;
        let temp = parent.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("automatic-reconnect"),
            std::process::id()
        ));
        let result = (|| {
            if let Ok(metadata) = fs::symlink_metadata(&self.path) {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(ServiceError::State);
                }
            }
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)
                .map_err(|_| ServiceError::State)?;
            file.write_all(if enabled { b"true\n" } else { b"false\n" })
                .and_then(|()| file.sync_all())
                .map_err(|_| ServiceError::State)?;
            fs::rename(&temp, &self.path).map_err(|_| ServiceError::State)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|_| ServiceError::State)?;
            fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(|_| ServiceError::State)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

#[derive(Clone, Copy)]
pub struct RealClock;
impl SystemClock for RealClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct SharedClock(Arc<dyn SystemClock>);
impl SystemClock for SharedClock {
    fn now(&self) -> SystemTime {
        self.0.now()
    }
}

pub trait MacHelper: HelperRunner + HelperSessionRunner {}
impl<T> MacHelper for T where T: HelperRunner + HelperSessionRunner {}

type NetworkServices = (
    Arc<dyn NetworkMonitor>,
    Arc<dyn PortalProbe>,
    Arc<dyn TunnelHealthProbe>,
);

pub struct ServiceConfig {
    socket: PathBuf,
    status: PathBuf,
    automatic: PathBuf,
    counter: PathBuf,
    uid: u32,
    credentials: Arc<dyn CredentialRepository>,
    helper: Arc<dyn MacHelper>,
    clock: Arc<dyn SystemClock>,
    network: Option<NetworkServices>,
    cleanup_timeout: Duration,
}

impl ServiceConfig {
    pub fn production(home: &Path) -> Result<Self, ServiceError> {
        let paths = MacPaths::production(home).map_err(|_| ServiceError::InvalidConfiguration)?;
        let uid = fs::symlink_metadata(home)
            .map_err(|_| ServiceError::InvalidConfiguration)?
            .uid();
        Ok(Self {
            socket: paths.socket.clone(),
            status: paths.status.clone(),
            automatic: paths.automatic_reconnect.clone(),
            counter: paths.totp_counter.clone(),
            uid,
            credentials: Arc::new(MacCredentialRepository::new(paths, uid)),
            helper: Arc::new(InstalledHelperRunner::new()),
            clock: Arc::new(RealClock),
            network: Some((
                Arc::new(MacNetworkMonitor::production()),
                Arc::new(MacPortalProbe::production()),
                Arc::new(MacTunnelDnsProbe::production()),
            )),
            cleanup_timeout: Duration::from_secs(5),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_test<C, H>(
        socket: PathBuf,
        status: PathBuf,
        automatic: PathBuf,
        counter: PathBuf,
        uid: u32,
        credentials: Arc<dyn CredentialRepository>,
        helper: Arc<H>,
        clock: C,
    ) -> Self
    where
        C: SystemClock + 'static,
        H: MacHelper + 'static,
    {
        Self {
            socket,
            status,
            automatic,
            counter,
            uid,
            credentials,
            helper,
            clock: Arc::new(clock),
            network: None,
            cleanup_timeout: Duration::from_secs(5),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_test_with_network<C, H, M, P, T>(
        socket: PathBuf,
        status: PathBuf,
        automatic: PathBuf,
        counter: PathBuf,
        uid: u32,
        credentials: Arc<dyn CredentialRepository>,
        helper: Arc<H>,
        clock: C,
        monitor: M,
        portal: P,
        tunnel_health: T,
    ) -> Self
    where
        C: SystemClock + 'static,
        H: MacHelper + 'static,
        M: NetworkMonitor + 'static,
        P: PortalProbe + 'static,
        T: TunnelHealthProbe + 'static,
    {
        Self {
            socket,
            status,
            automatic,
            counter,
            uid,
            credentials,
            helper,
            clock: Arc::new(clock),
            network: Some((Arc::new(monitor), Arc::new(portal), Arc::new(tunnel_health))),
            cleanup_timeout: Duration::from_secs(5),
        }
    }

    pub fn with_cleanup_timeout_for_test(mut self, cleanup_timeout: Duration) -> Self {
        self.cleanup_timeout = cleanup_timeout;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedOtp {
    pub code: String,
    pub remaining_seconds: u8,
}

pub fn current_otp_preview(
    credentials: &Credentials,
    now: SystemTime,
    _counter_path: impl AsRef<Path>,
) -> Result<ReservedOtp, ServiceError> {
    let code = current_otp_code(credentials, now)?;
    Ok(ReservedOtp {
        code: code.value,
        remaining_seconds: code.remaining_seconds,
    })
}

pub fn current_otp_reserved(
    credentials: &Credentials,
    now: SystemTime,
    counter_path: impl AsRef<Path>,
) -> Result<ReservedOtp, ServiceError> {
    let code = current_otp_code(credentials, now)?;
    CounterGuard::new(counter_path)
        .reserve(code.counter)
        .map_err(|_| ServiceError::State)?;
    Ok(ReservedOtp {
        code: code.value,
        remaining_seconds: code.remaining_seconds,
    })
}

fn current_otp_code(
    credentials: &Credentials,
    now: SystemTime,
) -> Result<hyu_vpn_core::totp::OtpCode, ServiceError> {
    let secret = TotpSecret::parse(credentials.totp_seed()).map_err(|_| ServiceError::State)?;
    TotpGenerator::new(secret)
        .code_at(now)
        .map_err(|_| ServiceError::State)
}

struct GuardedTotp {
    generator: TotpGenerator,
    guard: CounterGuard,
}

#[async_trait]
impl HelperTotpProvider for GuardedTotp {
    async fn next_totp(&self) -> Result<SecretBytes, HelperError> {
        loop {
            let code = self
                .generator
                .code_at(SystemTime::now())
                .map_err(|_| HelperError::PromptInputUnavailable)?;
            match self.guard.reserve(code.counter) {
                Ok(()) => return Ok(SecretBytes::from_utf8_for_test(&code.value)),
                Err(TotpError::CounterAlreadyUsed) => {
                    tokio::time::sleep(
                        Duration::from_secs(u64::from(code.remaining_seconds))
                            + Duration::from_millis(25),
                    )
                    .await;
                }
                Err(_) => return Err(HelperError::PromptInputUnavailable),
            }
        }
    }
}

static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct SessionControl {
    id: u64,
    cancel: watch::Sender<bool>,
    join: tokio::task::JoinHandle<SessionCompletion>,
}

const CONNECT_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(150);
const CONNECT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTED_TUNNEL_HEALTH_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct SessionCompletion {
    outcome: Result<HelperSessionOutcome, HelperError>,
}

fn send_connector_exited_and_remove_current(
    sessions: &Arc<Mutex<HashMap<ConnectionGeneration, SessionControl>>>,
    generation: ConnectionGeneration,
    id: u64,
    events: &mpsc::UnboundedSender<EngineEvent>,
    return_code: i32,
    runtime_seconds: u64,
) {
    let mut sessions = sessions.lock().expect("session lock poisoned");
    let _ = events.send(EngineEvent::ConnectorExited {
        generation,
        return_code,
        runtime_seconds,
    });
    if sessions
        .get(&generation)
        .is_some_and(|control| control.id == id)
    {
        sessions.remove(&generation);
    }
}

fn send_connect_timed_out_and_remove_current(
    sessions: &Arc<Mutex<HashMap<ConnectionGeneration, SessionControl>>>,
    generation: ConnectionGeneration,
    id: u64,
    events: &mpsc::UnboundedSender<EngineEvent>,
) {
    let mut sessions = sessions.lock().expect("session lock poisoned");
    let _ = events.send(EngineEvent::ConnectTimedOut { generation });
    if sessions
        .get(&generation)
        .is_some_and(|control| control.id == id)
    {
        sessions.remove(&generation);
    }
}

fn publish_session_outcome_and_remove_current(
    sessions: &Arc<Mutex<HashMap<ConnectionGeneration, SessionControl>>>,
    generation: ConnectionGeneration,
    id: u64,
    events: &mpsc::UnboundedSender<EngineEvent>,
    repair_blocked: &Arc<Mutex<Option<ErrorCode>>>,
    outcome: &Result<HelperSessionOutcome, HelperError>,
) {
    let mut sessions = sessions.lock().expect("session lock poisoned");
    publish_session_outcome(generation, events, repair_blocked, outcome);
    if sessions
        .get(&generation)
        .is_some_and(|control| control.id == id)
    {
        sessions.remove(&generation);
    }
}

pub struct MacActionExecutor<H: MacHelper + ?Sized> {
    credentials: Arc<dyn CredentialRepository>,
    preference: AutomaticPreference,
    helper: Arc<H>,
    counter_path: PathBuf,
    events: mpsc::UnboundedSender<EngineEvent>,
    sessions: Arc<Mutex<HashMap<ConnectionGeneration, SessionControl>>>,
    repair_blocked: Arc<Mutex<Option<ErrorCode>>>,
    retry: Mutex<Option<watch::Sender<bool>>>,
    connect_timeout: Duration,
}

impl<H: MacHelper + ?Sized + 'static> MacActionExecutor<H> {
    pub fn new(
        credentials: Arc<dyn CredentialRepository>,
        preference: AutomaticPreference,
        helper: Arc<H>,
        counter_path: impl AsRef<Path>,
        events: mpsc::UnboundedSender<EngineEvent>,
    ) -> Self {
        Self {
            credentials,
            preference,
            helper,
            counter_path: counter_path.as_ref().to_path_buf(),
            events,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            repair_blocked: Arc::new(Mutex::new(None)),
            retry: Mutex::new(None),
            connect_timeout: CONNECT_ESTABLISH_TIMEOUT,
        }
    }

    pub fn with_connect_timeout_for_test(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    async fn start_connection(&self, generation: ConnectionGeneration) {
        if self
            .sessions
            .lock()
            .expect("session lock poisoned")
            .contains_key(&generation)
        {
            return;
        }
        if reconcile_helper_at_startup(Arc::clone(&self.helper))
            .await
            .is_err()
        {
            let _ = self.events.send(EngineEvent::ConnectorError {
                generation,
                error_code: ErrorCode::RepairRequired,
            });
            return;
        }
        let blocked_error = *self.repair_blocked.lock().expect("repair lock poisoned");
        if let Some(error_code) = blocked_error {
            match reconcile_helper_at_startup(Arc::clone(&self.helper)).await {
                Ok(()) => {
                    *self.repair_blocked.lock().expect("repair lock poisoned") = None;
                }
                Err(_) => {
                    let _ = self.events.send(EngineEvent::ConnectorError {
                        generation,
                        error_code,
                    });
                    return;
                }
            }
        }
        let repository = Arc::clone(&self.credentials);
        let credentials = match tokio::task::spawn_blocking(move || repository.load()).await {
            Ok(Ok(credentials)) => credentials,
            _ => {
                let _ = self.events.send(EngineEvent::ConnectorExited {
                    generation,
                    return_code: 1,
                    runtime_seconds: 0,
                });
                return;
            }
        };
        let secret = match TotpSecret::parse(credentials.totp_seed()) {
            Ok(secret) => secret,
            Err(_) => {
                let _ = self.events.send(EngineEvent::ConnectorExited {
                    generation,
                    return_code: 1,
                    runtime_seconds: 0,
                });
                return;
            }
        };
        let provider = Arc::new(GuardedTotp {
            generator: TotpGenerator::new(secret),
            guard: CounterGuard::new(&self.counter_path),
        });
        let password = SecretBytes::from_utf8_for_test(credentials.password());
        let input =
            match HelperStartInput::new(credentials.username().to_owned(), password, provider) {
                Ok(input) => input,
                Err(_) => {
                    let _ = self.events.send(EngineEvent::ConnectorExited {
                        generation,
                        return_code: 1,
                        runtime_seconds: 0,
                    });
                    return;
                }
            };
        let helper = Arc::clone(&self.helper);
        let events = self.events.clone();
        let repair_blocked = Arc::clone(&self.repair_blocked);
        let sessions_for_task = Arc::clone(&self.sessions);
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let session_id = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let connect_timeout = self.connect_timeout;
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        let join = tokio::spawn(async move {
            let mut session = match helper.start_session(input).await {
                Ok(session) => session,
                Err(error) => {
                    let outcome = Err(error);
                    send_connector_exited_and_remove_current(
                        &sessions_for_task,
                        generation,
                        session_id,
                        &events,
                        1,
                        0,
                    );
                    return SessionCompletion { outcome };
                }
            };
            let mut connected_tunnel = None;
            let mut hip_submitted = false;
            let establish_deadline = tokio::time::sleep(connect_timeout);
            tokio::pin!(establish_deadline);
            loop {
                let event = tokio::select! {
                    _ = cancel_rx.changed() => {
                        let _ = session.cancel().await;
                        let outcome = session.wait().await;
                        publish_session_outcome_and_remove_current(
                            &sessions_for_task,
                            generation,
                            session_id,
                            &events,
                            &repair_blocked,
                            &outcome,
                        );
                        return SessionCompletion { outcome };
                    }
                    _ = &mut establish_deadline => {
                        let _ = session.cancel().await;
                        let outcome = match tokio::time::timeout(
                            CONNECT_CLEANUP_TIMEOUT,
                            session.wait(),
                        ).await {
                            Ok(outcome) => outcome,
                            Err(_) => Ok(HelperSessionOutcome::RepairRequired),
                        };
                        if shutdown_outcome_clean(&outcome) {
                            send_connect_timed_out_and_remove_current(
                                &sessions_for_task,
                                generation,
                                session_id,
                                &events,
                            );
                        } else {
                            publish_session_outcome_and_remove_current(
                                &sessions_for_task,
                                generation,
                                session_id,
                                &events,
                                &repair_blocked,
                                &outcome,
                            );
                        }
                        return SessionCompletion { outcome };
                    }
                    event = session.next_event() => event,
                };
                match event {
                    Ok(Some(HelperSessionEvent::HipSubmitted)) => hip_submitted = true,
                    Ok(Some(HelperSessionEvent::Connected { tunnel })) => {
                        connected_tunnel = Some(tunnel)
                    }
                    _ => break,
                }
                if hip_submitted && connected_tunnel.is_some() {
                    break;
                }
            }
            if hip_submitted && let Some(tunnel_interface) = connected_tunnel {
                let _ = events.send(EngineEvent::ConnectorConnected {
                    generation,
                    tunnel_interface: Some(tunnel_interface),
                    hip_succeeded: true,
                });
            }
            let outcome = tokio::select! {
                _ = cancel_rx.changed() => {
                    let _ = session.cancel().await;
                    session.wait().await
                }
                outcome = session.wait() => outcome,
            };
            publish_session_outcome_and_remove_current(
                &sessions_for_task,
                generation,
                session_id,
                &events,
                &repair_blocked,
                &outcome,
            );
            SessionCompletion { outcome }
        });
        sessions.insert(
            generation,
            SessionControl {
                id: session_id,
                cancel: cancel_tx,
                join,
            },
        );
    }

    pub async fn execute_start_for_test(&self, generation: ConnectionGeneration) {
        self.start_connection(generation).await;
    }
    pub async fn execute_stop_for_test(&self, generation: ConnectionGeneration) {
        self.stop_connection(generation);
    }
    pub async fn execute_schedule_retry_for_test(&self, delay_seconds: u64) {
        self.schedule_retry(delay_seconds);
    }
    pub async fn execute_cancel_retry_for_test(&self) {
        self.cancel_retry();
    }

    fn stop_connection(&self, generation: ConnectionGeneration) {
        if let Some(control) = self
            .sessions
            .lock()
            .expect("session lock poisoned")
            .get(&generation)
        {
            let _ = control.cancel.send(true);
        }
    }

    fn schedule_retry(&self, delay_seconds: u64) {
        self.cancel_retry();
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        *self.retry.lock().expect("retry lock poisoned") = Some(cancel_tx);
        let events = self.events.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(delay_seconds)) => { let _ = events.send(EngineEvent::RetryElapsed); }
                _ = cancel_rx.changed() => {}
            }
        });
    }

    fn cancel_retry(&self) {
        if let Some(sender) = self.retry.lock().expect("retry lock poisoned").take() {
            let _ = sender.send(true);
        }
    }

    pub async fn shutdown_sessions(&self, timeout: Duration) -> Result<(), ServiceError> {
        self.cancel_retry();
        let sessions = std::mem::take(&mut *self.sessions.lock().expect("session lock poisoned"));
        for control in sessions.values() {
            let _ = control.cancel.send(true);
        }
        for (_generation, control) in sessions {
            let completion = tokio::time::timeout(timeout, control.join)
                .await
                .map_err(|_| ServiceError::Failed)?
                .map_err(|_| ServiceError::Failed)?;
            if !shutdown_outcome_clean(&completion.outcome) {
                if session_error_code(&completion.outcome) == Some(ErrorCode::RepairRequired)
                    && reconcile_helper_at_startup(Arc::clone(&self.helper))
                        .await
                        .is_ok()
                {
                    *self.repair_blocked.lock().expect("repair lock poisoned") = None;
                    continue;
                }
                return Err(ServiceError::Failed);
            }
        }
        Ok(())
    }

    pub async fn shutdown_sessions_for_test(&self, timeout: Duration) -> Result<(), ServiceError> {
        self.shutdown_sessions(timeout).await
    }

    pub async fn force_replace_session_for_test(&self, generation: ConnectionGeneration) {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let id = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let join = tokio::spawn(async move {
            let _ = cancel_rx.changed().await;
            SessionCompletion {
                outcome: Ok(HelperSessionOutcome::Cancelled),
            }
        });
        self.sessions.lock().expect("session lock poisoned").insert(
            generation,
            SessionControl {
                id,
                cancel: cancel_tx,
                join,
            },
        );
    }

    pub fn active_session_count_for_test(&self) -> usize {
        self.sessions.lock().expect("session lock poisoned").len()
    }
}

fn shutdown_outcome_clean(outcome: &Result<HelperSessionOutcome, HelperError>) -> bool {
    matches!(
        outcome,
        Ok(HelperSessionOutcome::Stopped)
            | Ok(HelperSessionOutcome::Cancelled)
            | Ok(HelperSessionOutcome::Exited { status: 0 })
    )
}

fn publish_session_outcome(
    generation: ConnectionGeneration,
    events: &mpsc::UnboundedSender<EngineEvent>,
    repair_blocked: &Arc<Mutex<Option<ErrorCode>>>,
    outcome: &Result<HelperSessionOutcome, HelperError>,
) {
    if let Some(error_code) = session_error_code(outcome) {
        *repair_blocked.lock().expect("repair lock poisoned") = Some(error_code);
        let _ = events.send(EngineEvent::ConnectorError {
            generation,
            error_code,
        });
    } else {
        let (return_code, runtime_seconds) = outcome_to_exit(outcome.clone());
        let _ = events.send(EngineEvent::ConnectorExited {
            generation,
            return_code,
            runtime_seconds,
        });
    }
}

fn session_error_code(outcome: &Result<HelperSessionOutcome, HelperError>) -> Option<ErrorCode> {
    match outcome {
        Ok(HelperSessionOutcome::RepairRequired)
        | Ok(HelperSessionOutcome::FailedWithCleanup {
            cleanup: HelperCleanupOutcome::RepairRequired,
            ..
        }) => Some(ErrorCode::RepairRequired),
        Ok(HelperSessionOutcome::Failed)
        | Ok(HelperSessionOutcome::FailedWithCleanup {
            cleanup: HelperCleanupOutcome::Failed | HelperCleanupOutcome::CleanupFailed,
            ..
        }) => Some(ErrorCode::ServiceUnavailable),
        _ => None,
    }
}

fn outcome_to_exit(outcome: Result<HelperSessionOutcome, HelperError>) -> (i32, u64) {
    match outcome {
        Ok(HelperSessionOutcome::Stopped | HelperSessionOutcome::Cancelled) => (0, 0),
        Ok(HelperSessionOutcome::Exited { status }) => (status, 0),
        Ok(HelperSessionOutcome::RepairRequired)
        | Ok(HelperSessionOutcome::Failed)
        | Ok(HelperSessionOutcome::FailedWithCleanup {
            cleanup:
                HelperCleanupOutcome::RepairRequired
                | HelperCleanupOutcome::Failed
                | HelperCleanupOutcome::CleanupFailed,
            ..
        }) => (2, 0),
        Ok(HelperSessionOutcome::FailedWithCleanup { .. }) | Err(_) => (1, 0),
    }
}

#[async_trait]
impl<H: MacHelper + ?Sized + 'static> ActionExecutor for MacActionExecutor<H> {
    async fn execute(&self, action: EngineAction) -> Option<EngineEvent> {
        match action {
            EngineAction::PersistAutomaticReconnect(enabled) => {
                let preference = self.preference.clone();
                let _ = tokio::task::spawn_blocking(move || preference.store(enabled)).await;
            }
            EngineAction::StartConnection { generation } => self.start_connection(generation).await,
            EngineAction::StopConnection { generation } => self.stop_connection(generation),
            EngineAction::ScheduleRetry { delay_seconds } => self.schedule_retry(delay_seconds),
            EngineAction::CancelRetry => self.cancel_retry(),
            EngineAction::PublishState(_) | EngineAction::PublishError(_) => {}
        }
        None
    }
}

#[derive(Default)]
pub struct NetworkReadinessTracker {
    candidate: Option<NetworkIdentity>,
    stable_samples: u8,
    published: Option<NetworkIdentity>,
    last_connected_health_probe: Option<Instant>,
    consecutive_connected_health_failures: u8,
    tunnel_health_failure_episodes: u8,
    tunnel_health_cooldown_until: Option<Instant>,
    tunnel_health_failure_identity: Option<NetworkIdentity>,
}

impl NetworkReadinessTracker {
    pub fn portal_probe_required(&self, sample: Option<&NetworkIdentity>) -> bool {
        self.portal_probe_required_at(sample, Instant::now())
    }

    pub fn portal_probe_required_at(&self, sample: Option<&NetworkIdentity>, now: Instant) -> bool {
        sample.is_some()
            && !self.tunnel_health_cooldown_active_for(sample, now)
            && sample != self.published.as_ref()
    }

    pub fn observe(
        &mut self,
        sample: Option<NetworkIdentity>,
        portal_reachable: bool,
    ) -> Option<EngineEvent> {
        self.observe_at(sample, portal_reachable, Instant::now())
    }

    pub fn observe_at(
        &mut self,
        sample: Option<NetworkIdentity>,
        portal_reachable: bool,
        now: Instant,
    ) -> Option<EngineEvent> {
        if self.tunnel_health_cooldown_active_for(sample.as_ref(), now) {
            return None;
        }
        if self.tunnel_health_cooldown_until.is_some() {
            if sample.is_some() && sample.as_ref() != self.tunnel_health_failure_identity.as_ref() {
                self.tunnel_health_failure_episodes = 0;
                self.tunnel_health_failure_identity = None;
            }
            self.tunnel_health_cooldown_until = None;
        }
        if sample.as_ref() != self.published.as_ref() {
            self.last_connected_health_probe = None;
            self.consecutive_connected_health_failures = 0;
        }
        let ready = match sample {
            Some(identity) if self.published.as_ref() == Some(&identity) || portal_reachable => {
                Some(identity)
            }
            _ => None,
        };
        if ready == self.candidate {
            self.stable_samples = self.stable_samples.saturating_add(1);
        } else {
            self.candidate = ready.clone();
            self.stable_samples = 1;
        }
        if self.stable_samples < 2 || ready == self.published {
            return None;
        }
        self.published = ready.clone();
        Some(match ready {
            Some(identity) => EngineEvent::NetworkReady(identity),
            None => EngineEvent::NetworkUnavailable,
        })
    }

    pub fn connected_health_probe_required_at(
        &self,
        sample: Option<&NetworkIdentity>,
        connected: bool,
        now: Instant,
        interval: Duration,
    ) -> bool {
        connected
            && sample.is_some()
            && sample == self.published.as_ref()
            && self
                .last_connected_health_probe
                .is_none_or(|last| now.saturating_duration_since(last) >= interval)
    }

    pub fn observe_connected_health_at(
        &mut self,
        healthy: bool,
        now: Instant,
    ) -> Option<EngineEvent> {
        if self.published.is_none() {
            self.last_connected_health_probe = None;
            self.consecutive_connected_health_failures = 0;
            return None;
        }
        self.last_connected_health_probe = Some(now);
        if healthy {
            self.consecutive_connected_health_failures = 0;
            self.tunnel_health_failure_episodes = 0;
            self.tunnel_health_cooldown_until = None;
            self.tunnel_health_failure_identity = None;
            return None;
        }
        self.consecutive_connected_health_failures =
            self.consecutive_connected_health_failures.saturating_add(1);
        if self.consecutive_connected_health_failures < 2 {
            return None;
        }
        self.candidate = None;
        self.stable_samples = 0;
        self.tunnel_health_failure_episodes = self.tunnel_health_failure_episodes.saturating_add(1);
        let exponent = self.tunnel_health_failure_episodes.saturating_sub(1).min(4);
        let delay_seconds = 120_u64.min(10_u64.saturating_mul(1_u64 << exponent));
        self.tunnel_health_cooldown_until = now.checked_add(Duration::from_secs(delay_seconds));
        self.tunnel_health_failure_identity = self.published.clone();
        self.published = None;
        self.last_connected_health_probe = None;
        self.consecutive_connected_health_failures = 0;
        Some(EngineEvent::NetworkUnavailable)
    }

    fn tunnel_health_cooldown_active_for(
        &self,
        sample: Option<&NetworkIdentity>,
        now: Instant,
    ) -> bool {
        self.tunnel_health_cooldown_until
            .is_some_and(|until| now < until)
            && (sample.is_none() || sample == self.tunnel_health_failure_identity.as_ref())
    }
}

pub async fn run_network_watch<R, C>(
    control: Arc<ControlPlane<R, C>>,
    monitor: Arc<dyn NetworkMonitor>,
    portal: Arc<dyn PortalProbe>,
    tunnel_health: Arc<dyn TunnelHealthProbe>,
    mut shutdown: watch::Receiver<bool>,
) where
    R: CredentialRepository + 'static,
    C: SystemClock + 'static,
{
    let mut tracker = NetworkReadinessTracker::default();
    loop {
        if *shutdown.borrow() {
            return;
        }
        let sample: Option<NetworkIdentity> = monitor.current_identity().await.unwrap_or_default();
        let now = Instant::now();
        let portal_reachable = if tracker.portal_probe_required_at(sample.as_ref(), now) {
            match sample.as_ref() {
                Some(identity) => portal.reachable(identity).await.unwrap_or(false),
                None => false,
            }
        } else {
            sample.is_some()
        };
        if let Some(event) = tracker.observe_at(sample.clone(), portal_reachable, now) {
            control.apply_event(event);
        }
        if tracker.connected_health_probe_required_at(
            sample.as_ref(),
            control.status().state == VpnState::Connected,
            now,
            CONNECTED_TUNNEL_HEALTH_INTERVAL,
        ) {
            let healthy = tunnel_health.healthy().await.unwrap_or(false);
            if let Some(event) = tracker.observe_connected_health_at(healthy, now) {
                control.apply_event(event);
            }
        }
        tokio::select! { _ = shutdown.changed() => {}, result = monitor.wait_for_change(Duration::from_secs(1)) => { let _ = result; } }
        tokio::task::yield_now().await;
    }
}

pub fn bind_owner_socket(
    path: impl AsRef<Path>,
    owner_uid: u32,
) -> Result<UnixListener, ServiceError> {
    let path = path.as_ref();
    let parent = path.parent().ok_or(ServiceError::Transport)?;
    prepare_owner_dir(parent, owner_uid)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(ServiceError::Transport);
        }
        fs::remove_file(path).map_err(|_| ServiceError::Transport)?;
    }
    let listener = UnixListener::bind(path).map_err(|_| ServiceError::Transport)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| ServiceError::Transport)?;
    Ok(listener)
}

fn prepare_owner_dir(path: &Path, owner_uid: u32) -> Result<(), ServiceError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::Transport)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
            return Err(ServiceError::Transport);
        }
    } else {
        fs::create_dir_all(path).map_err(|_| ServiceError::Transport)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| ServiceError::Transport)
}

pub fn peer_uid_authorized_for_test(peer_uid: u32, owner_uid: u32) -> bool {
    owner_uid != 0 && peer_uid == owner_uid
}

#[cfg(target_os = "macos")]
fn authorize_stream(stream: &tokio::net::UnixStream, owner_uid: u32) -> Result<bool, ServiceError> {
    use std::os::fd::AsRawFd;
    let mut cred = unsafe { std::mem::zeroed::<libc::xucred>() };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            0,
            libc::LOCAL_PEERCRED,
            (&mut cred as *mut libc::xucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(ServiceError::Transport);
    }
    Ok(peer_uid_authorized_for_test(cred.cr_uid, owner_uid))
}

#[cfg(not(target_os = "macos"))]
fn authorize_stream(
    _stream: &tokio::net::UnixStream,
    _owner_uid: u32,
) -> Result<bool, ServiceError> {
    Ok(true)
}

pub async fn serve_owner_socket<H>(
    listener: UnixListener,
    owner_uid: u32,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
) -> usize
where
    H: RequestHandler + ?Sized + 'static,
{
    serve_owner_socket_with_connection_timeout(
        listener,
        owner_uid,
        handler,
        shutdown,
        Duration::from_secs(5),
    )
    .await
}

async fn serve_owner_socket_with_connection_timeout<H>(
    listener: UnixListener,
    owner_uid: u32,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    connection_timeout: Duration,
) -> usize
where
    H: RequestHandler + ?Sized + 'static,
{
    let mut connections = JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue; };
                if !authorize_stream(&stream, owner_uid).unwrap_or(false) { continue; }
                let handler = Arc::clone(&handler);
                let mut connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    tokio::select! {
                        _ = connection_shutdown.changed() => {}
                        _ = tokio::time::timeout(connection_timeout, serve_connection(stream, handler)) => {}
                    }
                });
            }
        }
    }
    drain_connection_tasks(&mut connections, connection_timeout).await;
    connections.len()
}

async fn drain_connection_tasks(connections: &mut JoinSet<()>, timeout: Duration) {
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(timeout, drain).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

pub async fn serve_owner_socket_for_test<H>(
    listener: UnixListener,
    owner_uid: u32,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
    connection_timeout: Duration,
) -> usize
where
    H: RequestHandler + ?Sized + 'static,
{
    serve_owner_socket_with_connection_timeout(
        listener,
        owner_uid,
        handler,
        shutdown,
        connection_timeout,
    )
    .await
}

pub async fn reconcile_helper_at_startup<H: HelperRunner + ?Sized>(
    helper: Arc<H>,
) -> Result<(), ServiceError> {
    const ATTEMPTS: usize = 4;
    let mut last_error = ServiceError::Failed;
    for attempt in 0..ATTEMPTS {
        let state = match helper.run(HelperCommand::Status).await {
            Ok(state) => state,
            Err(_) => {
                if attempt + 1 < ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                return Err(last_error);
            }
        };
        let command = match state {
            HelperState::Stopped => return Ok(()),
            HelperState::Running { .. } => {
                last_error = ServiceError::Failed;
                HelperCommand::Stop
            }
            HelperState::RepairRequired => {
                last_error = ServiceError::RepairRequired;
                HelperCommand::Repair
            }
        };
        match helper.run(command).await {
            Ok(HelperState::Stopped) => return Ok(()),
            Ok(HelperState::RepairRequired) => last_error = ServiceError::RepairRequired,
            Ok(HelperState::Running { .. }) | Err(_) => {}
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    Err(last_error)
}

struct StatusPublishingHandler<R, C> {
    control: Arc<ControlPlane<R, C>>,
    credentials: Arc<dyn CredentialRepository>,
    counter_path: PathBuf,
    clock: Arc<dyn SystemClock>,
    status_file: AtomicStatusFile,
}

#[async_trait]
impl<R, C> RequestHandler for StatusPublishingHandler<R, C>
where
    R: CredentialRepository + 'static,
    C: SystemClock + 'static,
{
    async fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope {
        let request_id = request.request_id.clone();
        let response = if matches!(request.request, Request::CurrentOtp) {
            let credentials = Arc::clone(&self.credentials);
            let counter_path = self.counter_path.clone();
            let now = self.clock.now();
            match tokio::task::spawn_blocking(move || {
                let credentials = credentials.load()?;
                current_otp_preview(&credentials, now, counter_path)
                    .map_err(|_| RepositoryError::Storage)
            })
            .await
            {
                Ok(Ok(otp)) => ResponseEnvelope::new(
                    request_id,
                    Response::CurrentOtp {
                        code: otp.code,
                        remaining_seconds: otp.remaining_seconds,
                    },
                ),
                _ => ResponseEnvelope::new(
                    request_id,
                    Response::Error {
                        error_code: ErrorCode::CredentialStoreFailure,
                    },
                ),
            }
        } else {
            <ControlPlane<R, C> as RequestHandler>::handle(&*self.control, request).await
        };
        let _ = self.status_file.write(&self.control.status());
        response
    }
}

pub async fn run_service(
    config: ServiceConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    reconcile_helper_at_startup(Arc::clone(&config.helper)).await?;
    let automatic = AutomaticPreference::new(&config.automatic).load()?;
    let (control, actions) = ControlPlane::new(
        automatic,
        Arc::clone(&config.credentials),
        SharedClock(Arc::clone(&config.clock)),
    );
    let control = Arc::new(control);
    let status_file = AtomicStatusFile::new(&config.status);
    status_file
        .write(&control.status())
        .map_err(|_| ServiceError::State)?;
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let executor = Arc::new(MacActionExecutor::new(
        Arc::clone(&config.credentials),
        AutomaticPreference::new(&config.automatic),
        Arc::clone(&config.helper),
        &config.counter,
        event_tx,
    ));
    let runtime = DaemonRuntime::new_with_events(
        Arc::clone(&control),
        actions,
        event_rx,
        Arc::clone(&executor),
    );
    let runtime_shutdown = shutdown.clone();
    let runtime_task = tokio::spawn(runtime.run(runtime_shutdown));
    let network_task = config.network.map(|(monitor, portal, tunnel_health)| {
        tokio::spawn(run_network_watch(
            Arc::clone(&control),
            monitor,
            portal,
            tunnel_health,
            shutdown.clone(),
        ))
    });
    let listener = bind_owner_socket(&config.socket, config.uid)?;
    let handler = Arc::new(StatusPublishingHandler {
        control,
        credentials: Arc::clone(&config.credentials),
        counter_path: config.counter.clone(),
        clock: Arc::clone(&config.clock),
        status_file,
    });
    serve_owner_socket(listener, config.uid, handler, shutdown.clone()).await;
    executor.shutdown_sessions(config.cleanup_timeout).await?;
    let _ = runtime_task.await;
    if let Some(task) = network_task {
        let _ = task.await;
    }
    Ok(())
}

pub async fn run_health_check(
    config: ServiceConfig,
    timeout: Duration,
) -> Result<(), ServiceError> {
    run_health_check_socket(&config.socket, timeout).await
}

async fn run_health_check_socket(path: &Path, timeout: Duration) -> Result<(), ServiceError> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or(ServiceError::Transport)?;
    let request_id = "health";
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(ServiceError::Transport);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(remaining, single_health_check_attempt(path, request_id)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(_)) => {
                let sleep_for = Duration::from_millis(10)
                    .min(deadline.saturating_duration_since(std::time::Instant::now()));
                if sleep_for.is_zero() {
                    return Err(ServiceError::Transport);
                }
                tokio::time::sleep(sleep_for).await;
            }
            Err(_) => return Err(ServiceError::Transport),
        }
    }
}

async fn single_health_check_attempt(path: &Path, request_id: &str) -> Result<(), ServiceError> {
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|_| ServiceError::Transport)?;
    let request =
        hyu_vpn_protocol::encode_request(&RequestEnvelope::new(request_id, Request::Status))
            .map_err(|_| ServiceError::Transport)?;
    stream
        .write_u32(request.len() as u32)
        .await
        .map_err(|_| ServiceError::Transport)?;
    stream
        .write_all(&request)
        .await
        .map_err(|_| ServiceError::Transport)?;
    let length = stream
        .read_u32()
        .await
        .map_err(|_| ServiceError::Transport)? as usize;
    if length > hyu_vpn_protocol::MAX_FRAME_BYTES {
        return Err(ServiceError::Transport);
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|_| ServiceError::Transport)?;
    let response =
        hyu_vpn_protocol::decode_response(&frame).map_err(|_| ServiceError::Transport)?;
    if response.request_id() != request_id {
        return Err(ServiceError::Transport);
    }
    match response.into_response() {
        Response::Status { status }
            if status.schema_version == hyu_vpn_protocol::PROTOCOL_VERSION =>
        {
            Ok(())
        }
        _ => Err(ServiceError::Transport),
    }
}

pub async fn run_health_check_socket_for_test(
    path: &Path,
    timeout: Duration,
) -> Result<(), ServiceError> {
    run_health_check_socket(path, timeout).await
}
#[cfg(unix)]
pub async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler must install");
    let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler must install");
    let mut hangup = signal(SignalKind::hangup()).expect("SIGHUP handler must install");
    tokio::select! {
        _ = interrupt.recv() => {},
        _ = terminate.recv() => {},
        _ = hangup.recv() => {},
    }
}

#[cfg(not(unix))]
pub async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

pub fn shutdown_signal_names_for_test() -> &'static [&'static str] {
    #[cfg(unix)]
    {
        &["SIGINT", "SIGTERM", "SIGHUP"]
    }
    #[cfg(not(unix))]
    {
        &["CTRL_C"]
    }
}
