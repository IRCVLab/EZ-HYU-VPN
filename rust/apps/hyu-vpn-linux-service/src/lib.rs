use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, PortalProbe};
use hyu_vpn_core::state::{ConnectionGeneration, EngineAction, EngineEvent, NetworkIdentity};
use hyu_vpn_core::totp::{CounterGuard, TotpError, TotpGenerator, TotpSecret};
use hyu_vpn_daemon::ipc::{RequestHandler, serve_connection};
use hyu_vpn_daemon::runtime::{ActionExecutor, CredentialRepository, SystemClock};
use hyu_vpn_platform_linux::{
    ChallengeCodeProvider, LaunchError, LinuxPortalProbe, LinuxRouteMonitor, OpenConnectLaunch,
    authorize_peer_uid, run_interactive_openconnect,
};
use thiserror::Error;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    #[error("service configuration is invalid")]
    InvalidConfiguration,
    #[error("service state operation failed")]
    State,
    #[error("service transport failed")]
    Transport,
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
            || metadata.len() > 8
            || metadata.permissions().mode() & 0o777 != 0o600
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
        fs::create_dir_all(parent).map_err(|_| ServiceError::State)?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| ServiceError::State)?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(ServiceError::State);
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| ServiceError::State)?;
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|_| ServiceError::State)?;
            file.write_all(if enabled { b"true\n" } else { b"false\n" })
                .and_then(|()| file.sync_all())
                .map_err(|_| ServiceError::State)?;
            if self.path.exists() {
                let metadata = fs::symlink_metadata(&self.path).map_err(|_| ServiceError::State)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(ServiceError::State);
                }
            }
            fs::rename(&temporary, &self.path).map_err(|_| ServiceError::State)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|_| ServiceError::State)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

pub fn read_owner_uid(path: impl AsRef<Path>) -> Result<u32, ServiceError> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::InvalidConfiguration)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16 {
        return Err(ServiceError::InvalidConfiguration);
    }
    let raw = fs::read_to_string(path).map_err(|_| ServiceError::InvalidConfiguration)?;
    let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ServiceError::InvalidConfiguration);
    }
    let uid = trimmed
        .parse::<u32>()
        .map_err(|_| ServiceError::InvalidConfiguration)?;
    if uid == 0 {
        return Err(ServiceError::InvalidConfiguration);
    }
    Ok(uid)
}

#[derive(Clone, Copy)]
pub struct RealClock;

impl SystemClock for RealClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct GuardedCodes {
    generator: TotpGenerator,
    guard: CounterGuard,
}

impl GuardedCodes {
    fn new(secret: TotpSecret, path: impl AsRef<Path>) -> Self {
        Self {
            generator: TotpGenerator::new(secret),
            guard: CounterGuard::new(path),
        }
    }
}

#[async_trait]
impl ChallengeCodeProvider for GuardedCodes {
    async fn next_code(&self) -> Result<Zeroizing<String>, LaunchError> {
        loop {
            let code = self
                .generator
                .code_at(SystemTime::now())
                .map_err(|_| LaunchError::ProcessFailed)?;
            match self.guard.reserve(code.counter) {
                Ok(()) => {
                    eprintln!("hyu-vpn-connect-stage: totp-generated");
                    return Ok(Zeroizing::new(code.value));
                }
                Err(TotpError::CounterAlreadyUsed) => {
                    eprintln!("hyu-vpn-connect-stage: waiting-for-next-totp-step");
                    tokio::time::sleep(
                        Duration::from_secs(u64::from(code.remaining_seconds))
                            + Duration::from_millis(50),
                    )
                    .await;
                }
                Err(_) => return Err(LaunchError::ProcessFailed),
            }
        }
    }
}

pub struct LinuxActionExecutor {
    credentials: Arc<dyn CredentialRepository>,
    preference: AutomaticPreference,
    launch: OpenConnectLaunch,
    counter_path: PathBuf,
    events: mpsc::UnboundedSender<EngineEvent>,
    sessions: Arc<Mutex<HashMap<ConnectionGeneration, watch::Sender<bool>>>>,
    retry: Mutex<Option<watch::Sender<bool>>>,
}

impl LinuxActionExecutor {
    pub fn new(
        credentials: Arc<dyn CredentialRepository>,
        preference: AutomaticPreference,
        launch: OpenConnectLaunch,
        counter_path: impl AsRef<Path>,
        events: mpsc::UnboundedSender<EngineEvent>,
    ) -> Self {
        Self {
            credentials,
            preference,
            launch,
            counter_path: counter_path.as_ref().to_path_buf(),
            events,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            retry: Mutex::new(None),
        }
    }

    async fn start_connection(&self, generation: ConnectionGeneration) {
        let repository = self.credentials.clone();
        let credentials = match tokio::task::spawn_blocking(move || repository.load()).await {
            Ok(Ok(credentials)) => credentials,
            Err(_) | Ok(Err(_)) => {
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
        let codes = GuardedCodes::new(secret, &self.counter_path);
        let launch = self.launch.clone();
        let events = self.events.clone();
        let sessions = Arc::clone(&self.sessions);
        let baseline = tunnel_interfaces();
        let (stop_tx, stop_rx) = watch::channel(false);
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .insert(generation, stop_tx);
        tokio::spawn(async move {
            let mut runner = Box::pin(run_interactive_openconnect(
                launch,
                &credentials,
                &codes,
                stop_rx,
            ));
            let mut connected = false;
            let outcome = loop {
                tokio::select! {
                    outcome = &mut runner => break outcome,
                    () = tokio::time::sleep(Duration::from_millis(250)), if !connected => {
                        if !tunnel_interfaces().is_subset(&baseline) {
                            connected = true;
                            eprintln!("hyu-vpn-connect-stage: tunnel-detected");
                            let _ = events.send(EngineEvent::ConnectorConnected { generation });
                        }
                    }
                }
            };
            sessions
                .lock()
                .expect("session lock poisoned")
                .remove(&generation);
            let (return_code, runtime_seconds) = match outcome {
                Ok(outcome) => (outcome.return_code, outcome.runtime_seconds),
                Err(_) => (1, 0),
            };
            let _ = events.send(EngineEvent::ConnectorExited {
                generation,
                return_code,
                runtime_seconds,
            });
        });
    }

    pub fn stop_all(&self) {
        for sender in self
            .sessions
            .lock()
            .expect("session lock poisoned")
            .values()
        {
            let _ = sender.send(true);
        }
        if let Some(sender) = self.retry.lock().expect("retry lock poisoned").take() {
            let _ = sender.send(true);
        }
    }
}

#[async_trait]
impl ActionExecutor for LinuxActionExecutor {
    async fn execute(&self, action: EngineAction) -> Option<EngineEvent> {
        match action {
            EngineAction::PersistAutomaticReconnect(enabled) => {
                let preference = self.preference.clone();
                let _ = tokio::task::spawn_blocking(move || preference.store(enabled)).await;
            }
            EngineAction::StartConnection { generation } => self.start_connection(generation).await,
            EngineAction::StopConnection { generation } => {
                if let Some(sender) = self
                    .sessions
                    .lock()
                    .expect("session lock poisoned")
                    .get(&generation)
                {
                    let _ = sender.send(true);
                }
            }
            EngineAction::ScheduleRetry { delay_seconds } => {
                if let Some(sender) = self.retry.lock().expect("retry lock poisoned").take() {
                    let _ = sender.send(true);
                }
                let (cancel_tx, mut cancel_rx) = watch::channel(false);
                *self.retry.lock().expect("retry lock poisoned") = Some(cancel_tx);
                let events = self.events.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(delay_seconds)) => {
                            let _ = events.send(EngineEvent::RetryElapsed);
                        }
                        _ = cancel_rx.changed() => {}
                    }
                });
            }
            EngineAction::CancelRetry => {
                if let Some(sender) = self.retry.lock().expect("retry lock poisoned").take() {
                    let _ = sender.send(true);
                }
            }
            EngineAction::PublishState(_) => {}
        }
        None
    }
}

#[derive(Default)]
pub struct NetworkReadinessTracker {
    candidate: Option<NetworkIdentity>,
    stable_samples: u8,
    published: Option<NetworkIdentity>,
}

impl NetworkReadinessTracker {
    pub fn portal_probe_required(&self, sample: Option<&NetworkIdentity>) -> bool {
        sample.is_some() && sample != self.published.as_ref()
    }

    pub fn observe(
        &mut self,
        sample: Option<NetworkIdentity>,
        portal_reachable: bool,
    ) -> Option<EngineEvent> {
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
}

pub async fn run_network_watch<R, C>(
    control: Arc<hyu_vpn_daemon::runtime::ControlPlane<R, C>>,
    monitor: LinuxRouteMonitor,
    portal: LinuxPortalProbe,
    mut shutdown: watch::Receiver<bool>,
) where
    R: CredentialRepository + 'static,
    C: SystemClock + 'static,
{
    let mut tracker = NetworkReadinessTracker::default();
    let error_delay = Duration::from_secs(1);
    loop {
        if *shutdown.borrow() {
            return;
        }
        let sample = match monitor.current_identity().await {
            Ok(sample) => sample,
            Err(_) => {
                tokio::select! {
                    _ = shutdown.changed() => {},
                    _ = tokio::time::sleep(error_delay) => {},
                }
                continue;
            }
        };
        let portal_reachable = if tracker.portal_probe_required(sample.as_ref()) {
            match sample.as_ref() {
                Some(identity) => portal.reachable(identity).await.unwrap_or(false),
                None => false,
            }
        } else {
            sample.is_some()
        };
        if let Some(event) = tracker.observe(sample, portal_reachable) {
            control.apply_event(event);
        }
        let wait_result = tokio::select! {
            _ = shutdown.changed() => Ok(()),
            result = monitor.wait_for_change(Duration::from_secs(1)) => result,
        };
        if wait_result.is_err() {
            tokio::select! {
                _ = shutdown.changed() => {},
                _ = tokio::time::sleep(error_delay) => {},
            }
        }
    }
}

pub fn bind_owner_socket(
    runtime_dir: impl AsRef<Path>,
    socket_path: impl AsRef<Path>,
    owner_uid: u32,
) -> Result<UnixListener, ServiceError> {
    let runtime_dir = runtime_dir.as_ref();
    let socket_path = socket_path.as_ref();
    let owner_gid = primary_gid(owner_uid)?;
    if runtime_dir.exists() {
        let metadata = fs::symlink_metadata(runtime_dir).map_err(|_| ServiceError::Transport)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ServiceError::Transport);
        }
    } else {
        fs::create_dir_all(runtime_dir).map_err(|_| ServiceError::Transport)?;
    }
    fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o750))
        .map_err(|_| ServiceError::Transport)?;
    chown(runtime_dir, 0, owner_gid)?;
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        if !metadata.file_type().is_socket() {
            return Err(ServiceError::Transport);
        }
        fs::remove_file(socket_path).map_err(|_| ServiceError::Transport)?;
    }
    let listener = UnixListener::bind(socket_path).map_err(|_| ServiceError::Transport)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))
        .map_err(|_| ServiceError::Transport)?;
    chown(socket_path, 0, owner_gid)?;
    Ok(listener)
}

pub async fn serve_owner_socket<H>(
    listener: UnixListener,
    owner_uid: u32,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) where
    H: RequestHandler + ?Sized + 'static,
{
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue; };
                let authorized = authorize_peer_uid(&stream, owner_uid).unwrap_or(false)
                    || authorize_peer_uid(&stream, 0).unwrap_or(false);
                if !authorized { continue; }
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let _ = serve_connection(stream, handler).await;
                });
            }
        }
    }
}

fn tunnel_interfaces() -> HashSet<String> {
    let mut result = HashSet::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return result;
    };
    for entry in entries.flatten().take(256) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if ["tun", "tap", "vpn"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            result.insert(name);
        }
    }
    result
}

fn primary_gid(uid: u32) -> Result<u32, ServiceError> {
    let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut result = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(ServiceError::InvalidConfiguration);
    }
    Ok(passwd.pw_gid)
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), ServiceError> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ServiceError::InvalidConfiguration)?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
        return Err(ServiceError::Transport);
    }
    Ok(())
}
