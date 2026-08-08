use std::collections::HashMap;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use hyu_vpn_core::ports::{NetworkMonitor, PortalProbe};
use hyu_vpn_core::state::{ConnectionGeneration, EngineAction, EngineEvent};
use hyu_vpn_core::totp::{CounterGuard, TotpError, TotpGenerator, TotpSecret};
use hyu_vpn_daemon::ipc::serve_connection;
use hyu_vpn_daemon::runtime::{
    ActionExecutor, ControlPlane, CredentialRepository, DaemonRuntime, SystemClock,
};
use hyu_vpn_platform_windows::{
    ChallengeCodeProvider, HiddenProcessSpec, ProcessSpecError, WindowsCredentialRepository,
    WindowsNetworkMonitor, WindowsPaths, WindowsPortalProbe, active_vpn_interface,
    authorize_active_pipe_client, run_interactive_openconnect,
};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::{AutomaticPreference, NetworkReadinessTracker};

#[derive(Clone, Copy)]
struct RealClock;

impl SystemClock for RealClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct GuardedCodes {
    generator: TotpGenerator,
    guard: CounterGuard,
}

#[async_trait]
impl ChallengeCodeProvider for GuardedCodes {
    async fn next_code(&self) -> Result<Zeroizing<String>, ProcessSpecError> {
        loop {
            let code = self
                .generator
                .code_at(SystemTime::now())
                .map_err(|_| ProcessSpecError::ProcessOperation)?;
            match self.guard.reserve(code.counter) {
                Ok(()) => return Ok(Zeroizing::new(code.value)),
                Err(TotpError::CounterAlreadyUsed) => {
                    tokio::time::sleep(
                        Duration::from_secs(u64::from(code.remaining_seconds))
                            + Duration::from_millis(50),
                    )
                    .await;
                }
                Err(_) => return Err(ProcessSpecError::ProcessOperation),
            }
        }
    }
}

type WindowsControlPlane = ControlPlane<Arc<dyn CredentialRepository>, RealClock>;

struct WindowsActionExecutor {
    credentials: Arc<dyn CredentialRepository>,
    preference: AutomaticPreference,
    launch: HiddenProcessSpec,
    counter_path: PathBuf,
    events: mpsc::UnboundedSender<EngineEvent>,
    sessions: Arc<Mutex<HashMap<ConnectionGeneration, watch::Sender<bool>>>>,
    retry: Mutex<Option<watch::Sender<bool>>>,
}

impl WindowsActionExecutor {
    fn new(
        credentials: Arc<dyn CredentialRepository>,
        preference: AutomaticPreference,
        launch: HiddenProcessSpec,
        counter_path: PathBuf,
        events: mpsc::UnboundedSender<EngineEvent>,
    ) -> Self {
        Self {
            credentials,
            preference,
            launch,
            counter_path,
            events,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            retry: Mutex::new(None),
        }
    }

    async fn start_connection(&self, generation: ConnectionGeneration) {
        let repository = Arc::clone(&self.credentials);
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
        let codes = GuardedCodes {
            generator: TotpGenerator::new(secret),
            guard: CounterGuard::new(&self.counter_path),
        };
        let launch = self.launch.clone();
        let events = self.events.clone();
        let sessions = Arc::clone(&self.sessions);
        let baseline = active_vpn_interface();
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
                        let current = active_vpn_interface();
                        if current.is_some() && current != baseline {
                            connected = true;
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

    fn stop_all(&self) {
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
impl ActionExecutor for WindowsActionExecutor {
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

pub async fn run_daemon(mut shutdown: watch::Receiver<bool>) -> Result<(), &'static str> {
    let paths = WindowsPaths::production();
    let credentials: Arc<dyn CredentialRepository> =
        Arc::new(WindowsCredentialRepository::production());
    let preference = AutomaticPreference::new(&paths.automatic_reconnect);
    let automatic = preference.load().map_err(|_| "preference")?;
    let (control, actions) = ControlPlane::new(automatic, Arc::clone(&credentials), RealClock);
    let control = Arc::new(control);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let executor = Arc::new(WindowsActionExecutor::new(
        credentials,
        preference,
        HiddenProcessSpec::production().map_err(|_| "launch")?,
        paths.state_dir.join("totp-counter.json"),
        event_tx,
    ));
    let daemon = DaemonRuntime::new_with_events(
        Arc::clone(&control),
        actions,
        event_rx,
        Arc::clone(&executor),
    );
    let (daemon_shutdown_tx, daemon_shutdown_rx) = watch::channel(false);
    let daemon_task = tokio::spawn(daemon.run(daemon_shutdown_rx));
    let network_task = tokio::spawn(run_network_watch(
        Arc::clone(&control),
        WindowsNetworkMonitor,
        WindowsPortalProbe::production(),
        shutdown.clone(),
    ));
    let pipe_task = tokio::spawn(serve_pipe(Arc::clone(&control), shutdown.clone()));
    loop {
        if *shutdown.borrow() {
            break;
        }
        if shutdown.changed().await.is_err() {
            break;
        }
    }
    executor.stop_all();
    let _ = daemon_shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), daemon_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), network_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), pipe_task).await;
    Ok(())
}

async fn run_network_watch<M, P>(
    control: Arc<WindowsControlPlane>,
    monitor: M,
    probe: P,
    mut shutdown: watch::Receiver<bool>,
) where
    M: NetworkMonitor,
    P: PortalProbe,
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
        let reachable = if tracker.portal_probe_required(sample.as_ref()) {
            match sample.as_ref() {
                Some(identity) => probe.reachable(identity).await.unwrap_or(false),
                None => false,
            }
        } else {
            sample.is_some()
        };
        if let Some(event) = tracker.observe(sample, reachable) {
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

async fn serve_pipe(control: Arc<WindowsControlPlane>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let server = match create_secured_pipe() {
            Ok(server) => server,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        tokio::select! {
            _ = shutdown.changed() => return,
            connected = server.connect() => {
                if connected.is_err() {
                    continue;
                }
            }
        }
        let raw = server.as_raw_handle().cast();
        if unsafe { authorize_active_pipe_client(raw) }.is_err() {
            let _ = server.disconnect();
            continue;
        }
        let _ = serve_connection(server, Arc::clone(&control)).await;
    }
}

fn create_secured_pipe() -> std::io::Result<NamedPipeServer> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GRGW;;;IU)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| std::io::Error::other("security attributes"))?,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .max_instances(16)
            .in_buffer_size(64 * 1024)
            .out_buffer_size(64 * 1024)
            .create_with_security_attributes_raw(
                r"\\.\pipe\hyu-vpn-v1",
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    };
    unsafe {
        LocalFree(descriptor);
    }
    server
}
