#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Stdio;
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

use async_trait::async_trait;
use hyu_vpn_protocol::Credentials;
#[cfg(windows)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
#[cfg(windows)]
use tokio::sync::mpsc;
use tokio::sync::watch;
use zeroize::Zeroizing;

use hyu_vpn_core::openconnect::{ConnectorConfig, build_openconnect_args};
use thiserror::Error;

use crate::WindowsPaths;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSpecError {
    #[error("invalid Windows process specification")]
    InvalidSpecification,
    #[error("Windows process operation failed")]
    ProcessOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    Username,
    Password,
    Challenge,
}

#[derive(Debug, Default)]
pub struct PromptDetector {
    tail: Vec<u8>,
}

impl PromptDetector {
    pub fn feed(&mut self, chunk: &[u8]) -> Option<PromptKind> {
        self.tail.extend_from_slice(chunk);
        if self.tail.len() > 512 {
            self.tail.drain(..self.tail.len() - 512);
        }
        let segment = self
            .tail
            .rsplit(|byte| matches!(byte, b'\n' | b'\r'))
            .next()
            .unwrap_or_default();
        let compact = String::from_utf8_lossy(segment)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        let prompt = if compact.ends_with("username:") {
            Some(PromptKind::Username)
        } else if compact.ends_with("password:") {
            Some(PromptKind::Password)
        } else if compact.ends_with("challenge:") {
            Some(PromptKind::Challenge)
        } else {
            None
        };
        if prompt.is_some() {
            self.tail.clear();
        }
        prompt
    }

    pub fn buffered_bytes(&self) -> usize {
        self.tail.len()
    }
}

#[async_trait]
pub trait ChallengeCodeProvider: Send + Sync {
    async fn next_code(&self) -> Result<Zeroizing<String>, ProcessSpecError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractiveOutcome {
    pub return_code: i32,
    pub runtime_seconds: u64,
}

#[cfg(windows)]
pub async fn run_interactive_openconnect<P>(
    spec: HiddenProcessSpec,
    credentials: &Credentials,
    codes: &P,
    mut stop: watch::Receiver<bool>,
) -> Result<InteractiveOutcome, ProcessSpecError>
where
    P: ChallengeCodeProvider,
{
    let mut managed = JobChild::spawn(&spec).await?;
    let mut stdin = managed
        .child
        .stdin
        .take()
        .ok_or(ProcessSpecError::ProcessOperation)?;
    write_line(&mut stdin, credentials.password().as_bytes()).await?;
    eprintln!("hyu-vpn-windows-stage: child-started");
    let stdout = managed
        .child
        .stdout
        .take()
        .ok_or(ProcessSpecError::ProcessOperation)?;
    let stderr = managed
        .child
        .stderr
        .take()
        .ok_or(ProcessSpecError::ProcessOperation)?;
    let (output_tx, mut output_rx) = mpsc::channel::<(usize, Vec<u8>)>(16);
    tokio::spawn(pump_output(0, stdout, output_tx.clone()));
    tokio::spawn(pump_output(1, stderr, output_tx));
    let mut detectors = [PromptDetector::default(), PromptDetector::default()];
    let started = Instant::now();
    let status = loop {
        tokio::select! {
            status = managed.child.wait() => {
                break status.map_err(|_| ProcessSpecError::ProcessOperation)?;
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    if !managed.request_graceful_termination() {
                        managed.force_termination();
                    }
                    match tokio::time::timeout(Duration::from_secs(10), managed.child.wait()).await {
                        Ok(status) => break status.map_err(|_| ProcessSpecError::ProcessOperation)?,
                        Err(_) => {
                            managed.force_termination();
                            break managed
                                .child
                                .wait()
                                .await
                                .map_err(|_| ProcessSpecError::ProcessOperation)?;
                        }
                    }
                }
            }
            output = output_rx.recv() => {
                if let Some((source, chunk)) = output
                    && let Some(prompt) = detectors[source].feed(&chunk)
                {
                    match prompt {
                        PromptKind::Username => {
                            eprintln!("hyu-vpn-windows-stage: username-prompt");
                            write_line(&mut stdin, credentials.username().as_bytes()).await?;
                        }
                        PromptKind::Password => {
                            eprintln!("hyu-vpn-windows-stage: password-prompt");
                            write_line(&mut stdin, credentials.password().as_bytes()).await?;
                        }
                        PromptKind::Challenge => {
                            eprintln!("hyu-vpn-windows-stage: challenge-prompt");
                            let code = codes.next_code().await?;
                            write_line(&mut stdin, code.as_bytes()).await?;
                            eprintln!("hyu-vpn-windows-stage: challenge-sent");
                        }
                    }
                }
            }
        }
    };
    Ok(InteractiveOutcome {
        return_code: status.code().unwrap_or(1),
        runtime_seconds: started.elapsed().as_secs(),
    })
}

#[cfg(not(windows))]
pub async fn run_interactive_openconnect<P>(
    _spec: HiddenProcessSpec,
    _credentials: &Credentials,
    _codes: &P,
    _stop: watch::Receiver<bool>,
) -> Result<InteractiveOutcome, ProcessSpecError>
where
    P: ChallengeCodeProvider,
{
    Err(ProcessSpecError::ProcessOperation)
}

#[cfg(windows)]
async fn write_line(
    stdin: &mut tokio::process::ChildStdin,
    value: &[u8],
) -> Result<(), ProcessSpecError> {
    if value.is_empty() || value.len() > 4096 || value.contains(&b'\n') || value.contains(&b'\r') {
        return Err(ProcessSpecError::InvalidSpecification);
    }
    stdin
        .write_all(value)
        .await
        .map_err(|_| ProcessSpecError::ProcessOperation)?;
    stdin
        .write_all(b"\n")
        .await
        .map_err(|_| ProcessSpecError::ProcessOperation)?;
    stdin
        .flush()
        .await
        .map_err(|_| ProcessSpecError::ProcessOperation)
}

#[cfg(windows)]
async fn pump_output<R>(source: usize, mut reader: R, output: mpsc::Sender<(usize, Vec<u8>)>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 4096];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        if output
            .send((source, buffer[..read].to_vec()))
            .await
            .is_err()
        {
            return;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenProcessSpec {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub create_no_window: bool,
    pub kill_job_on_close: bool,
}

impl HiddenProcessSpec {
    pub fn production() -> Result<Self, ProcessSpecError> {
        let paths = WindowsPaths::production();
        let config = ConnectorConfig {
            executable: paths.openconnect.clone(),
            portal: "secure.hanyang.ac.kr".to_owned(),
            authgroup: "HYU-ExternalGW-General".to_owned(),
            vpnc_script: paths.vpnc_script,
            hip_wrapper: paths.hip_wrapper,
        };
        let argv =
            build_openconnect_args(&config).map_err(|_| ProcessSpecError::InvalidSpecification)?;
        Ok(Self {
            executable: paths.openconnect,
            argv,
            create_no_window: true,
            kill_job_on_close: true,
        })
    }

    #[cfg(windows)]
    fn valid(&self) -> bool {
        self.executable.is_absolute()
            && !self.argv.is_empty()
            && self
                .argv
                .iter()
                .all(|argument| !argument.chars().any(char::is_control))
    }
}

#[cfg(windows)]
pub struct JobChild {
    pub child: tokio::process::Child,
    job: OwnedHandle,
}

#[cfg(windows)]
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<JobChild>();
};

#[cfg(windows)]
impl JobChild {
    pub async fn spawn(spec: &HiddenProcessSpec) -> Result<Self, ProcessSpecError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::{CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP};

        if !spec.valid() || !spec.create_no_window || !spec.kill_job_on_close {
            return Err(ProcessSpecError::InvalidSpecification);
        }
        let mut command = tokio::process::Command::new(&spec.executable);
        command
            .args(&spec.argv)
            // The service runs in isolated session 0. A dedicated console is
            // required so the service can deliver CTRL_C for clean vpnc teardown.
            .creation_flags(CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = command
            .spawn()
            .map_err(|_| ProcessSpecError::ProcessOperation)?;
        let raw_process = child
            .raw_handle()
            .ok_or(ProcessSpecError::ProcessOperation)?;
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(ProcessSpecError::ProcessOperation);
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| ProcessSpecError::ProcessOperation)?,
            )
        };
        let assigned = if configured != 0 {
            unsafe { AssignProcessToJobObject(job, raw_process.cast()) }
        } else {
            0
        };
        if configured == 0 || assigned == 0 {
            unsafe {
                CloseHandle(job);
            }
            return Err(ProcessSpecError::ProcessOperation);
        }
        let job = unsafe { OwnedHandle::from_raw_handle(job.cast()) };
        Ok(Self { child, job })
    }

    pub fn request_graceful_termination(&self) -> bool {
        use std::sync::Mutex;
        use windows_sys::Win32::System::Console::{
            AttachConsole, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
            SetConsoleCtrlHandler,
        };

        static CONSOLE_SIGNAL_LOCK: Mutex<()> = Mutex::new(());
        let Ok(_guard) = CONSOLE_SIGNAL_LOCK.lock() else {
            return false;
        };
        let Some(process_id) = self.child.id() else {
            return false;
        };
        unsafe {
            // Windows console attachment is process-global. Serialize it and
            // ignore the generated control event in the service itself.
            FreeConsole();
            if SetConsoleCtrlHandler(None, 1) == 0 {
                return false;
            }
            if AttachConsole(process_id) == 0 {
                SetConsoleCtrlHandler(None, 0);
                return false;
            }
            let delivered = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) != 0;
            FreeConsole();
            SetConsoleCtrlHandler(None, 0);
            delivered
        }
    }

    pub fn force_termination(&self) {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        unsafe {
            TerminateJobObject(self.job.as_raw_handle().cast(), 1);
        }
    }

    pub async fn terminate(mut self, timeout: Duration) -> Result<(), ProcessSpecError> {
        if !self.request_graceful_termination() {
            self.force_termination();
        }
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => {
                status.map_err(|_| ProcessSpecError::ProcessOperation)?;
            }
            Err(_) => {
                self.force_termination();
                self.child
                    .wait()
                    .await
                    .map_err(|_| ProcessSpecError::ProcessOperation)?;
            }
        }
        Ok(())
    }
}

#[cfg(not(windows))]
pub struct JobChild;

#[cfg(not(windows))]
impl JobChild {
    pub async fn spawn(_spec: &HiddenProcessSpec) -> Result<Self, ProcessSpecError> {
        Err(ProcessSpecError::ProcessOperation)
    }

    pub async fn terminate(self, _timeout: Duration) -> Result<(), ProcessSpecError> {
        Err(ProcessSpecError::ProcessOperation)
    }
}
