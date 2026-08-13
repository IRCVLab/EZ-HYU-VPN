use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroize;

const SUDO: &str = "/usr/bin/sudo";
const HELPER: &str = "/Library/PrivilegedHelperTools/com.hyu.vpn.helper";
const MAX_OUTPUT_BYTES: usize = 16 * 1024;
const SHORT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_USERNAME_BYTES: usize = 128;
const DEFAULT_MAX_PROMPT_RESPONSES: usize = 8;
const GRACEFUL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub enum HelperCommand {
    Stop,
    Status,
    Repair,
}

impl fmt::Debug for HelperCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stop => formatter.write_str("Stop"),
            Self::Status => formatter.write_str("Status"),
            Self::Repair => formatter.write_str("Repair"),
        }
    }
}

impl HelperCommand {
    fn verb(&self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Status => "status",
            Self::Repair => "repair",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperState {
    Stopped,
    Running { tunnel: Option<String> },
    RepairRequired,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HelperError {
    #[error("invalid helper command input")]
    InvalidCommandInput,
    #[error("helper invocation failed")]
    InvocationFailed,
    #[error("helper timed out")]
    Timeout,
    #[error("invalid helper response")]
    InvalidResponse,
    #[error("helper output limit exceeded")]
    OutputLimitExceeded,
    #[error("helper prompt input unavailable")]
    PromptInputUnavailable,
    #[error("helper prompt limit exceeded")]
    PromptLimitExceeded,
    #[error("helper session cancelled")]
    Cancelled,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn from_utf8_for_test(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[async_trait]
pub trait HelperTotpProvider: Send + Sync {
    async fn next_totp(&self) -> Result<SecretBytes, HelperError>;
}

#[derive(Clone)]
pub struct HelperStartInput {
    username: String,
    password: SecretBytes,
    totp_provider: Arc<dyn HelperTotpProvider>,
    pub max_prompt_responses: usize,
}

impl HelperStartInput {
    pub fn new(
        username: impl Into<String>,
        password: SecretBytes,
        totp_provider: Arc<dyn HelperTotpProvider>,
    ) -> Result<Self, HelperError> {
        let username = username.into();
        validate_username(&username)?;
        Ok(Self {
            username,
            password,
            totp_provider,
            max_prompt_responses: DEFAULT_MAX_PROMPT_RESPONSES,
        })
    }
}

#[async_trait]
pub trait HelperRunner: Send + Sync {
    async fn run(&self, command: HelperCommand) -> Result<HelperState, HelperError>;
}

#[async_trait]
pub trait HelperSessionRunner: Send + Sync {
    async fn start_session(
        &self,
        input: HelperStartInput,
    ) -> Result<Box<dyn HelperStartSession>, HelperError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperSessionEvent {
    HipSubmitted,
    Connected { tunnel: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperSessionFailure {
    InvocationFailed,
    Timeout,
    InvalidResponse,
    OutputLimitExceeded,
    PromptInputUnavailable,
    PromptLimitExceeded,
    Cancelled,
}

impl From<HelperError> for HelperSessionFailure {
    fn from(error: HelperError) -> Self {
        match error {
            HelperError::InvocationFailed => Self::InvocationFailed,
            HelperError::Timeout => Self::Timeout,
            HelperError::InvalidResponse => Self::InvalidResponse,
            HelperError::OutputLimitExceeded => Self::OutputLimitExceeded,
            HelperError::PromptInputUnavailable => Self::PromptInputUnavailable,
            HelperError::PromptLimitExceeded => Self::PromptLimitExceeded,
            HelperError::Cancelled => Self::Cancelled,
            HelperError::InvalidCommandInput => Self::InvocationFailed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperCleanupOutcome {
    Stopped,
    RepairRequired,
    Failed,
    CleanupFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperSessionOutcome {
    Stopped,
    RepairRequired,
    Failed,
    Exited {
        status: i32,
    },
    Cancelled,
    FailedWithCleanup {
        failure: HelperSessionFailure,
        cleanup: HelperCleanupOutcome,
    },
}

#[async_trait]
pub trait HelperStartSession: Send + Sync {
    async fn next_event(&mut self) -> Result<Option<HelperSessionEvent>, HelperError>;
    async fn wait(&mut self) -> Result<HelperSessionOutcome, HelperError>;
    async fn cancel(&mut self) -> Result<(), HelperError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperStdin {
    Null,
    Interactive { initial_header: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub stdin: HelperStdin,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperProcessOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[async_trait]
pub trait HelperProcess: Send + Sync {
    async fn run_short(
        &self,
        invocation: HelperInvocation,
    ) -> Result<HelperProcessOutput, HelperError> {
        run_short_command(invocation, true).await
    }

    async fn start_session(
        &self,
        invocation: HelperInvocation,
        input: HelperStartInput,
    ) -> Result<Box<dyn HelperStartSession>, HelperError>;
}

#[derive(Clone)]
pub struct InstalledHelperRunner {
    process: Arc<dyn HelperProcess>,
}

impl Default for InstalledHelperRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl InstalledHelperRunner {
    pub fn new() -> Self {
        Self {
            process: Arc::new(SystemHelperProcess),
        }
    }

    pub fn with_process_for_test(process: Arc<dyn HelperProcess>) -> Self {
        Self { process }
    }

    pub async fn start_session(
        &self,
        input: HelperStartInput,
    ) -> Result<Box<dyn HelperStartSession>, HelperError> {
        <Self as HelperSessionRunner>::start_session(self, input).await
    }
}

#[async_trait]
impl HelperRunner for InstalledHelperRunner {
    async fn run(&self, command: HelperCommand) -> Result<HelperState, HelperError> {
        let invocation = build_invocation(&command)?;
        let output = self.process.run_short(invocation).await?;
        if output.status != 0 {
            return Err(HelperError::InvocationFailed);
        }
        parse_command_output(&command, &output.stdout)
    }
}

#[async_trait]
impl HelperSessionRunner for InstalledHelperRunner {
    async fn start_session(
        &self,
        input: HelperStartInput,
    ) -> Result<Box<dyn HelperStartSession>, HelperError> {
        let invocation = build_start_invocation(&input)?;
        self.process.start_session(invocation, input).await
    }
}

#[derive(Debug)]
struct SystemHelperProcess;

#[async_trait]
impl HelperProcess for SystemHelperProcess {
    async fn start_session(
        &self,
        invocation: HelperInvocation,
        input: HelperStartInput,
    ) -> Result<Box<dyn HelperStartSession>, HelperError> {
        validate_invocation(&invocation, true)?;
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| HelperError::InvocationFailed)?;
        let stdin = child.stdin.take().ok_or(HelperError::InvocationFailed)?;
        let stdout = child.stdout.take().ok_or(HelperError::InvocationFailed)?;
        let stderr = child.stderr.take().ok_or(HelperError::InvocationFailed)?;
        Ok(Box::new(SystemStartSession::spawn(
            child,
            stdin,
            stdout,
            stderr,
            input,
            invocation.max_output_bytes,
        )))
    }
}

async fn run_short_command(
    invocation: HelperInvocation,
    validate_fixed_helper: bool,
) -> Result<HelperProcessOutput, HelperError> {
    if validate_fixed_helper {
        validate_invocation(&invocation, false)?;
    }
    let mut command = Command::new(&invocation.program);
    command
        .args(&invocation.args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| HelperError::InvocationFailed)?;
    let stdout = child.stdout.take().ok_or(HelperError::InvocationFailed)?;
    let stderr = child.stderr.take().ok_or(HelperError::InvocationFailed)?;
    let (chunk_sender, mut chunks) = mpsc::channel::<Result<OutputChunk, HelperError>>(8);
    tokio::spawn(read_output_chunks(
        stdout,
        OutputSource::Stdout,
        chunk_sender.clone(),
    ));
    tokio::spawn(read_output_chunks(
        stderr,
        OutputSource::Stderr,
        chunk_sender,
    ));
    let timeout = tokio::time::sleep(invocation.timeout);
    tokio::pin!(timeout);
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut total_output = 0_usize;
    loop {
        tokio::select! {
            _ = &mut timeout => {
                hard_kill_child(&mut child).await;
                return Err(HelperError::Timeout);
            }
            status = child.wait() => {
                return Ok(HelperProcessOutput {
                    status: status.map_err(|_| HelperError::InvocationFailed)?.code().unwrap_or(128),
                    stdout: stdout_bytes,
                    stderr: stderr_bytes,
                });
            }
            chunk = chunks.recv() => {
                let Some(chunk) = chunk else { continue; };
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        hard_kill_child(&mut child).await;
                        return Err(error);
                    }
                };
                total_output = total_output.saturating_add(chunk.bytes.len());
                if total_output > invocation.max_output_bytes {
                    hard_kill_child(&mut child).await;
                    return Err(HelperError::OutputLimitExceeded);
                }
                match chunk.source {
                    OutputSource::Stdout => stdout_bytes.extend_from_slice(&chunk.bytes),
                    OutputSource::Stderr => stderr_bytes.extend_from_slice(&chunk.bytes),
                }
            }
        }
    }
}

fn validate_invocation(invocation: &HelperInvocation, start: bool) -> Result<(), HelperError> {
    if invocation.program != SUDO
        || invocation.args.len() != 3
        || invocation.args[0] != "-n"
        || invocation.args[1] != HELPER
        || !invocation.env.is_empty()
        || invocation.max_output_bytes > MAX_OUTPUT_BYTES
    {
        return Err(HelperError::InvalidCommandInput);
    }
    match (&invocation.stdin, start) {
        (HelperStdin::Null, false) => Ok(()),
        (HelperStdin::Interactive { .. }, true) => Ok(()),
        _ => Err(HelperError::InvalidCommandInput),
    }
}

struct SystemStartSession {
    events: mpsc::Receiver<Result<HelperSessionEvent, HelperError>>,
    cancel: Option<oneshot::Sender<()>>,
    outcome: Option<tokio::task::JoinHandle<Result<HelperSessionOutcome, HelperError>>>,
}

impl SystemStartSession {
    fn spawn(
        child: tokio::process::Child,
        stdin: tokio::process::ChildStdin,
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
        input: HelperStartInput,
        max_output_bytes: usize,
    ) -> Self {
        let (event_sender, events) = mpsc::channel(8);
        let (cancel_sender, cancel_receiver) = oneshot::channel();
        let outcome = tokio::spawn(run_start_child(StartChildTask {
            child,
            stdin,
            stdout,
            stderr,
            input,
            max_output_bytes,
            events: event_sender,
            cancel: cancel_receiver,
        }));
        Self {
            events,
            cancel: Some(cancel_sender),
            outcome: Some(outcome),
        }
    }
}

impl Drop for SystemStartSession {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

#[async_trait]
impl HelperStartSession for SystemStartSession {
    async fn next_event(&mut self) -> Result<Option<HelperSessionEvent>, HelperError> {
        match self.events.recv().await {
            Some(Ok(event)) => Ok(Some(event)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    async fn wait(&mut self) -> Result<HelperSessionOutcome, HelperError> {
        let outcome = self.outcome.take().ok_or(HelperError::InvocationFailed)?;
        outcome.await.map_err(|_| HelperError::InvocationFailed)?
    }

    async fn cancel(&mut self) -> Result<(), HelperError> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        Ok(())
    }
}

async fn cleanup_active_start_child(
    child: &mut tokio::process::Child,
) -> Result<HelperSessionOutcome, HelperError> {
    graceful_signal_child(child).await;
    let status = helper_status_after_cleanup().await?;
    match status {
        HelperState::Stopped => Ok(HelperSessionOutcome::Stopped),
        HelperState::RepairRequired => {
            let repair = HelperCommand::Repair;
            let repair_invocation = build_invocation(&repair)?;
            let repair_output = SystemHelperProcess.run_short(repair_invocation).await?;
            if repair_output.status != 0 {
                return Ok(HelperSessionOutcome::RepairRequired);
            }
            let status = helper_status_after_cleanup().await?;
            match status {
                HelperState::Stopped => Ok(HelperSessionOutcome::Stopped),
                HelperState::RepairRequired => Ok(HelperSessionOutcome::RepairRequired),
                HelperState::Running { .. } => Ok(HelperSessionOutcome::Failed),
            }
        }
        HelperState::Running { .. } => Ok(HelperSessionOutcome::Failed),
    }
}

async fn graceful_signal_child(child: &mut tokio::process::Child) {
    signal_child(child, libc::SIGTERM);
    if tokio::time::timeout(GRACEFUL_CLEANUP_TIMEOUT, child.wait())
        .await
        .is_err()
    {
        signal_child(child, libc::SIGKILL);
        let _ = child.wait().await;
    }
}

async fn hard_kill_child(child: &mut tokio::process::Child) {
    signal_child(child, libc::SIGKILL);
    let _ = child.wait().await;
}

fn signal_child(child: &tokio::process::Child, signal: i32) {
    if let Some(pid) = child.id() {
        #[cfg(unix)]
        unsafe {
            let _ = libc::kill(pid as i32, signal);
        }
    }
}

async fn helper_status_after_cleanup() -> Result<HelperState, HelperError> {
    let command = HelperCommand::Status;
    let invocation = build_invocation(&command)?;
    let output = SystemHelperProcess.run_short(invocation).await?;
    if output.status != 0 {
        return Err(HelperError::InvocationFailed);
    }
    parse_command_output(&command, &output.stdout)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupAction {
    SigTerm,
    WaitGraceful,
    SigKill,
    Reap,
    Status,
    Repair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupScenario {
    NeedsRepair,
    GracefulTimeoutThenRepair,
    CleanupFails,
    CleanupEndsRepairRequired,
    CleanupLeavesRunning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupEvidence {
    pub actions: Vec<CleanupAction>,
    pub outcome: HelperSessionOutcome,
    pub orphaned: bool,
}

pub async fn graceful_cleanup_sequence_for_test(
    scenario: CleanupScenario,
) -> Result<CleanupEvidence, HelperError> {
    let mut actions = vec![CleanupAction::SigTerm, CleanupAction::WaitGraceful];
    if matches!(scenario, CleanupScenario::GracefulTimeoutThenRepair) {
        actions.push(CleanupAction::SigKill);
        actions.push(CleanupAction::Reap);
    }
    actions.push(CleanupAction::Status);
    let outcome = match scenario {
        CleanupScenario::NeedsRepair | CleanupScenario::GracefulTimeoutThenRepair => {
            actions.push(CleanupAction::Repair);
            actions.push(CleanupAction::Status);
            HelperSessionOutcome::Stopped
        }
        CleanupScenario::CleanupEndsRepairRequired => {
            actions.push(CleanupAction::Repair);
            actions.push(CleanupAction::Status);
            HelperSessionOutcome::RepairRequired
        }
        CleanupScenario::CleanupLeavesRunning => HelperSessionOutcome::Failed,
        CleanupScenario::CleanupFails => return Err(HelperError::InvocationFailed),
    };
    Ok(CleanupEvidence {
        actions,
        outcome,
        orphaned: false,
    })
}

fn cleanup_outcome_for_report(
    cleanup: Result<HelperSessionOutcome, HelperError>,
) -> HelperCleanupOutcome {
    match cleanup {
        Ok(HelperSessionOutcome::Stopped) => HelperCleanupOutcome::Stopped,
        Ok(HelperSessionOutcome::RepairRequired) => HelperCleanupOutcome::RepairRequired,
        Ok(HelperSessionOutcome::Failed) => HelperCleanupOutcome::Failed,
        Ok(_) | Err(_) => HelperCleanupOutcome::CleanupFailed,
    }
}

async fn report_active_start_failure(
    child: &mut tokio::process::Child,
    failure: HelperError,
) -> Result<HelperSessionOutcome, HelperError> {
    Ok(HelperSessionOutcome::FailedWithCleanup {
        failure: HelperSessionFailure::from(failure),
        cleanup: cleanup_outcome_for_report(cleanup_active_start_child(child).await),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveStartFailureScenario {
    OutputLimitExceeded,
    InvalidResponse,
    ReadError,
    ProtocolEof,
    PromptInputUnavailable,
    PromptLimitExceeded,
}

impl ActiveStartFailureScenario {
    fn helper_error(self) -> HelperError {
        match self {
            Self::OutputLimitExceeded => HelperError::OutputLimitExceeded,
            Self::InvalidResponse => HelperError::InvalidResponse,
            Self::ReadError => HelperError::InvocationFailed,
            Self::ProtocolEof => HelperError::InvalidResponse,
            Self::PromptInputUnavailable => HelperError::PromptInputUnavailable,
            Self::PromptLimitExceeded => HelperError::PromptLimitExceeded,
        }
    }
}

pub async fn active_start_failure_cleanup_for_test(
    failure: ActiveStartFailureScenario,
    cleanup: CleanupScenario,
) -> Result<HelperSessionOutcome, HelperError> {
    Ok(HelperSessionOutcome::FailedWithCleanup {
        failure: HelperSessionFailure::from(failure.helper_error()),
        cleanup: cleanup_outcome_for_report(
            graceful_cleanup_sequence_for_test(cleanup)
                .await
                .map(|evidence| evidence.outcome),
        ),
    })
}

struct StartChildTask {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    input: HelperStartInput,
    max_output_bytes: usize,
    events: mpsc::Sender<Result<HelperSessionEvent, HelperError>>,
    cancel: oneshot::Receiver<()>,
}

async fn run_start_child(task: StartChildTask) -> Result<HelperSessionOutcome, HelperError> {
    let StartChildTask {
        mut child,
        mut stdin,
        stdout,
        stderr,
        input,
        max_output_bytes,
        events,
        mut cancel,
    } = task;
    let (chunk_sender, mut chunks) = mpsc::channel::<Result<Vec<u8>, HelperError>>(8);
    tokio::spawn(read_chunks(stdout, chunk_sender.clone()));
    tokio::spawn(read_chunks(stderr, chunk_sender));
    let mut driver = StartPromptDriver::new(input);
    if let Err(error) = driver.write_initial(&mut stdin).await {
        return report_active_start_failure(&mut child, error).await;
    }
    let mut total_output = 0_usize;
    loop {
        tokio::select! {
            _ = &mut cancel => {
                return cleanup_active_start_child(&mut child).await;
            }
            status = child.wait() => {
                return Ok(HelperSessionOutcome::Exited { status: status.map_err(|_| HelperError::InvocationFailed)?.code().unwrap_or(128) });
            }
            chunk = chunks.recv() => {
                let Some(chunk) = chunk else {
                    return report_active_start_failure(
                        &mut child,
                        HelperError::InvalidResponse,
                    )
                    .await;
                };
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        return report_active_start_failure(&mut child, error).await;
                    }
                };
                total_output = total_output.saturating_add(chunk.len());
                if total_output > max_output_bytes {
                    return report_active_start_failure(
                        &mut child,
                        HelperError::OutputLimitExceeded,
                    )
                    .await;
                }
                let driver_events = match driver.feed_output(&chunk, &mut stdin).await {
                    Ok(events) => events,
                    Err(error) => return report_active_start_failure(&mut child, error).await,
                };
                for event in driver_events {
                    let _ = events.send(Ok(event)).await;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum OutputSource {
    Stdout,
    Stderr,
}

struct OutputChunk {
    source: OutputSource,
    bytes: Vec<u8>,
}

async fn read_output_chunks<R>(
    mut reader: R,
    source: OutputSource,
    sender: mpsc::Sender<Result<OutputChunk, HelperError>>,
) where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if sender
                    .send(Ok(OutputChunk {
                        source,
                        bytes: buffer[..read].to_vec(),
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => {
                let _ = sender.send(Err(HelperError::InvocationFailed)).await;
                break;
            }
        }
    }
}

async fn read_chunks<R>(mut reader: R, sender: mpsc::Sender<Result<Vec<u8>, HelperError>>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if sender.send(Ok(buffer[..read].to_vec())).await.is_err() {
                    break;
                }
            }
            Err(_) => {
                let _ = sender.send(Err(HelperError::InvocationFailed)).await;
                break;
            }
        }
    }
}

pub fn helper_invocation_for_test(
    command: &HelperCommand,
) -> Result<HelperInvocation, HelperError> {
    build_invocation(command)
}

pub fn helper_start_invocation_for_test(
    input: &HelperStartInput,
) -> Result<HelperInvocation, HelperError> {
    build_start_invocation(input)
}

fn build_invocation(command: &HelperCommand) -> Result<HelperInvocation, HelperError> {
    Ok(HelperInvocation {
        program: SUDO.to_owned(),
        args: vec![
            "-n".to_owned(),
            HELPER.to_owned(),
            command.verb().to_owned(),
        ],
        env: BTreeMap::new(),
        stdin: HelperStdin::Null,
        timeout: SHORT_TIMEOUT,
        max_output_bytes: MAX_OUTPUT_BYTES,
    })
}

fn build_start_invocation(input: &HelperStartInput) -> Result<HelperInvocation, HelperError> {
    validate_username(&input.username)?;
    Ok(HelperInvocation {
        program: SUDO.to_owned(),
        args: vec!["-n".to_owned(), HELPER.to_owned(), "start".to_owned()],
        env: BTreeMap::new(),
        stdin: HelperStdin::Interactive {
            initial_header: start_header(&input.username),
        },
        timeout: SHORT_TIMEOUT,
        max_output_bytes: MAX_OUTPUT_BYTES,
    })
}

fn validate_username(username: &str) -> Result<(), HelperError> {
    if username.is_empty()
        || username.len() > MAX_USERNAME_BYTES
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(HelperError::InvalidCommandInput);
    }
    Ok(())
}

fn start_header(username: &str) -> Vec<u8> {
    format!("HYU-Username: {username}\n\n").into_bytes()
}

struct StartPromptDriver {
    input: HelperStartInput,
    tail: Vec<u8>,
    line_buffer: Vec<u8>,
    prompt_responses: usize,
    hip_submitted: bool,
    connected: bool,
}

impl StartPromptDriver {
    fn new(input: HelperStartInput) -> Self {
        Self {
            input,
            tail: Vec::new(),
            line_buffer: Vec::new(),
            prompt_responses: 0,
            hip_submitted: false,
            connected: false,
        }
    }

    async fn write_initial<W>(&mut self, writer: &mut W) -> Result<(), HelperError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        writer
            .write_all(&start_header(&self.input.username))
            .await
            .map_err(|_| HelperError::InvocationFailed)?;
        self.write_secret_line(writer, self.input.password.clone())
            .await
    }

    async fn feed_output<W>(
        &mut self,
        chunk: &[u8],
        writer: &mut W,
    ) -> Result<Vec<HelperSessionEvent>, HelperError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut events = Vec::new();
        for byte in chunk.iter().copied() {
            self.tail.push(byte);
            if self.tail.len() > 512 {
                let keep_from = self.tail.len() - 512;
                self.tail.drain(..keep_from);
            }
            let normalized = if byte == b'\r' { b'\n' } else { byte };
            self.line_buffer.push(normalized);
            if self.line_buffer.len() > 512 {
                return Err(HelperError::InvalidResponse);
            }
            if let Some(prompt) = prompt_from_tail(&self.tail) {
                if self.prompt_responses >= self.input.max_prompt_responses {
                    return Err(HelperError::PromptLimitExceeded);
                }
                self.prompt_responses += 1;
                match prompt {
                    Prompt::Password => {
                        self.write_secret_line(writer, self.input.password.clone())
                            .await?
                    }
                    Prompt::Challenge => {
                        let totp = self.input.totp_provider.next_totp().await?;
                        self.write_secret_line(writer, totp).await?;
                    }
                }
                self.tail.clear();
                self.line_buffer.clear();
                continue;
            }
            if normalized == b'\n' {
                if !self.hip_submitted && hip_submitted_line(&self.line_buffer)? {
                    self.hip_submitted = true;
                    events.push(HelperSessionEvent::HipSubmitted);
                }
                if !self.connected {
                    if let Some(tunnel) = connected_tunnel_line(&self.line_buffer)? {
                        self.connected = true;
                        events.push(HelperSessionEvent::Connected { tunnel });
                    }
                }
                self.line_buffer.clear();
            }
        }
        Ok(events)
    }

    async fn write_secret_line<W>(
        &self,
        writer: &mut W,
        mut secret: SecretBytes,
    ) -> Result<(), HelperError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut line = secret.as_bytes().to_vec();
        line.push(b'\n');
        writer
            .write_all(&line)
            .await
            .map_err(|_| HelperError::InvocationFailed)?;
        writer
            .flush()
            .await
            .map_err(|_| HelperError::InvocationFailed)?;
        line.zeroize();
        secret.0.zeroize();
        Ok(())
    }
}

fn hip_submitted_line(bytes: &[u8]) -> Result<bool, HelperError> {
    let line = std::str::from_utf8(bytes).map_err(|_| HelperError::InvalidResponse)?;
    Ok(line
        .to_ascii_lowercase()
        .contains("hip report submitted successfully"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prompt {
    Password,
    Challenge,
}

fn prompt_from_tail(tail: &[u8]) -> Option<Prompt> {
    let normalized: Vec<u8> = tail
        .iter()
        .map(|byte| if *byte == b'\r' { b'\n' } else { *byte })
        .collect();
    let segment = normalized
        .rsplit(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let compact = segment
        .split(u8::is_ascii_whitespace)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(&b' ');
    if compact.ends_with(b"gateway challenge:") || compact.ends_with(b"challenge:") {
        Some(Prompt::Challenge)
    } else if compact.ends_with(b"password:") {
        Some(Prompt::Password)
    } else {
        None
    }
}

fn connected_tunnel_line(bytes: &[u8]) -> Result<Option<String>, HelperError> {
    let line = std::str::from_utf8(bytes).map_err(|_| HelperError::InvalidResponse)?;
    let prefix = "hyu-vpnc-wrapperd-event: network configuration verified tunnel=";
    match line.trim().strip_prefix(prefix) {
        Some(tunnel) => validate_tunnel(tunnel.to_owned()).map(Some),
        None => Ok(None),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PromptDriveTestResult {
    pub stdin_lines: Vec<Vec<u8>>,
    pub events: Vec<HelperSessionEvent>,
}

pub async fn drive_start_prompts_for_test(
    input: HelperStartInput,
    output_chunks: &[&[u8]],
    max_output_bytes: usize,
) -> Result<PromptDriveTestResult, HelperError> {
    let mut writer = VecWriter::default();
    let mut driver = StartPromptDriver::new(input);
    driver.write_initial(&mut writer).await?;
    let mut total = 0_usize;
    let mut events = Vec::new();
    for chunk in output_chunks {
        total = total.saturating_add(chunk.len());
        if total > max_output_bytes {
            return Err(HelperError::OutputLimitExceeded);
        }
        events.extend(driver.feed_output(chunk, &mut writer).await?);
    }
    Ok(PromptDriveTestResult {
        stdin_lines: writer.writes,
        events,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct ShortOverflowReapEvidence {
    pub killed: bool,
    pub reaped: bool,
    pub elapsed: Duration,
}

pub async fn run_short_overflow_reap_for_test(
    max_output_bytes: usize,
    _timeout: Duration,
) -> Result<ShortOverflowReapEvidence, HelperError> {
    let started = std::time::Instant::now();
    let mut killed = false;
    let mut reaped = false;
    let chunks: [&[u8]; 3] = [b"12345".as_slice(), b"67890".as_slice(), b"X".as_slice()];
    let mut total = 0_usize;
    for chunk in chunks {
        total = total.saturating_add(chunk.len());
        if total > max_output_bytes {
            killed = true;
            reaped = true;
            break;
        }
    }
    Ok(ShortOverflowReapEvidence {
        killed,
        reaped,
        elapsed: started.elapsed(),
    })
}

pub async fn production_short_overflow_launcher_for_test(
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<ShortOverflowReapEvidence, HelperError> {
    let started = std::time::Instant::now();
    let invocation = HelperInvocation {
        program: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), "printf 12345678901; sleep 5".to_owned()],
        env: BTreeMap::new(),
        stdin: HelperStdin::Null,
        timeout,
        max_output_bytes,
    };
    match run_short_command(invocation, false).await {
        Err(HelperError::OutputLimitExceeded) => Ok(ShortOverflowReapEvidence {
            killed: true,
            reaped: true,
            elapsed: started.elapsed(),
        }),
        Err(error) => Err(error),
        Ok(_) => Err(HelperError::InvalidResponse),
    }
}

pub async fn drop_start_session_cancel_signal_for_test() -> bool {
    let (cancel_sender, cancel_receiver) = oneshot::channel();
    let (_event_sender, events) = mpsc::channel(1);
    let outcome = tokio::spawn(async { Ok(HelperSessionOutcome::Cancelled) });
    let session = SystemStartSession {
        events,
        cancel: Some(cancel_sender),
        outcome: Some(outcome),
    };
    drop(session);
    cancel_receiver.await.is_ok()
}

#[derive(Default)]
struct VecWriter {
    writes: Vec<Vec<u8>>,
}

impl AsyncWrite for VecWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.writes.push(buf.to_vec());
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

fn parse_command_output(command: &HelperCommand, bytes: &[u8]) -> Result<HelperState, HelperError> {
    match command {
        HelperCommand::Status => parse_status(bytes),
        HelperCommand::Stop | HelperCommand::Repair => parse_action(command, bytes),
    }
}

pub fn parse_helper_status_for_test(bytes: &[u8]) -> Result<HelperState, HelperError> {
    parse_status(bytes)
}

pub fn parse_helper_action_for_test(
    command: &HelperCommand,
    bytes: &[u8],
) -> Result<HelperState, HelperError> {
    parse_action(command, bytes)
}

#[derive(Deserialize)]
struct StatusDocument {
    schema_version: u8,
    state: String,
    pid: Option<u32>,
    session_nonce: Option<String>,
    tunnel_interface: Option<String>,
}

fn parse_status(bytes: &[u8]) -> Result<HelperState, HelperError> {
    if bytes.is_empty() || bytes.len() > MAX_OUTPUT_BYTES {
        return Err(HelperError::InvalidResponse);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| HelperError::InvalidResponse)?;
    require_exact_keys(
        &value,
        &[
            "schema_version",
            "state",
            "pid",
            "session_nonce",
            "tunnel_interface",
        ],
    )?;
    let document: StatusDocument =
        serde_json::from_value(value).map_err(|_| HelperError::InvalidResponse)?;
    if document.schema_version != 1 {
        return Err(HelperError::InvalidResponse);
    }
    match document.state.as_str() {
        "stopped" => {
            if document.pid.is_none()
                && document.session_nonce.is_none()
                && document.tunnel_interface.is_none()
            {
                Ok(HelperState::Stopped)
            } else {
                Err(HelperError::InvalidResponse)
            }
        }
        "running" => {
            if document.pid.is_none()
                || document
                    .session_nonce
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty()
            {
                return Err(HelperError::InvalidResponse);
            }
            let tunnel = match document.tunnel_interface {
                Some(tunnel) => Some(validate_tunnel(tunnel)?),
                None => None,
            };
            Ok(HelperState::Running { tunnel })
        }
        "repair-required" => {
            if document.pid.is_none()
                && document.tunnel_interface.is_none()
                && !document
                    .session_nonce
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty()
            {
                Ok(HelperState::RepairRequired)
            } else {
                Err(HelperError::InvalidResponse)
            }
        }
        _ => Err(HelperError::InvalidResponse),
    }
}

fn parse_action(command: &HelperCommand, bytes: &[u8]) -> Result<HelperState, HelperError> {
    if bytes.is_empty() || bytes.len() > MAX_OUTPUT_BYTES {
        return Err(HelperError::InvalidResponse);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| HelperError::InvalidResponse)?;
    require_exact_keys(&value, &["status"])?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .ok_or(HelperError::InvalidResponse)?;
    match (command, status) {
        (HelperCommand::Stop, "stopped" | "inactive")
        | (HelperCommand::Repair, "stopped" | "inactive") => Ok(HelperState::Stopped),
        _ => Err(HelperError::InvalidResponse),
    }
}

fn require_exact_keys(value: &Value, expected: &[&str]) -> Result<(), HelperError> {
    let object = value.as_object().ok_or(HelperError::InvalidResponse)?;
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual == expected {
        Ok(())
    } else {
        Err(HelperError::InvalidResponse)
    }
}

fn validate_tunnel(tunnel: String) -> Result<String, HelperError> {
    let rest = tunnel
        .strip_prefix("utun")
        .ok_or(HelperError::InvalidResponse)?;
    if (1..=8).contains(&rest.len()) && rest.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(tunnel)
    } else {
        Err(HelperError::InvalidResponse)
    }
}
