use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hyu_vpn_core::openconnect::{ConnectorConfig, ConnectorConfigError, build_openconnect_args};
use hyu_vpn_protocol::Credentials;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    #[error("invalid OpenConnect launch configuration")]
    InvalidConfiguration,
    #[error("OpenConnect process failed")]
    ProcessFailed,
}

impl From<ConnectorConfigError> for LaunchError {
    fn from(_: ConnectorConfigError) -> Self {
        Self::InvalidConfiguration
    }
}

#[derive(Debug, Clone)]
pub struct OpenConnectLaunch {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub environment: Vec<(String, String)>,
    stdin: Zeroizing<Vec<u8>>,
}

impl OpenConnectLaunch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executable: &str,
        portal: &str,
        authgroup: &str,
        vpnc_script: &str,
        hip_wrapper: &str,
        credentials: &Credentials,
        otp: &str,
    ) -> Result<Self, LaunchError> {
        if otp.len() != 6 || !otp.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(LaunchError::InvalidConfiguration);
        }
        let config = ConnectorConfig {
            executable: executable.into(),
            portal: portal.to_owned(),
            authgroup: authgroup.to_owned(),
            vpnc_script: vpnc_script.into(),
            hip_wrapper: hip_wrapper.into(),
        };
        let argv = build_openconnect_args(&config)?;
        let stdin = Zeroizing::new(
            format!(
                "{}\n{}\n{}\n",
                credentials.username(),
                credentials.password(),
                otp
            )
            .into_bytes(),
        );
        Ok(Self {
            executable: config.executable,
            argv,
            environment: Vec::new(),
            stdin,
        })
    }

    pub fn production() -> Result<Self, LaunchError> {
        let config = ConnectorConfig {
            executable: "/usr/lib/hyu-vpn/runtime/openconnect".into(),
            portal: "secure.hanyang.ac.kr".to_owned(),
            authgroup: "HYU-ExternalGW-General".to_owned(),
            vpnc_script: "/usr/lib/hyu-vpn/hyu-vpnc-script".into(),
            hip_wrapper: "/usr/lib/hyu-vpn/hyu-vpn-hip".into(),
        };
        Ok(Self {
            executable: config.executable.clone(),
            argv: build_openconnect_args(&config)?,
            environment: Vec::new(),
            stdin: Zeroizing::new(Vec::new()),
        })
    }

    pub fn from_parts(executable: &str, argv: Vec<String>) -> Result<Self, LaunchError> {
        if !valid_executable(executable)
            || argv.iter().any(|value| value.chars().any(char::is_control))
        {
            return Err(LaunchError::InvalidConfiguration);
        }
        Ok(Self {
            executable: executable.into(),
            argv,
            environment: Vec::new(),
            stdin: Zeroizing::new(Vec::new()),
        })
    }

    pub fn stdin_payload(&self) -> &[u8] {
        self.stdin.as_slice()
    }
}

#[async_trait]
pub trait ChallengeCodeProvider: Send + Sync {
    async fn next_code(&self) -> Result<Zeroizing<String>, LaunchError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractiveOutcome {
    pub return_code: i32,
    pub runtime_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    Username,
    Password,
    Challenge,
}

#[derive(Default)]
struct PromptDetector {
    tail: Vec<u8>,
}

impl PromptDetector {
    fn feed(&mut self, chunk: &[u8]) -> Option<PromptKind> {
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
}

pub async fn run_interactive_openconnect<P>(
    launch: OpenConnectLaunch,
    credentials: &Credentials,
    codes: &P,
    mut stop: watch::Receiver<bool>,
) -> Result<InteractiveOutcome, LaunchError>
where
    P: ChallengeCodeProvider,
{
    if !valid_executable(launch.executable.to_string_lossy().as_ref()) {
        return Err(LaunchError::InvalidConfiguration);
    }
    let mut command = tokio::process::Command::new(&launch.executable);
    command
        .args(&launch.argv)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in &launch.environment {
        command.env(key, value);
    }
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| LaunchError::ProcessFailed)?;
    eprintln!("hyu-vpn-connect-stage: child-started");
    let pid = child.id().ok_or(LaunchError::ProcessFailed)?;
    let mut stdin = child.stdin.take().ok_or(LaunchError::ProcessFailed)?;
    write_line(&mut stdin, credentials.password().as_bytes()).await?;
    eprintln!("hyu-vpn-connect-stage: initial-password-sent");

    let stdout = child.stdout.take().ok_or(LaunchError::ProcessFailed)?;
    let stderr = child.stderr.take().ok_or(LaunchError::ProcessFailed)?;
    let (output_tx, mut output_rx) = mpsc::channel::<(usize, Vec<u8>)>(16);
    tokio::spawn(pump_output(0, stdout, output_tx.clone()));
    tokio::spawn(pump_output(1, stderr, output_tx));
    let mut detectors = [PromptDetector::default(), PromptDetector::default()];
    let mut progress_tail = Vec::new();
    let mut progress_emitted = HashSet::new();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| LaunchError::ProcessFailed)? {
            break status;
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    terminate_group(pid, libc::SIGTERM);
                    let status = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                        Ok(Ok(status)) => status,
                        _ => {
                            terminate_group(pid, libc::SIGKILL);
                            child.wait().await.map_err(|_| LaunchError::ProcessFailed)?
                        }
                    };
                    break status;
                }
            }
            output = output_rx.recv() => {
                if let Some((source, chunk)) = output {
                    emit_progress_stages(&chunk, &mut progress_tail, &mut progress_emitted);
                    if let Some(prompt) = detectors[source].feed(&chunk) {
                        match prompt {
                            PromptKind::Username => {
                                eprintln!("hyu-vpn-connect-stage: username-prompt");
                                write_line(&mut stdin, credentials.username().as_bytes()).await?;
                            }
                            PromptKind::Password => {
                                eprintln!("hyu-vpn-connect-stage: password-prompt");
                                write_line(&mut stdin, credentials.password().as_bytes()).await?;
                            }
                            PromptKind::Challenge => {
                                eprintln!("hyu-vpn-connect-stage: challenge-prompt");
                                let code = codes.next_code().await?;
                                write_line(&mut stdin, code.as_bytes()).await?;
                                eprintln!("hyu-vpn-connect-stage: challenge-sent");
                            }
                        }
                    }
                }
            }
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    };
    let return_code = status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(1, |signal| 128 + signal)
        }
        #[cfg(not(unix))]
        {
            1
        }
    });
    eprintln!("hyu-vpn-connect-stage: child-exited-{return_code}");
    Ok(InteractiveOutcome {
        return_code,
        runtime_seconds: started.elapsed().as_secs(),
    })
}

fn emit_progress_stages(chunk: &[u8], tail: &mut Vec<u8>, emitted: &mut HashSet<&'static str>) {
    tail.extend_from_slice(chunk);
    if tail.len() > 4096 {
        tail.drain(..tail.len() - 4096);
    }
    let lower = String::from_utf8_lossy(tail).to_ascii_lowercase();
    const STAGES: [(&str, &str); 14] = [
        ("connected to https", "https-connected"),
        ("enter login credentials", "portal-login-form"),
        ("globalprotect login returned", "login-response-received"),
        ("please select globalprotect gateway", "gateway-selection"),
        ("authentication failure", "authentication-failure"),
        (
            "failed to complete authentication",
            "authentication-incomplete",
        ),
        ("incorrect device id or password", "credential-rejected"),
        ("unexpected 512", "server-auth-rejected"),
        ("invalid authentication cookie", "invalid-auth-cookie"),
        ("hip script", "hip-script-invoked"),
        ("hip report submitted successfully", "hip-submitted"),
        ("hip report submission failed", "hip-submission-failed"),
        ("gateway disconnected immediately", "gateway-disconnected"),
        ("fgets (stdin)", "stdin-read-failed"),
    ];
    for (needle, stage) in STAGES {
        if lower.contains(needle) && emitted.insert(stage) {
            eprintln!("hyu-vpn-connect-stage: {stage}");
        }
    }
}

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

async fn write_line(
    stdin: &mut tokio::process::ChildStdin,
    value: &[u8],
) -> Result<(), LaunchError> {
    if value.is_empty() || value.len() > 4096 || value.contains(&b'\n') || value.contains(&b'\r') {
        return Err(LaunchError::InvalidConfiguration);
    }
    stdin
        .write_all(value)
        .await
        .map_err(|_| LaunchError::ProcessFailed)?;
    stdin
        .write_all(b"\n")
        .await
        .map_err(|_| LaunchError::ProcessFailed)?;
    stdin.flush().await.map_err(|_| LaunchError::ProcessFailed)
}

fn terminate_group(pid: u32, signal: i32) {
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}

fn valid_executable(executable: &str) -> bool {
    executable.starts_with('/') && !executable.chars().any(char::is_control)
}

pub struct ManagedChild {
    child: tokio::process::Child,
    pid: u32,
}

impl ManagedChild {
    pub async fn spawn(
        executable: &str,
        argv: &[&str],
        stdin_payload: &[u8],
    ) -> Result<Self, LaunchError> {
        if !valid_executable(executable) {
            return Err(LaunchError::InvalidConfiguration);
        }
        let mut command = tokio::process::Command::new(executable);
        command
            .args(argv)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| LaunchError::ProcessFailed)?;
        let pid = child.id().ok_or(LaunchError::ProcessFailed)?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_payload)
                .await
                .map_err(|_| LaunchError::ProcessFailed)?;
            stdin
                .shutdown()
                .await
                .map_err(|_| LaunchError::ProcessFailed)?;
        }
        Ok(Self { child, pid })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub async fn terminate(mut self, timeout: Duration) -> Result<(), LaunchError> {
        terminate_group(self.pid, libc::SIGTERM);
        if tokio::time::timeout(timeout, self.child.wait())
            .await
            .is_err()
        {
            terminate_group(self.pid, libc::SIGKILL);
            self.child
                .wait()
                .await
                .map_err(|_| LaunchError::ProcessFailed)?;
        }
        Ok(())
    }
}
