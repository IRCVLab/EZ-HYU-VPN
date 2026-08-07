use std::sync::{Mutex, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use hyu_vpn_core::state::{Engine, EngineAction, EngineEvent};
use hyu_vpn_core::totp::{TotpGenerator, TotpSecret};
use hyu_vpn_protocol::{
    Credentials, ErrorCode, Request, RequestEnvelope, Response, ResponseEnvelope, VpnState,
    VpnStatus,
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

use crate::ipc::RequestHandler;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryError {
    #[error("credentials are missing")]
    Missing,
    #[error("credential data is corrupt")]
    Corrupt,
    #[error("credential storage failed")]
    Storage,
}

pub trait CredentialRepository: Send + Sync {
    fn present(&self) -> Result<bool, RepositoryError>;
    fn load(&self) -> Result<Credentials, RepositoryError>;
    fn replace(&self, credentials: Credentials) -> Result<(), RepositoryError>;
}

pub trait SystemClock: Send + Sync {
    fn now(&self) -> SystemTime;
}

#[async_trait]
pub trait ActionExecutor: Send + Sync {
    async fn execute(&self, action: EngineAction) -> Option<EngineEvent>;
}

pub struct DaemonRuntime<R, C, E> {
    control_plane: std::sync::Arc<ControlPlane<R, C>>,
    actions: mpsc::UnboundedReceiver<EngineAction>,
    executor: std::sync::Arc<E>,
}

impl<R, C, E> DaemonRuntime<R, C, E>
where
    R: CredentialRepository + 'static,
    C: SystemClock + 'static,
    E: ActionExecutor + 'static,
{
    pub fn new(
        control_plane: std::sync::Arc<ControlPlane<R, C>>,
        actions: mpsc::UnboundedReceiver<EngineAction>,
        executor: std::sync::Arc<E>,
    ) -> Self {
        Self {
            control_plane,
            actions,
            executor,
        }
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                action = self.actions.recv() => {
                    let Some(action) = action else { break; };
                    if let Some(event) = self.executor.execute(action).await {
                        self.control_plane.apply_event(event);
                    }
                }
            }
        }
    }
}

pub struct ControlPlane<R, C> {
    engine: Mutex<Engine>,
    status: RwLock<VpnStatus>,
    credentials: R,
    clock: C,
    action_tx: mpsc::UnboundedSender<EngineAction>,
}

impl<R, C> ControlPlane<R, C>
where
    R: CredentialRepository,
    C: SystemClock,
{
    pub fn new(
        automatic_reconnect_enabled: bool,
        credentials: R,
        clock: C,
    ) -> (Self, mpsc::UnboundedReceiver<EngineAction>) {
        let engine = Engine::new(automatic_reconnect_enabled);
        let status = VpnStatus {
            schema_version: hyu_vpn_protocol::PROTOCOL_VERSION,
            state: engine.state(),
            automatic_reconnect_enabled,
            connected_at: None,
            session_expires_at: None,
            last_successful_hip_at: None,
            tunnel_interface: None,
            next_retry_at: None,
            error_code: None,
            last_transition_at: format_system_time(clock.now()),
            backend_build_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        };
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        (
            Self {
                engine: Mutex::new(engine),
                status: RwLock::new(status),
                credentials,
                clock,
                action_tx,
            },
            action_rx,
        )
    }

    pub fn status(&self) -> VpnStatus {
        self.status.read().expect("status lock poisoned").clone()
    }

    pub fn apply_event(&self, event: EngineEvent) {
        let actions = self
            .engine
            .lock()
            .expect("engine lock poisoned")
            .handle(event);
        self.publish_actions(actions);
    }

    pub fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope {
        let request_id = request.request_id;
        let response = match request.request {
            Request::Status => Response::Status {
                status: self.status(),
            },
            Request::Connect | Request::AutomaticOn => {
                self.apply_event(EngineEvent::ConnectRequested);
                Response::Ack
            }
            Request::Disconnect | Request::AutomaticOff => {
                self.apply_event(EngineEvent::DisconnectRequested);
                Response::Ack
            }
            Request::Reconnect => {
                self.apply_event(EngineEvent::ReconnectRequested);
                Response::Ack
            }
            Request::CredentialsPresent => match self.credentials.present() {
                Ok(present) => Response::CredentialsPresent { present },
                Err(_) => Response::Error {
                    error_code: ErrorCode::CredentialStoreFailure,
                },
            },
            Request::ReplaceCredentials { credentials } => {
                match self.credentials.replace(credentials) {
                    Ok(()) => Response::Ack,
                    Err(_) => Response::Error {
                        error_code: ErrorCode::CredentialStoreFailure,
                    },
                }
            }
            Request::CurrentOtp => self.current_otp_response(),
        };
        ResponseEnvelope::new(request_id, response)
    }

    fn current_otp_response(&self) -> Response {
        let credentials = match self.credentials.load() {
            Ok(credentials) => credentials,
            Err(_) => {
                return Response::Error {
                    error_code: ErrorCode::CredentialStoreFailure,
                };
            }
        };
        let secret = match TotpSecret::parse(credentials.totp_seed()) {
            Ok(secret) => secret,
            Err(_) => {
                return Response::Error {
                    error_code: ErrorCode::CredentialStoreFailure,
                };
            }
        };
        match TotpGenerator::new(secret).code_at(self.clock.now()) {
            Ok(otp) => Response::CurrentOtp {
                code: otp.value,
                remaining_seconds: otp.remaining_seconds,
            },
            Err(_) => Response::Error {
                error_code: ErrorCode::CredentialStoreFailure,
            },
        }
    }

    fn publish_actions(&self, actions: Vec<EngineAction>) {
        for action in actions {
            if let EngineAction::PublishState(state) = action {
                self.update_status_state(state);
            } else if let EngineAction::PersistAutomaticReconnect(enabled) = action {
                self.status
                    .write()
                    .expect("status lock poisoned")
                    .automatic_reconnect_enabled = enabled;
            }
            let _ = self.action_tx.send(action);
        }
    }

    fn update_status_state(&self, state: VpnState) {
        let mut status = self.status.write().expect("status lock poisoned");
        status.state = state;
        status.last_transition_at = format_system_time(self.clock.now());
        if matches!(
            state,
            VpnState::Disabled | VpnState::Connecting | VpnState::Backoff | VpnState::Error
        ) {
            status.connected_at = None;
            status.session_expires_at = None;
            status.last_successful_hip_at = None;
            status.tunnel_interface = None;
        }
        if state != VpnState::Backoff {
            status.next_retry_at = None;
        }
        if state != VpnState::Error {
            status.error_code = None;
        }
    }
}

#[async_trait]
impl<R, C> RequestHandler for ControlPlane<R, C>
where
    R: CredentialRepository + 'static,
    C: SystemClock + 'static,
{
    async fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope {
        ControlPlane::handle(self, request)
    }
}

fn format_system_time(value: SystemTime) -> String {
    let datetime = time::OffsetDateTime::from(value);
    datetime
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}
