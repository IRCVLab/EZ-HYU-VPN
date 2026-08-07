mod network;
mod paths;
mod peer;
mod posture;
mod process;
mod storage;

pub use network::{
    NetworkSnapshot, WindowsNetworkMonitor, WindowsPortalProbe, active_vpn_interface,
};
pub use paths::WindowsPaths;
pub use peer::{PeerAuthorizationError, authorize_pipe_client_sid};
#[cfg(windows)]
pub use peer::{authorize_active_pipe_client, authorize_pipe_server_system};
pub use process::{
    ChallengeCodeProvider, HiddenProcessSpec, InteractiveOutcome, JobChild, ProcessSpecError,
    PromptDetector, PromptKind, run_interactive_openconnect,
};
pub use storage::{
    DPAPI_DOCUMENT_VERSION, DpapiMachineProtector, KeyProtectionError, KeyProtector,
    PRIVATE_STATE_SDDL, ProtectedKeyDocument, ProtectedKeyError, WindowsCredentialRepository,
};

pub use posture::{
    WindowsEvidence, WindowsHipContext, WindowsPosture, WindowsPostureCollector,
    WindowsPostureError,
};
