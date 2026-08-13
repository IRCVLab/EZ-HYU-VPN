mod helper;
mod network;
mod paths;
mod storage;

pub use network::{
    InterfaceConnector, InterfaceScopedResolver, MacNetworkMonitor, MacPortalProbe, ResumeNotifier,
    SocketBindParameters, parse_default_route, socket_bind_parameters_for_test,
};
pub use paths::{MacPaths, PlatformError};
pub use storage::MacCredentialRepository;

pub use helper::{
    ActiveStartFailureScenario, CleanupAction, CleanupEvidence, CleanupScenario,
    HelperCleanupOutcome, HelperCommand, HelperError, HelperInvocation, HelperProcess,
    HelperProcessOutput, HelperRunner, HelperSessionEvent, HelperSessionFailure,
    HelperSessionOutcome, HelperSessionRunner, HelperStartInput, HelperStartSession, HelperState,
    HelperStdin, HelperTotpProvider, InstalledHelperRunner, SecretBytes, ShortOverflowReapEvidence,
    active_start_failure_cleanup_for_test, drive_start_prompts_for_test,
    drop_start_session_cancel_signal_for_test, graceful_cleanup_sequence_for_test,
    helper_invocation_for_test, helper_start_invocation_for_test, parse_helper_action_for_test,
    parse_helper_status_for_test, production_short_overflow_launcher_for_test,
    run_short_overflow_reap_for_test,
};
