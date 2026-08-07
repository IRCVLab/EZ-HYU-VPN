#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() -> Result<(), windows_service::Error> {
    if std::env::args().any(|argument| argument == "--smoke-test") {
        return Ok(());
    }
    windows_service::service_dispatcher::start(
        hyu_vpn_windows_service::SERVICE_NAME,
        ffi_service_main,
    )
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    let _ = run_service();
}

#[cfg(windows)]
fn run_service() -> Result<(), windows_service::Error> {
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let status_handle =
        service_control_handler::register(hyu_vpn_windows_service::SERVICE_NAME, move |control| {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        })?;
    let status = |state, accepted, exit_code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
    ))?;
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return status_handle.set_service_status(status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(1),
            ));
        }
    };
    status_handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    ))?;
    let result = runtime.block_on(hyu_vpn_windows_service::run_daemon(shutdown_rx));
    status_handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        if result.is_ok() {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(1)
        },
    ))
}

#[cfg(not(windows))]
fn main() {
    if std::env::args().any(|argument| argument == "--smoke-test") {
        println!("HYU VPN Windows service model smoke test passed");
        return;
    }
    eprintln!("HYU VPN Windows service is only available on Windows");
    std::process::exit(2);
}
