use std::sync::Arc;
use std::time::Duration;

use hyu_vpn_daemon::runtime::{ControlPlane, DaemonRuntime};
use hyu_vpn_daemon::status_file::AtomicStatusFile;
use hyu_vpn_linux_service::{
    AutomaticPreference, LinuxActionExecutor, RealClock, bind_owner_socket, read_owner_uid,
    run_network_watch, serve_owner_socket,
};
use hyu_vpn_platform_linux::{
    LinuxCredentialRepository, LinuxPaths, LinuxPortalProbe, LinuxRouteMonitor, OpenConnectLaunch,
};
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("HYU VPN service failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--smoke-test")
    {
        OpenConnectLaunch::production()?;
        println!("HYU VPN Linux service smoke test passed");
        return Ok(());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("service must run as root".into());
    }
    let paths = LinuxPaths::production();
    let owner_uid = read_owner_uid("/etc/hyu-vpn/owner.uid")?;
    let credentials = Arc::new(LinuxCredentialRepository::new(paths.clone(), 0));
    let preference = AutomaticPreference::new(paths.state_dir.join("automatic-reconnect"));
    let automatic = preference.load()?;
    let (control, actions) = ControlPlane::new(automatic, credentials.clone(), RealClock);
    let control = Arc::new(control);
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let executor = Arc::new(LinuxActionExecutor::new(
        credentials,
        preference,
        OpenConnectLaunch::production()?,
        paths.state_dir.join("totp-counter.json"),
        event_tx,
    ));
    let runtime = DaemonRuntime::new_with_events(
        Arc::clone(&control),
        actions,
        event_rx,
        Arc::clone(&executor),
    );
    let listener = bind_owner_socket(&paths.runtime_dir, &paths.socket, owner_uid)?;
    let status_path = paths.runtime_dir.join("status.json");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime_task = tokio::spawn(runtime.run(shutdown_rx.clone()));
    let network_task = tokio::spawn(run_network_watch(
        Arc::clone(&control),
        LinuxRouteMonitor::production(),
        LinuxPortalProbe::production(),
        shutdown_rx.clone(),
    ));
    let socket_task = tokio::spawn(serve_owner_socket(
        listener,
        owner_uid,
        Arc::clone(&control),
        shutdown_rx.clone(),
    ));
    let status_task = tokio::spawn({
        let control = Arc::clone(&control);
        let mut shutdown = shutdown_rx.clone();
        async move {
            let file = AtomicStatusFile::new(status_path);
            loop {
                let _ = file.write(&control.status());
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { return; }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    });

    wait_for_shutdown().await?;
    executor.stop_all();
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(7), runtime_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), network_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), socket_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), status_task).await;
    let _ = std::fs::remove_file(paths.socket);
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
    Ok(())
}
