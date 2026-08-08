use std::path::{Path, PathBuf};
use std::time::Duration;

use hyu_vpn_gtk::{AutostartManager, MenuModel, UnixIpcClient};
use hyu_vpn_protocol::{ErrorCode, Request, Response, VpnState, VpnStatus};
use ksni::TrayMethods;

const SOCKET: &str = "/run/hyu-vpn/daemon.sock";
const EXECUTABLE: &str = "/usr/bin/hyu-vpn";

#[derive(Debug)]
struct TrayApp {
    socket: PathBuf,
    model: MenuModel,
    otp: Option<String>,
}

impl ksni::Tray for TrayApp {
    fn id(&self) -> String {
        "com.hyu.vpn".into()
    }

    fn title(&self) -> String {
        format!("HYU VPN — {}", self.model.status_label)
    }

    fn icon_name(&self) -> String {
        "hyu-vpn".into()
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::{CheckmarkItem, MenuItem, StandardItem};
        let mut items: Vec<MenuItem<Self>> = vec![
            StandardItem {
                label: self.model.status_label.clone(),
                enabled: false,
                ..Default::default()
            }
            .into(),
        ];
        if let Some(label) = &self.model.otp_label {
            items.push(
                StandardItem {
                    label: label.clone(),
                    enabled: self.otp.is_some(),
                    activate: Box::new(|this: &mut TrayApp| {
                        if let Some(code) = this.otp.as_deref() {
                            copy_otp(code);
                        }
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
        items.extend([
            MenuItem::Separator,
            StandardItem {
                label: "Connect".into(),
                enabled: self.model.connect_enabled,
                activate: Box::new(|this: &mut TrayApp| this.send(Request::Connect)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Disconnect".into(),
                enabled: self.model.disconnect_enabled,
                activate: Box::new(|this: &mut TrayApp| this.send(Request::Disconnect)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Reconnect".into(),
                enabled: self.model.reconnect_enabled,
                activate: Box::new(|this: &mut TrayApp| this.send(Request::Reconnect)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            CheckmarkItem {
                label: "Launch at Login".into(),
                checked: self.model.launch_at_login,
                activate: Box::new(|this: &mut TrayApp| {
                    let target = !this.model.launch_at_login;
                    if autostart_manager().set_enabled(target).is_ok() {
                        this.model.launch_at_login = target;
                    }
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Change Credentials…".into(),
                activate: Box::new(|this: &mut TrayApp| show_credentials_window(&this.socket)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit HYU VPN".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]);
        items
    }
}

impl TrayApp {
    fn send(&self, request: Request) {
        let socket = self.socket.clone();
        tokio::spawn(async move {
            let _ = UnixIpcClient::new(socket).request(request).await;
        });
    }
}

fn autostart_manager() -> AutostartManager {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    AutostartManager::new(home.join(".config/autostart/hyu-vpn.desktop"), EXECUTABLE)
}

fn fallback_status() -> VpnStatus {
    VpnStatus {
        schema_version: 1,
        state: VpnState::Error,
        automatic_reconnect_enabled: false,
        connected_at: None,
        session_expires_at: None,
        last_successful_hip_at: None,
        tunnel_interface: None,
        next_retry_at: None,
        error_code: Some(ErrorCode::ServiceUnavailable),
        last_transition_at: "1970-01-01T00:00:00Z".into(),
        backend_build_version: None,
    }
}

async fn refresh(socket: &Path) -> (VpnStatus, Option<(String, u8)>) {
    let client = UnixIpcClient::new(socket);
    let status = match client.request(Request::Status).await {
        Ok(Response::Status { status }) => status,
        _ => fallback_status(),
    };
    let otp = match client.request(Request::CurrentOtp).await {
        Ok(Response::CurrentOtp {
            code,
            remaining_seconds,
        }) => Some((code, remaining_seconds)),
        _ => None,
    };
    (status, otp)
}

#[cfg(feature = "gtk-ui")]
fn copy_otp(code: &str) {
    use gtk4::prelude::*;
    if let Some(display) = gtk4::gdk::Display::default() {
        display.clipboard().set_text(code);
    }
}

#[cfg(not(feature = "gtk-ui"))]
fn copy_otp(_code: &str) {}

#[cfg(feature = "gtk-ui")]
fn show_credentials_window(socket: &Path) {
    use gtk4::prelude::*;
    use gtk4::{Button, Entry, Grid, Label, Window};
    use hyu_vpn_gtk::CredentialForm;

    let window = Window::builder()
        .title("HYU VPN Credentials")
        .default_width(520)
        .default_height(330)
        .build();
    let grid = Grid::builder()
        .margin_top(20)
        .margin_bottom(20)
        .margin_start(20)
        .margin_end(20)
        .row_spacing(10)
        .column_spacing(12)
        .build();
    let username = Entry::new();
    let password = Entry::new();
    let password_confirmation = Entry::new();
    let totp_seed = Entry::new();
    let totp_seed_confirmation = Entry::new();
    for entry in [
        &password,
        &password_confirmation,
        &totp_seed,
        &totp_seed_confirmation,
    ] {
        entry.set_visibility(false);
    }
    let rows = [
        ("HYU ID", &username),
        ("Password", &password),
        ("Confirm password", &password_confirmation),
        ("TOTP setup secret", &totp_seed),
        ("Confirm TOTP secret", &totp_seed_confirmation),
    ];
    for (row, (label, entry)) in rows.into_iter().enumerate() {
        grid.attach(&Label::new(Some(label)), 0, row as i32, 1, 1);
        grid.attach(entry, 1, row as i32, 1, 1);
    }
    let error = Label::new(None);
    grid.attach(&error, 0, 5, 2, 1);
    let save = Button::with_label("Save");
    let cancel = Button::with_label("Cancel");
    grid.attach(&cancel, 0, 6, 1, 1);
    grid.attach(&save, 1, 6, 1, 1);
    window.set_child(Some(&grid));
    let closing = window.clone();
    cancel.connect_clicked(move |_| closing.close());
    let target = socket.to_path_buf();
    let saving_window = window.clone();
    save.connect_clicked(move |_| {
        let form = CredentialForm {
            username: username.text().into(),
            password: password.text().into(),
            password_confirmation: password_confirmation.text().into(),
            totp_seed: totp_seed.text().into(),
            totp_seed_confirmation: totp_seed_confirmation.text().into(),
        };
        match form.validate() {
            Ok(credentials) => {
                let target = target.clone();
                let window = saving_window.clone();
                gtk4::glib::MainContext::default().spawn_local(async move {
                    if UnixIpcClient::new(target)
                        .request(Request::ReplaceCredentials { credentials })
                        .await
                        .is_ok()
                    {
                        window.close();
                    }
                });
            }
            Err(problem) => error.set_text(&problem.to_string()),
        }
    });
    window.present();
}

#[cfg(not(feature = "gtk-ui"))]
fn show_credentials_window(_socket: &Path) {}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    #[cfg(feature = "gtk-ui")]
    let gtk_ready = gtk4::init().is_ok();
    #[cfg(not(feature = "gtk-ui"))]
    let gtk_ready = false;

    if std::env::args().any(|argument| argument == "--smoke-test") {
        if cfg!(feature = "gtk-ui") && !gtk_ready {
            std::process::exit(2);
        }
        println!("HYU VPN tray smoke test passed");
        return;
    }

    let socket = PathBuf::from(SOCKET);
    let (status, otp) = refresh(&socket).await;
    let launch = autostart_manager().is_enabled().unwrap_or(false);
    let model = MenuModel::project(
        &status,
        otp.as_ref()
            .map(|(code, seconds)| (code.as_str(), *seconds)),
        launch,
    );
    let tray = TrayApp {
        socket: socket.clone(),
        model,
        otp: otp.map(|(code, _)| code),
    };
    let handle = tray.spawn().await.expect("status notifier unavailable");
    let polling_socket = socket.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let (status, otp) = refresh(&polling_socket).await;
            let launch = autostart_manager().is_enabled().unwrap_or(false);
            handle
                .update(move |tray| {
                    tray.model = MenuModel::project(
                        &status,
                        otp.as_ref()
                            .map(|(code, seconds)| (code.as_str(), *seconds)),
                        launch,
                    );
                    tray.otp = otp.map(|(code, _)| code);
                })
                .await;
        }
    });

    loop {
        #[cfg(feature = "gtk-ui")]
        if gtk_ready {
            let context = gtk4::glib::MainContext::default();
            while context.pending() {
                context.iteration(false);
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
