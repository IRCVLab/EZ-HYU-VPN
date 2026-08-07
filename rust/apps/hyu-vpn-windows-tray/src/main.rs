#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod windows_app {
    use std::cell::RefCell;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    use hyu_vpn_protocol::{Request, Response, VpnStatus};
    use hyu_vpn_windows_tray::{CredentialForm, MenuModel, WindowsAutostart, WindowsPipeClient};
    use windows_sys::Win32::Foundation::{
        GlobalFree, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
    };
    use windows_sys::Win32::Graphics::Gdi::{DEFAULT_GUI_FONT, GetStockObject};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
        Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreatePopupMenu,
        CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW,
        ES_AUTOHSCROLL, ES_PASSWORD, GWLP_USERDATA, GetCursorPos, GetMessageW, GetWindowLongPtrW,
        GetWindowTextLengthW, GetWindowTextW, HICON, HWND_MESSAGE, IDC_ARROW, IDI_APPLICATION,
        IMAGE_ICON, IsDialogMessageW, KillTimer, LR_LOADFROMFILE, LoadCursorW, LoadIconW,
        LoadImageW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MF_CHECKED, MF_DISABLED, MF_GRAYED,
        MF_SEPARATOR, MF_STRING, MSG, MessageBoxW, PostQuitMessage, RegisterClassW, SW_SHOW,
        SendMessageW, SetForegroundWindow, SetTimer, SetWindowLongPtrW, SetWindowTextW, ShowWindow,
        TPM_NONOTIFY, TPM_RETURNCMD, TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE,
        WM_COMMAND, WM_CREATE, WM_DESTROY, WM_LBUTTONUP, WM_NCCREATE, WM_NCDESTROY, WM_RBUTTONUP,
        WM_SETFONT, WM_TIMER, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE,
        WS_EX_DLGMODALFRAME, WS_OVERLAPPEDWINDOW, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
    };

    const WM_TRAY: u32 = WM_APP + 1;
    const TIMER_ID: usize = 1;
    const ICON_ID: u32 = 1;
    const CMD_CONNECT: usize = 1001;
    const CMD_DISCONNECT: usize = 1002;
    const CMD_RECONNECT: usize = 1003;
    const CMD_COPY_OTP: usize = 1004;
    const CMD_CREDENTIALS: usize = 1005;
    const CMD_AUTOSTART: usize = 1006;
    const CMD_QUIT: usize = 1007;
    const FIELD_USERNAME: i32 = 1101;
    const FIELD_PASSWORD: i32 = 1102;
    const FIELD_TOTP: i32 = 1103;
    const BUTTON_SAVE: usize = 1104;
    const BUTTON_CANCEL: usize = 1105;
    const CF_UNICODETEXT: u32 = 13;

    struct AppState {
        hwnd: HWND,
        icon: HICON,
        client: WindowsPipeClient,
        autostart: Option<WindowsAutostart>,
        status: Option<VpnStatus>,
        otp: Option<(String, u8)>,
        dialog: HWND,
    }

    thread_local! {
        static APP: RefCell<Option<AppState>> = const { RefCell::new(None) };
    }

    struct DialogState {
        owner: HWND,
        username: HWND,
        password: HWND,
        totp: HWND,
    }

    impl DialogState {
        fn new(owner: HWND) -> Self {
            Self {
                owner,
                username: null_mut(),
                password: null_mut(),
                totp: null_mut(),
            }
        }
    }

    pub fn run() -> Result<(), ()> {
        let instance = unsafe { GetModuleHandleW(null()) };
        if instance.is_null() {
            return Err(());
        }
        let tray_class = wide("HYUVPNTrayWindow");
        let dialog_class = wide("HYUVPNCredentialWindow");
        if !register_class(instance, &tray_class, Some(tray_window_proc))
            || !register_class(instance, &dialog_class, Some(dialog_window_proc))
        {
            return Err(());
        }
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                tray_class.as_ptr(),
                wide("HYU VPN").as_ptr(),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                0,
                0,
                HWND_MESSAGE,
                null_mut(),
                instance,
                null(),
            )
        };
        if hwnd.is_null() {
            return Err(());
        }
        let icon = load_app_icon(instance);
        APP.with(|cell| {
            *cell.borrow_mut() = Some(AppState {
                hwnd,
                icon,
                client: WindowsPipeClient::production(),
                autostart: WindowsAutostart::production().ok(),
                status: None,
                otp: None,
                dialog: null_mut(),
            });
        });
        if !notify_icon(NIM_ADD, "HYU VPN") {
            unsafe { DestroyWindow(hwnd) };
            return Err(());
        }
        unsafe { SetTimer(hwnd, TIMER_ID, 1000, None) };
        refresh();
        let mut message = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if result <= 0 {
                break;
            }
            let dialog = APP.with(|cell| {
                cell.borrow()
                    .as_ref()
                    .map(|state| state.dialog)
                    .unwrap_or(null_mut())
            });
            if !dialog.is_null() && unsafe { IsDialogMessageW(dialog, &message) } != 0 {
                continue;
            }
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        Ok(())
    }

    fn register_class(
        instance: HINSTANCE,
        class_name: &[u16],
        procedure: Option<unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT>,
    ) -> bool {
        let class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: procedure,
            hInstance: instance,
            hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
            lpszClassName: class_name.as_ptr(),
            ..Default::default()
        };
        unsafe { RegisterClassW(&class) != 0 }
    }

    unsafe extern "system" fn tray_window_proc(
        hwnd: HWND,
        message: u32,
        _wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            WM_TRAY => {
                let event = lparam as u32;
                if event == WM_RBUTTONUP || event == WM_LBUTTONUP {
                    show_menu(hwnd);
                }
                0
            }
            WM_TIMER => {
                refresh();
                0
            }
            WM_DESTROY => {
                let _ = notify_icon(NIM_DELETE, "");
                unsafe { KillTimer(hwnd, TIMER_ID) };
                unsafe { PostQuitMessage(0) };
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, message, 0, lparam) },
        }
    }

    fn refresh() {
        let tip = APP.with(|cell| {
            let mut guard = cell.borrow_mut();
            let state = guard.as_mut()?;
            state.status = match state.client.request(Request::Status) {
                Ok(Response::Status { status }) => Some(status),
                _ => None,
            };
            state.otp = match state.client.request(Request::CurrentOtp) {
                Ok(Response::CurrentOtp {
                    code,
                    remaining_seconds,
                }) => Some((code, remaining_seconds)),
                _ => None,
            };
            let status = state
                .status
                .as_ref()
                .map(|status| MenuModel::project(status, None, false).status_label)
                .unwrap_or_else(|| "Service unavailable".to_owned());
            Some(
                state
                    .otp
                    .as_ref()
                    .map(|(code, seconds)| format!("HYU VPN - {status} - OTP {code} ({seconds}s)"))
                    .unwrap_or_else(|| format!("HYU VPN - {status}")),
            )
        });
        if let Some(tip) = tip
            && !notify_icon(NIM_MODIFY, &tip)
        {
            let _ = notify_icon(NIM_ADD, &tip);
        }
    }

    fn notify_icon(action: u32, tip: &str) -> bool {
        APP.with(|cell| {
            let guard = cell.borrow();
            let Some(state) = guard.as_ref() else {
                return false;
            };
            let mut data = NOTIFYICONDATAW {
                cbSize: u32::try_from(std::mem::size_of::<NOTIFYICONDATAW>()).unwrap_or(0),
                hWnd: state.hwnd,
                uID: ICON_ID,
                uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage: WM_TRAY,
                hIcon: state.icon,
                ..Default::default()
            };
            copy_wide_fixed(tip, &mut data.szTip);
            unsafe { Shell_NotifyIconW(action, &data) != 0 }
        })
    }

    fn show_menu(hwnd: HWND) {
        refresh();
        let (model, service_available) = APP.with(|cell| {
            let guard = cell.borrow();
            let state = guard.as_ref().expect("tray state");
            let launch = state
                .autostart
                .as_ref()
                .and_then(|manager| manager.is_enabled().ok())
                .unwrap_or(false);
            (
                state.status.as_ref().map(|status| {
                    MenuModel::project(
                        status,
                        state
                            .otp
                            .as_ref()
                            .map(|(code, seconds)| (code.as_str(), *seconds)),
                        launch,
                    )
                }),
                state.status.is_some(),
            )
        });
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return;
        }
        let model = model.unwrap_or(MenuModel {
            status_label: "Service unavailable".into(),
            otp_label: None,
            connect_enabled: false,
            disconnect_enabled: false,
            reconnect_enabled: false,
            launch_at_login: false,
        });
        append_item(menu, 0, &model.status_label, false, false);
        if let Some(label) = &model.otp_label {
            append_item(menu, CMD_COPY_OTP, label, true, false);
        }
        unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, null()) };
        append_item(
            menu,
            CMD_CONNECT,
            "Connect",
            service_available && model.connect_enabled,
            false,
        );
        append_item(
            menu,
            CMD_DISCONNECT,
            "Disconnect",
            service_available && model.disconnect_enabled,
            false,
        );
        append_item(
            menu,
            CMD_RECONNECT,
            "Reconnect",
            service_available && model.reconnect_enabled,
            false,
        );
        unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, null()) };
        append_item(
            menu,
            CMD_AUTOSTART,
            "Launch at login",
            true,
            model.launch_at_login,
        );
        append_item(
            menu,
            CMD_CREDENTIALS,
            "Change credentials...",
            service_available,
            false,
        );
        append_item(menu, CMD_QUIT, "Quit", true, false);
        let mut point = POINT::default();
        unsafe {
            GetCursorPos(&mut point);
            SetForegroundWindow(hwnd);
        }
        let command = unsafe {
            TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_NONOTIFY,
                point.x,
                point.y,
                0,
                hwnd,
                null(),
            )
        };
        unsafe { DestroyMenu(menu) };
        dispatch_command(hwnd, command as usize);
    }

    fn append_item(
        menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
        id: usize,
        label: &str,
        enabled: bool,
        checked: bool,
    ) {
        let mut flags = MF_STRING;
        if !enabled {
            flags |= MF_DISABLED | MF_GRAYED;
        }
        if checked {
            flags |= MF_CHECKED;
        }
        unsafe { AppendMenuW(menu, flags, id, wide(label).as_ptr()) };
    }

    fn dispatch_command(hwnd: HWND, command: usize) {
        match command {
            CMD_CONNECT => request(Request::Connect),
            CMD_DISCONNECT => request(Request::Disconnect),
            CMD_RECONNECT => request(Request::Reconnect),
            CMD_COPY_OTP => {
                let code = APP.with(|cell| {
                    cell.borrow()
                        .as_ref()
                        .and_then(|state| state.otp.as_ref().map(|(code, _)| code.clone()))
                });
                if let Some(code) = code {
                    let _ = copy_clipboard(hwnd, &code);
                }
            }
            CMD_CREDENTIALS => show_credentials(hwnd),
            CMD_AUTOSTART => APP.with(|cell| {
                let guard = cell.borrow();
                if let Some(manager) = guard.as_ref().and_then(|state| state.autostart.as_ref()) {
                    if let Ok(enabled) = manager.is_enabled() {
                        let _ = manager.set_enabled(!enabled);
                    }
                }
            }),
            CMD_QUIT => unsafe {
                DestroyWindow(hwnd);
            },
            _ => {}
        }
        refresh();
    }

    fn request(request: Request) {
        APP.with(|cell| {
            if let Some(state) = cell.borrow().as_ref() {
                let _ = state.client.request(request);
            }
        });
    }

    fn load_app_icon(instance: HINSTANCE) -> HICON {
        let path = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.join("hyu-vpn.ico")));
        if let Some(path) = path.and_then(|path| path.to_str().map(str::to_owned)) {
            let loaded = unsafe {
                LoadImageW(
                    null_mut(),
                    wide(&path).as_ptr(),
                    IMAGE_ICON,
                    32,
                    32,
                    LR_LOADFROMFILE,
                )
            };
            if !loaded.is_null() {
                return loaded as HICON;
            }
        }
        unsafe {
            let icon = LoadIconW(instance, wide("HYUVPN").as_ptr());
            if icon.is_null() {
                LoadIconW(null_mut(), IDI_APPLICATION)
            } else {
                icon
            }
        }
    }

    fn copy_clipboard(hwnd: HWND, value: &str) -> bool {
        let wide = wide(value);
        let bytes = wide.len() * std::mem::size_of::<u16>();
        if unsafe { OpenClipboard(hwnd) } == 0 {
            return false;
        }
        unsafe { EmptyClipboard() };
        let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
        if memory.is_null() {
            unsafe { CloseClipboard() };
            return false;
        }
        let destination = unsafe { GlobalLock(memory) } as *mut u16;
        if destination.is_null() {
            unsafe {
                GlobalFree(memory);
                CloseClipboard();
            }
            return false;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), destination, wide.len());
            GlobalUnlock(memory);
        }
        let accepted = unsafe { SetClipboardData(CF_UNICODETEXT, memory) };
        if accepted.is_null() {
            unsafe { GlobalFree(memory) };
        }
        unsafe { CloseClipboard() };
        !accepted.is_null()
    }

    fn show_credentials(owner: HWND) {
        let already_open = APP.with(|cell| {
            cell.borrow()
                .as_ref()
                .map(|state| !state.dialog.is_null())
                .unwrap_or(false)
        });
        if already_open {
            return;
        }
        let state = Box::new(DialogState::new(owner));
        let raw = Box::into_raw(state);
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_DLGMODALFRAME,
                wide("HYUVPNCredentialWindow").as_ptr(),
                wide("HYU VPN credentials").as_ptr(),
                WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                560,
                300,
                owner,
                null_mut(),
                GetModuleHandleW(null()),
                raw.cast(),
            )
        };
        if hwnd.is_null() {
            return;
        }
        APP.with(|cell| {
            if let Some(state) = cell.borrow_mut().as_mut() {
                state.dialog = hwnd;
            }
        });
        unsafe {
            EnableWindow(owner, 0);
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        }
    }

    unsafe extern "system" fn dialog_window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_NCCREATE {
            let create = lparam as *const CREATESTRUCTW;
            let state = unsafe { (*create).lpCreateParams as *mut DialogState };
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize) };
        }
        let state = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut DialogState };
        match message {
            WM_CREATE => {
                if state.is_null() || !unsafe { create_dialog_controls(hwnd, &mut *state) } {
                    return -1;
                }
                0
            }
            WM_COMMAND => {
                let id = wparam & 0xffff;
                if id == BUTTON_SAVE {
                    if !state.is_null() {
                        unsafe { save_credentials(hwnd, &*state) };
                    }
                } else if id == BUTTON_CANCEL {
                    unsafe { DestroyWindow(hwnd) };
                }
                0
            }
            WM_CLOSE => {
                unsafe { DestroyWindow(hwnd) };
                0
            }
            WM_NCDESTROY => {
                if !state.is_null() {
                    let owner = unsafe { (*state).owner };
                    unsafe {
                        EnableWindow(owner, 1);
                        SetForegroundWindow(owner);
                        drop(Box::from_raw(state));
                    }
                    APP.with(|cell| {
                        if let Some(app) = cell.borrow_mut().as_mut() {
                            app.dialog = null_mut();
                        }
                    });
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
                }
                unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
            }
            _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
        }
    }

    unsafe fn create_dialog_controls(hwnd: HWND, state: &mut DialogState) -> bool {
        let labels = [("HYU ID", 30), ("Password", 85), ("TOTP seed", 140)];
        for (label, y) in labels {
            unsafe {
                create_control(
                    hwnd,
                    "STATIC",
                    label,
                    WS_CHILD | WS_VISIBLE,
                    24,
                    y,
                    170,
                    24,
                    0,
                )
            };
        }
        let edit_style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32;
        state.username = unsafe {
            create_control(
                hwnd,
                "EDIT",
                "",
                edit_style,
                200,
                25,
                320,
                30,
                FIELD_USERNAME,
            )
        };
        state.password = unsafe {
            create_control(
                hwnd,
                "EDIT",
                "",
                edit_style | ES_PASSWORD as u32,
                200,
                80,
                320,
                30,
                FIELD_PASSWORD,
            )
        };
        state.totp = unsafe {
            create_control(
                hwnd,
                "EDIT",
                "",
                edit_style | ES_PASSWORD as u32,
                200,
                135,
                320,
                30,
                FIELD_TOTP,
            )
        };
        let save = unsafe {
            create_control(
                hwnd,
                "BUTTON",
                "Save",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                320,
                205,
                95,
                32,
                BUTTON_SAVE as i32,
            )
        };
        let cancel = unsafe {
            create_control(
                hwnd,
                "BUTTON",
                "Cancel",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                425,
                205,
                95,
                32,
                BUTTON_CANCEL as i32,
            )
        };
        let all = [state.username, state.password, state.totp, save, cancel];
        if all.iter().any(|control| control.is_null()) {
            return false;
        }
        unsafe { SetFocus(state.username) };
        true
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_control(
        owner: HWND,
        class: &str,
        text: &str,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        id: i32,
    ) -> HWND {
        let control = unsafe {
            CreateWindowExW(
                if class == "EDIT" { WS_EX_CLIENTEDGE } else { 0 },
                wide(class).as_ptr(),
                wide(text).as_ptr(),
                style,
                x,
                y,
                width,
                height,
                owner,
                id as usize as *mut c_void,
                GetModuleHandleW(null()),
                null(),
            )
        };
        if !control.is_null() {
            let font = unsafe { GetStockObject(DEFAULT_GUI_FONT) };
            unsafe { SendMessageW(control, WM_SETFONT, font as usize, 1) };
        }
        control
    }

    unsafe fn save_credentials(hwnd: HWND, state: &DialogState) {
        let form = CredentialForm {
            username: unsafe { read_text(state.username) },
            password: unsafe { read_text(state.password) },
            totp_seed: unsafe { read_text(state.totp) },
        };
        let credentials = match form.validate() {
            Ok(credentials) => credentials,
            Err(error) => {
                message_box(
                    hwnd,
                    &error.to_string(),
                    "Invalid credentials",
                    MB_ICONERROR,
                );
                return;
            }
        };
        let result = APP.with(|cell| {
            cell.borrow().as_ref().map(|app| {
                app.client
                    .request(Request::ReplaceCredentials { credentials })
            })
        });
        if matches!(result, Some(Ok(Response::Ack))) {
            unsafe {
                SetWindowTextW(state.password, wide("").as_ptr());
                SetWindowTextW(state.totp, wide("").as_ptr());
            }
            message_box(
                hwnd,
                "Credentials were saved securely by the HYU VPN service.",
                "HYU VPN",
                MB_ICONINFORMATION,
            );
            unsafe { DestroyWindow(hwnd) };
        } else {
            message_box(
                hwnd,
                "The HYU VPN service could not save the credentials.",
                "HYU VPN",
                MB_ICONERROR,
            );
        }
    }

    unsafe fn read_text(control: HWND) -> String {
        let length = unsafe { GetWindowTextLengthW(control) };
        if length <= 0 || length > 8192 {
            return String::new();
        }
        let mut buffer = vec![0_u16; length as usize + 1];
        let read = unsafe { GetWindowTextW(control, buffer.as_mut_ptr(), length + 1) };
        String::from_utf16_lossy(&buffer[..read.max(0) as usize])
    }

    fn message_box(owner: HWND, text: &str, caption: &str, icon: u32) {
        unsafe {
            MessageBoxW(
                owner,
                wide(text).as_ptr(),
                wide(caption).as_ptr(),
                MB_OK | icon,
            )
        };
    }

    fn copy_wide_fixed<const N: usize>(value: &str, target: &mut [u16; N]) {
        target.fill(0);
        for (destination, source) in target
            .iter_mut()
            .take(N.saturating_sub(1))
            .zip(value.encode_utf16())
        {
            *destination = source;
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(windows)]
fn main() {
    if std::env::args().any(|argument| argument == "--smoke-test") {
        return;
    }
    if windows_app::run().is_err() {
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    if std::env::args().any(|argument| argument == "--smoke-test") {
        println!("HYU VPN Windows tray model smoke test passed");
        return;
    }
    eprintln!("HYU VPN Windows tray is only available on Windows");
    std::process::exit(2);
}
