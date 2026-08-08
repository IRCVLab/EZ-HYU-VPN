use std::path::PathBuf;

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, RRF_RT_REG_SZ, RegCloseKey,
    RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "HYU VPN";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AutostartError {
    #[error("unable to update launch-at-login")]
    UpdateFailed,
}

pub struct WindowsAutostart {
    executable: PathBuf,
}

impl WindowsAutostart {
    pub fn production() -> Result<Self, AutostartError> {
        let executable = std::env::current_exe().map_err(|_| AutostartError::UpdateFailed)?;
        Ok(Self { executable })
    }

    pub fn is_enabled(&self) -> Result<bool, AutostartError> {
        let expected = quoted_executable(&self.executable)?;
        match read_value()? {
            Some(value) => Ok(value == expected),
            None => Ok(false),
        }
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), AutostartError> {
        if enabled {
            write_value(&quoted_executable(&self.executable)?)
        } else {
            delete_value()
        }
    }
}

fn quoted_executable(path: &std::path::Path) -> Result<String, AutostartError> {
    let value = path.to_str().ok_or(AutostartError::UpdateFailed)?;
    if !path.is_absolute() || value.contains('"') || value.chars().any(char::is_control) {
        return Err(AutostartError::UpdateFailed);
    }
    Ok(format!("\"{value}\""))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_key(access: u32) -> Result<windows_sys::Win32::System::Registry::HKEY, AutostartError> {
    let path = wide(RUN_KEY);
    let mut key = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut key) };
    if status == ERROR_SUCCESS {
        Ok(key)
    } else {
        Err(AutostartError::UpdateFailed)
    }
}

fn read_value() -> Result<Option<String>, AutostartError> {
    let key = open_key(KEY_QUERY_VALUE)?;
    let name = wide(VALUE_NAME);
    let mut bytes = 0_u32;
    let status = unsafe {
        RegGetValueW(
            key,
            std::ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        unsafe { RegCloseKey(key) };
        return Ok(None);
    }
    if status != ERROR_SUCCESS || !(2..=32 * 1024).contains(&bytes) {
        unsafe { RegCloseKey(key) };
        return Err(AutostartError::UpdateFailed);
    }
    let mut buffer =
        vec![0_u16; usize::try_from(bytes / 2).map_err(|_| AutostartError::UpdateFailed)?];
    let status = unsafe {
        RegGetValueW(
            key,
            std::ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    unsafe { RegCloseKey(key) };
    if status != ERROR_SUCCESS {
        return Err(AutostartError::UpdateFailed);
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length])
        .map(Some)
        .map_err(|_| AutostartError::UpdateFailed)
}

fn write_value(value: &str) -> Result<(), AutostartError> {
    let key = open_key(KEY_SET_VALUE)?;
    let name = wide(VALUE_NAME);
    let value = wide(value);
    let bytes = u32::try_from(value.len() * 2).map_err(|_| AutostartError::UpdateFailed)?;
    let status =
        unsafe { RegSetValueExW(key, name.as_ptr(), 0, REG_SZ, value.as_ptr().cast(), bytes) };
    unsafe { RegCloseKey(key) };
    (status == ERROR_SUCCESS)
        .then_some(())
        .ok_or(AutostartError::UpdateFailed)
}

fn delete_value() -> Result<(), AutostartError> {
    let key = open_key(KEY_SET_VALUE)?;
    let name = wide(VALUE_NAME);
    let status = unsafe { RegDeleteValueW(key, name.as_ptr()) };
    unsafe { RegCloseKey(key) };
    (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND)
        .then_some(())
        .ok_or(AutostartError::UpdateFailed)
}
