use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorConfig {
    pub executable: PathBuf,
    pub authgroup: String,
    pub vpnc_script: PathBuf,
    pub hip_wrapper: PathBuf,
    pub portal: String,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorConfigError {
    #[error("invalid OpenConnect configuration")]
    InvalidConfiguration,
}

pub fn build_openconnect_args(
    config: &ConnectorConfig,
) -> Result<Vec<String>, ConnectorConfigError> {
    if !valid_absolute_path(&config.executable)
        || !valid_absolute_path(&config.vpnc_script)
        || !valid_absolute_path(&config.hip_wrapper)
        || !valid_token(&config.authgroup)
        || !valid_hostname(&config.portal)
    {
        return Err(ConnectorConfigError::InvalidConfiguration);
    }
    Ok(vec![
        "--protocol=gp".to_owned(),
        format!("--authgroup={}", config.authgroup),
        "--no-dtls".to_owned(),
        "--passwd-on-stdin".to_owned(),
        format!(
            "--script={}",
            config
                .vpnc_script
                .to_str()
                .ok_or(ConnectorConfigError::InvalidConfiguration)?
        ),
        format!(
            "--csd-wrapper={}",
            config
                .hip_wrapper
                .to_str()
                .ok_or(ConnectorConfigError::InvalidConfiguration)?
        ),
        config.portal.clone(),
    ])
}

fn valid_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|value| !value.chars().any(char::is_control))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b' '))
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}
