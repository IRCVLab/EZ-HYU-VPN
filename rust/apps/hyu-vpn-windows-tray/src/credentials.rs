use hyu_vpn_protocol::Credentials;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Username,
    Password,
    TotpSeed,
    Save,
    Cancel,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    #[error("HYU ID is invalid")]
    InvalidUsername,
    #[error("credential input is invalid")]
    InvalidCredentials,
}

#[derive(Debug, Default)]
pub struct CredentialForm {
    pub username: String,
    pub password: String,
    pub totp_seed: String,
}

impl CredentialForm {
    pub fn tab_order() -> [FormField; 5] {
        [
            FormField::Username,
            FormField::Password,
            FormField::TotpSeed,
            FormField::Save,
            FormField::Cancel,
        ]
    }

    pub fn validate(&self) -> Result<Credentials, ValidationError> {
        if self.username.is_empty()
            || self.username.len() > 256
            || self.username.chars().any(char::is_control)
        {
            return Err(ValidationError::InvalidUsername);
        }
        let seed = normalize_seed(&self.totp_seed)?;
        Credentials::new(&self.username, &self.password, seed)
            .map_err(|_| ValidationError::InvalidCredentials)
    }
}

fn normalize_seed(value: &str) -> Result<String, ValidationError> {
    let normalized: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if normalized.len() < 16
        || normalized.len() > 1024
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7'))
    {
        return Err(ValidationError::InvalidCredentials);
    }
    Ok(normalized)
}

impl Drop for CredentialForm {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.totp_seed.zeroize();
    }
}
