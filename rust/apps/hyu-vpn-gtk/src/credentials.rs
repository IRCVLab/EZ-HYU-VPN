use hyu_vpn_protocol::Credentials;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Username,
    Password,
    PasswordConfirmation,
    TotpSeed,
    TotpSeedConfirmation,
    Save,
    Cancel,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    #[error("HYU ID is invalid")]
    InvalidUsername,
    #[error("password confirmation does not match")]
    PasswordMismatch,
    #[error("TOTP confirmation does not match")]
    TotpMismatch,
    #[error("credential input is invalid")]
    InvalidCredentials,
}

#[derive(Debug, Default)]
pub struct CredentialForm {
    pub username: String,
    pub password: String,
    pub password_confirmation: String,
    pub totp_seed: String,
    pub totp_seed_confirmation: String,
}

impl CredentialForm {
    pub fn tab_order() -> [FormField; 7] {
        [
            FormField::Username,
            FormField::Password,
            FormField::PasswordConfirmation,
            FormField::TotpSeed,
            FormField::TotpSeedConfirmation,
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
        if self.password != self.password_confirmation {
            return Err(ValidationError::PasswordMismatch);
        }
        let seed = normalize_seed(&self.totp_seed)?;
        let confirmation = normalize_seed(&self.totp_seed_confirmation)?;
        if seed != confirmation {
            return Err(ValidationError::TotpMismatch);
        }
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
