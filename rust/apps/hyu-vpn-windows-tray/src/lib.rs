mod client;
mod credentials;
mod menu;

#[cfg(windows)]
mod autostart;
#[cfg(windows)]
pub use autostart::WindowsAutostart;
pub use client::{ClientError, WindowsPipeClient, decode_framed_response, encode_framed_request};
pub use credentials::{CredentialForm, FormField, ValidationError};
pub use menu::{MenuCommand, MenuModel};
