use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use hyu_vpn_platform_linux::{HipContext, LinuxPostureCollector, PostureError};
#[cfg(windows)]
use hyu_vpn_platform_windows::{WindowsHipContext, WindowsPostureCollector, WindowsPostureError};
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HipCliError {
    #[error("invalid HIP invocation")]
    InvalidInvocation,
    #[error("HIP collection failed")]
    Collection,
    #[error("HIP XML generation failed")]
    Xml,
}

pub const MAX_HIP_COOKIE_BYTES: usize = 8192;

pub fn resolve_cookie_stdin_args<R: Read>(
    args: &[String],
    mut reader: R,
) -> Result<Vec<String>, HipCliError> {
    const COOKIE_STDIN: &str = "--cookie-on-stdin";
    if args
        .iter()
        .any(|argument| argument.starts_with(COOKIE_STDIN) && argument != COOKIE_STDIN)
    {
        return Err(HipCliError::InvalidInvocation);
    }
    let occurrences = args
        .iter()
        .filter(|argument| *argument == COOKIE_STDIN)
        .count();
    if occurrences == 0 {
        return Ok(args.to_vec());
    }
    if occurrences != 1 {
        return Err(HipCliError::InvalidInvocation);
    }
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_HIP_COOKIE_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| HipCliError::InvalidInvocation)?;
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    if bytes.is_empty()
        || bytes.len() > MAX_HIP_COOKIE_BYTES
        || bytes.contains(&b'\n')
        || bytes.contains(&b'\r')
        || bytes.contains(&0)
    {
        return Err(HipCliError::InvalidInvocation);
    }
    let cookie = String::from_utf8(bytes).map_err(|_| HipCliError::InvalidInvocation)?;
    let mut resolved = Vec::with_capacity(args.len() + 1);
    for argument in args {
        if argument == COOKIE_STDIN {
            resolved.push("--cookie".to_owned());
            resolved.push(cookie.clone());
        } else {
            resolved.push(argument.clone());
        }
    }
    Ok(resolved)
}

struct ParsedInvocation {
    md5: String,
    user: String,
    domain: String,
    computer: Option<String>,
    client_ip: String,
    client_ipv6: String,
    client_version: String,
    generated_at: String,
}

#[cfg(target_os = "linux")]
pub fn build_hip_from_args(
    args: &[String],
    collector: &LinuxPostureCollector,
    generated_at: &str,
    environment_app_version: Option<&str>,
) -> Result<String, HipCliError> {
    let invocation = parse_invocation(args, generated_at, environment_app_version)?;
    let mut posture = collector.collect().map_err(|_| HipCliError::Collection)?;
    if let Some(computer) = invocation.computer {
        posture.hostname = computer;
    }
    posture
        .to_hip_xml(&HipContext {
            md5: invocation.md5,
            user: invocation.user,
            domain: invocation.domain,
            client_ip: invocation.client_ip,
            client_ipv6: invocation.client_ipv6,
            client_version: invocation.client_version,
            generated_at: invocation.generated_at,
        })
        .map_err(|error| match error {
            PostureError::InvalidEvidence => HipCliError::Collection,
            PostureError::InvalidXml => HipCliError::Xml,
        })
}

#[cfg(windows)]
pub fn build_windows_hip_from_args(
    args: &[String],
    collector: &WindowsPostureCollector,
    generated_at: &str,
    environment_app_version: Option<&str>,
) -> Result<String, HipCliError> {
    let invocation = parse_invocation(args, generated_at, environment_app_version)?;
    let mut posture = collector.collect().map_err(|_| HipCliError::Collection)?;
    if let Some(computer) = invocation.computer {
        posture.hostname = computer;
    }
    posture
        .to_hip_xml(&WindowsHipContext {
            md5: invocation.md5,
            user: invocation.user,
            domain: invocation.domain,
            client_ip: invocation.client_ip,
            client_ipv6: invocation.client_ipv6,
            client_version: invocation.client_version,
            generated_at: invocation.generated_at,
        })
        .map_err(|error| match error {
            WindowsPostureError::InvalidEvidence => HipCliError::Collection,
            WindowsPostureError::InvalidXml => HipCliError::Xml,
        })
}

fn parse_invocation(
    args: &[String],
    generated_at: &str,
    environment_app_version: Option<&str>,
) -> Result<ParsedInvocation, HipCliError> {
    let values = parse_options(args)?;
    let cookie = required(&values, "--cookie")?;
    let md5 = required(&values, "--md5")?;
    if md5.len() != 32 || !md5.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HipCliError::InvalidInvocation);
    }
    let client_ip = values.get("--client-ip").cloned();
    let client_ipv6 = values.get("--client-ipv6").cloned();
    if client_ip.is_none() && client_ipv6.is_none() {
        return Err(HipCliError::InvalidInvocation);
    }
    if let Some(value) = &client_ip
        && !matches!(value.parse::<IpAddr>(), Ok(IpAddr::V4(_)))
    {
        return Err(HipCliError::InvalidInvocation);
    }
    if let Some(value) = &client_ipv6
        && !matches!(value.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
    {
        return Err(HipCliError::InvalidInvocation);
    }
    let identity = parse_cookie(cookie)?;
    let user = identity
        .get("user")
        .filter(|value| !value.is_empty())
        .ok_or(HipCliError::InvalidInvocation)?
        .clone();
    let domain = identity.get("domain").cloned().unwrap_or_default();
    let computer = identity
        .get("computer")
        .filter(|value| !value.is_empty())
        .cloned();
    let client_version = values
        .get("--app-version")
        .map(String::as_str)
        .or(environment_app_version)
        .unwrap_or("unknown");
    for value in [&user, &domain, client_version, generated_at] {
        if !bounded_text(value, 256) {
            return Err(HipCliError::InvalidInvocation);
        }
    }
    Ok(ParsedInvocation {
        md5: md5.to_ascii_lowercase(),
        user,
        domain,
        computer,
        client_ip: client_ip.unwrap_or_else(|| "0.0.0.0".to_owned()),
        client_ipv6: client_ipv6.unwrap_or_else(|| "::".to_owned()),
        client_version: client_version.to_owned(),
        generated_at: generated_at.to_owned(),
    })
}

fn parse_options(args: &[String]) -> Result<HashMap<&'static str, String>, HipCliError> {
    const OPTIONS: [&str; 6] = [
        "--cookie",
        "--client-ip",
        "--client-ipv6",
        "--md5",
        "--client-os",
        "--app-version",
    ];
    if args.iter().map(String::len).sum::<usize>() > 16 * 1024 {
        return Err(HipCliError::InvalidInvocation);
    }
    let mut values = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let raw = &args[index];
        let (name, value) = if let Some((name, value)) = raw.split_once('=') {
            (name, value.to_owned())
        } else {
            index += 1;
            let value = args.get(index).ok_or(HipCliError::InvalidInvocation)?;
            (raw.as_str(), value.clone())
        };
        let canonical = OPTIONS
            .iter()
            .copied()
            .find(|option| *option == name)
            .ok_or(HipCliError::InvalidInvocation)?;
        if !bounded_text(&value, 8192) || values.insert(canonical, value).is_some() {
            return Err(HipCliError::InvalidInvocation);
        }
        index += 1;
    }
    Ok(values)
}

fn required<'a>(
    values: &'a HashMap<&'static str, String>,
    key: &str,
) -> Result<&'a str, HipCliError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or(HipCliError::InvalidInvocation)
}

fn parse_cookie(value: &str) -> Result<HashMap<String, String>, HipCliError> {
    let mut result = HashMap::new();
    for field in value.split('&').take(64) {
        let (name, value) = field
            .split_once('=')
            .ok_or(HipCliError::InvalidInvocation)?;
        let name = percent_decode(name)?;
        let value = percent_decode(value)?;
        if !matches!(name.as_str(), "user" | "domain" | "computer") {
            continue;
        }
        result.entry(name).or_insert(value);
    }
    Ok(result)
}

fn percent_decode(value: &str) -> Result<String, HipCliError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = *bytes.get(index + 1).ok_or(HipCliError::InvalidInvocation)?;
                let low = *bytes.get(index + 2).ok_or(HipCliError::InvalidInvocation)?;
                decoded.push(hex(high)? << 4 | hex(low)?);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            value => {
                decoded.push(value);
                index += 1;
            }
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| HipCliError::InvalidInvocation)?;
    if !bounded_text(&decoded, 1024) {
        return Err(HipCliError::InvalidInvocation);
    }
    Ok(decoded)
}

fn hex(value: u8) -> Result<u8, HipCliError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(HipCliError::InvalidInvocation),
    }
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
}
