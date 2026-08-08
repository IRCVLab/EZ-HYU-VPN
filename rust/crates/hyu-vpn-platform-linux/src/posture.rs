use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

const MAX_EVIDENCE_BYTES: usize = 16 * 1024;
const MAX_XML_BYTES: usize = 64 * 1024;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PostureError {
    #[error("posture evidence is invalid")]
    InvalidEvidence,
    #[error("HIP XML is invalid")]
    InvalidXml,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HipContext {
    pub md5: String,
    pub user: String,
    pub domain: String,
    pub client_ip: String,
    pub client_ipv6: String,
    pub client_version: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxInterface {
    pub name: String,
    pub mac_address: String,
    pub ipv4: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPosture {
    pub os_name: String,
    pub os_version: String,
    pub kernel: String,
    pub hostname: String,
    pub interfaces: Vec<LinuxInterface>,
    pub updates: Option<u32>,
    pub firewall: String,
    pub endpoint: String,
    pub encryption: String,
}

pub struct LinuxPostureCollector {
    fixture_dir: Option<PathBuf>,
}

impl LinuxPostureCollector {
    pub fn production() -> Self {
        Self { fixture_dir: None }
    }

    pub fn from_fixture_dir(path: impl AsRef<Path>) -> Self {
        Self {
            fixture_dir: Some(path.as_ref().to_path_buf()),
        }
    }

    pub fn collect(&self) -> Result<LinuxPosture, PostureError> {
        let os_release = self.evidence("os-release.txt", "/etc/os-release", &[]);
        let kernel = self.evidence("kernel.txt", "/usr/bin/uname", &["-r"]);
        let hostname = self.evidence("hostname.txt", "/usr/bin/hostname", &[]);
        let interfaces = self.evidence(
            "interfaces.txt",
            "/usr/sbin/ip",
            &["-o", "-4", "addr", "show"],
        );
        let updates = self.evidence("updates.txt", "/usr/bin/apt", &["list", "--upgradable"]);
        let firewall = self.evidence("firewall.txt", "/usr/sbin/ufw", &["status"]);
        let endpoint = self.evidence(
            "endpoint.txt",
            "/usr/bin/systemctl",
            &["is-active", "clamav-daemon.service"],
        );
        let encryption = self.evidence("encryption.txt", "/usr/bin/lsblk", &["-ndo", "TYPE"]);
        let (os_name, os_version) = parse_os_release(os_release.as_deref());
        Ok(LinuxPosture {
            os_name,
            os_version,
            kernel: bounded_value(kernel.as_deref()).unwrap_or_else(|| "unknown".into()),
            hostname: bounded_value(hostname.as_deref()).unwrap_or_else(|| "unknown".into()),
            interfaces: parse_interfaces(interfaces.as_deref()),
            updates: parse_updates(updates.as_deref()),
            firewall: normalize_firewall(firewall.as_deref()),
            endpoint: normalize_state(endpoint.as_deref()),
            encryption: normalize_encryption(encryption.as_deref()),
        })
    }

    fn evidence(&self, fixture: &str, executable: &str, arguments: &[&str]) -> Option<String> {
        if let Some(directory) = &self.fixture_dir {
            return read_bounded(&directory.join(fixture));
        }
        run_bounded(executable, arguments)
    }
}

impl LinuxPosture {
    pub fn to_hip_xml(&self, context: &HipContext) -> Result<String, PostureError> {
        let interface = self.interfaces.first().cloned().unwrap_or(LinuxInterface {
            name: "unknown".into(),
            mac_address: "unknown".into(),
            ipv4: context.client_ip.clone(),
        });
        let host_id = if interface.mac_address.is_empty() {
            "unknown"
        } else {
            &interface.mac_address
        };
        let os = format!("{} {} ({})", self.os_name, self.os_version, self.kernel);
        let firewall_enabled = match self.firewall.as_str() {
            "active" | "yes" => "yes",
            "inactive" | "no" => "no",
            _ => "unknown",
        };
        let update_title = self
            .updates
            .map(|count| format!("{count} updates available"))
            .unwrap_or_else(|| "unknown updates available".into());
        let mut lines = Vec::new();
        lines.push("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".into());
        line(&mut lines, 0, "<hip-report name=\"hip-report\">");
        text(&mut lines, 1, "md5-sum", &context.md5);
        text(&mut lines, 1, "user-name", &context.user);
        text(&mut lines, 1, "domain", &context.domain);
        text(&mut lines, 1, "host-name", &self.hostname);
        text(&mut lines, 1, "host-id", host_id);
        text(&mut lines, 1, "ip-address", &context.client_ip);
        text(&mut lines, 1, "ipv6-address", &context.client_ipv6);
        text(&mut lines, 1, "generate-time", &context.generated_at);
        text(&mut lines, 1, "hip-report-version", "4");
        line(&mut lines, 1, "<categories>");
        line(&mut lines, 2, "<entry name=\"host-info\">");
        text(&mut lines, 3, "client-version", &context.client_version);
        text(&mut lines, 3, "os", &os);
        text(&mut lines, 3, "os-vendor", "Canonical");
        text(&mut lines, 3, "domain", &context.domain);
        text(&mut lines, 3, "host-name", &self.hostname);
        text(&mut lines, 3, "host-id", host_id);
        line(&mut lines, 3, "<network-interface>");
        line(
            &mut lines,
            4,
            &format!("<entry name=\"{}\">", escape_attr(&interface.name)),
        );
        text(&mut lines, 5, "description", &interface.name);
        text(&mut lines, 5, "mac-address", &interface.mac_address);
        line(&mut lines, 5, "<ip-address>");
        line(
            &mut lines,
            6,
            &format!("<entry name=\"{}\"/>", escape_attr(&interface.ipv4)),
        );
        line(&mut lines, 5, "</ip-address>");
        line(&mut lines, 4, "</entry>");
        line(&mut lines, 3, "</network-interface>");
        line(&mut lines, 2, "</entry>");

        line(&mut lines, 2, "<entry name=\"anti-malware\">");
        line(&mut lines, 3, "<list>");
        line(&mut lines, 4, "<entry>");
        line(&mut lines, 5, "<ProductInfo>");
        line(
            &mut lines,
            6,
            &format!(
                "<Prod vendor=\"Linux\" name=\"Endpoint Protection\" version=\"{}\"/>",
                escape_attr(&self.endpoint)
            ),
        );
        text(&mut lines, 6, "real-time-protection", &self.endpoint);
        text(&mut lines, 6, "last-full-scan-time", "unknown");
        line(&mut lines, 5, "</ProductInfo>");
        line(&mut lines, 4, "</entry>");
        line(&mut lines, 3, "</list>");
        line(&mut lines, 2, "</entry>");

        line(&mut lines, 2, "<entry name=\"disk-backup\">");
        line(&mut lines, 3, "<list/>");
        line(&mut lines, 2, "</entry>");

        line(&mut lines, 2, "<entry name=\"disk-encryption\">");
        line(&mut lines, 3, "<list>");
        line(&mut lines, 4, "<entry>");
        line(&mut lines, 5, "<ProductInfo>");
        line(
            &mut lines,
            6,
            "<Prod vendor=\"Linux\" name=\"dm-crypt\" version=\"unknown\"/>",
        );
        line(&mut lines, 6, "<drives>");
        line(&mut lines, 7, "<entry>");
        text(&mut lines, 8, "drive-name", "All");
        text(&mut lines, 8, "enc-state", &self.encryption);
        line(&mut lines, 7, "</entry>");
        line(&mut lines, 6, "</drives>");
        line(&mut lines, 5, "</ProductInfo>");
        line(&mut lines, 4, "</entry>");
        line(&mut lines, 3, "</list>");
        line(&mut lines, 2, "</entry>");

        line(&mut lines, 2, "<entry name=\"firewall\">");
        line(&mut lines, 3, "<list>");
        line(&mut lines, 4, "<entry>");
        line(&mut lines, 5, "<ProductInfo>");
        line(
            &mut lines,
            6,
            "<Prod vendor=\"Linux\" name=\"Firewall\" version=\"unknown\"/>",
        );
        text(&mut lines, 6, "is-enabled", firewall_enabled);
        line(&mut lines, 5, "</ProductInfo>");
        line(&mut lines, 4, "</entry>");
        line(&mut lines, 3, "</list>");
        line(&mut lines, 2, "</entry>");

        line(&mut lines, 2, "<entry name=\"patch-management\">");
        line(&mut lines, 3, "<list>");
        line(&mut lines, 4, "<entry>");
        line(&mut lines, 5, "<ProductInfo>");
        line(
            &mut lines,
            6,
            "<Prod vendor=\"Ubuntu\" name=\"APT\" version=\"unknown\"/>",
        );
        text(&mut lines, 6, "is-enabled", "yes");
        line(&mut lines, 5, "</ProductInfo>");
        line(&mut lines, 4, "</entry>");
        line(&mut lines, 3, "</list>");
        line(&mut lines, 3, "<missing-patches>");
        line(&mut lines, 4, "<entry>");
        text(&mut lines, 5, "title", &update_title);
        text(&mut lines, 5, "is-installed", "no");
        line(&mut lines, 4, "</entry>");
        line(&mut lines, 3, "</missing-patches>");
        line(&mut lines, 2, "</entry>");

        line(&mut lines, 2, "<entry name=\"data-loss-prevention\">");
        line(&mut lines, 3, "<list/>");
        line(&mut lines, 2, "</entry>");
        line(&mut lines, 1, "</categories>");
        line(&mut lines, 0, "</hip-report>");
        let xml = lines.join("\n") + "\n";
        if xml.len() > MAX_XML_BYTES {
            return Err(PostureError::InvalidXml);
        }
        Ok(xml)
    }
}

fn read_bounded(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_EVIDENCE_BYTES as u64
    {
        return None;
    }
    let raw = fs::read(path).ok()?;
    if raw.len() > MAX_EVIDENCE_BYTES {
        return None;
    }
    String::from_utf8(raw).ok()
}

fn run_bounded(executable: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(executable)
        .args(arguments)
        .env_clear()
        .output()
        .ok()?;
    if output.stdout.len() > MAX_EVIDENCE_BYTES {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn parse_os_release(value: Option<&str>) -> (String, String) {
    let mut name = None;
    let mut version = None;
    for line in value.unwrap_or_default().lines() {
        if let Some(raw) = line.strip_prefix("NAME=") {
            name = bounded_value(Some(raw.trim_matches('"')));
        } else if let Some(raw) = line.strip_prefix("VERSION_ID=") {
            version = bounded_value(Some(raw.trim_matches('"')));
        }
    }
    (
        name.unwrap_or_else(|| "unknown".into()),
        version.unwrap_or_else(|| "unknown".into()),
    )
}

fn parse_interfaces(value: Option<&str>) -> Vec<LinuxInterface> {
    let mut result = Vec::new();
    for line in value.unwrap_or_default().lines().take(32) {
        if line.contains('|') {
            let fields: Vec<_> = line.split('|').collect();
            if fields.len() == 3 {
                if let (Some(name), Some(mac), Some(ipv4)) = (
                    bounded_value(Some(fields[0])),
                    bounded_value(Some(fields[1])),
                    bounded_value(Some(fields[2])),
                ) {
                    result.push(LinuxInterface {
                        name,
                        mac_address: mac,
                        ipv4,
                    });
                }
            }
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 4 {
            let name = fields[1].trim_end_matches(':');
            let ipv4 = fields[3].split('/').next().unwrap_or("unknown");
            if let (Some(name), Some(ipv4)) = (bounded_value(Some(name)), bounded_value(Some(ipv4)))
            {
                result.push(LinuxInterface {
                    name,
                    mac_address: "unknown".into(),
                    ipv4,
                });
            }
        }
    }
    result
}

fn parse_updates(value: Option<&str>) -> Option<u32> {
    let value = value?;
    if let Ok(number) = value.trim().parse::<u32>() {
        return Some(number.min(100_000));
    }
    Some(
        value
            .lines()
            .filter(|line| line.contains("upgradable from"))
            .count() as u32,
    )
}

fn normalize_firewall(value: Option<&str>) -> String {
    let lower = value.unwrap_or_default().to_ascii_lowercase();
    if lower.contains("inactive") {
        "inactive".into()
    } else if lower.contains("active") {
        "active".into()
    } else {
        "unknown".into()
    }
}

fn normalize_state(value: Option<&str>) -> String {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "active" | "yes" | "enabled" => "yes".into(),
        "inactive" | "no" | "disabled" => "no".into(),
        _ => "unknown".into(),
    }
}

fn normalize_encryption(value: Option<&str>) -> String {
    let lower = value.unwrap_or_default().to_ascii_lowercase();
    if lower.contains("encrypted") || lower.lines().any(|line| line.trim() == "crypt") {
        "encrypted".into()
    } else {
        "unknown".into()
    }
}

fn bounded_value(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.into())
}

fn line(lines: &mut Vec<String>, indent: usize, value: &str) {
    lines.push(format!("{}{}", "  ".repeat(indent), value));
}

fn text(lines: &mut Vec<String>, indent: usize, tag: &str, value: &str) {
    line(
        lines,
        indent,
        &format!("<{tag}>{}</{tag}>", escape_text(value)),
    );
}

fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(value: &str) -> String {
    escape_text(value)
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
