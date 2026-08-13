use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{HipCliError, ParsedInvocation, bounded_text, parse_invocation};

const SYSTEM_VERSION_PLIST: &str = "/System/Library/CoreServices/SystemVersion.plist";
const XPROTECT_PLIST: &str =
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";
const MAX_COMMAND_OUTPUT: u64 = 4 * 1024 * 1024;
const UPDATE_CACHE_MAX_AGE_SECONDS: i64 = 6 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostInfo {
    pub host_name: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub client_version: Option<String>,
    pub os_vendor: Option<String>,
    pub domain: Option<String>,
    pub host_id: Option<String>,
    pub interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Product {
    pub name: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub defver: Option<String>,
    pub engver: Option<String>,
    pub datemon: Option<String>,
    pub dateday: Option<String>,
    pub dateyear: Option<String>,
    pub prod_type: Option<String>,
    pub os_type: Option<String>,
    pub real_time_protection: Option<String>,
    pub last_full_scan_time: Option<String>,
    pub last_backup_time: Option<String>,
    pub is_enabled: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Drive {
    pub drive_name: String,
    pub enc_state: Option<String>,
    pub product_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Patch {
    pub title: String,
    pub description: Option<String>,
    pub product: Option<String>,
    pub vendor: Option<String>,
    pub info_url: Option<String>,
    pub kb_article_id: Option<String>,
    pub security_bulletin_id: Option<String>,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub is_installed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacPosture {
    pub host_info: HostInfo,
    pub anti_malware: Vec<Product>,
    pub disk_backup: Vec<Product>,
    pub disk_encryption: Vec<Drive>,
    pub firewall: Vec<Product>,
    pub patch_management_product: Product,
    pub patches: Vec<Patch>,
}

impl Default for MacPosture {
    fn default() -> Self {
        Self {
            host_info: HostInfo {
                os_vendor: Some("Apple".to_owned()),
                ..HostInfo::default()
            },
            anti_malware: vec![
                anti_malware_product("Xprotect", "n/a", "n/a"),
                anti_malware_product("Gatekeeper", "n/a", "n/a"),
            ],
            disk_backup: vec![Product {
                vendor: Some("Apple Inc.".to_owned()),
                name: "Time Machine".to_owned(),
                version: Some("1.3".to_owned()),
                last_backup_time: Some("n/a".to_owned()),
                ..Product::default()
            }],
            disk_encryption: vec![Drive {
                drive_name: "All".to_owned(),
                enc_state: Some("unknown".to_owned()),
                product_version: None,
            }],
            firewall: vec![
                firewall_product("Apple Inc.", "Mac OS X Builtin Firewall", None, "n/a"),
                firewall_product("OpenBSD", "Packet Filter", None, "n/a"),
            ],
            patch_management_product: Product {
                vendor: Some("Apple Inc.".to_owned()),
                name: "Software Update".to_owned(),
                version: Some("3.0".to_owned()),
                is_enabled: Some("n/a".to_owned()),
                ..Product::default()
            },
            patches: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct CommandResult {
    success: bool,
    stdout: String,
}

trait CommandRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> CommandResult;
}

struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> CommandResult {
        run_command(program, args, timeout)
    }
}

pub fn build_macos_hip_with_posture_from_args(
    args: &[String],
    posture: &MacPosture,
    generated_at: &str,
    environment_app_version: Option<&str>,
) -> Result<String, HipCliError> {
    let invocation = parse_invocation(args, generated_at, environment_app_version)?;
    build_macos_xml(&invocation, posture)
}

pub(super) fn collect_production_posture() -> MacPosture {
    collect_posture(
        &SystemCommandRunner,
        Path::new(SYSTEM_VERSION_PLIST),
        Path::new(XPROTECT_PLIST),
        &update_cache_path(),
        OffsetDateTime::now_utc(),
    )
}

fn collect_posture(
    runner: &dyn CommandRunner,
    system_version_plist: &Path,
    xprotect_plist: &Path,
    update_cache: &Path,
    now: OffsetDateTime,
) -> MacPosture {
    let os_version = plist_value(runner, system_version_plist, "ProductVersion");
    let physical = collect_physical_identity(runner);
    let interfaces = physical
        .as_ref()
        .map(|(name, mac)| {
            vec![NetworkInterface {
                name: name.clone(),
                description: Some(name.clone()),
                mac_address: Some(mac.clone()),
                ..NetworkInterface::default()
            }]
        })
        .unwrap_or_default();

    let xprotect_version = plist_value(runner, xprotect_plist, "CFBundleShortVersionString")
        .or_else(|| plist_value(runner, xprotect_plist, "CFBundleVersion"));
    let xprotect_date = plist_value(runner, xprotect_plist, "LastModification")
        .or_else(|| plist_value(runner, xprotect_plist, "BuildDate"))
        .and_then(|value| date_parts(&value))
        .or_else(|| file_mtime_date_parts(xprotect_plist));
    let (xprotect_month, xprotect_day, xprotect_year) =
        xprotect_date.unwrap_or_else(empty_date_parts);
    let xprotect_status = if xprotect_version.is_some() {
        "yes"
    } else {
        "n/a"
    };
    let xprotect_version_value = xprotect_version.clone().unwrap_or_else(|| "n/a".to_owned());

    let gatekeeper = runner.run("/usr/sbin/spctl", &["--status"], Duration::from_secs(5));
    let gatekeeper_enabled =
        command_state(&gatekeeper, "assessments enabled", "assessments disabled");
    let gatekeeper_date = if gatekeeper_enabled == "n/a" {
        empty_date_parts()
    } else {
        (
            format!("{:02}", u8::from(now.month())),
            format!("{:02}", now.day()),
            format!("{:04}", now.year()),
        )
    };

    let filevault = runner.run("/usr/bin/fdesetup", &["status"], Duration::from_secs(5));
    let encryption_state = if filevault.success {
        let output = filevault.stdout.to_ascii_lowercase();
        if output.contains("filevault is on") {
            "encrypted"
        } else if output.contains("filevault is off") {
            "unencrypted"
        } else {
            "unknown"
        }
    } else {
        "unknown"
    };

    let app_firewall = runner.run(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
        Duration::from_secs(5),
    );
    let app_firewall_enabled =
        command_state(&app_firewall, "firewall is enabled", "firewall is disabled");
    let packet_filter = runner.run("/sbin/pfctl", &["-s", "info"], Duration::from_secs(5));
    let packet_filter_enabled =
        command_state(&packet_filter, "status: enabled", "status: disabled");

    let (patches, patch_state) = collect_software_updates(runner, update_cache, now);
    let os_version_or_na = os_version.clone().unwrap_or_else(|| "n/a".to_owned());
    let host_id = physical.as_ref().map(|(_, mac)| mac.clone());

    MacPosture {
        host_info: HostInfo {
            os: Some(match &os_version {
                Some(version) => format!("Apple Mac OS X {version}"),
                None => "Apple Mac OS X".to_owned(),
            }),
            os_version,
            os_vendor: Some("Apple".to_owned()),
            host_id,
            interfaces,
            ..HostInfo::default()
        },
        anti_malware: vec![
            Product {
                vendor: Some("Apple Inc.".to_owned()),
                name: "Xprotect".to_owned(),
                version: Some(xprotect_version_value),
                defver: Some(xprotect_version.unwrap_or_default()),
                engver: Some(String::new()),
                datemon: Some(xprotect_month),
                dateday: Some(xprotect_day),
                dateyear: Some(xprotect_year),
                prod_type: Some("3".to_owned()),
                os_type: Some("4".to_owned()),
                real_time_protection: Some(xprotect_status.to_owned()),
                last_full_scan_time: Some("n/a".to_owned()),
                ..Product::default()
            },
            Product {
                vendor: Some("Apple Inc.".to_owned()),
                name: "Gatekeeper".to_owned(),
                version: Some(os_version_or_na.clone()),
                defver: Some(String::new()),
                engver: Some(String::new()),
                datemon: Some(gatekeeper_date.0),
                dateday: Some(gatekeeper_date.1),
                dateyear: Some(gatekeeper_date.2),
                prod_type: Some("3".to_owned()),
                os_type: Some("4".to_owned()),
                real_time_protection: Some(gatekeeper_enabled),
                last_full_scan_time: Some("n/a".to_owned()),
                ..Product::default()
            },
        ],
        disk_backup: vec![Product {
            vendor: Some("Apple Inc.".to_owned()),
            name: "Time Machine".to_owned(),
            version: Some("1.3".to_owned()),
            last_backup_time: Some("n/a".to_owned()),
            ..Product::default()
        }],
        disk_encryption: vec![Drive {
            drive_name: "All".to_owned(),
            enc_state: Some(encryption_state.to_owned()),
            product_version: Some(os_version_or_na.clone()),
        }],
        firewall: vec![
            firewall_product(
                "Apple Inc.",
                "Mac OS X Builtin Firewall",
                Some(&os_version_or_na),
                &app_firewall_enabled,
            ),
            firewall_product(
                "OpenBSD",
                "Packet Filter",
                Some(&os_version_or_na),
                &packet_filter_enabled,
            ),
        ],
        patch_management_product: Product {
            vendor: Some("Apple Inc.".to_owned()),
            name: "Software Update".to_owned(),
            version: Some("3.0".to_owned()),
            is_enabled: Some(patch_state),
            ..Product::default()
        },
        patches,
    }
}

pub(super) fn build_macos_xml(
    invocation: &ParsedInvocation,
    posture: &MacPosture,
) -> Result<String, HipCliError> {
    let generated = OffsetDateTime::parse(
        &invocation.generated_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| HipCliError::InvalidInvocation)?;
    let timestamp_format = time::format_description::parse(
        "[month repr:numerical padding:zero]/[day padding:zero]/[year] [hour padding:zero]:[minute padding:zero]:[second padding:zero]",
    )
    .map_err(|_| HipCliError::Xml)?;
    let generated_at = generated
        .format(&timestamp_format)
        .map_err(|_| HipCliError::Xml)?;
    let root_computer = invocation.computer.as_deref();
    let host_computer = posture
        .host_info
        .host_name
        .as_deref()
        .or(invocation.computer.as_deref());
    let host_id = posture.host_info.host_id.as_deref();

    let mut xml = XmlWriter::new();
    xml.declaration();
    xml.start("hip-report", &[("name", "hip-report")]);
    xml.text("md5-sum", Some(&invocation.md5));
    xml.text("user-name", Some(&invocation.user));
    xml.text("domain", Some(&invocation.domain));
    xml.text("host-name", root_computer);
    xml.text("host-id", host_id);
    xml.text("ip-address", Some(&invocation.client_ip));
    xml.text("ipv6-address", Some(&invocation.client_ipv6));
    xml.text("generate-time", Some(&generated_at));
    xml.text("hip-report-version", Some("4"));
    xml.start("categories", &[]);

    add_host_info(&mut xml, invocation, posture, host_computer, host_id);
    add_anti_malware(&mut xml, &posture.anti_malware);
    add_disk_backup(&mut xml, &posture.disk_backup);
    add_disk_encryption(&mut xml, &posture.disk_encryption);
    add_firewall(&mut xml, &posture.firewall);
    add_patch_management(
        &mut xml,
        &posture.patch_management_product,
        &posture.patches,
    );
    xml.start("entry", &[("name", "data-loss-prevention")]);
    xml.empty("list", &[]);
    xml.end("entry");

    xml.end("categories");
    xml.end("hip-report");
    Ok(xml.finish())
}

fn add_host_info(
    xml: &mut XmlWriter,
    invocation: &ParsedInvocation,
    posture: &MacPosture,
    computer: Option<&str>,
    host_id: Option<&str>,
) {
    let host = &posture.host_info;
    xml.start("entry", &[("name", "host-info")]);
    xml.text(
        "client-version",
        host.client_version
            .as_deref()
            .or(Some(&invocation.client_version)),
    );
    xml.text("os", host.os.as_deref());
    xml.text("os-vendor", host.os_vendor.as_deref().or(Some("Apple")));
    xml.text(
        "domain",
        host.domain.as_deref().or(Some(&invocation.domain)),
    );
    xml.text("host-name", computer);
    xml.text("host-id", host_id);
    xml.start("network-interface", &[]);
    let interfaces = effective_interfaces(host, invocation);
    for interface in interfaces {
        xml.start("entry", &[("name", &interface.name)]);
        xml.text("description", interface.description.as_deref());
        xml.text("mac-address", interface.mac_address.as_deref());
        add_addresses(xml, "ip-address", &interface.ipv4_addresses);
        add_addresses(xml, "ipv6-address", &interface.ipv6_addresses);
        xml.end("entry");
    }
    xml.end("network-interface");
    xml.end("entry");
}

fn effective_interfaces(host: &HostInfo, invocation: &ParsedInvocation) -> Vec<NetworkInterface> {
    if !host.interfaces.is_empty() {
        return host
            .interfaces
            .iter()
            .cloned()
            .map(|mut interface| {
                if interface.ipv4_addresses.is_empty() && invocation.client_ip != "0.0.0.0" {
                    interface.ipv4_addresses.push(invocation.client_ip.clone());
                }
                if interface.ipv6_addresses.is_empty() && invocation.client_ipv6 != "::" {
                    interface
                        .ipv6_addresses
                        .push(invocation.client_ipv6.clone());
                }
                interface
            })
            .collect();
    }
    if invocation.client_ip != "0.0.0.0" || invocation.client_ipv6 != "::" {
        return vec![NetworkInterface {
            name: "unknown".to_owned(),
            ipv4_addresses: (invocation.client_ip != "0.0.0.0")
                .then(|| invocation.client_ip.clone())
                .into_iter()
                .collect(),
            ipv6_addresses: (invocation.client_ipv6 != "::")
                .then(|| invocation.client_ipv6.clone())
                .into_iter()
                .collect(),
            ..NetworkInterface::default()
        }];
    }
    Vec::new()
}

fn add_addresses(xml: &mut XmlWriter, tag: &str, addresses: &[String]) {
    if addresses.is_empty() {
        return;
    }
    xml.start(tag, &[]);
    for address in addresses {
        xml.empty("entry", &[("name", address)]);
    }
    xml.end(tag);
}

fn add_anti_malware(xml: &mut XmlWriter, products: &[Product]) {
    xml.start("entry", &[("name", "anti-malware")]);
    xml.start("list", &[]);
    for product in products {
        add_product_start(xml, product);
        xml.text(
            "real-time-protection",
            Some(product.real_time_protection.as_deref().unwrap_or("n/a")),
        );
        xml.text(
            "last-full-scan-time",
            Some(product.last_full_scan_time.as_deref().unwrap_or("n/a")),
        );
        add_product_end(xml);
    }
    xml.end("list");
    xml.end("entry");
}

fn add_disk_backup(xml: &mut XmlWriter, products: &[Product]) {
    xml.start("entry", &[("name", "disk-backup")]);
    xml.start("list", &[]);
    for product in products {
        add_product_start(xml, product);
        xml.text(
            "last-backup-time",
            Some(product.last_backup_time.as_deref().unwrap_or("n/a")),
        );
        add_product_end(xml);
    }
    xml.end("list");
    xml.end("entry");
}

fn add_disk_encryption(xml: &mut XmlWriter, drives: &[Drive]) {
    let version = drives
        .first()
        .and_then(|drive| drive.product_version.as_deref())
        .unwrap_or("n/a");
    let product = Product {
        vendor: Some("Apple Inc.".to_owned()),
        name: "FileVault".to_owned(),
        version: Some(version.to_owned()),
        ..Product::default()
    };
    xml.start("entry", &[("name", "disk-encryption")]);
    xml.start("list", &[]);
    add_product_start(xml, &product);
    xml.start("drives", &[]);
    for drive in drives {
        xml.start("entry", &[]);
        xml.text("drive-name", Some(&drive.drive_name));
        xml.text(
            "enc-state",
            Some(drive.enc_state.as_deref().unwrap_or("unknown")),
        );
        xml.end("entry");
    }
    xml.end("drives");
    add_product_end(xml);
    xml.end("list");
    xml.end("entry");
}

fn add_firewall(xml: &mut XmlWriter, products: &[Product]) {
    xml.start("entry", &[("name", "firewall")]);
    xml.start("list", &[]);
    for product in products {
        add_product_start(xml, product);
        xml.text(
            "is-enabled",
            Some(product.is_enabled.as_deref().unwrap_or("n/a")),
        );
        add_product_end(xml);
    }
    xml.end("list");
    xml.end("entry");
}

fn add_patch_management(xml: &mut XmlWriter, product: &Product, patches: &[Patch]) {
    xml.start("entry", &[("name", "patch-management")]);
    xml.start("list", &[]);
    add_product_start(xml, product);
    xml.text(
        "is-enabled",
        Some(product.is_enabled.as_deref().unwrap_or("n/a")),
    );
    add_product_end(xml);
    xml.end("list");
    xml.start("missing-patches", &[]);
    for patch in patches {
        xml.start("entry", &[]);
        xml.text("title", Some(&patch.title));
        xml.text("description", patch.description.as_deref());
        xml.text("product", patch.product.as_deref());
        xml.text("vendor", patch.vendor.as_deref());
        xml.text("info-url", patch.info_url.as_deref());
        xml.text("kb-article-id", patch.kb_article_id.as_deref());
        xml.text(
            "security-bulletin-id",
            patch.security_bulletin_id.as_deref(),
        );
        xml.text("severity", patch.severity.as_deref());
        xml.text("category", patch.category.as_deref());
        xml.text(
            "is-installed",
            Some(patch.is_installed.as_deref().unwrap_or("n/a")),
        );
        xml.end("entry");
    }
    xml.end("missing-patches");
    xml.end("entry");
}

fn add_product_start(xml: &mut XmlWriter, product: &Product) {
    xml.start("entry", &[]);
    xml.start("ProductInfo", &[]);
    let attributes = [
        ("vendor", product.vendor.as_deref()),
        ("name", Some(product.name.as_str())),
        ("version", product.version.as_deref()),
        ("defver", product.defver.as_deref()),
        ("engver", product.engver.as_deref()),
        ("datemon", product.datemon.as_deref()),
        ("dateday", product.dateday.as_deref()),
        ("dateyear", product.dateyear.as_deref()),
        ("prodType", product.prod_type.as_deref()),
        ("osType", product.os_type.as_deref()),
    ];
    let present: Vec<(&str, &str)> = attributes
        .into_iter()
        .filter_map(|(name, value)| value.map(|value| (name, value)))
        .collect();
    xml.empty("Prod", &present);
}

fn add_product_end(xml: &mut XmlWriter) {
    xml.end("ProductInfo");
    xml.end("entry");
}

fn collect_physical_identity(runner: &dyn CommandRunner) -> Option<(String, String)> {
    let networksetup = runner.run(
        "/usr/sbin/networksetup",
        &["-listallhardwareports"],
        Duration::from_secs(5),
    );
    if networksetup.success
        && let Some(identity) = parse_networksetup(&networksetup.stdout)
    {
        return Some(identity);
    }
    let ifconfig = runner.run("/sbin/ifconfig", &[], Duration::from_secs(5));
    if ifconfig.success {
        parse_ifconfig(&ifconfig.stdout)
    } else {
        None
    }
}

fn parse_networksetup(output: &str) -> Option<(String, String)> {
    let mut candidates = Vec::new();
    let mut port = String::new();
    let mut device = String::new();
    let mut mac = String::new();
    for line in output.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.is_empty() {
            if is_physical_interface(&device)
                && let Some(valid_mac) = valid_mac(&mac)
            {
                candidates.push((port.clone(), device.clone(), valid_mac));
            }
            port.clear();
            device.clear();
            mac.clear();
        } else if let Some((key, value)) = line.split_once(':') {
            match key.trim() {
                "Hardware Port" => port = value.trim().to_owned(),
                "Device" => device = value.trim().to_owned(),
                "Ethernet Address" => mac = value.trim().to_owned(),
                _ => {}
            }
        }
    }
    candidates
        .iter()
        .find(|(port, _, _)| port.eq_ignore_ascii_case("Wi-Fi"))
        .or_else(|| candidates.first())
        .map(|(_, device, mac)| (device.clone(), mac.clone()))
}

fn parse_ifconfig(output: &str) -> Option<(String, String)> {
    let mut current = None;
    for line in output.lines() {
        if !line.starts_with(char::is_whitespace)
            && let Some((name, rest)) = line.split_once(':')
            && rest.contains("flags=")
        {
            current = is_physical_interface(name).then(|| name.to_owned());
            continue;
        }
        if let Some(name) = &current
            && line.contains("ether")
            && let Some(mac) = valid_mac(line)
        {
            return Some((name.clone(), mac));
        }
    }
    None
}

fn valid_mac(value: &str) -> Option<String> {
    value.split_whitespace().find_map(|word| {
        let candidate =
            word.trim_matches(|character: char| !character.is_ascii_hexdigit() && character != ':');
        let parts: Vec<&str> = candidate.split(':').collect();
        (parts.len() == 6
            && parts
                .iter()
                .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
            && !parts.iter().all(|part| *part == "00"))
        .then(|| candidate.to_ascii_lowercase())
    })
}

fn is_physical_interface(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    !name.is_empty()
        && ![
            "lo", "utun", "tun", "tap", "ipsec", "gif", "stf", "awdl", "llw", "bridge",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn plist_value(runner: &dyn CommandRunner, path: &Path, key: &str) -> Option<String> {
    let path = path.to_str()?;
    let result = runner.run(
        "/usr/bin/plutil",
        &["-extract", key, "raw", "-o", "-", path],
        Duration::from_secs(5),
    );
    result
        .success
        .then(|| result.stdout.trim().to_owned())
        .filter(|value| bounded_text(value, 1024))
}

fn command_state(result: &CommandResult, enabled: &str, disabled: &str) -> String {
    if !result.success {
        return "n/a".to_owned();
    }
    let output = result.stdout.to_ascii_lowercase();
    if output.contains(enabled) {
        "yes".to_owned()
    } else if output.contains(disabled) {
        "no".to_owned()
    } else {
        "n/a".to_owned()
    }
}

fn anti_malware_product(name: &str, version: &str, state: &str) -> Product {
    Product {
        vendor: Some("Apple Inc.".to_owned()),
        name: name.to_owned(),
        version: Some(version.to_owned()),
        defver: Some(String::new()),
        engver: Some(String::new()),
        datemon: Some(String::new()),
        dateday: Some(String::new()),
        dateyear: Some(String::new()),
        prod_type: Some("3".to_owned()),
        os_type: Some("4".to_owned()),
        real_time_protection: Some(state.to_owned()),
        last_full_scan_time: Some("n/a".to_owned()),
        ..Product::default()
    }
}

fn firewall_product(vendor: &str, name: &str, version: Option<&str>, enabled: &str) -> Product {
    Product {
        vendor: Some(vendor.to_owned()),
        name: name.to_owned(),
        version: version.map(str::to_owned),
        is_enabled: Some(enabled.to_owned()),
        ..Product::default()
    }
}

fn date_parts(value: &str) -> Option<(String, String, String)> {
    let bytes = value.as_bytes();
    if bytes.len() < 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    Some((
        value[5..7].to_owned(),
        value[8..10].to_owned(),
        value[..4].to_owned(),
    ))
}

fn file_mtime_date_parts(path: &Path) -> Option<(String, String, String)> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let datetime = OffsetDateTime::from(modified);
    Some((
        format!("{:02}", u8::from(datetime.month())),
        format!("{:02}", datetime.day()),
        format!("{:04}", datetime.year()),
    ))
}

fn empty_date_parts() -> (String, String, String) {
    (String::new(), String::new(), String::new())
}

#[derive(Serialize, Deserialize)]
struct UpdateCache {
    created_unix: i64,
    patches: Vec<Patch>,
}

fn collect_software_updates(
    runner: &dyn CommandRunner,
    cache_path: &Path,
    now: OffsetDateTime,
) -> (Vec<Patch>, String) {
    if let Some(patches) = read_update_cache(cache_path, now) {
        return (patches, "yes".to_owned());
    }
    let result = runner.run(
        "/usr/sbin/softwareupdate",
        &["--list"],
        Duration::from_secs(45),
    );
    if !result.success {
        return (Vec::new(), "n/a".to_owned());
    }
    match parse_software_updates(&result.stdout) {
        Some(patches) => {
            let _ = write_update_cache(cache_path, now, &patches);
            (patches, "yes".to_owned())
        }
        None => (Vec::new(), "n/a".to_owned()),
    }
}

fn patch(title: String, severity: &str) -> Patch {
    Patch {
        description: Some(title.clone()),
        product: Some("macOS".to_owned()),
        vendor: Some("Apple Inc.".to_owned()),
        severity: Some(severity.to_owned()),
        category: Some("update".to_owned()),
        is_installed: Some("no".to_owned()),
        title,
        ..Patch::default()
    }
}

fn parse_software_updates(output: &str) -> Option<Vec<Patch>> {
    if output
        .to_ascii_lowercase()
        .contains("no new software available")
    {
        return Some(Vec::new());
    }
    let mut patches = Vec::new();
    let mut label: Option<String> = None;
    let mut restart = false;
    for line in output.lines().chain(std::iter::once("")) {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("* Label:") {
            if let Some(previous) = label.take() {
                patches.push(patch(previous, if restart { "2" } else { "1" }));
            }
            let value = value.trim();
            label = (!value.is_empty()).then(|| value.to_owned());
            restart = false;
        } else if label.is_some() && trimmed.to_ascii_lowercase().contains("restart") {
            restart = true;
        } else if trimmed.is_empty()
            && let Some(previous) = label.take()
        {
            patches.push(patch(previous, if restart { "2" } else { "1" }));
            restart = false;
        }
    }
    (!patches.is_empty()).then_some(patches)
}

fn read_update_cache(path: &Path, now: OffsetDateTime) -> Option<Vec<Patch>> {
    if fs::metadata(path).ok()?.len() > 1024 * 1024 {
        return None;
    }
    let cache: UpdateCache = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    let age = now.unix_timestamp().saturating_sub(cache.created_unix);
    (0..=UPDATE_CACHE_MAX_AGE_SECONDS)
        .contains(&age)
        .then_some(cache.patches)
}

fn write_update_cache(path: &Path, now: OffsetDateTime, patches: &[Patch]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("updates"),
        std::process::id(),
        now.unix_timestamp_nanos()
    ));
    let payload = serde_json::to_vec(&UpdateCache {
        created_unix: now.unix_timestamp(),
        patches: patches.to_vec(),
    })?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&payload)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn update_cache_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/root"))
        .join(".cache/hyu-openconnect/softwareupdate-cache.json")
}

fn run_command(program: &str, args: &[&str], timeout: Duration) -> CommandResult {
    let mut child = match Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            return CommandResult {
                success: false,
                stdout: String::new(),
            };
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let _ = stderr_reader.join();
    CommandResult {
        success: status.is_some_and(|status| status.success()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
    }
}

fn read_bounded<R: Read>(reader: Option<R>) -> Vec<u8> {
    let mut output = Vec::new();
    if let Some(reader) = reader {
        let _ = reader.take(MAX_COMMAND_OUTPUT).read_to_end(&mut output);
    }
    output
}

struct XmlWriter {
    output: String,
    depth: usize,
}

impl XmlWriter {
    fn new() -> Self {
        Self {
            output: String::with_capacity(8192),
            depth: 0,
        }
    }

    fn declaration(&mut self) {
        self.output
            .push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    }

    fn start(&mut self, tag: &str, attributes: &[(&str, &str)]) {
        self.indent();
        self.output.push('<');
        self.output.push_str(tag);
        self.attributes(attributes);
        self.output.push_str(">\n");
        self.depth += 1;
    }

    fn end(&mut self, tag: &str) {
        self.depth -= 1;
        self.indent();
        self.output.push_str("</");
        self.output.push_str(tag);
        self.output.push_str(">\n");
    }

    fn empty(&mut self, tag: &str, attributes: &[(&str, &str)]) {
        self.indent();
        self.output.push('<');
        self.output.push_str(tag);
        self.attributes(attributes);
        self.output.push_str(" />\n");
    }

    fn text(&mut self, tag: &str, value: Option<&str>) {
        match value {
            Some(value) if !value.is_empty() => {
                self.indent();
                self.output.push('<');
                self.output.push_str(tag);
                self.output.push('>');
                escape_xml_into(&mut self.output, value);
                self.output.push_str("</");
                self.output.push_str(tag);
                self.output.push_str(">\n");
            }
            _ => self.empty(tag, &[]),
        }
    }

    fn attributes(&mut self, attributes: &[(&str, &str)]) {
        for (name, value) in attributes {
            self.output.push(' ');
            self.output.push_str(name);
            self.output.push_str("=\"");
            escape_xml_into(&mut self.output, value);
            self.output.push('"');
        }
    }

    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.output.push_str("  ");
        }
    }

    fn finish(self) -> String {
        self.output
    }
}

fn escape_xml_into(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            character => output.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[derive(Default)]
    struct FakeRunner {
        results: HashMap<String, CommandResult>,
    }

    impl FakeRunner {
        fn add(&mut self, program: &str, args: &[&str], stdout: &str) {
            self.results.insert(
                command_key(program, args),
                CommandResult {
                    success: true,
                    stdout: stdout.to_owned(),
                },
            );
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str], _timeout: Duration) -> CommandResult {
            self.results
                .get(&command_key(program, args))
                .cloned()
                .unwrap_or(CommandResult {
                    success: false,
                    stdout: String::new(),
                })
        }
    }

    fn command_key(program: &str, args: &[&str]) -> String {
        std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join("\0")
    }

    #[test]
    fn collector_ports_python_security_identity_and_update_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let system = temporary.path().join("SystemVersion.plist");
        let xprotect = temporary.path().join("XProtect.plist");
        fs::write(&system, b"fixture").unwrap();
        fs::write(&xprotect, b"fixture").unwrap();
        let system_path = system.to_str().unwrap();
        let xprotect_path = xprotect.to_str().unwrap();
        let mut runner = FakeRunner::default();
        runner.add(
            "/usr/bin/plutil",
            &["-extract", "ProductVersion", "raw", "-o", "-", system_path],
            "14.5\n",
        );
        runner.add(
            "/usr/bin/plutil",
            &[
                "-extract",
                "CFBundleShortVersionString",
                "raw",
                "-o",
                "-",
                xprotect_path,
            ],
            "2176\n",
        );
        runner.add(
            "/usr/bin/plutil",
            &[
                "-extract",
                "LastModification",
                "raw",
                "-o",
                "-",
                xprotect_path,
            ],
            "2026-08-01T00:00:00Z\n",
        );
        runner.add(
            "/usr/sbin/networksetup",
            &["-listallhardwareports"],
            "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n",
        );
        runner.add("/usr/sbin/spctl", &["--status"], "assessments enabled\n");
        runner.add("/usr/bin/fdesetup", &["status"], "FileVault is On.\n");
        runner.add(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
            "Firewall is enabled. (State = 1)\n",
        );
        runner.add("/sbin/pfctl", &["-s", "info"], "Status: Disabled\n");
        runner.add(
            "/usr/sbin/softwareupdate",
            &["--list"],
            "Software Update Tool\nNo new software available.\n",
        );

        let posture = collect_posture(
            &runner,
            &system,
            &xprotect,
            &temporary.path().join("cache/updates.json"),
            OffsetDateTime::parse(
                "2026-08-04T09:10:11Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap(),
        );

        assert_eq!(posture.host_info.os.as_deref(), Some("Apple Mac OS X 14.5"));
        assert_eq!(
            posture.host_info.host_id.as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(posture.host_info.interfaces[0].name, "en0");
        assert_eq!(posture.anti_malware[0].version.as_deref(), Some("2176"));
        assert_eq!(posture.anti_malware[0].datemon.as_deref(), Some("08"));
        assert_eq!(
            posture.anti_malware[1].real_time_protection.as_deref(),
            Some("yes")
        );
        assert_eq!(
            posture.disk_encryption[0].enc_state.as_deref(),
            Some("encrypted")
        );
        assert_eq!(posture.firewall[0].is_enabled.as_deref(), Some("yes"));
        assert_eq!(posture.firewall[1].is_enabled.as_deref(), Some("no"));
        assert_eq!(
            posture.patch_management_product.is_enabled.as_deref(),
            Some("yes")
        );
        let mode = fs::metadata(temporary.path().join("cache/updates.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn collector_never_turns_missing_security_evidence_into_positive_state() {
        let temporary = tempfile::tempdir().unwrap();
        let posture = collect_posture(
            &FakeRunner::default(),
            &temporary.path().join("missing-system"),
            &temporary.path().join("missing-xprotect"),
            &temporary.path().join("updates.json"),
            OffsetDateTime::UNIX_EPOCH,
        );

        assert_eq!(
            posture.anti_malware[0].real_time_protection.as_deref(),
            Some("n/a")
        );
        assert_eq!(
            posture.anti_malware[1].real_time_protection.as_deref(),
            Some("n/a")
        );
        assert_eq!(
            posture.disk_encryption[0].enc_state.as_deref(),
            Some("unknown")
        );
        assert_eq!(posture.firewall[0].is_enabled.as_deref(), Some("n/a"));
        assert_eq!(posture.firewall[1].is_enabled.as_deref(), Some("n/a"));
        assert_eq!(
            posture.patch_management_product.is_enabled.as_deref(),
            Some("n/a")
        );
    }

    #[test]
    fn physical_interface_parsers_prefer_wifi_and_exclude_tunnels() {
        let output = "Hardware Port: Thunderbolt Ethernet\nDevice: en7\nEthernet Address: 11:22:33:44:55:66\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: AA:BB:CC:DD:EE:FF\n";
        assert_eq!(
            parse_networksetup(output),
            Some(("en0".to_owned(), "aa:bb:cc:dd:ee:ff".to_owned()))
        );
        let fallback = "lo0: flags=8049<UP,LOOPBACK>\n\tether 00:00:00:00:00:00\nutun4: flags=8051<UP>\n\tether 12:34:56:78:9a:bc\nen5: flags=8863<UP,BROADCAST>\n\tether 22:33:44:55:66:77\n";
        assert_eq!(
            parse_ifconfig(fallback),
            Some(("en5".to_owned(), "22:33:44:55:66:77".to_owned()))
        );
    }

    #[test]
    fn software_update_parser_marks_restart_and_rejects_malformed_output() {
        let output = "Software Update Tool\n   * Label: macOS-14.6\n        Title: macOS, Version: 14.6, Size: 1K, Recommended: YES, Action: restart,\n   * Label: Safari-17.6\n        Title: Safari, Version: 17.6, Recommended: YES,\n";
        let patches = parse_software_updates(output).unwrap();
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0].severity.as_deref(), Some("2"));
        assert_eq!(patches[1].severity.as_deref(), Some("1"));
        assert!(parse_software_updates("localized unknown output").is_none());
    }

    #[test]
    fn xml_escaping_covers_text_and_attributes() {
        let mut output = String::new();
        escape_xml_into(&mut output, "&<>\"'");
        assert_eq!(output, "&amp;&lt;&gt;&quot;&apos;");
    }
}
