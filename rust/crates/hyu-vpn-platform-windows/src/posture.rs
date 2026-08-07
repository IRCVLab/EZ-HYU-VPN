use thiserror::Error;

const MAX_XML_BYTES: usize = 64 * 1024;
const MAX_VALUE_BYTES: usize = 1024;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WindowsPostureError {
    #[error("Windows posture evidence is invalid")]
    InvalidEvidence,
    #[error("HIP XML is invalid")]
    InvalidXml,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsHipContext {
    pub md5: String,
    pub user: String,
    pub domain: String,
    pub client_ip: String,
    pub client_ipv6: String,
    pub client_version: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPosture {
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
    pub firewall: String,
    pub endpoint: String,
    pub encryption: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsEvidence {
    pub product_name: Option<String>,
    pub display_version: Option<String>,
    pub build_number: Option<String>,
    pub hostname: Option<String>,
    pub firewall_enabled: Option<bool>,
    pub defender_enabled: Option<bool>,
    pub encryption: Option<String>,
}

pub struct WindowsPostureCollector {
    fixture: Option<WindowsEvidence>,
}

impl WindowsPostureCollector {
    pub fn production() -> Self {
        Self { fixture: None }
    }

    pub fn from_evidence(evidence: WindowsEvidence) -> Self {
        Self {
            fixture: Some(evidence),
        }
    }

    pub fn collect(&self) -> Result<WindowsPosture, WindowsPostureError> {
        let evidence = self
            .fixture
            .clone()
            .unwrap_or_else(collect_windows_evidence);
        let product = bounded(evidence.product_name.as_deref()).unwrap_or("Windows");
        let display = bounded(evidence.display_version.as_deref()).unwrap_or("unknown");
        let build = bounded(evidence.build_number.as_deref()).unwrap_or("unknown");
        let hostname = bounded(evidence.hostname.as_deref()).unwrap_or("unknown");
        let encryption = bounded(evidence.encryption.as_deref()).unwrap_or("unknown");
        Ok(WindowsPosture {
            os_name: product.to_owned(),
            os_version: format!("{display} (build {build})"),
            hostname: hostname.to_owned(),
            firewall: state(evidence.firewall_enabled),
            endpoint: state(evidence.defender_enabled),
            encryption: encryption.to_owned(),
        })
    }
}

impl WindowsPosture {
    pub fn to_hip_xml(&self, context: &WindowsHipContext) -> Result<String, WindowsPostureError> {
        for value in [
            &self.os_name,
            &self.os_version,
            &self.hostname,
            &self.firewall,
            &self.endpoint,
            &self.encryption,
            &context.md5,
            &context.user,
            &context.domain,
            &context.client_ip,
            &context.client_ipv6,
            &context.client_version,
            &context.generated_at,
        ] {
            if bounded(Some(value)).is_none() {
                return Err(WindowsPostureError::InvalidEvidence);
            }
        }
        let os = format!("{} {}", self.os_name, self.os_version);
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        line(&mut xml, 0, "<hip-report name=\"hip-report\">");
        text(&mut xml, 1, "md5-sum", &context.md5);
        text(&mut xml, 1, "user-name", &context.user);
        text(&mut xml, 1, "domain", &context.domain);
        text(&mut xml, 1, "host-name", &self.hostname);
        text(&mut xml, 1, "host-id", "unknown");
        text(&mut xml, 1, "ip-address", &context.client_ip);
        text(&mut xml, 1, "ipv6-address", &context.client_ipv6);
        text(&mut xml, 1, "generate-time", &context.generated_at);
        text(&mut xml, 1, "hip-report-version", "4");
        line(&mut xml, 1, "<categories>");
        line(&mut xml, 2, "<entry name=\"host-info\">");
        text(&mut xml, 3, "client-version", &context.client_version);
        text(&mut xml, 3, "os", &os);
        text(&mut xml, 3, "os-vendor", "Microsoft");
        text(&mut xml, 3, "domain", &context.domain);
        text(&mut xml, 3, "host-name", &self.hostname);
        text(&mut xml, 3, "host-id", "unknown");
        line(&mut xml, 3, "<network-interface>");
        line(&mut xml, 4, "<entry name=\"Windows network\">");
        text(&mut xml, 5, "description", "Windows network");
        text(&mut xml, 5, "mac-address", "unknown");
        line(&mut xml, 5, "<ip-address>");
        line(
            &mut xml,
            6,
            &format!("<entry name=\"{}\"/>", escape_attr(&context.client_ip)),
        );
        line(&mut xml, 5, "</ip-address>");
        line(&mut xml, 4, "</entry>");
        line(&mut xml, 3, "</network-interface>");
        line(&mut xml, 2, "</entry>");
        product_category(
            &mut xml,
            "anti-malware",
            "Microsoft",
            "Microsoft Defender Antivirus",
            &self.endpoint,
            "real-time-protection",
        );
        line(&mut xml, 2, "<entry name=\"disk-backup\"><list/></entry>");
        line(&mut xml, 2, "<entry name=\"disk-encryption\">");
        line(&mut xml, 3, "<list><entry><ProductInfo>");
        line(
            &mut xml,
            4,
            "<Prod vendor=\"Microsoft\" name=\"BitLocker\" version=\"unknown\"/>",
        );
        line(&mut xml, 4, "<drives><entry>");
        text(&mut xml, 5, "drive-name", "System");
        text(&mut xml, 5, "enc-state", &self.encryption);
        line(&mut xml, 4, "</entry></drives>");
        line(&mut xml, 3, "</ProductInfo></entry></list>");
        line(&mut xml, 2, "</entry>");
        product_category(
            &mut xml,
            "firewall",
            "Microsoft",
            "Windows Defender Firewall",
            &self.firewall,
            "is-enabled",
        );
        product_category(
            &mut xml,
            "patch-management",
            "Microsoft",
            "Windows Update",
            "yes",
            "is-enabled",
        );
        line(
            &mut xml,
            2,
            "<entry name=\"data-loss-prevention\"><list/></entry>",
        );
        line(&mut xml, 1, "</categories>");
        line(&mut xml, 0, "</hip-report>");
        if xml.len() > MAX_XML_BYTES {
            return Err(WindowsPostureError::InvalidXml);
        }
        Ok(xml)
    }
}

fn product_category(
    xml: &mut String,
    category: &str,
    vendor: &str,
    name: &str,
    value: &str,
    field: &str,
) {
    line(
        xml,
        2,
        &format!("<entry name=\"{}\">", escape_attr(category)),
    );
    line(xml, 3, "<list><entry><ProductInfo>");
    line(
        xml,
        4,
        &format!(
            "<Prod vendor=\"{}\" name=\"{}\" version=\"unknown\"/>",
            escape_attr(vendor),
            escape_attr(name)
        ),
    );
    text(xml, 4, field, value);
    line(xml, 3, "</ProductInfo></entry></list>");
    line(xml, 2, "</entry>");
}

fn state(value: Option<bool>) -> String {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
    .to_owned()
}

fn bounded(value: Option<&str>) -> Option<&str> {
    value.filter(|value| {
        !value.is_empty()
            && value.len() <= MAX_VALUE_BYTES
            && !value.chars().any(|character| character.is_control())
    })
}

fn line(xml: &mut String, indent: usize, value: &str) {
    xml.push_str(&"  ".repeat(indent));
    xml.push_str(value);
    xml.push('\n');
}

fn text(xml: &mut String, indent: usize, tag: &str, value: &str) {
    line(
        xml,
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

#[cfg(windows)]
fn collect_windows_evidence() -> WindowsEvidence {
    WindowsEvidence {
        product_name: read_registry_string(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        ),
        display_version: read_registry_string(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "DisplayVersion",
        ),
        build_number: read_registry_string(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentBuildNumber",
        ),
        hostname: windows_hostname(),
        firewall_enabled: registry_firewall_enabled(),
        defender_enabled: registry_defender_enabled(),
        encryption: None,
    }
}

#[cfg(not(windows))]
fn collect_windows_evidence() -> WindowsEvidence {
    WindowsEvidence {
        product_name: None,
        display_version: None,
        build_number: None,
        hostname: None,
        firewall_enabled: None,
        defender_enabled: None,
        encryption: None,
    }
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn read_registry_string(
    root: windows_sys::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RRF_RT_REG_SZ, RegGetValueW};

    let path = wide(path);
    let name = wide(name);
    let mut bytes = 0_u32;
    let query = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if query != ERROR_SUCCESS || !(2..=4096).contains(&bytes) {
        return None;
    }
    let mut buffer = vec![0_u16; usize::try_from(bytes / 2).ok()?];
    let query = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if query != ERROR_SUCCESS {
        return None;
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    bounded(Some(String::from_utf16(&buffer[..length]).ok()?.as_str())).map(str::to_owned)
}

#[cfg(windows)]
fn read_registry_dword(path: &str, name: &str) -> Option<u32> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW,
    };

    let path = wide(path);
    let name = wide(name);
    let mut value = 0_u32;
    let mut bytes = u32::try_from(std::mem::size_of::<u32>()).ok()?;
    let query = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut bytes,
        )
    };
    (query == ERROR_SUCCESS && bytes == 4).then_some(value)
}

#[cfg(windows)]
fn registry_firewall_enabled() -> Option<bool> {
    const PROFILES: [&str; 3] = [
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
    ];
    let values: Vec<_> = PROFILES
        .iter()
        .filter_map(|path| read_registry_dword(path, "EnableFirewall"))
        .collect();
    (!values.is_empty()).then(|| values.iter().any(|value| *value != 0))
}

#[cfg(windows)]
fn registry_defender_enabled() -> Option<bool> {
    read_registry_dword(r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware")
        .map(|disabled| disabled == 0)
}

#[cfg(windows)]
fn windows_hostname() -> Option<String> {
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

    let mut buffer = vec![0_u16; 256];
    let mut length = u32::try_from(buffer.len()).ok()?;
    let ok = unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut length) };
    if ok == 0 {
        return None;
    }
    let value = String::from_utf16(&buffer[..usize::try_from(length).ok()?]).ok()?;
    bounded(Some(&value)).map(str::to_owned)
}
