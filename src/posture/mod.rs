//! Cross-platform posture collector. Dispatches to the OS-specific module
//! and assembles the final `PostureReport` + derived findings.

use crate::report::{Finding, PostureReport};
use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};
use sysinfo::System;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub async fn collect() -> Result<PostureReport> {
    let mut sys = System::new();
    sys.refresh_cpu_all();
    sys.refresh_memory();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".into());
    let kernel = System::kernel_version().unwrap_or_default();
    let os_name = System::name().unwrap_or_default();
    let os_ver = System::os_version().unwrap_or_default();
    let uptime = System::uptime();

    let mut report = PostureReport {
        schema: 1,
        collected_at: Utc::now(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        device_fingerprint_v2: String::new(),
        host_uid: host_uid(),
        hostname,
        platform: std::env::consts::OS.to_string(),
        os_name,
        os_version: os_ver,
        kernel,
        arch: std::env::consts::ARCH.to_string(),
        uptime_secs: uptime,
        current_user: current_user(),
        disk_encryption: Default::default(),
        screen_lock: Default::default(),
        firewall: Default::default(),
        antivirus: Default::default(),
        os_updates: Default::default(),
        remote_access: Default::default(),
        hardware_root_of_trust: Default::default(),
        findings: Vec::new(),
    };

    #[cfg(target_os = "macos")]
    macos::populate(&mut report).await;
    #[cfg(target_os = "linux")]
    linux::populate(&mut report).await;
    #[cfg(target_os = "windows")]
    windows::populate(&mut report).await;

    report.device_fingerprint_v2 = device_fingerprint_v2(&report);
    derive_findings(&mut report);
    Ok(report)
}

/// Stable per-host identifier — survives reinstall of cydevice itself.
/// macOS: IOPlatformUUID via ioreg
/// Linux: /etc/machine-id
/// Windows: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
/// Fallback: hostname (not great, but better than nothing).
fn host_uid() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if let Some(idx) = line.find("\"IOPlatformUUID\" = \"") {
                    let rest = &line[idx + 21..];
                    if let Some(end) = rest.find('"') {
                        return rest[..end].to_string();
                    }
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
            if let Ok(guid) = key.get_value::<String, _>("MachineGuid") {
                return guid;
            }
        }
    }
    System::host_name().unwrap_or_else(|| "unknown".into())
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn device_fingerprint_v2(r: &PostureReport) -> String {
    let mut fields = vec![
        ("v", "2".to_string()),
        ("platform", r.platform.clone()),
        ("host_uid", r.host_uid.clone()),
        ("arch", r.arch.clone()),
        ("os_name", r.os_name.clone()),
        ("os_version", r.os_version.clone()),
        ("disk_mechanism", r.disk_encryption.mechanism.clone()),
        (
            "hrt_kind",
            if r.hardware_root_of_trust.kind.is_empty() {
                "unknown".into()
            } else {
                r.hardware_root_of_trust.kind.clone()
            },
        ),
        (
            "hrt_vendor",
            r.hardware_root_of_trust
                .vendor
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        ),
        (
            "hrt_present",
            if r.hardware_root_of_trust.present {
                "true".into()
            } else {
                "false".into()
            },
        ),
    ];
    fields.sort_by(|a, b| a.0.cmp(b.0));

    let canonical = fields
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, sanitize_fingerprint_value(&v)))
        .collect::<Vec<_>>()
        .join("\n");

    let digest = Sha256::digest(canonical.as_bytes());
    hex_lower(&digest)
}

fn sanitize_fingerprint_value(value: &str) -> String {
    value.trim().replace(['\n', '\r'], " ").to_ascii_lowercase()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!(),
    }
}

/// Build findings from the populated report. Every rule has a stable id so
/// the backend can dedupe + render a per-rule history.
fn derive_findings(r: &mut PostureReport) {
    let host = &r.hostname;

    if r.disk_encryption.assessed && !r.disk_encryption.enabled {
        r.findings.push(Finding::new(
            "device.disk_encryption.disabled",
            "critical",
            &format!("Disk not encrypted: {}", host),
            "Full-disk encryption is not active. Theft or seizure of the device exposes all on-disk data.",
            match r.platform.as_str() {
                "macos"   => "Enable FileVault: System Settings → Privacy & Security → FileVault → Turn On.",
                "linux"   => "Re-image with LUKS-on-LVM, or migrate /home to an encrypted volume.",
                "windows" => "Enable BitLocker: Control Panel → BitLocker Drive Encryption → Turn On.",
                _ => "Enable full-disk encryption.",
            },
        ));
    }
    if let Some(false) = r.disk_encryption.recovery_key_escrowed {
        r.findings.push(Finding::new(
            "device.disk_encryption.recovery_key_not_escrowed",
            "high",
            &format!("Recovery key not escrowed: {}", host),
            "Encryption is on but the recovery key isn't escrowed centrally. A lost passphrase = data loss.",
            "Configure recovery-key escrow with your IdP / Cybrium device profile.",
        ));
    }

    if r.screen_lock.assessed && !r.screen_lock.enabled {
        r.findings.push(Finding::new(
            "device.screen_lock.disabled",
            "high",
            &format!("Screen lock disabled: {}", host),
            "The device does not lock when idle. Anyone with physical proximity can access it.",
            "Set an idle screen-lock of 5–10 minutes with a password requirement.",
        ));
    } else if r.screen_lock.assessed
        && r.screen_lock.idle_timeout_assessed
        && r.screen_lock.idle_timeout_secs.unwrap_or(0) > 900
    {
        r.findings.push(Finding::new(
            "device.screen_lock.timeout_too_long",
            "medium",
            &format!("Screen lock timeout > 15min: {}", host),
            format!(
                "Idle timeout is {}s — SOC 2 CC6.6 expects ≤15min.",
                r.screen_lock.idle_timeout_secs.unwrap_or(0)
            )
            .as_str(),
            "Reduce the idle timeout to 600 seconds (10 minutes) or less.",
        ));
    }

    if r.firewall.assessed && !r.firewall.enabled {
        r.findings.push(Finding::new(
            "device.firewall.disabled",
            "high",
            &format!("Host firewall disabled: {}", host),
            "Inbound network filtering is not active.",
            match r.platform.as_str() {
                "macos" => "Enable: System Settings → Network → Firewall → Turn On.",
                "linux" => "Enable ufw / firewalld with default-deny on inbound.",
                "windows" => "Enable Windows Defender Firewall (all profiles).",
                _ => "Enable the host firewall.",
            },
        ));
    }

    if r.antivirus.assessed && !r.antivirus.running {
        r.findings.push(Finding::new(
            "device.antivirus.not_running",
            "medium",
            &format!("No real-time AV detected: {}", host),
            "Endpoint protection (XProtect / Defender / equivalent) is not reporting active.",
            "Confirm endpoint protection is running and real-time scanning is enabled.",
        ));
    }

    if r.os_updates.assessed && r.os_updates.pending_updates > 0 {
        let sev = if r.os_updates.pending_updates > 5 {
            "high"
        } else {
            "medium"
        };
        r.findings.push(Finding::new(
            "device.os_updates.pending",
            sev,
            &format!(
                "{} pending OS updates on {}",
                r.os_updates.pending_updates, host
            ),
            "Operating-system patches are available but not installed.",
            "Run software updates and reboot if required.",
        ));
    }
    if r.os_updates.auto_update_enabled == Some(false) {
        r.findings.push(Finding::new(
            "device.os_updates.auto_disabled",
            "medium",
            &format!("Automatic OS updates disabled: {}", host),
            "Patch lag widens the exploitation window.",
            "Enable automatic OS updates.",
        ));
    }

    if r.remote_access.assessed
        && (r.remote_access.ssh_enabled || r.remote_access.remote_desktop_enabled)
    {
        let svc = if r.remote_access.remote_desktop_enabled {
            "Remote Desktop / ARD"
        } else {
            "SSH"
        };
        r.findings.push(Finding::new(
            "device.remote_access.enabled",
            "medium",
            &format!("{} enabled: {}", svc, host),
            format!(
                "Remote access service '{}' is enabled or running. This increases attack surface, especially on portable devices.",
                svc
            )
            .as_str(),
            "Disable unless explicitly required; gate behind WireGuard / Tailscale if needed.",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::derive_findings;
    use crate::report::{
        Antivirus, DiskEncryption, Firewall, HardwareRootOfTrust, OsUpdates, PostureReport,
        RemoteAccess, ScreenLock,
    };
    use chrono::Utc;

    fn base_report() -> PostureReport {
        PostureReport {
            schema: 1,
            collected_at: Utc::now(),
            agent_version: "test".into(),
            device_fingerprint_v2: String::new(),
            host_uid: "host-1".into(),
            hostname: "laptop-1".into(),
            platform: "linux".into(),
            os_name: "Linux".into(),
            os_version: "1".into(),
            kernel: "1".into(),
            arch: "x86_64".into(),
            uptime_secs: 1,
            current_user: "tester".into(),
            disk_encryption: DiskEncryption::default(),
            screen_lock: ScreenLock::default(),
            firewall: Firewall::default(),
            antivirus: Antivirus::default(),
            os_updates: OsUpdates::default(),
            remote_access: RemoteAccess::default(),
            hardware_root_of_trust: HardwareRootOfTrust::default(),
            findings: Vec::new(),
        }
    }

    #[test]
    fn unknown_controls_do_not_emit_failure_findings() {
        let mut report = base_report();
        derive_findings(&mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn assessed_controls_still_emit_findings() {
        let mut report = base_report();
        report.firewall.assessed = true;
        report.antivirus.assessed = true;
        report.os_updates.assessed = true;
        report.os_updates.pending_updates = 2;
        derive_findings(&mut report);

        let ids: Vec<_> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"device.firewall.disabled"));
        assert!(ids.contains(&"device.antivirus.not_running"));
        assert!(ids.contains(&"device.os_updates.pending"));
    }

    #[test]
    fn contract_shape_is_unchanged_for_internal_fields() {
        let json = serde_json::to_value(base_report()).unwrap();
        let obj = json.as_object().unwrap();

        assert!(obj.contains_key("disk_encryption"));
        assert!(obj.contains_key("screen_lock"));
        assert!(obj.contains_key("firewall"));
        assert!(obj.contains_key("antivirus"));
        assert!(obj.contains_key("os_updates"));
        assert!(obj.contains_key("remote_access"));
        assert!(obj.contains_key("hardware_root_of_trust"));
        assert!(obj.contains_key("device_fingerprint_v2"));

        for key in [
            "assessed",
            "idle_timeout_assessed",
            "pending_updates_assessed",
        ] {
            assert!(!json.to_string().contains(key));
        }
    }

    #[test]
    fn fingerprint_is_stable_and_hex_encoded() {
        let mut report = base_report();
        report.hardware_root_of_trust.kind = "tpm2".into();
        report.hardware_root_of_trust.vendor = Some("IFX".into());
        report.disk_encryption.mechanism = "LUKS".into();

        let a = super::device_fingerprint_v2(&report);
        let b = super::device_fingerprint_v2(&report);

        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
