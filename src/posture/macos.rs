//! macOS-specific posture readers — shells out to system utilities + reads
//! defaults. No private APIs.

use crate::report::PostureReport;
use std::path::Path;
use std::process::Command;

pub async fn populate(r: &mut PostureReport) {
    // Disk encryption — FileVault status
    if let Ok(out) = Command::new("/usr/bin/fdesetup").arg("status").output() {
        r.disk_encryption.assessed = true;
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        r.disk_encryption.enabled = s.contains("filevault is on");
        r.disk_encryption.mechanism = "FileVault".into();
        // Recovery-key escrow surface — best-effort via mdmclient
        if let Ok(o2) = Command::new("/usr/libexec/mdmclient")
            .arg("QueryDeviceInformation")
            .output()
        {
            let s2 = String::from_utf8_lossy(&o2.stdout);
            if s2.to_lowercase().contains("personalrecoverykey") {
                r.disk_encryption.recovery_key_escrowed = Some(true);
            }
        }
    }

    // Screen lock — defaults read com.apple.screensaver askForPassword{,Delay}
    let ask = read_user_default("com.apple.screensaver", "askForPassword");
    let delay = read_user_default("com.apple.screensaver", "askForPasswordDelay");
    let idle = read_user_default("com.apple.screensaver", "idleTime");
    r.screen_lock.assessed = ask.is_some() || idle.is_some();

    let ask_enabled = ask.as_deref().map(str::trim) == Some("1");
    let idle_secs = idle
        .as_deref()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|secs| *secs > 0);
    let delay_secs = delay
        .as_deref()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .map(|secs| secs as u32)
        .unwrap_or(0);

    r.screen_lock.enabled = ask_enabled && idle_secs.is_some();
    if let Some(idle_secs) = idle_secs {
        r.screen_lock.idle_timeout_assessed = true;
        r.screen_lock.idle_timeout_secs = Some(idle_secs.saturating_add(delay_secs));
    }

    // Firewall — socketfilterfw
    if let Ok(out) = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .arg("--getglobalstate")
        .output()
    {
        r.firewall.assessed = true;
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        r.firewall.enabled = s.contains("enabled");
        r.firewall.mechanism = "macOS Application Firewall".into();
    }

    // Antivirus — detect common 3rd-party agents, then fall back to platform XProtect signals.
    r.antivirus.assessed = true;
    let (running, product, realtime_protection) = detect_antivirus();
    r.antivirus.running = running;
    r.antivirus.product = product;
    r.antivirus.realtime_protection = realtime_protection;

    // OS updates — softwareupdate -l (cached state, fast)
    if let Ok(out) = Command::new("/usr/sbin/softwareupdate").arg("-l").output() {
        r.os_updates.assessed = true;
        let s = String::from_utf8_lossy(&out.stderr)
            + std::borrow::Cow::from(String::from_utf8_lossy(&out.stdout).into_owned());
        // Each update is prefixed with `* Label: ...` in modern versions.
        let count = s
            .lines()
            .filter(|l| l.trim_start().starts_with("* ") || l.contains("Label:"))
            .count() as i32;
        r.os_updates.pending_updates = count;
    }
    let auto = read_global_default("com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
        .unwrap_or_default();
    if !auto.is_empty() {
        r.os_updates.assessed = true;
        r.os_updates.auto_update_enabled = Some(auto.trim() == "1");
    }

    // Remote access
    if let Ok(out) = Command::new("/usr/sbin/systemsetup")
        .arg("-getremotelogin")
        .output()
    {
        r.remote_access.assessed = true;
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        r.remote_access.ssh_enabled = s.contains("on") && !s.contains("off");
    }
    // ARD = ARDAgent
    if let Ok(out) = Command::new("/bin/launchctl")
        .args(["list", "com.apple.RemoteDesktop.agent"])
        .output()
    {
        r.remote_access.assessed = true;
        r.remote_access.remote_desktop_enabled = out.status.success();
    }

    populate_hardware_root_of_trust(r);
}

fn detect_antivirus() -> (bool, String, Option<bool>) {
    if let Ok(out) = Command::new("/bin/ls")
        .arg("/Library/LaunchDaemons")
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        for (key, name) in [
            ("crowdstrike", "CrowdStrike Falcon"),
            ("sentinelone", "SentinelOne"),
            ("sophos", "Sophos"),
            ("malwarebytes", "Malwarebytes"),
            ("eset", "ESET"),
            ("clamav", "ClamAV"),
        ] {
            if s.contains(key) {
                return (true, name.into(), Some(true));
            }
        }
    }

    let xprotect_present = [
        "/System/Library/CoreServices/XProtect.app",
        "/System/Library/CoreServices/XProtect.bundle",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
    ]
    .iter()
    .any(|path| Path::new(path).exists());

    if xprotect_present {
        let running = process_running("XProtectService") || process_running("syspolicyd");
        return (running, "XProtect".into(), Some(running));
    }

    (false, String::new(), Some(false))
}

fn process_running(name: &str) -> bool {
    Command::new("/usr/bin/pgrep")
        .args(["-x", name])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn populate_hardware_root_of_trust(r: &mut PostureReport) {
    r.hardware_root_of_trust.assessed = true;
    r.hardware_root_of_trust.attested = false;
    r.hardware_root_of_trust.vendor = Some("Apple".into());

    let present = has_apple_silicon() || has_t2_bridge();
    r.hardware_root_of_trust.present = present;
    r.hardware_root_of_trust.enabled = present;
    r.hardware_root_of_trust.kind = if present {
        "secure_enclave".into()
    } else {
        "none".into()
    };
}

fn has_apple_silicon() -> bool {
    std::env::consts::ARCH == "aarch64"
}

fn has_t2_bridge() -> bool {
    Command::new("/usr/sbin/system_profiler")
        .arg("SPiBridgeDataType")
        .output()
        .map(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .to_ascii_lowercase()
                    .contains("apple t2")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{has_apple_silicon, process_running};

    #[test]
    fn process_running_is_safe_for_missing_process() {
        assert!(!process_running("cydevice-process-that-should-not-exist"));
    }

    #[test]
    fn apple_silicon_detector_matches_arch_constant() {
        assert_eq!(has_apple_silicon(), std::env::consts::ARCH == "aarch64");
    }
}

fn read_user_default(domain: &str, key: &str) -> Option<String> {
    let out = Command::new("/usr/bin/defaults")
        .args(["read", domain, key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn read_global_default(domain: &str, key: &str) -> Option<String> {
    let out = Command::new("/usr/bin/defaults")
        .args(["read", domain, key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}
