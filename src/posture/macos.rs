//! macOS-specific posture readers — shells out to system utilities + reads
//! defaults. No private APIs.

use crate::report::PostureReport;
use std::process::Command;

pub async fn populate(r: &mut PostureReport) {
    // Disk encryption — FileVault status
    if let Ok(out) = Command::new("/usr/bin/fdesetup").arg("status").output() {
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
    let ask = read_user_default("com.apple.screensaver", "askForPassword").unwrap_or_default();
    let delay =
        read_user_default("com.apple.screensaver", "askForPasswordDelay").unwrap_or_default();
    r.screen_lock.enabled = ask.trim() == "1";
    if let Ok(secs) = delay.trim().parse::<f64>() {
        r.screen_lock.idle_timeout_secs = Some(secs as u32);
    }

    // Firewall — socketfilterfw
    if let Ok(out) = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .arg("--getglobalstate")
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        r.firewall.enabled = s.contains("enabled");
        r.firewall.mechanism = "macOS Application Firewall".into();
    }

    // Antivirus — Apple's XProtect runs by default; flag presence as 'running' baseline.
    // For 3rd-party AV detection: scan /Library/LaunchDaemons for known plists.
    r.antivirus.running = true;
    r.antivirus.product = "XProtect".into();
    r.antivirus.realtime_protection = Some(true);
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
                r.antivirus.product = format!("{} (over XProtect)", name);
                break;
            }
        }
    }

    // OS updates — softwareupdate -l (cached state, fast)
    if let Ok(out) = Command::new("/usr/sbin/softwareupdate").arg("-l").output() {
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
        r.os_updates.auto_update_enabled = Some(auto.trim() == "1");
    }

    // Remote access
    if let Ok(out) = Command::new("/usr/sbin/systemsetup")
        .arg("-getremotelogin")
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        r.remote_access.ssh_enabled = s.contains("on") && !s.contains("off");
    }
    // ARD = ARDAgent
    if let Ok(out) = Command::new("/bin/launchctl")
        .args(["list", "com.apple.RemoteDesktop.agent"])
        .output()
    {
        r.remote_access.remote_desktop_enabled = out.status.success();
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
