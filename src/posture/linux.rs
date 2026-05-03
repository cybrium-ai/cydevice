//! Linux posture readers — shells out to standard utilities. Works on
//! systemd-based distros (Ubuntu, Debian, RHEL, Fedora, Arch).

use crate::report::PostureReport;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

pub async fn populate(r: &mut PostureReport) {
    // Disk encryption — LUKS via blkid -t TYPE=crypto_LUKS, or check rootfs in /etc/crypttab.
    if let Ok(out) = Command::new("blkid")
        .args(["-t", "TYPE=crypto_LUKS"])
        .output()
    {
        r.disk_encryption.assessed = true;
        if out.status.success() && !out.stdout.is_empty() {
            r.disk_encryption.enabled = true;
            r.disk_encryption.mechanism = "LUKS".into();
        }
    }
    if !r.disk_encryption.enabled {
        if let Ok(s) = std::fs::read_to_string("/etc/crypttab") {
            r.disk_encryption.assessed = true;
            if s.lines()
                .any(|l| !l.trim().is_empty() && !l.starts_with('#'))
            {
                r.disk_encryption.enabled = true;
                r.disk_encryption.mechanism = "LUKS (via crypttab)".into();
            }
        }
    }

    // Screen lock — GNOME / KDE / sway. Best effort.
    if let Ok(out) = Command::new("gsettings")
        .args(["get", "org.gnome.desktop.screensaver", "lock-enabled"])
        .output()
    {
        if out.status.success() {
            r.screen_lock.assessed = true;
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            r.screen_lock.enabled = s == "true";
        }
    }
    if let Ok(out) = Command::new("gsettings")
        .args(["get", "org.gnome.desktop.session", "idle-delay"])
        .output()
    {
        if out.status.success() {
            r.screen_lock.idle_timeout_assessed = true;
            let s = String::from_utf8_lossy(&out.stdout);
            // gsettings prints `uint32 600`
            if let Some(num) = s.split_whitespace().last() {
                if let Ok(secs) = num.trim().parse::<u32>() {
                    if secs > 0 {
                        r.screen_lock.idle_timeout_secs = Some(secs);
                    }
                }
            }
        }
    }
    if !r.screen_lock.assessed {
        if let Some((enabled, idle_timeout_secs)) = kde_screen_lock() {
            r.screen_lock.assessed = true;
            r.screen_lock.enabled = enabled;
            if let Some(secs) = idle_timeout_secs {
                r.screen_lock.idle_timeout_assessed = true;
                r.screen_lock.idle_timeout_secs = Some(secs);
            }
        }
    }
    if !r.screen_lock.assessed {
        if let Some((enabled, idle_timeout_secs)) = sway_screen_lock() {
            r.screen_lock.assessed = true;
            r.screen_lock.enabled = enabled;
            if let Some(secs) = idle_timeout_secs {
                r.screen_lock.idle_timeout_assessed = true;
                r.screen_lock.idle_timeout_secs = Some(secs);
            }
        }
    }

    // Firewall — ufw / firewalld / nftables
    if let Ok(out) = Command::new("ufw").arg("status").output() {
        if out.status.success() {
            r.firewall.assessed = true;
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            r.firewall.enabled = s.contains("status: active");
            r.firewall.mechanism = "ufw".into();
        }
    }
    if !r.firewall.enabled {
        if let Ok(out) = Command::new("systemctl")
            .args(["is-active", "firewalld"])
            .output()
        {
            r.firewall.assessed = true;
            if out.status.success() {
                r.firewall.enabled = true;
                r.firewall.mechanism = "firewalld".into();
            }
        }
    }
    if !r.firewall.enabled {
        if let Ok(out) = Command::new("systemctl")
            .args(["is-active", "nftables"])
            .output()
        {
            r.firewall.assessed = true;
            if out.status.success() {
                r.firewall.enabled = true;
                r.firewall.mechanism = "nftables".into();
            }
        }
    }

    // AV — ClamAV daemon (best-effort detection of common host AVs)
    for svc in [
        "clamav-daemon",
        "clamd",
        "falcon-sensor",
        "sentinelone-agent",
    ] {
        if let Ok(out) = Command::new("systemctl").args(["is-active", svc]).output() {
            r.antivirus.assessed = true;
            if out.status.success() {
                r.antivirus.running = true;
                r.antivirus.product = svc.to_string();
                r.antivirus.realtime_protection = Some(true);
                break;
            }
        }
    }

    // OS updates — apt / dnf / pacman
    if let Ok(out) = Command::new("apt").args(["list", "--upgradable"]).output() {
        if out.status.success() {
            r.os_updates.assessed = true;
            let s = String::from_utf8_lossy(&out.stdout);
            // First line is "Listing..."; subsequent non-empty lines = upgradable packages.
            let count = s.lines().skip(1).filter(|l| !l.trim().is_empty()).count() as i32;
            r.os_updates.pending_updates = count;
        }
    } else if let Ok(out) = Command::new("dnf").args(["check-update", "-q"]).output() {
        // dnf returns 100 when updates are available, 0 when none.
        if let Some(code) = out.status.code() {
            if code == 0 || code == 100 {
                r.os_updates.assessed = true;
            }
            if code == 100 {
                let s = String::from_utf8_lossy(&out.stdout);
                r.os_updates.pending_updates =
                    s.lines().filter(|l| !l.trim().is_empty()).count() as i32;
            } else if code == 0 {
                r.os_updates.pending_updates = 0;
            }
        }
    } else if let Ok(out) = Command::new("pacman").args(["-Qu"]).output() {
        if let Some(code) = out.status.code() {
            if code == 0 || code == 1 {
                r.os_updates.assessed = true;
            }
            if code == 0 {
                let s = String::from_utf8_lossy(&out.stdout);
                r.os_updates.pending_updates =
                    s.lines().filter(|l| !l.trim().is_empty()).count() as i32;
            } else if code == 1 {
                r.os_updates.pending_updates = 0;
            }
        }
    }

    // Remote access
    if let Ok(out) = Command::new("systemctl")
        .args(["is-active", "ssh"])
        .output()
    {
        r.remote_access.assessed = true;
        if out.status.success() {
            r.remote_access.ssh_enabled = true;
        }
    }
    if !r.remote_access.ssh_enabled {
        if let Ok(out) = Command::new("systemctl")
            .args(["is-active", "sshd"])
            .output()
        {
            r.remote_access.assessed = true;
            if out.status.success() {
                r.remote_access.ssh_enabled = true;
            }
        }
    }
    for svc in [
        "x11vnc",
        "vino-server",
        "vncserver@:1",
        "vncserver",
        "gnome-remote-desktop",
    ] {
        if let Ok(out) = Command::new("systemctl").args(["is-active", svc]).output() {
            r.remote_access.assessed = true;
            if out.status.success() {
                r.remote_access.remote_desktop_enabled = true;
                break;
            }
        }
    }

    populate_hardware_root_of_trust(r);
}

fn populate_hardware_root_of_trust(r: &mut PostureReport) {
    let tpmrm = Path::new("/dev/tpmrm0");
    let tpm = Path::new("/dev/tpm0");
    let sysfs = Path::new("/sys/class/tpm/tpm0");

    if tpmrm.exists() || tpm.exists() || sysfs.exists() {
        r.hardware_root_of_trust.assessed = true;
        r.hardware_root_of_trust.present = true;
        r.hardware_root_of_trust.kind = "tpm2".into();
        r.hardware_root_of_trust.enabled = true;
        r.hardware_root_of_trust.attested = false;

        if let Some(vendor) = linux_tpm_vendor(sysfs) {
            r.hardware_root_of_trust.vendor = Some(vendor);
        }

        if let Some(enabled) = linux_tpm_enabled() {
            r.hardware_root_of_trust.enabled = enabled;
        }
    } else {
        r.hardware_root_of_trust.assessed = true;
        r.hardware_root_of_trust.present = false;
        r.hardware_root_of_trust.kind = "none".into();
        r.hardware_root_of_trust.enabled = false;
        r.hardware_root_of_trust.attested = false;
    }
}

fn linux_tpm_vendor(sysfs_root: &Path) -> Option<String> {
    for name in ["manufacturer_name", "manufacturer", "description"] {
        let value = fs::read_to_string(sysfs_root.join("device").join(name))
            .or_else(|_| fs::read_to_string(sysfs_root.join(name)))
            .ok()?;
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn linux_tpm_enabled() -> Option<bool> {
    let out = Command::new("tpm2_getcap")
        .args(["properties-fixed"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    Some(text.contains("tpm2") || text.contains("family_indicator"))
}

fn kde_screen_lock() -> Option<(bool, Option<u32>)> {
    for tool in ["kreadconfig6", "kreadconfig5", "kreadconfig"] {
        let enabled = Command::new(tool)
            .args([
                "--file",
                "kscreenlockerrc",
                "--group",
                "Daemon",
                "--key",
                "Autolock",
            ])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());

        let timeout = Command::new(tool)
            .args([
                "--file",
                "kscreenlockerrc",
                "--group",
                "Daemon",
                "--key",
                "Timeout",
            ])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());

        if enabled.is_some() || timeout.is_some() {
            let lock_enabled = enabled.as_deref().map(parse_kde_bool).unwrap_or(false);
            let idle_timeout_secs = timeout.as_deref().and_then(parse_kde_timeout_secs);
            return Some((lock_enabled, idle_timeout_secs));
        }
    }
    None
}

fn sway_screen_lock() -> Option<(bool, Option<u32>)> {
    let home = env::var_os("HOME")?;
    let home = PathBuf::from(home);

    for path in [
        home.join(".config/swayidle/config"),
        home.join(".config/sway/config"),
    ] {
        if let Ok(contents) = fs::read_to_string(&path) {
            if let Some(result) = parse_sway_screen_lock(&contents) {
                return Some(result);
            }
        }
    }

    None
}

fn parse_kde_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

fn parse_kde_timeout_secs(raw: &str) -> Option<u32> {
    raw.trim().parse::<u32>().ok()
}

fn parse_sway_screen_lock(raw: &str) -> Option<(bool, Option<u32>)> {
    let mut best_timeout: Option<u32> = None;
    let mut has_lock = false;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(timeout) = parse_sway_timeout_secs(line) {
            has_lock = true;
            best_timeout = Some(match best_timeout {
                Some(current) => current.min(timeout),
                None => timeout,
            });
        }
    }

    if has_lock {
        Some((true, best_timeout))
    } else {
        None
    }
}

fn parse_sway_timeout_secs(line: &str) -> Option<u32> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains("swaylock") {
        return None;
    }

    let timeout_token = line.split_whitespace().next()?;
    if timeout_token != "timeout" {
        return None;
    }

    let value = line.split_whitespace().nth(1)?;
    parse_duration_secs(value)
}

fn parse_duration_secs(raw: &str) -> Option<u32> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(secs) = raw.parse::<u32>() {
        return Some(secs);
    }
    if let Some(stripped) = raw.strip_suffix('m') {
        return stripped
            .trim()
            .parse::<u32>()
            .ok()
            .map(|mins| mins.saturating_mul(60));
    }
    if let Some(stripped) = raw.strip_suffix('h') {
        return stripped
            .trim()
            .parse::<u32>()
            .ok()
            .map(|hours| hours.saturating_mul(3600));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        linux_tpm_vendor, parse_duration_secs, parse_kde_bool, parse_kde_timeout_secs,
        parse_sway_screen_lock,
    };
    use std::fs;

    #[test]
    fn parses_kde_values() {
        assert!(parse_kde_bool("true"));
        assert!(parse_kde_bool("1"));
        assert!(!parse_kde_bool("false"));
        assert_eq!(parse_kde_timeout_secs("300"), Some(300));
    }

    #[test]
    fn parses_sway_lock_timeout() {
        let cfg = r#"
            timeout 300 'swaylock -f -c 000000'
            timeout 600 'swaymsg "output * dpms off"'
        "#;
        assert_eq!(parse_sway_screen_lock(cfg), Some((true, Some(300))));
    }

    #[test]
    fn parses_duration_suffixes() {
        assert_eq!(parse_duration_secs("600"), Some(600));
        assert_eq!(parse_duration_secs("10m"), Some(600));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs(""), None);
    }

    #[test]
    fn reads_tpm_vendor_from_sysfs_like_layout() {
        let root = std::env::temp_dir().join(format!("cydevice-linux-tpm-{}", std::process::id()));
        let device_dir = root.join("device");
        fs::create_dir_all(&device_dir).unwrap();
        fs::write(device_dir.join("manufacturer"), "IFX").unwrap();

        assert_eq!(linux_tpm_vendor(&root), Some("IFX".into()));

        fs::remove_dir_all(root).unwrap();
    }
}
