//! Linux posture readers — shells out to standard utilities. Works on
//! systemd-based distros (Ubuntu, Debian, RHEL, Fedora, Arch).

use crate::report::PostureReport;
use std::process::Command;

pub async fn populate(r: &mut PostureReport) {
    // Disk encryption — LUKS via blkid -t TYPE=crypto_LUKS, or check rootfs in /etc/crypttab.
    if let Ok(out) = Command::new("blkid")
        .args(["-t", "TYPE=crypto_LUKS"])
        .output()
    {
        if out.status.success() && !out.stdout.is_empty() {
            r.disk_encryption.enabled = true;
            r.disk_encryption.mechanism = "LUKS".into();
        }
    }
    if !r.disk_encryption.enabled {
        if let Ok(s) = std::fs::read_to_string("/etc/crypttab") {
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
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        r.screen_lock.enabled = s == "true";
    }
    if let Ok(out) = Command::new("gsettings")
        .args(["get", "org.gnome.desktop.session", "idle-delay"])
        .output()
    {
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

    // Firewall — ufw / firewalld / nftables
    if let Ok(out) = Command::new("ufw").arg("status").output() {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        r.firewall.enabled = s.contains("status: active");
        r.firewall.mechanism = "ufw".into();
    }
    if !r.firewall.enabled {
        if let Ok(out) = Command::new("systemctl")
            .args(["is-active", "firewalld"])
            .output()
        {
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
            let s = String::from_utf8_lossy(&out.stdout);
            // First line is "Listing..."; subsequent non-empty lines = upgradable packages.
            let count = s.lines().skip(1).filter(|l| !l.trim().is_empty()).count() as i32;
            r.os_updates.pending_updates = count;
        }
    } else if let Ok(out) = Command::new("dnf").args(["check-update", "-q"]).output() {
        // dnf returns 100 when updates are available, 0 when none.
        if let Some(code) = out.status.code() {
            if code == 100 {
                let s = String::from_utf8_lossy(&out.stdout);
                r.os_updates.pending_updates =
                    s.lines().filter(|l| !l.trim().is_empty()).count() as i32;
            }
        }
    }

    // Remote access
    if let Ok(out) = Command::new("systemctl")
        .args(["is-active", "ssh"])
        .output()
    {
        if out.status.success() {
            r.remote_access.ssh_enabled = true;
        }
    }
    if !r.remote_access.ssh_enabled {
        if let Ok(out) = Command::new("systemctl")
            .args(["is-active", "sshd"])
            .output()
        {
            if out.status.success() {
                r.remote_access.ssh_enabled = true;
            }
        }
    }
}
