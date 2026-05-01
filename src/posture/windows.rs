//! Windows posture readers — uses PowerShell + WMI / CIM. v1 stub; the
//! macOS + Linux paths have been validated end-to-end. Wire-up follows the
//! same pattern; expand the queries here as we get a Windows test fleet.

use crate::report::PostureReport;
use std::process::Command;

pub async fn populate(r: &mut PostureReport) {
    // BitLocker — Get-BitLockerVolume on the system drive.
    if let Some(out) = run_ps(
        r#"
        $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($v) { $v.ProtectionStatus }
    "#,
    ) {
        if out.trim() == "On" {
            r.disk_encryption.enabled = true;
            r.disk_encryption.mechanism = "BitLocker".into();
        }
    }

    // Screen lock — registry: ScreenSaverIsSecure under HKCU\Control Panel\Desktop
    if let Some(out) = run_ps(
        r#"(Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue).ScreenSaverIsSecure"#,
    ) {
        r.screen_lock.enabled = out.trim() == "1";
    }
    if let Some(out) = run_ps(
        r#"(Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue).ScreenSaveTimeOut"#,
    ) {
        if let Ok(secs) = out.trim().parse::<u32>() {
            r.screen_lock.idle_timeout_secs = Some(secs);
        }
    }

    // Firewall — Get-NetFirewallProfile
    if let Some(out) = run_ps(
        r#"(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | Measure-Object).Count"#,
    ) {
        r.firewall.enabled = out.trim() == "0";
        r.firewall.mechanism = "Windows Defender Firewall".into();
    }

    // Antivirus — Defender or 3rd-party via SecurityCenter2
    if let Some(out) = run_ps(
        r#"
        $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($av) { $av.displayName -join ',' }
    "#,
    ) {
        let trimmed = out.trim();
        if !trimmed.is_empty() {
            r.antivirus.running = true;
            r.antivirus.product = trimmed.to_string();
        }
    }
    if let Some(out) =
        run_ps(r#"(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled"#)
    {
        if !out.trim().is_empty() {
            r.antivirus.realtime_protection = Some(out.trim().eq_ignore_ascii_case("True"));
        }
    }

    // OS updates — Windows Update — quick heuristic: PendingReboot key.
    if let Some(out) = run_ps(
        r#"
        $u = New-Object -ComObject Microsoft.Update.Session
        $s = $u.CreateupdateSearcher()
        ($s.Search('IsInstalled=0').Updates).Count
    "#,
    ) {
        if let Ok(n) = out.trim().parse::<i32>() {
            r.os_updates.pending_updates = n;
        }
    }
    if let Some(out) = run_ps(r#"(Get-WUSettings -ErrorAction SilentlyContinue).NotificationLevel"#)
    {
        if !out.trim().is_empty() {
            r.os_updates.auto_update_enabled = Some(out.trim() != "1");
        }
    }

    // Remote access
    if let Some(out) =
        run_ps(r#"(Get-Service -Name TermService -ErrorAction SilentlyContinue).Status"#)
    {
        r.remote_access.remote_desktop_enabled = out.trim() == "Running";
    }
    if let Some(out) = run_ps(r#"(Get-Service -Name sshd -ErrorAction SilentlyContinue).Status"#) {
        r.remote_access.ssh_enabled = out.trim() == "Running";
    }
}

fn run_ps(script: &str) -> Option<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}
