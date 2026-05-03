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
        if ($v) { "$($v.ProtectionStatus)|$($v.VolumeStatus)|$($v.EncryptionMethod)" }
    "#,
    ) {
        r.disk_encryption.assessed = true;
        if let Some((enabled, mechanism)) = parse_bitlocker_status(&out) {
            r.disk_encryption.enabled = enabled;
            r.disk_encryption.mechanism = mechanism;
        }
    }

    // Screen lock — registry: ScreenSaverIsSecure under HKCU\Control Panel\Desktop
    if let Some(out) = run_ps(
        r#"(Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue).ScreenSaverIsSecure"#,
    ) {
        r.screen_lock.assessed = true;
        r.screen_lock.enabled = out.trim() == "1";
    }
    if let Some(out) = run_ps(
        r#"(Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue).ScreenSaveTimeOut"#,
    ) {
        r.screen_lock.idle_timeout_assessed = true;
        if let Ok(secs) = out.trim().parse::<u32>() {
            r.screen_lock.idle_timeout_secs = Some(secs);
        }
    }

    // Firewall — Get-NetFirewallProfile
    if let Some(out) = run_ps(
        r#"(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | Measure-Object).Count"#,
    ) {
        r.firewall.assessed = true;
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
        r.antivirus.assessed = true;
        let trimmed = out.trim();
        if !trimmed.is_empty() {
            r.antivirus.running = true;
            r.antivirus.product = trimmed.to_string();
        }
    }
    if let Some(out) =
        run_ps(r#"(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled"#)
    {
        r.antivirus.assessed = true;
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
        r.os_updates.assessed = true;
        if let Ok(n) = out.trim().parse::<i32>() {
            r.os_updates.pending_updates = n;
        }
    }
    if let Some(out) = run_ps(r#"(Get-WUSettings -ErrorAction SilentlyContinue).NotificationLevel"#)
    {
        r.os_updates.assessed = true;
        if !out.trim().is_empty() {
            r.os_updates.auto_update_enabled = Some(out.trim() != "1");
        }
    }

    // Remote access
    if let Some(out) =
        run_ps(r#"(Get-Service -Name TermService -ErrorAction SilentlyContinue).Status"#)
    {
        r.remote_access.assessed = true;
        r.remote_access.remote_desktop_enabled = out.trim() == "Running";
    }
    if let Some(out) = run_ps(r#"(Get-Service -Name sshd -ErrorAction SilentlyContinue).Status"#) {
        r.remote_access.assessed = true;
        r.remote_access.ssh_enabled = out.trim() == "Running";
    }

    if let Some(out) = run_ps(
        r#"
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            "$($tpm.TpmPresent)|$($tpm.TpmReady)|$($tpm.ManufacturerIdTxt)"
        }
    "#,
    ) {
        r.hardware_root_of_trust.assessed = true;
        if let Some((present, enabled, vendor)) = parse_tpm_status(&out) {
            r.hardware_root_of_trust.present = present;
            r.hardware_root_of_trust.kind = if present {
                "tpm2".into()
            } else {
                "none".into()
            };
            r.hardware_root_of_trust.enabled = enabled;
            r.hardware_root_of_trust.attested = false;
            r.hardware_root_of_trust.vendor = vendor;
        }
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

fn parse_bitlocker_status(raw: &str) -> Option<(bool, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split('|').map(str::trim);
    let protection = parts.next().unwrap_or_default();
    let volume_status = parts.next().unwrap_or_default();
    let method = parts.next().unwrap_or_default();

    let protection_on = matches!(protection, "1" | "On" | "ProtectionOn" | "True" | "true");
    let volume_encrypted = matches!(
        volume_status,
        "FullyEncrypted" | "EncryptionInProgress" | "FullyEncryptedInUseSpaceOnly"
    );

    let mechanism = if method.is_empty() {
        "BitLocker".into()
    } else {
        format!("BitLocker ({})", method)
    };

    Some((protection_on || volume_encrypted, mechanism))
}

fn parse_tpm_status(raw: &str) -> Option<(bool, bool, Option<String>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split('|').map(str::trim);
    let present = parse_ps_bool(parts.next().unwrap_or_default())?;
    let enabled = parse_ps_bool(parts.next().unwrap_or_default()).unwrap_or(false);
    let vendor = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Some((present, enabled, vendor))
}

fn parse_ps_bool(raw: &str) -> Option<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bitlocker_status, parse_tpm_status};

    #[test]
    fn parses_bitlocker_enabled_output() {
        assert_eq!(
            parse_bitlocker_status("1|FullyEncrypted|XtsAes256"),
            Some((true, "BitLocker (XtsAes256)".into()))
        );
    }

    #[test]
    fn parses_bitlocker_disabled_output() {
        assert_eq!(
            parse_bitlocker_status("0|FullyDecrypted|"),
            Some((false, "BitLocker".into()))
        );
    }

    #[test]
    fn ignores_empty_bitlocker_output() {
        assert_eq!(parse_bitlocker_status(" "), None);
    }

    #[test]
    fn parses_tpm_present_output() {
        assert_eq!(
            parse_tpm_status("True|True|IFX"),
            Some((true, true, Some("IFX".into())))
        );
    }

    #[test]
    fn parses_tpm_absent_output() {
        assert_eq!(parse_tpm_status("False|False|"), Some((false, false, None)));
    }
}
