//! Posture report — the JSON payload pushed to the Cybrium API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub schema:     u32,                   // bump on breaking field changes
    pub collected_at: DateTime<Utc>,
    pub agent_version: String,

    /// Stable identifier for this host. macOS = hardware UUID, Linux = /etc/machine-id,
    /// Windows = MachineGuid. Falls back to a hash of hostname+MAC if unavailable.
    pub host_uid:   String,
    pub hostname:   String,
    pub platform:   String,                 // "macos" | "linux" | "windows"
    pub os_name:    String,
    pub os_version: String,
    pub kernel:     String,
    pub arch:       String,
    pub uptime_secs: u64,
    pub current_user: String,

    pub disk_encryption: DiskEncryption,
    pub screen_lock:     ScreenLock,
    pub firewall:        Firewall,
    pub antivirus:       Antivirus,
    pub os_updates:      OsUpdates,
    pub remote_access:   RemoteAccess,

    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskEncryption {
    pub enabled: bool,
    pub mechanism: String,                   // "FileVault" | "BitLocker" | "LUKS" | "none"
    pub recovery_key_escrowed: Option<bool>, // None = unknown
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScreenLock {
    pub enabled: bool,
    pub idle_timeout_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Firewall {
    pub enabled: bool,
    pub mechanism: String,                   // "pf" | "Windows Defender Firewall" | "ufw" | "firewalld"
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Antivirus {
    pub running: bool,
    pub product: String,                     // "Defender" | "XProtect" | "ClamAV" | "" if none
    pub realtime_protection: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsUpdates {
    /// Best-effort: macOS = `softwareupdate -l` count of available, Linux = pkg manager output,
    /// Windows = wuauclt / Get-WindowsUpdate. -1 means unknown.
    pub pending_updates: i32,
    pub last_check: Option<DateTime<Utc>>,
    pub auto_update_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemoteAccess {
    pub ssh_enabled: bool,                   // macOS Remote Login / Linux sshd / Win OpenSSH
    pub remote_desktop_enabled: bool,        // macOS ARD / Win RDP / Linux VNC
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,                          // stable rule id, e.g. "device.disk_encryption.disabled"
    pub severity: String,                    // "critical" | "high" | "medium" | "low" | "info"
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

impl Finding {
    pub fn new(id: &str, severity: &str, title: &str, description: &str, recommendation: &str) -> Self {
        Self {
            id: id.into(),
            severity: severity.into(),
            title: title.into(),
            description: description.into(),
            recommendation: recommendation.into(),
        }
    }
}
