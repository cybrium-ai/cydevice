//! Persistent enrolment config — stored in the user's config directory so
//! the daemon and one-shot commands share state.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub url: String,
    pub api_key: String,
    pub device_id: String,
    pub label: Option<String>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

impl Config {
    /// Path: `$XDG_CONFIG_HOME/cydevice/config.json` (Linux),
    /// `~/Library/Application Support/Cybrium/cydevice/config.json` (macOS),
    /// `%APPDATA%\Cybrium\cydevice\config.json` (Windows).
    fn path() -> Result<PathBuf> {
        let proj = directories::ProjectDirs::from("ai", "Cybrium", "cydevice")
            .context("could not resolve config directory")?;
        let dir = proj.config_dir();
        fs::create_dir_all(dir).with_context(|| format!("failed to create {:?}", dir))?;
        Ok(dir.join("config.json"))
    }

    pub fn load() -> Result<Self> {
        let p = Self::path()?;
        if !p.exists() {
            bail!("device not enrolled — run `cydevice register --url ... --api-key ...` first");
        }
        let raw = fs::read_to_string(&p).with_context(|| format!("read {:?}", p))?;
        let cfg: Self = serde_json::from_str(&raw).context("parse config.json")?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        let p = Self::path()?;
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(&p, raw).with_context(|| format!("write {:?}", p))?;
        // Tighten perms on Unix — file contains a long-lived API key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&p)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&p, perms)?;
        }
        Ok(())
    }

    /// Initial registration — POSTs to `/scans/device-posture/register/`, gets
    /// back a device_id, persists locally, returns the new config.
    pub async fn register(url: &str, api_key: &str, label: Option<String>) -> Result<Self> {
        let url = url.trim_end_matches('/').to_string();
        let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());
        let body = serde_json::json!({
            "hostname": hostname,
            "label":    label,
            "platform": std::env::consts::OS,
        });
        let resp = reqwest::Client::new()
            .post(format!("{}/scans/device-posture/register/", url))
            .header("Authorization", format!("Api-Key {}", api_key))
            .json(&body)
            .send()
            .await
            .context("register POST failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("register HTTP {}: {}", status, text);
        }
        let parsed: serde_json::Value = serde_json::from_str(&text).context("parse register response")?;
        let device_id = parsed.get("device_id")
            .and_then(|v| v.as_str())
            .context("response missing device_id")?
            .to_string();

        let cfg = Self {
            url,
            api_key: api_key.to_string(),
            device_id,
            label,
            registered_at: chrono::Utc::now(),
        };
        cfg.save()?;
        Ok(cfg)
    }
}
