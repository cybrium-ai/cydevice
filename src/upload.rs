//! Push the posture report to the Cybrium API.

use crate::config::Config;
use crate::report::PostureReport;
use anyhow::{Context, Result, bail};

pub async fn send(cfg: &Config, report: &PostureReport) -> Result<()> {
    let url = format!("{}/scans/device-posture/{}/", cfg.url, cfg.device_id);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Api-Key {}", cfg.api_key))
        .header("User-Agent", format!("cydevice/{}", env!("CARGO_PKG_VERSION")))
        .json(report)
        .send()
        .await
        .context("device-posture upload POST failed")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("upload HTTP {}: {}", status, body);
    }
    Ok(())
}
