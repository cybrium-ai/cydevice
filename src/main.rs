//! cydevice — host-side compliance posture agent for non-MDM environments.
//!
//! Subcommands:
//!   register   one-time enrolment with the Cybrium tenant (mints a device_id)
//!   scan       run a posture check, print JSON to stdout
//!   upload     run a posture check + push to the Cybrium API
//!   run        long-running daemon mode: scan + upload every interval
//!   show       print the saved enrolment config
//!   version    print version

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

mod config;
mod posture;
mod report;
mod upload;

#[derive(Parser)]
#[command(name = "cydevice", version, about = "Cybrium endpoint posture agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// One-time enrolment: bind this device to a Cybrium tenant via API key.
    Register {
        /// Cybrium API endpoint (e.g. https://app.cybrium.ai/api).
        #[arg(long, env = "CYBRIUM_URL")]
        url: String,
        /// Tenant API key (scopes: scan:upload).
        #[arg(long, env = "CYBRIUM_API_KEY")]
        api_key: String,
        /// Optional friendly label for the device. Defaults to hostname.
        #[arg(long)]
        label: Option<String>,
    },
    /// Run a posture check and print the JSON report to stdout.
    Scan,
    /// Run a posture check and POST to the Cybrium API.
    Upload,
    /// Long-running daemon: scan + upload every `interval` seconds (default 21_600 = 6h).
    Run {
        #[arg(long, default_value_t = 21_600)]
        interval: u64,
    },
    /// Print the current enrolment config (URL + device_id; api_key is masked).
    Show,
    /// Print version info.
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .compact()
        .try_init();

    let cli = Cli::parse();

    match cli.command {
        Command::Register {
            url,
            api_key,
            label,
        } => {
            let cfg = config::Config::register(&url, &api_key, label).await?;
            println!("Registered device_id={} at {}", cfg.device_id, cfg.url);
        }
        Command::Scan => {
            let report = posture::collect().await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Upload => {
            let cfg = config::Config::load()?;
            let report = posture::collect().await?;
            upload::send(&cfg, &report).await?;
            tracing::info!(
                "uploaded — device_id={} hostname={}",
                cfg.device_id,
                report.hostname
            );
        }
        Command::Run { interval } => {
            let cfg = config::Config::load()?;
            tracing::info!(
                "daemon mode — interval={}s device_id={}",
                interval,
                cfg.device_id
            );
            loop {
                match posture::collect().await {
                    Ok(report) => {
                        if let Err(e) = upload::send(&cfg, &report).await {
                            tracing::warn!("upload failed: {}", e);
                        } else {
                            tracing::info!("posture uploaded ({} findings)", report.findings.len());
                        }
                    }
                    Err(e) => tracing::warn!("posture collection failed: {}", e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }
        Command::Show => {
            let cfg = config::Config::load()?;
            println!("URL:        {}", cfg.url);
            println!("device_id:  {}", cfg.device_id);
            println!("label:      {}", cfg.label.unwrap_or_default());
            println!(
                "api_key:    ****{}",
                &cfg.api_key[cfg.api_key.len().saturating_sub(4)..]
            );
        }
        Command::Version => {
            println!("cydevice {}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}
