# cydevice

Host-side device posture agent for non-MDM environments.

A small Rust binary that runs on every employee laptop (or contractor / BYOD)
and reports the host's own compliance state to a Cybrium tenant — disk
encryption, screen lock, host firewall, antivirus, OS updates, remote-access
services. Findings are SOC 2 / ISO 27001-aligned.

If you have Jamf / Intune / Kandji, you don't need this — Cybrium pulls the
same evidence from the MDM. `cydevice` is for laptops that are *not* MDM-enrolled
(small companies, contractors, BYOD).

## Install

```bash
# Homebrew (macOS / Linux)
brew tap cybrium-ai/cli
brew install cydevice

# Or download a release binary
curl -L https://github.com/cybrium-ai/cydevice/releases/latest/download/cydevice-$(uname -s | tr A-Z a-z)-$(uname -m) -o cydevice
chmod +x cydevice && sudo mv cydevice /usr/local/bin/
```

## Quick start

```bash
# 1. Enrol the device (once per host).
cydevice register \
  --url https://app.cybrium.ai/api \
  --api-key <token-with-scan:upload> \
  --label "anand-mbp"

# 2. Run a scan and look at the JSON locally.
cydevice scan

# 3. Push posture to Cybrium (one-shot).
cydevice upload

# 4. Run as a daemon — checks in every 6 hours.
cydevice run --interval 21600
```

API tokens are scoped per tenant; `scan:upload` is the minimum scope. Tokens
are stored in `$XDG_CONFIG_HOME/cydevice/config.json` with `0600` permissions
(macOS / Linux) or `%APPDATA%\Cybrium\cydevice\` (Windows).

## What it checks

| Domain | macOS | Linux | Windows |
|---|---|---|---|
| Disk encryption | FileVault | LUKS / crypttab | BitLocker |
| Screen lock + idle timeout | yes | GNOME / KDE | yes |
| Host firewall | Application Firewall | ufw / firewalld / nftables | Defender Firewall |
| Antivirus | XProtect + 3rd-party detection | clam / falcon / SentinelOne | Defender + SecurityCenter2 |
| Pending OS updates | softwareupdate -l | apt / dnf | Microsoft.Update.Session |
| Remote SSH / RDP | systemsetup / launchctl | systemctl | Get-Service |

Each finding has a stable rule id (`device.disk_encryption.disabled`,
`device.screen_lock.timeout_too_long`, …) so the backend can dedupe and chart
history per host.

## Architecture

```
┌─────────────────────┐    HTTPS + Api-Key
│   cydevice (Rust)   ├──────────────────────┐
└─────────────────────┘                      │
   │                                          ▼
   │ collects locally                ┌─────────────────────────┐
   │   FileVault / Defender / …      │  Cybrium API            │
   │                                  │  POST /scans/           │
   │                                  │      device-posture/<id>│
   │                                  └─────────────────────────┘
                                                 │
                                                 ▼
                                       Personnel & Access page —
                                       per-device row + drift over time
```

Run as a systemd timer (Linux), `launchd` plist (macOS) or scheduled task
(Windows) — see `dist/` for sample units once we cut a release.

## Building

```bash
cargo build --release
./target/release/cydevice scan
```

Binary is single-file, no runtime deps. With LTO + opt-level=z it lands at
~3 MB on Linux x86_64.

## License

Apache-2.0. PRs welcome at https://github.com/cybrium-ai/cydevice.
