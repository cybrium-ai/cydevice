# Changelog

All notable changes to **cydevice** are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-05-01

Initial public release.

### Added

- **Cross-platform posture collector** for macOS, Linux, and Windows.
  Each OS module reads disk encryption (FileVault / LUKS / BitLocker),
  screen-lock + idle timeout, host firewall, antivirus / EDR presence,
  pending OS updates, and remote-access service state (SSH / RDP / ARD).
- **Stable per-host identifier** (`host_uid`) — IOPlatformUUID on macOS,
  `/etc/machine-id` on Linux, registry `MachineGuid` on Windows.
- **Twelve built-in finding rules** with stable IDs for de-duplication
  (`device.disk_encryption.disabled`, `device.screen_lock.timeout_too_long`, …)
  and SOC 2 / ISO 27001-aligned recommendations.
- **CLI subcommands**: `register`, `scan`, `upload`, `run` (daemon),
  `show`, `version`.
- **Persistent enrolment** stored in the user's config dir with `0600`
  permissions on Unix.
- **Distribution scaffolding** in `dist/` — `launchd` plist (macOS),
  `systemd` service + 6-hour timer (Linux), and a one-shot `install.sh`.
- **Release pipeline** — multi-target builds for macOS arm64/x86_64,
  Linux musl arm64/x86_64 (via `cross`), and Windows x86_64; Apple
  Developer-ID code-signing + notarisation; Windows Authenticode
  signing; SHA-256 manifests; auto-bumps the `cybrium-ai/homebrew-cli`
  tap on tag push.
- **CI** — `cargo fmt`, `cargo clippy -D warnings`, `cargo test` on
  macOS + Linux every PR.

### Notes

- Compiled binary is single-file, no runtime deps. Release profile
  uses LTO, `panic=abort`, `strip`, and `opt-level=z`; final size
  lands around 3 MB on Linux x86_64.
- This is the v0.1 release: macOS + Linux readers have been validated
  end-to-end on the maintainer's hardware. Windows readers are
  PowerShell-driven and will get fleet validation in 0.2.

[Unreleased]: https://github.com/cybrium-ai/cydevice/compare/v0.1.0...HEAD
[0.1.0]:      https://github.com/cybrium-ai/cydevice/releases/tag/v0.1.0
