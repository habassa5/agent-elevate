# Changelog

All notable changes to AgentElevate are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-06-27

First public release — a hardened, allow-listed, audited **no-UAC elevation broker** for unattended AI agents
(Claude Code, Codex CLI) on **single-user Windows machines you own**. See [SECURITY.md](SECURITY.md) for the
threat model before installing.

### Added
- **SYSTEM scheduled-task broker** (`AgentElevate-Broker`) that runs admin-curated, allow-listed parameterized
  operations as `SYSTEM` with **no UAC prompt**, plus a **self-heal** task that restores it after reboots /
  Windows updates.
- **Operations:** `winget-install {id}` and `run-allowed-script {name}` ship enabled; `hosts-add`,
  `firewall-allow`, `set-machine-env` ship disabled (opt in via the admin-only `broker-policy.json`).
- **Agent helper** `Invoke-AgentElevate.ps1` accepting `-ParamsB64` (base64 JSON — robust across any shell and
  PowerShell 5.1/7), `-ParamsJson`, or an in-process `-Params` hashtable.
- **Elevated installer** `setup-agentelevate.ps1` with SHA-256 source + deployed pinning and fail-closed
  trust-anchor verification before any SYSTEM task is registered.
- **Test suite** (unit / functional / integration / regression) — green on Windows PowerShell 5.1 and 7.
- `SECURITY.md` (threat model + private vulnerability-reporting policy), MIT `LICENSE`.

### Security
- Trust anchor = **admin-only path ACL + Administrators ownership** of `C:\Program Files\AgentElevate\` (no
  signing certificate), re-verified at every broker run.
- Requests read through one exclusive `FILE_FLAG_OPEN_REPARSE_POINT` handle that refuses reparse points **and
  hard links**; audit owner is read from that validated handle (not a spoofable path lookup).
- Validate/execute split (`DENY-PARAM` before `ALLOW-RUN`), strict request-shape gate, at-most-once request
  handling, attacker-`CreationTime` clamping, audit log `Users`-none, exact Users-ACE rights/inheritance verify.
- Hardened across multiple adversarial-council rounds (Codex `gpt-5.5`, Grok-4.3, and a Claude multi-agent
  workflow running empirical proof-of-concept attacks); **no unresolved Critical/High findings**.

[1.0.0]: https://github.com/habassa5/agent-elevate/releases/tag/v1.0.0
