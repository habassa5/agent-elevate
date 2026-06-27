# AgentElevate

A **no-UAC elevation broker** for Windows. It lets local AI coding agents (Claude Code, Codex CLI, etc.)
perform a small, admin-curated set of elevated operations **as SYSTEM without a UAC prompt** — without a
broad security downgrade. Built for a single-user, single-admin machine where the user runs agents
autonomously and refuses to babysit UAC.

It is a standalone project: it has nothing to do with power/sleep/lock settings or Remote-Control keep-awake
(that is a separate effort). AgentElevate only brokers elevated operations.

## How it works

A SYSTEM scheduled task (`AgentElevate-Broker`) runs `broker.ps1` from the admin-only
`C:\Program Files\AgentElevate\`. A non-elevated agent calls `Invoke-AgentElevate.ps1`, which drops a JSON
request into the create-only queue `C:\ProgramData\AgentElevate\requests` and signals Application event
`AgentElevate` / EventID 4001. The broker validates the request against the admin-only per-operation
allow-list (`broker-policy.json`) and runs **only** allow-listed, parameterized operations, writing a result
the client reads plus a fail-closed audit line.

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
  -File "C:\Program Files\AgentElevate\Invoke-AgentElevate.ps1" -Op winget-install -Params @{ id = 'Git.Git' }
```

## Security model

- **Trust anchor = the admin-only path ACL + Administrators ownership** of `C:\Program Files\AgentElevate\`.
  There is **no signing certificate** (a prior cert-based design was proven exploitable). The broker
  re-verifies owner + DACL + non-reparse of its home, itself, the policy, the audit log, and `allowed\` at
  startup and refuses to run if anything is off.
- **Agents supply validated parameters to fixed operations — never code.** Every parameter is both
  character-validated and checked against an admin-curated allow-list. Adding a capability costs exactly one
  UAC (editing the admin-only `broker-policy.json`).
- **TOCTOU/reparse-safe** request reads (one exclusive `FILE_FLAG_OPEN_REPARSE_POINT` handle). **Fail-closed
  JSON-lines audit** attributed to the request file's OS-set owner (unforgeable). **Create-only** request
  queue: a client can drop a request but cannot list or read others'. (Its creator owns its own request and
  could rewrite that file's DACL, but that is harmless — the attacker already controls the request JSON, and
  safety comes from the exclusive no-reparse read plus the allow-list validation, not from the file ACL.)
- Install-time integrity rests on invoking a trusted `setup-agentelevate.ps1` from a reviewed copy; the
  deployed bytes are SHA-256 pinned (a source swap mid-install is caught) and the trust anchor is verified
  fail-closed before any SYSTEM task is registered.

Reviewed by a 3-model adversarial council (Codex, Grok, Claude) plus a full automated test suite.

## Operations

| Op | Default | Allow-list |
|----|---------|-----------|
| `winget-install {id}` | **enabled** | `allowedPackages` (exact ids; `--source winget` pinned) |
| `run-allowed-script {name}` | **enabled** | presence of the `.ps1` in the admin-only `allowed\` dir |
| `hosts-add {ip,host}` | disabled | `allowedHosts` + IP restricted to loopback/RFC1918 |
| `firewall-allow {direction,protocol,port}` | disabled | exact `{port,protocol,direction}` on `allowedRules` |
| `set-machine-env {name,value}` | disabled | `allowedEnvVars` + a hard denylist (Path/PSModulePath/…) |

Anything not allow-listed returns `ok=$false` — never a silent escalation. **Service control is
deliberately not brokered** (too deep a surface to bound safely as a no-UAC op; restart a service with a
one-off elevated command).

Accepted residual: an allow-listed winget package still runs its vendor installer as SYSTEM — inherent to
"install packages without UAC". Only list package ids you trust at that level.

## Install

```powershell
# from an elevated PowerShell (one UAC), from a freshly reviewed clone:
powershell -NoProfile -ExecutionPolicy Bypass -File C:\dev\agent-elevate\setup-agentelevate.ps1
```

Curate `broker-policy.json` (admin-only) to add packages, enable an op, etc. — each edit is one UAC.

## Tests

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1   # Windows PowerShell 5.1
pwsh          -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1   # PowerShell 7
```

Unit + functional + integration + regression coverage; loads the real broker functions (no copies) and never
mutates the live system. Integration / admin-only-positive-control cases skip gracefully when not deployed.

## Files

`broker.ps1` (the SYSTEM validate→dispatch engine, the security boundary) · `broker-policy.json` (admin-only
allow-lists) · `Invoke-AgentElevate.ps1` (non-elevated client) · `AgentElevate-tasks.ps1` (task definitions) ·
`selfheal.ps1` (restore missing/drifted broker tasks) · `setup-agentelevate.ps1` (elevated installer) ·
`build-broker-manifest.ps1` (regenerate the SHA-256 pin) · `tests/`.
