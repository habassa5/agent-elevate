# AgentElevate

### Admin, without the ask.

> **sudo for Windows, built for AI agents.** Your agent runs the admin tasks you approve. No UAC prompt, even unattended.

> [!WARNING]
> **Built for one machine: a single-user, single-admin Windows PC you own.** AgentElevate lets a non-admin
> process trigger a curated, allow-listed set of `SYSTEM` operations without UAC. **Do not run it on
> multi-user, shared, domain-joined, server, or enterprise machines.** There it is a privilege-escalation
> surface, not a convenience. If you only need *interactive* elevation, use
> [gsudo](https://github.com/gerardog/gsudo) or Windows 11's native `sudo`. Read **[SECURITY.md](SECURITY.md)** first.

**What it is.** A SYSTEM broker that runs a small, admin-curated set of parameterized elevated operations,
for example `winget install <allow-listed id>`, with no UAC prompt. Your agent never stalls on a consent
dialog, and you never hand it a blanket security downgrade. Standalone: it brokers elevated operations and
nothing else. No power, sleep, lock, or keep-awake.

## Why a custom broker (vs gsudo, Windows `sudo`, PowerToys)

UAC is a security boundary by design, so there is no general "make elevation never prompt." The existing
tools solve a different problem, interactive elevation with fewer prompts. None of them cover an unattended
agent that has to elevate while you are away from the keyboard, across a reboot.

| Tool | Fits "unattended, zero-UAC, survives reboot"? |
|------|------------------------------------------------|
| [**gsudo**](https://github.com/gerardog/gsudo) (the popular "sudo for Windows") | **No.** Its credential cache needs an interactive first UAC, expires (about 5 min idle, gone on reboot), and is rideable. gsudo's own docs warn that a malicious process can force a cached session to elevate silently. Great for interactive use. Not a locked-down unattended broker. |
| **Windows 11 native `sudo`** (24H2+) | **No.** Still prompts on every call. A convenience, not a bypass. |
| **PowerToys** | **No.** No elevation broker. "Run as admin" just runs PowerToys itself elevated, with UAC. |
| **Claude Code / Codex CLI** | **No.** They run as you. No built-in elevation. |
| **Privileged scheduled task + a validated request queue** | **Yes, and that is this project.** A SYSTEM task triggered by a non-admin is the standard Windows way to run elevated with no UAC. Nothing turnkey exists, because the allow-list is app-specific. AgentElevate is the hardened, audited version of that pattern. |

If you only need interactive elevation, use **gsudo**. It is excellent and far less machinery. Reach for
AgentElevate when an agent has to run a fixed, admin-curated set of elevated operations unattended.

## Threat model

The attacker is malware running as you, unelevated: medium integrity, no symlink or `SeTcb` privilege beyond
a normal user. It must not be able to run arbitrary code or args as SYSTEM, escape or inject past the
allow-list, forge or silently block the audit, or exploit a TOCTOU, reparse, or hardlink. A no-UAC bypass
*for the admin-curated, parameterized allow-list* is the intended behavior, not a defect.

## How it works

A SYSTEM scheduled task (`AgentElevate-Broker`) runs `broker.ps1` from the admin-only
`C:\Program Files\AgentElevate\`. A non-elevated agent calls `Invoke-AgentElevate.ps1`. That drops a JSON
request into the create-only queue `C:\ProgramData\AgentElevate\requests` and signals Application event
`AgentElevate` / EventID 4001. The broker validates the request against the admin-only per-operation
allow-list (`broker-policy.json`), runs only allow-listed, parameterized operations, and writes a result the
client reads plus a fail-closed audit line.

An agent spawns a fresh `powershell.exe`, so it passes params as a string (a hashtable cannot cross a
`-File` boundary). The robust form is `-ParamsB64`, base64 of the params JSON. It carries no quotes for a
shell or Windows PowerShell 5.1 to mangle:

```bash
# from an agent's shell: base64-encode the params JSON, pass it as -ParamsB64
B64=$(printf '%s' '{"id":"Git.Git"}' | base64 -w0)
powershell -NoProfile -ExecutionPolicy Bypass \
  -File "C:\Program Files\AgentElevate\Invoke-AgentElevate.ps1" -Op winget-install -ParamsB64 "$B64"
```

`-ParamsJson '{"id":"Git.Git"}'` also works from bash, cmd, or PowerShell 7 (more readable, but PS 5.1's `&`
can strip the quotes). Already inside PowerShell? Pass a hashtable:
`& "...\Invoke-AgentElevate.ps1" -Op winget-install -Params @{ id = 'Git.Git' }`.

## Security model

- **Trust anchor: the admin-only path ACL plus Administrators ownership** of `C:\Program Files\AgentElevate\`.
  No signing certificate (a prior cert design was proven exploitable). The broker re-verifies owner, DACL, and
  non-reparse of its home, itself, the policy, the audit log, and `allowed\` at startup, and refuses to run if
  anything is off.
- **Agents supply validated parameters to fixed operations, never code.** Every parameter is
  character-validated and checked against an admin-curated allow-list. Adding a capability costs exactly one
  UAC: editing the admin-only `broker-policy.json`.
- **TOCTOU and reparse-safe** request reads, one exclusive `FILE_FLAG_OPEN_REPARSE_POINT` handle.
  **Fail-closed JSON-lines audit**, attributed to the request file's OS-set owner, which cannot be forged.
  **Create-only** request queue: a client can drop a request but cannot list or read others'. Its creator owns
  its own request and could rewrite that file's DACL, which is harmless. The attacker already controls the
  request JSON, and safety comes from the exclusive no-reparse read and the allow-list validation, not the
  file ACL.
- Install-time integrity rests on running a trusted `setup-agentelevate.ps1` from a reviewed copy. The
  deployed bytes are SHA-256 pinned, so a source swap mid-install is caught, and the trust anchor is verified
  fail-closed before any SYSTEM task is registered.

Hardened across multiple adversarial-council rounds: Codex gpt-5.5, Grok-4.3, and a parallel Claude
multi-agent workflow that ran live proof-of-concept attacks. No unresolved Critical or High findings. 165
unit, functional, integration, and regression tests pass on Windows PowerShell 5.1 and PowerShell 7.

## Operations

| Op | Default | Allow-list |
|----|---------|-----------|
| `winget-install {id}` | **enabled** | `allowedPackages` (exact ids; `--source winget` pinned) |
| `run-allowed-script {name}` | **enabled** | presence of the `.ps1` in the admin-only `allowed\` dir |
| `hosts-add {ip,host}` | disabled | `allowedHosts` + IP restricted to loopback/RFC1918 |
| `firewall-allow {direction,protocol,port}` | disabled | exact `{port,protocol,direction}` on `allowedRules` |
| `set-machine-env {name,value}` | disabled | `allowedEnvVars` + a hard denylist (Path/PSModulePath/...) |

Anything not allow-listed returns `ok=$false`, never a silent escalation. **Service control is deliberately
not brokered**: too deep a surface to bound safely as a no-UAC op. Restart a service with a one-off elevated
command.

Accepted residual: an allow-listed winget package still runs its vendor installer as SYSTEM. That is inherent
to installing packages without UAC. List only package ids you trust at that level.

**What not to broker (a recommendation).** The operations that would trigger the most UACs (registry writes
to `HKLM`, ACL changes via `icacls`, scheduled-task registration, service control) are best kept *off* the
broker as general parameterized ops. Why: as a no-UAC `SYSTEM` operation, each is a keys-to-the-kingdom
primitive. A single `icacls` grant, `HKLM\...\Run` value, or SYSTEM scheduled task lets a caller escalate at
will, which quietly defeats the point of a bounded broker. The UAC prompt on those is a boundary worth
keeping. This is the posture this project's own deployment takes, but it is a recommendation, not a wall: if
your risk tolerance differs, enable the disabled ops or add your own. It is your machine. When a *specific*
dangerous task recurs and you want it prompt-free, the recommended path is a fixed, parameter-free `.ps1` you
review and drop in `allowed\` (the `run-allowed-script` op). It brokers that exact operation without handing
the caller the general primitive.

## Install

```powershell
# from an elevated PowerShell (one UAC), from a freshly reviewed clone:
powershell -NoProfile -ExecutionPolicy Bypass -File C:\dev\agent-elevate\setup-agentelevate.ps1
```

Curate `broker-policy.json` (admin-only) to add packages, enable an op, and so on. Each edit is one UAC.

## Tests

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1   # Windows PowerShell 5.1
pwsh          -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1   # PowerShell 7
```

Unit, functional, integration, and regression coverage. It loads the real broker functions, no copies, and
never mutates the live system. Integration and admin-only positive-control cases skip cleanly when the broker
is not deployed.

## Files

`broker.ps1` (the SYSTEM validate-and-dispatch engine, the security boundary) · `broker-policy.json`
(admin-only allow-lists) · `Invoke-AgentElevate.ps1` (non-elevated client) · `AgentElevate-tasks.ps1` (task
definitions) · `selfheal.ps1` (restore missing or drifted broker tasks) · `setup-agentelevate.ps1` (elevated
installer) · `build-broker-manifest.ps1` (regenerate the SHA-256 pin) · `tests/`.

## Audit

Every request produces exactly one tamper-evident JSON-lines record in the admin-only `audit.log` (mirrored
to the Windows Application event log, source `AgentElevate-Broker`), attributed to the request file's OS-set
owner read from the validated handle, so a hardlink or symlink cannot spoof it:

`ALLOW-RUN` (claimed, about to execute) then `ALLOW-OK` / `ALLOW-FAIL` (executed, with outcome) ·
`DENY-MALFORMED` (bad request shape) · `DENY-UNKNOWN` / `DENY-POLICY` (unknown or disabled op) · `DENY-PARAM`
(off the allow-list, never executed) · `DENY-UNDELETABLE` (request could not be removed, so it does not run,
preventing replay) · `DENY-READ` (unreadable or locked request) · `GC-STALE` (reaped) · `ERROR` /
`ABORT-ANCHOR` (broker fault or tamper).

## Built with

Authored and maintained by [Salim Habash](https://github.com/habassa5). Built with
[Claude Code](https://claude.com/claude-code) and the Codex CLI.

## License

[MIT](LICENSE) © 2026 Salim Habash. Security-sensitive software, provided "as is." Review the source and
curate the allow-list conservatively.
