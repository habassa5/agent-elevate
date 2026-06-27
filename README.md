# AgentElevate — sudo for Windows, for AI agents (no‑UAC elevation broker)

> Run **admin / elevated operations on Windows without a UAC prompt** — **unattended** and **surviving reboots** —
> from an AI coding agent (Claude Code, Codex CLI). A **hardened, allow‑listed, audited** take on the
> "sudo for Windows" / **gsudo** / **PsExec** pattern, built for a **single‑user machine you own**.

> [!WARNING]
> **Intended threat model: a single‑user, single‑admin Windows machine you personally own.** AgentElevate
> deliberately lets a non‑admin process trigger a *curated, allow‑listed* set of `SYSTEM` operations without UAC.
> **Do NOT use it on multi‑user, shared, domain‑joined, server, or enterprise machines** — there it is a local
> privilege‑escalation surface, not a convenience. If you only need *interactive* elevation, use
> [gsudo](https://github.com/gerardog/gsudo) or Windows 11's native `sudo` instead. Read
> **[SECURITY.md](SECURITY.md)** before installing.

**What it is:** a SYSTEM broker that runs a small, admin‑curated set of parameterized elevated operations
(e.g. `winget install <allow‑listed id>`) with **no UAC prompt** — so an autonomous agent never stalls on a UAC
dialog — without a broad security downgrade. It is a standalone project (nothing to do with power/sleep/lock or
keep‑awake); it only brokers elevated operations.

**Keywords:** sudo for Windows · run as administrator without UAC prompt · gsudo alternative · PsExec‑style
elevation · no‑UAC / silent elevation · unattended privilege broker · Claude Code / Codex CLI Windows admin.

## Why a custom broker? (vs gsudo, Windows `sudo`, PowerToys)

UAC is a security boundary *by design*, so there is no general "make elevation never prompt." The existing
tools solve a **different** problem — *interactive* elevation with fewer prompts — and none of them cover an
**unattended agent that may need to elevate while you're away from the keyboard and across a reboot**:

| Tool | Fits "unattended, zero-UAC, survives reboot"? |
|------|------------------------------------------------|
| [**gsudo**](https://github.com/gerardog/gsudo) (the popular "sudo for Windows") | **No.** Its credentials-cache needs an **interactive initial UAC**, expires (≈5 min idle, gone on reboot), and is **rideable** — gsudo's own docs warn a malicious process can force a cached session to elevate silently. Great for interactive use; not a locked-down unattended broker. |
| **Windows 11 native `sudo`** (24H2+) | **No.** Still shows a UAC prompt on every invocation. A convenience, not a bypass. |
| **PowerToys** | **No.** It has no elevation broker; "run as admin" just runs PowerToys itself elevated, with UAC. |
| **Claude Code / Codex CLI** | **No.** They run as the user; there's no built-in elevation. |
| **Privileged Scheduled Task + a validated request queue** | **Yes — and that's this project.** A SYSTEM task triggered by a non-admin is the standard Windows way to run elevated with no UAC; nothing turnkey exists because the *allow-list* is inherently app-specific. AgentElevate is the hardened, audited version of that pattern. |

If you only need *interactive* elevation, use **gsudo** — it's excellent and far less machinery. Reach for
AgentElevate when an agent must perform a **fixed, admin-curated** set of elevated operations **unattended**.

## Threat model

The attacker is malware running **as the single user, unelevated** (medium integrity, no symlink/`SeTcb`
privilege beyond what a normal user holds). It must NOT be able to: run arbitrary code/args as SYSTEM, escape
or inject past the allow-list, forge or silently block the audit, or exploit a TOCTOU/reparse/hardlink. A
no-UAC bypass *for the admin-curated, parameterized allow-list* is the **intended** behavior, not a defect.

## How it works

A SYSTEM scheduled task (`AgentElevate-Broker`) runs `broker.ps1` from the admin-only
`C:\Program Files\AgentElevate\`. A non-elevated agent calls `Invoke-AgentElevate.ps1`, which drops a JSON
request into the create-only queue `C:\ProgramData\AgentElevate\requests` and signals Application event
`AgentElevate` / EventID 4001. The broker validates the request against the admin-only per-operation
allow-list (`broker-policy.json`) and runs **only** allow-listed, parameterized operations, writing a result
the client reads plus a fail-closed audit line.

An agent spawns a fresh `powershell.exe`, so it passes params as a **string** (a hashtable can't cross a
`-File` boundary). The robust form is `-ParamsB64` — base64 of the params JSON, which has no quotes to be
mangled by any shell or by Windows PowerShell 5.1 native-arg quoting:

```bash
# from bash (e.g. an agent's shell): base64-encode the params JSON, pass it as -ParamsB64
B64=$(printf '%s' '{"id":"Git.Git"}' | base64 -w0)
powershell -NoProfile -ExecutionPolicy Bypass \
  -File "C:\Program Files\AgentElevate\Invoke-AgentElevate.ps1" -Op winget-install -ParamsB64 "$B64"
```

`-ParamsJson '{"id":"Git.Git"}'` also works from bash/cmd/PowerShell 7 (more readable, but PS 5.1's `&` can
strip the quotes). Already inside a PowerShell session? Use the hashtable: `& "...\Invoke-AgentElevate.ps1"
-Op winget-install -Params @{ id = 'Git.Git' }`.

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

Hardened across multiple adversarial-council rounds (Codex gpt-5.5, Grok-4.3, and a parallel Claude
multi-agent workflow that ran empirical proof-of-concept attacks on a live machine). No unresolved
Critical/High findings; 165 unit/functional/integration/regression tests pass on Windows PowerShell 5.1 and
PowerShell 7.

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

## Audit

Every request produces exactly one tamper-evident JSON-lines record in the admin-only `audit.log` (mirrored to
the Windows Application event log, source `AgentElevate-Broker`), attributed to the request file's OS-set owner
(read from the validated handle, so a hardlink/symlink cannot spoof it):

`ALLOW-RUN` (claimed + about to execute) → `ALLOW-OK` / `ALLOW-FAIL` (executed, outcome) · `DENY-MALFORMED`
(bad request shape) · `DENY-UNKNOWN` / `DENY-POLICY` (unknown or disabled op) · `DENY-PARAM` (off the
allow-list — never executed) · `DENY-UNDELETABLE` (request couldn't be removed, so not run, to prevent replay) ·
`DENY-READ` (unreadable/locked request) · `GC-STALE` (reaped) · `ERROR` / `ABORT-ANCHOR` (broker fault/tamper).

## License

[MIT](LICENSE) © 2026 Salim Habash. Security-sensitive software provided "as is" — review the source and
curate the allow-list conservatively.
