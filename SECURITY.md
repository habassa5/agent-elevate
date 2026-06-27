# Security Policy

## ⚠️ Read this first — intended threat model

AgentElevate **deliberately lets a non‑administrator process trigger a curated set of operations as `SYSTEM`
without a UAC prompt.** That is the entire point of the project, and it is only safe under a specific model:

> **AgentElevate is for a SINGLE‑USER, SINGLE‑ADMIN Windows machine that you personally own and control** — a
> developer/automation workstation where the one interactive user is also the administrator. In that model the
> "attacker" is unprivileged malware running *as that same user*, and the broker is a hardened, allow‑listed,
> audited reduction of UAC friction.

> ### 🚫 Do NOT deploy AgentElevate on:
> - **Multi‑user machines** (more than one human logs in) — a standard user could drive the broker.
> - **Domain‑joined / Active Directory / enterprise‑managed machines.**
> - **Shared, kiosk, server, or production hosts.**
> - **Any machine where "the local user" and "a local administrator" are different trust levels.**
>
> On those systems the broker is a **local privilege‑escalation surface**, not a convenience. You would be
> *lowering* the security posture of a machine whose threat model assumes standard users should NOT reach
> `SYSTEM`. Don't do it.

If your situation isn't the single‑user‑owner model, you almost certainly want **interactive** elevation instead
— use [gsudo](https://github.com/gerardog/gsudo) or the Windows 11 native `sudo`, which keep the UAC prompt.

## What the broker does and does not do

- It does **not** disable UAC globally, Windows Defender, SmartScreen, or any OS protection.
- It runs **only** operations that are (a) enabled in the admin‑only `broker-policy.json` **and** (b) whose every
  parameter is on that operation's admin‑curated allow‑list. It never executes attacker‑supplied code or shell
  strings.
- The trust anchor is the **admin‑only path ACL + Administrators ownership** of `C:\Program Files\AgentElevate\`
  (no signing certificate), re‑verified on every run. Requests are read through one exclusive, reparse/hard‑link‑
  refusing handle; every request is recorded in a fail‑closed, tamper‑evident audit log attributed to the OS‑set
  file owner.

### Accepted residuals (by design)

- An allow‑listed `winget` package still runs its **vendor installer as `SYSTEM`** — inherent to "install packages
  without UAC". Only list package ids you trust at that privilege level.
- Install‑time integrity rests on you invoking a **reviewed** `setup-agentelevate.ps1` from a trusted clone
  (SHA‑256 source + deployed pins and reparse checks are defense‑in‑depth); runtime is bounded by the admin‑only
  path + ownership, re‑verified every run.
- The at‑most‑once request removal is path‑based, so a request owner can race a re‑run of an **already
  allow‑listed** op (equivalent to submitting it twice) — bounded by the allow‑list and the per‑run cap; not an
  escalation.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for anything exploitable.

1. Preferred: GitHub **private vulnerability reporting** — this repo's **Security** tab → **Report a vulnerability**.
2. Please include repro steps, the affected file/line, and the impact under the threat model above.

This is a personal open‑source project provided **"as is" with no warranty** (see [LICENSE](LICENSE)) and no SLA,
but credible reports will be looked at and credited. Responsible disclosure appreciated: give a reasonable window
before public disclosure.

## Hardening provenance

The broker has been through multiple adversarial review rounds (Codex `gpt-5.5`, Grok‑4.3, and a parallel Claude
multi‑agent workflow that ran empirical proof‑of‑concept attacks on a live machine), with no unresolved
Critical/High findings, and ships with a unit/functional/integration/regression test suite that passes on both
Windows PowerShell 5.1 and PowerShell 7. That does not make it risk‑free — read this document and curate the
allow‑list conservatively.
