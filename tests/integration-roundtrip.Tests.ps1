# Integration test: exercises the DEPLOYED broker end-to-end via the installed helper
#   "C:\Program Files\AgentElevate\Invoke-AgentElevate.ps1"
# using ONLY benign DENY operations -- it never mutates the system (no enabled op is invoked, no package is
# installed, no hosts/firewall/env change). It proves four real broker behaviors:
#   (a) a DISABLED op (hosts-add) is refused with "not enabled in policy" and round-trips in time;
#   (b) an ENABLED op (winget-install) with an OFF-allow-list id is refused with "not on allowedPackages";
#   (c) the requests queue is CREATE-ONLY: a Users-written file can be created but NOT read back (no Users
#       read ACE on the created file) -- this is the confinement that stops a malicious user from reading
#       (or racing) another principal's queued request;
#   (d) the broker emits a fail-closed Application-log audit event (AgentElevate-Broker, EventID 4100) per request.
# If the broker/helper is not installed, every case SKIPS gracefully (counts as pass; nothing fails). These
# assertions hit only DENY/validation/confinement paths -- safe to run repeatedly on the live machine.
#
# Works in Windows PowerShell 5.1 AND PowerShell 7. Uses only the _framework.ps1 Assert-* helpers (no Pester,
# no broker internals -- this is a black-box test of the deployed artifact, not the repo source).

$RC_HELPER   = 'C:\Program Files\AgentElevate\Invoke-AgentElevate.ps1'
$RC_DATA     = 'C:\ProgramData\AgentElevate'
$RC_REQ_DIR  = Join-Path $RC_DATA 'requests'
$RC_CALL_TIMEOUT = 60   # per-call broker timeout (seconds), per spec

# Installed? Gate every It on this so the suite SKIPS (rather than fails) on a machine without the broker.
$RC_INSTALLED = (Test-Path -LiteralPath $RC_HELPER) -and (Test-Path -LiteralPath $RC_REQ_DIR)

# A skipped case still counts as a pass in the tiny framework; we surface the reason on the host so a SKIP is
# never mistaken for a real assertion. Returns $true when the body should be skipped.
function Skip-IfNoBroker {
  if (-not $RC_INSTALLED) {
    Write-Host ("    [SKIP] broker not installed (need '{0}' + '{1}')" -f $RC_HELPER, $RC_REQ_DIR)
    return $true
  }
  return $false
}

# Call the DEPLOYED helper and return its result object WITHOUT letting its non-terminating Write-Error
# (emitted on ok=$false) abort the test. run-tests.ps1 sets $ErrorActionPreference='Stop' at script scope,
# which would otherwise promote that Write-Error to a terminating error; the child scope resets it to
# 'Continue' and 2>$null discards the error record, so we cleanly capture the returned [pscustomobject].
function Invoke-RcDeny([string]$op, [hashtable]$params) {
  & {
    $ErrorActionPreference = 'Continue'
    & $RC_HELPER -Op $op -Params $params -TimeoutSec $RC_CALL_TIMEOUT 2>$null
  }
}

Describe 'Integration: deployed AgentElevate broker -- DENY round-trips (no system mutation)' {

  It '(a) hosts-add is DISABLED in policy -> ok=$false, detail says not enabled, returns within ~30s' {
    if (Skip-IfNoBroker) { return }
    $sw  = [System.Diagnostics.Stopwatch]::StartNew()
    # IP/host are deliberately well-formed + RFC1918 so the request reaches the policy gate; the op being
    # disabled is what denies it (proving the enabled=false branch, not mere param validation).
    $res = Invoke-RcDeny 'hosts-add' @{ ip = '10.99.99.99'; host = 'integration-probe.internal.test' }
    $sw.Stop()
    Assert-True  ($null -ne $res) 'helper returned no result object (broker timeout?)'
    Assert-Equal $res.ok $false   'a disabled op must NOT succeed'
    Assert-Match ([string]$res.detail) 'not enabled in policy' "detail was: '$($res.detail)'"
    # Spec bound is ~30s; the event-triggered broker answers a deny in ~1-3s. Allow generous slack but well
    # under the 60s call timeout so a regression to slow-poll-only is caught.
    Assert-True  ($sw.Elapsed.TotalSeconds -lt 30) "round-trip took $([int]$sw.Elapsed.TotalSeconds)s (expected <30s)"
  }

  It '(b) winget-install with an off-allow-list id -> ok=$false, detail says not on allowedPackages' {
    if (Skip-IfNoBroker) { return }
    # winget-install ships ENABLED, so this clears the enabled gate and V-PkgId charset check, then fails the
    # allowedPackages allow-list -- proving the per-parameter allow-list (not just the enabled flag) denies it.
    # The package id is syntactically valid but intentionally absent from allowedPackages: nothing is installed.
    $res = Invoke-RcDeny 'winget-install' @{ id = 'Bogus.NotAllowedPackage' }
    Assert-True  ($null -ne $res) 'helper returned no result object (broker timeout?)'
    Assert-Equal $res.ok $false   'an off-allow-list package must NOT install'
    Assert-Match ([string]$res.detail) 'not on allowedPackages' "detail was: '$($res.detail)'"
  }

  It '(c) requests queue is create-only: a Users-written file canNOT be read back (access denied)' {
    if (Skip-IfNoBroker) { return }
    # Unique name; NOT a *.req.json (so the broker treats it as garbage and GCs it, never processes it).
    $probe = Join-Path $RC_REQ_DIR ("integ_confine_{0}.probe" -f ([guid]::NewGuid().ToString('N')))
    # WRITE must SUCCEED -- Users hold CreateFiles on the queue dir (the drop right).
    Assert-NotThrows { [System.IO.File]::WriteAllText($probe, 'confinement-probe') } 'creating a request file should be allowed for Users'
    # READ-BACK must THROW -- the created file grants no read to Users (CREATOR OWNER is SYSTEM/Admins, not the
    # interactive user), which is exactly what prevents reading/racing a queued request. Assert it is an
    # ACCESS-DENIED throw specifically, not any incidental error, so this stays a meaningful assertion.
    $denied = $false
    try {
      $null = [System.IO.File]::ReadAllText($probe)
    } catch {
      $msg = ($_.Exception.ToString() + ' ' + $_.Exception.Message)
      if ($msg -match '(?i)denied|UnauthorizedAccess') { $denied = $true }
      else { throw "read-back threw, but NOT access-denied: $($_.Exception.Message)" }
    }
    Assert-True $denied 'reading back a self-created queue file should be denied to Users (create-only confinement)'
    # Do not delete: Users have no delete right here, and the broker GC reaps stray queue files. (A delete
    # attempt would itself throw -- the absence of that right is part of the confinement.)
  }

  It '(d) a request produces a AgentElevate-Broker EventID 4100 audit event in the Application log' {
    if (Skip-IfNoBroker) { return }
    # Mark a baseline, fire one fresh deny, then look for a 4100 at/after the baseline. Using a marker time
    # (minus 2s skew slack) instead of a global "recent" window ties the assertion to THIS request.
    $marker = (Get-Date).AddSeconds(-2)
    $res = Invoke-RcDeny 'hosts-add' @{ ip = '10.99.99.99'; host = 'integration-probe.internal.test' }
    Assert-True ($null -ne $res) 'helper returned no result object (broker timeout?)'

    # The audit/event write completes inside the broker right before it writes the result file the helper
    # waited on, but event-log visibility can lag a beat. Poll briefly (bounded) for the event.
    $deadline = (Get-Date).AddSeconds(20)
    $found = $null
    while ((Get-Date) -lt $deadline -and -not $found) {
      try {
        $found = Get-WinEvent -FilterHashtable @{
          LogName      = 'Application'
          ProviderName = 'AgentElevate-Broker'
          Id           = 4100
          StartTime    = $marker
        } -MaxEvents 5 -ErrorAction Stop | Select-Object -First 1
      } catch {
        # Get-WinEvent throws "No events were found that match..." when the window is momentarily empty;
        # treat that as "keep polling", but let any other error surface.
        if ($_.Exception.Message -notmatch '(?i)No events were found') { throw }
        $found = $null
      }
      if (-not $found) { Start-Sleep -Milliseconds 500 }
    }
    Assert-True ($null -ne $found) 'expected a AgentElevate-Broker EventID 4100 audit event after the request'
    Assert-Equal $found.Id 4100 'matched event must be EventID 4100'
    # The audit payload is the JSON-lines record; confirm it is the broker's audit shape (has a verdict),
    # so we are asserting on a real audit line, not just any 4100-numbered event.
    Assert-Match ([string]$found.Message) 'verdict' "4100 message did not look like an audit line: '$($found.Message)'"
  }
}
