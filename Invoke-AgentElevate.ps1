<#
.SYNOPSIS
  Agent-side helper to run an allow-listed elevated operation via the AgentElevate broker -- NO UAC.
.DESCRIPTION
  Runs as the normal (non-elevated) user. Drops a JSON request into the broker's create-only drop queue,
  signals the SYSTEM broker, and waits for the broker's result. The security boundary is the broker's
  per-operation admin-curated allow-list (broker-policy.json) + the admin-only path -- NOT this script.
  This client grants no privilege by itself: an op (or a parameter value) that is not allow-listed comes
  back ok=$false, never a silent escalation.
.EXAMPLE
  Invoke-AgentElevate -Op winget-install -Params @{ id = 'Git.Git' }      # id must be on allowedPackages
  Invoke-AgentElevate -Op run-allowed-script -Params @{ name = 'reset-iis.ps1' }   # script must be in the admin-only allowed\ dir
.NOTES
  Ships ENABLED: winget-install{id}, run-allowed-script{name}. Ships DISABLED (enable + curate with one UAC):
  hosts-add{ip,host}, firewall-allow{direction,protocol,port}, set-machine-env{name,value}. Service control
  is intentionally NOT brokered (restart a service manually with one UAC) -- adversarial review found it too
  deep a surface to bound safely as a no-UAC op.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Op,
  [hashtable]$Params = @{},
  [int]$TimeoutSec = 300
)
$DATA = 'C:\ProgramData\AgentElevate'; $REQ = Join-Path $DATA 'requests'; $RES = Join-Path $DATA 'results'
if (-not (Test-Path -LiteralPath $REQ)) {
  throw "AgentElevate broker is not installed (missing $REQ). Install it once (one UAC): run an elevated PowerShell and execute  C:\dev\agent-elevate\setup-agentelevate.ps1"
}
$id  = [guid]::NewGuid().ToString('N')
$who = "$env:USERNAME@$env:COMPUTERNAME pid=$PID"
# NOTE: this variable is $body, NOT $req -- PowerShell variable names are CASE-INSENSITIVE, so a $req
# here would be the SAME variable as $REQ (the requests path) and would clobber it, sending the request
# to a bogus path. Keep request-body and path variable names distinct.
$body = @{ op = $Op; params = $Params; by = $who; ts = (Get-Date -Format o) } | ConvertTo-Json -Compress -Depth 6
# Single direct write (no temp+rename: the queue is create-only, so the client has no delete right). The
# broker reads each request through ONE exclusive handle, so it only ever sees a fully-written file.
$final = Join-Path $REQ ($id + '.req.json')
[System.IO.File]::WriteAllText($final, $body, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
# Signal the broker (low latency). If the signal fails, the broker's safety poll still picks it up.
try { [System.Diagnostics.EventLog]::WriteEntry('AgentElevate',"broker request $id op=$Op",[System.Diagnostics.EventLogEntryType]::Information,4001) } catch {}
$resFile = Join-Path $RES ($id + '.res.json')
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
  if (Test-Path -LiteralPath $resFile) {
    # The broker writes the result with Set-Content (non-atomic: truncate -> write -> close). Tolerate the tiny
    # window where we catch a half-written/empty file: a parse/IO failure or whitespace-only content means
    # 'not ready yet' -> keep polling instead of throwing a confusing parse error.
    try {
      $raw = Get-Content -LiteralPath $resFile -Raw -ErrorAction Stop
      if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $result = $raw | ConvertFrom-Json
        if (-not $result.ok) { Write-Error "AgentElevate broker op '$Op' failed: $($result.detail)" }
        return $result
      }
    } catch { }   # transient mid-write read -> fall through and re-poll
  }
  Start-Sleep -Milliseconds 500
}
throw "AgentElevate broker timed out after ${TimeoutSec}s (no result for $id). Is the AgentElevate-Broker task running? Check the admin-only audit log at 'C:\Program Files\AgentElevate\audit.log'."
