# AgentElevate self-heal. Runs as SYSTEM from the admin-only path. FIXED logic, NO external/agent input (so
# it grants no escalation). Triggered after Windows Update (System EventID 19), at startup, and once daily.
# Its ONLY job: keep the two broker tasks (AgentElevate-Broker / -SelfHeal) present + correct. It restores a
# task that is missing OR drifted (wrong action/principal, or disabled). It does NOT touch power/sleep/lock,
# Wi-Fi, or any keep-awake/Remote-Control concern -- that belongs to the separate keep-awake daemon.
$ErrorActionPreference = 'Continue'
$AE_HOME = 'C:\Program Files\AgentElevate'
$TASKS   = Join-Path $AE_HOME 'AgentElevate-tasks.ps1'

# Guard: refuse to dot-source (= execute) the task definitions unless the admin-only path + that file are
# intact (non-reparse, admin-owned, no non-admin write). selfheal runs as SYSTEM; this keeps it from running
# tampered code if the trust anchor were ever subverted.
function Test-ReparsePoint($p){ try { (((Get-Item -LiteralPath $p -Force).Attributes) -band [IO.FileAttributes]::ReparsePoint) -ne 0 } catch { $false } }
function _Untrusted($p){
  if(-not (Test-Path -LiteralPath $p)){ return 'missing' }
  if(Test-ReparsePoint $p){ return 'reparse' }
  $acl = Get-Acl -LiteralPath $p; $o = $null
  try { $o = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return 'owner?' }
  if(($o -ne 'S-1-5-32-544') -and ($o -ne 'S-1-5-18') -and ($o -notlike 'S-1-5-80-956008885*')){ return "owner $o" }
  $wm = [Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteAttributes,WriteExtendedAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
  foreach($a in $acl.Access){
    if($a.AccessControlType -ne 'Allow'){ continue }
    $s = $null; try { $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $s = $null }
    if(-not $s){ return 'unresolvable ACE' }
    if(@('S-1-5-18','S-1-5-32-544') -contains $s -or $s -like 'S-1-5-80-956008885*'){ continue }
    if(([int]$a.FileSystemRights -band [int]$wm) -ne 0){ return "writable by $s" }
  }
  return ''
}

function Write-AEEvent($type,$id,$msg){
  try { if(-not [System.Diagnostics.EventLog]::SourceExists('AgentElevate')){ [System.Diagnostics.EventLog]::CreateEventSource('AgentElevate','Application') } } catch {}
  try { [System.Diagnostics.EventLog]::WriteEntry('AgentElevate',$msg,[System.Diagnostics.EventLogEntryType]::$type,$id) } catch {}
}

$g  = (_Untrusted $AE_HOME)
$g2 = (_Untrusted $TASKS)
if($g -or $g2){
  Write-AEEvent Error 3000 "AgentElevate self-heal ABORTED: trust anchor not admin-only (home: '$g'; tasks: '$g2'). Re-run setup-agentelevate.ps1 elevated from a reviewed copy."
  exit 1
}
. $TASKS

# Drift detection: a task is healthy iff present, enabled, with the expected action + a SYSTEM/Highest principal.
function Test-TaskHealth([string]$name,[string]$file){
  $t = Get-ScheduledTask -TaskName $name -EA SilentlyContinue
  if(-not $t){ return 'missing' }
  if($t.State -eq 'Disabled'){ return 'disabled' }
  $exp = Get-AEExpectedAction $file
  $act = $t.Actions | Select-Object -First 1
  if($null -eq $act -or $act.Execute -ne $exp.Execute){ return 'action-exe-drift' }
  if($act.Arguments -ne $exp.Argument){ return 'action-args-drift' }
  $uid = ($t.Principal.UserId)
  if(($uid -notmatch '(?i)system') -and ($uid -ne 'S-1-5-18')){ return "principal-drift ($uid)" }
  if($t.Principal.RunLevel -ne 'Highest'){ return 'runlevel-drift' }
  return ''
}

$repaired = @(); $errors = @()
foreach($pair in @(@{n='AgentElevate-Broker'; f='broker.ps1'; reg={Register-BrokerTask}}, @{n='AgentElevate-SelfHeal'; f='selfheal.ps1'; reg={Register-SelfHealTask}})){
  try {
    $h = Test-TaskHealth $pair.n $pair.f
    if($h){ & $pair.reg; if($pair.n -eq 'AgentElevate-Broker'){ Start-ScheduledTask -TaskName $pair.n -EA SilentlyContinue }; $repaired += ("{0} ({1} -> re-registered)" -f $pair.n,$h) }
  } catch { $errors += ("{0}: {1}" -f $pair.n,$_) }
}

if($errors.Count -gt 0){
  $msg = "AgentElevate self-heal could not fully repair the broker tasks:`r`n - " + ($errors -join "`r`n - ")
  if($repaired.Count){ $msg += "`r`n`r`nAlso repaired:`r`n - " + ($repaired -join "`r`n - ") }
  Write-AEEvent Error 3000 $msg
} elseif($repaired.Count -gt 0){
  Write-AEEvent Warning 2000 ("AgentElevate self-heal restored broker task(s) after drift (likely a Windows/driver update):`r`n - " + ($repaired -join "`r`n - "))
}
# all-good run is silent (no event, no resource waste).
