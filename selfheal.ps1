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
  $acl = $null; try { $acl = Get-Acl -LiteralPath $p } catch { return 'acl-unreadable' }
  $o = $null; try { $o = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return 'owner?' }
  if(($o -ne 'S-1-5-32-544') -and ($o -ne 'S-1-5-18') -and ($o -notlike 'S-1-5-80-956008885*')){ return "owner $o" }
  $wm = [Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteAttributes,WriteExtendedAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
  foreach($a in $acl.Access){
    if($a.AccessControlType -ne 'Allow'){ continue }
    $s = $null; try { $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $s = $null }
    if(-not $s){ return 'unresolvable ACE' }
    if(@('S-1-5-18','S-1-5-32-544') -contains $s -or $s -like 'S-1-5-80-956008885*'){ continue }
    if(([int]$a.FileSystemRights -band ([int]$wm -bor 0x40000000 -bor 0x10000000)) -ne 0){ return "writable by $s" }  # +GENERIC_WRITE/ALL (dir inherit-only)
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

# Ensure BOTH Application event sources exist. The broker's 4100 audit mirror (Write-Audit) does NOT self-
# create its source; a Windows feature update can wipe registered sources, so selfheal -- which runs post-
# update/startup/daily -- restores them so the tamper-evident mirror never silently goes dark.
foreach($s in @('AgentElevate','AgentElevate-Broker')){ try { if(-not [System.Diagnostics.EventLog]::SourceExists($s)){ [System.Diagnostics.EventLog]::CreateEventSource($s,'Application') } } catch {} }

# Exact command-line tokenizer (the Windows parser PowerShell itself uses). Lets drift detection compare the
# action's ARG VECTOR token-for-token instead of substring/flag-presence (which would accept an injected -Command
# or a '...broker.ps1.bak' look-alike). A dummy argv[0] is prepended so the real args parse with normal rules.
if(-not ('AeArgv' -as [type])){
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class AeArgv {
  [DllImport("shell32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CommandLineToArgvW(string cmd, out int n);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  public static string[] Parse(string cmd) {
    int n; IntPtr p = CommandLineToArgvW("ae " + cmd, out n);
    if (p == IntPtr.Zero) return null;
    try {
      string[] r = new string[n > 0 ? n - 1 : 0];
      for (int i = 1; i < n; i++) r[i-1] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, i * IntPtr.Size));
      return r;
    } finally { LocalFree(p); }
  }
}
"@
}
function ConvertTo-AeArgv($s){ try { return [AeArgv]::Parse([string]$s) } catch { return $null } }

# Drift detection: a task is healthy iff present + enabled, with EXACTLY one action whose Execute + full arg
# VECTOR (tokenized) match the expected, a SYSTEM/Highest principal, IgnoreNew, and the expected set of trigger
# TYPES all enabled. $expTrig is the expected trigger array (Get-AE*Triggers) -- the same source registration uses.
function Test-TaskHealth([string]$name,[string]$file,$expTrig){
  $t = Get-ScheduledTask -TaskName $name -EA SilentlyContinue
  if(-not $t){ return 'missing' }
  if($t.State -eq 'Disabled'){ return 'disabled' }
  $acts = @($t.Actions)
  if($acts.Count -ne 1){ return "action-count-drift ($($acts.Count))" }
  $act = $acts[0]
  $exp = Get-AEExpectedAction $file
  if($act.Execute -ne $exp.Execute){ return 'action-exe-drift' }
  # EXACT arg-vector match. Tokenizing normalizes Task Scheduler's quote/space re-formatting (so a healthy task
  # matches) AND rejects an injected -Command, a missing flag, an unquoted space-path, or a '-File ...broker.ps1.bak'.
  $expTok = ConvertTo-AeArgv $exp.Argument
  $actTok = ConvertTo-AeArgv ([string]$act.Arguments)
  if(($null -eq $expTok) -or ($null -eq $actTok)){ return 'action-arg-untokenizable' }
  if(@($expTok).Count -ne @($actTok).Count){ return "action-arg-drift (count $(@($actTok).Count)!=$(@($expTok).Count))" }
  for($i=0; $i -lt @($expTok).Count; $i++){ if($expTok[$i] -ne $actTok[$i]){ return "action-arg-drift (token $i)" } }   # -ne is case-insensitive (flags + Windows paths)
  $uid = [string]$t.Principal.UserId
  if(($uid -ne 'S-1-5-18') -and ($uid -notmatch '(?i)^(NT AUTHORITY\\)?SYSTEM$')){ return "principal-drift ($uid)" }
  if($t.Principal.RunLevel -ne 'Highest'){ return 'runlevel-drift' }
  if(([string]$t.Settings.MultipleInstances) -ne 'IgnoreNew'){ return "multiinstance-drift ($($t.Settings.MultipleInstances))" }  # must stay IgnoreNew (single-instance)
  # Triggers: compare the TYPE multiset to expected (catches count drift + a wrong-type trigger) and require every
  # trigger ENABLED. We do NOT deep-compare event subscription XML / repetition values: Task Scheduler normalizes
  # them -> false-drift thrash, and a same-type wrong-content trigger needs ADMIN to create (out of threat model).
  $expTypes  = @($expTrig | ForEach-Object { [string]$_.CimClass.CimClassName } | Sort-Object)
  $liveTrig  = @($t.Triggers)
  $liveTypes = @($liveTrig | ForEach-Object { [string]$_.CimClass.CimClassName } | Sort-Object)
  if(($expTypes -join '|') -ne ($liveTypes -join '|')){ return "trigger-drift (types [$($liveTypes -join ',')] != [$($expTypes -join ',')])" }
  if(@($liveTrig | Where-Object { -not $_.Enabled }).Count -gt 0){ return 'trigger-disabled' }
  return ''
}

$repaired = @(); $errors = @()
# trig = the expected trigger array, from the SAME Get-AE*Triggers that Register-*Task registers (single source --
# no hardcoded baseline to desync). Test-TaskHealth derives both the count and the expected trigger TYPES from it.
foreach($pair in @(@{n='AgentElevate-Broker'; f='broker.ps1'; trig=@(Get-AEBrokerTriggers); reg={Register-BrokerTask}}, @{n='AgentElevate-SelfHeal'; f='selfheal.ps1'; trig=@(Get-AESelfHealTriggers); reg={Register-SelfHealTask}})){
  try {
    $h = Test-TaskHealth $pair.n $pair.f $pair.trig
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
