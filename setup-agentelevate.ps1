# AgentElevate installer. RUN ELEVATED (one UAC). Idempotent -- safe to re-run.
#
# TRUST NOTE: the integrity of this install rests on YOU invoking a trusted copy of this script from a freshly
# reviewed/cloned C:\dev\agent-elevate. Once installed, the RUNTIME trust anchor is the admin-only path ACL +
# Administrators ownership of C:\Program Files\AgentElevate\ -- which this script sets AND verifies fail-closed
# before registering any SYSTEM task, which the DEPLOYED bytes are SHA256-pinned against (so a source swap mid-
# install is caught), and which broker.ps1 re-verifies at startup. This project is ONLY the elevation broker:
# it sets no power/sleep/lock/Wi-Fi settings and manages no keep-awake/Remote-Control tasks.
$ErrorActionPreference = 'Stop'

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "setup-agentelevate.ps1 must run elevated. Open an elevated PowerShell (one UAC) and re-run it."
  exit 1
}

$SRC      = 'C:\dev\agent-elevate'
$HOME_DIR = 'C:\Program Files\AgentElevate'
$DATA     = 'C:\ProgramData\AgentElevate'; $REQ = Join-Path $DATA 'requests'; $RES = Join-Path $DATA 'results'
$ALLOWED  = Join-Path $HOME_DIR 'allowed'; $AUDIT = Join-Path $HOME_DIR 'audit.log'
$ICACLS   = "$env:SystemRoot\System32\icacls.exe"
$log      = Join-Path $SRC '_setup-result.txt'
function L($m){ $line = ("{0}  {1}" -f (Get-Date -Format o), $m); $line | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $line }
"=== setup-agentelevate $(Get-Date -Format o) ===" | Set-Content $log -Encoding utf8

# Broker subsystem -- the complete deployed file set (no keep-awake/notify; that is a separate project).
$BROKER_FILES = @('broker.ps1','broker-policy.json','AgentElevate-tasks.ps1','selfheal.ps1','Invoke-AgentElevate.ps1')

# SHA256 pin of each file (defense-in-depth). Populate with build-broker-manifest.ps1 before deploy. Verified
# on BOTH the source (early) and the DEPLOYED admin-only copy (before registering tasks) -- so a swap of the
# writable source between those points is caught. Empty = pin skipped (the owner/DACL verify is always-on).
$PIN = @{
  'broker.ps1' = '236409B871241EEA10068E4398B1C534881A057C0DA35364E2DEC11F4488A528'
  'broker-policy.json' = '232917403DC9B6190E8E0B321CCC6AEE3C8EEF1E89B577DBE11531B9B3CAE2CE'
  'AgentElevate-tasks.ps1' = '25BA75B95E2151F78C1D166F1BEF900168C2DD3CED5443D8F049AFC66355E459'
  'selfheal.ps1' = '293758D0CF2595684F16061C0971EEA7A3B645601893CB7F26A2F4DD99EED069'
  'Invoke-AgentElevate.ps1' = '631EE085A428AC0E70661DE597FFDB171F2A89D68032C6936A7E05517A255E85'
}

$SID_SYSTEM='S-1-5-18'; $SID_ADMINS='S-1-5-32-544'; $SID_USERS='S-1-5-32-545'; $SID_TI_PFX='S-1-5-80-956008885'; $SID_CREATOR='S-1-3-0'
function Test-ReparsePoint($p){ try { (((Get-Item -LiteralPath $p -Force).Attributes) -band [IO.FileAttributes]::ReparsePoint) -ne 0 } catch { $false } }
function Get-Untrusted($p,$isDir){
  if(-not (Test-Path -LiteralPath $p)){ return 'missing' }
  if(Test-ReparsePoint $p){ return 'reparse point' }
  $acl = Get-Acl -LiteralPath $p
  $o = $null; try { $o = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return 'owner unresolved' }
  if(($o -ne $SID_ADMINS) -and ($o -ne $SID_SYSTEM) -and ($o -notlike "$SID_TI_PFX*")){ return "owner $o" }
  $wm = [Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteAttributes,WriteExtendedAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
  $allow = @($SID_SYSTEM,$SID_ADMINS); if(-not $isDir){ $allow += $SID_CREATOR }
  $bad = @()
  foreach($a in $acl.Access){
    if($a.AccessControlType -ne 'Allow'){ continue }
    $s = $null; try { $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $s = $null }
    if(-not $s){ $bad += 'UNRESOLVABLE'; continue }
    if(($allow -contains $s) -or ($s -like "$SID_TI_PFX*")){ continue }
    if(([int]$a.FileSystemRights -band ([int]$wm -bor 0x40000000 -bor 0x10000000)) -ne 0){ $bad += $a.IdentityReference.Value }  # +GENERIC_WRITE/ALL (dir inherit-only)
  }
  return ($bad -join '; ')
}
function Test-OwnerTrusted($p){ try { $o=(Get-Acl -LiteralPath $p).GetOwner([Security.Principal.SecurityIdentifier]).Value; ($o -eq $SID_ADMINS) -or ($o -eq $SID_SYSTEM) -or ($o -like "$SID_TI_PFX*") } catch { $false } }
# Queue dirs intentionally grant Users a create ACE, so Get-Untrusted can't be used; verify non-reparse +
# trusted owner + NO Allow ACE for a SID outside {SYSTEM, Admins, TrustedInstaller, Users}.
function Get-UnexpectedAce($dir){
  if(Test-ReparsePoint $dir){ return 'reparse' }
  $acl = Get-Acl -LiteralPath $dir
  $o = $null; try { $o = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return 'owner unresolved' }
  if(($o -ne $SID_ADMINS) -and ($o -ne $SID_SYSTEM) -and ($o -notlike "$SID_TI_PFX*")){ return "owner $o" }
  $okSids = @($SID_SYSTEM,$SID_ADMINS,$SID_USERS)
  foreach($a in $acl.Access){
    if($a.AccessControlType -ne 'Allow'){ continue }
    $s = $null; try { $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $s = $null }
    if(-not $s){ return 'unresolvable ACE' }
    if(($okSids -contains $s) -or ($s -like "$SID_TI_PFX*")){ continue }
    return "unexpected ACE for $s"
  }
  return ''
}
function Icacls(){ $r = & $ICACLS @args 2>&1; if($LASTEXITCODE -ne 0){ throw "icacls $($args -join ' ') -> exit $LASTEXITCODE :: $r" } }
function Hash($p){ (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

# --- 0. verify SOURCE files: present, not reparse, (optionally) hash-pinned (early abort) ---
foreach($f in $BROKER_FILES){
  $sp = Join-Path $SRC $f
  if(-not (Test-Path -LiteralPath $sp -PathType Leaf)){ throw "source missing: $sp" }
  if(Test-ReparsePoint $sp){ throw "source is a reparse point (refusing to deploy): $sp" }
  if($PIN.ContainsKey($f) -and ((Hash $sp) -ne $PIN[$f])){ throw "SOURCE hash mismatch for $f -- refusing to deploy a possibly-tampered payload" }
}
L "source files verified (reparse + $(if($PIN.Count){'hash-pin'}else{'no pin'}))"

# --- 1. directories ---
# SQUAT DEFENSE: C:\ProgramData lets non-admins create subdirectories, so an attacker can pre-create
# C:\ProgramData\AgentElevate (owning it + planting a DENY-Administrators ACE) and make `icacls /setowner`
# below FAIL -> setup aborts -> persistent install DoS. If the data root exists but is NOT admin-owned,
# reclaim it (takeown bypasses the DENY via SeTakeOwnership) and remove the whole tree so the (re)creation
# below yields a known-good admin-owned tree. (DoS defense; never an escalation -- the broker anchor + setup
# verify both fail-closed on a foreign owner regardless.)
if((Test-Path $DATA) -and -not (Test-ReparsePoint $DATA) -and -not (Test-OwnerTrusted $DATA)){
  & "$env:SystemRoot\System32\takeown.exe" /F $DATA /A /R /D Y *> $null
  Remove-Item -LiteralPath $DATA -Recurse -Force -EA SilentlyContinue
  if(Test-Path $DATA){ throw "a non-admin pre-created $DATA and it could not be reclaimed -- delete it manually (elevated) and re-run" }
}
foreach($d in @($HOME_DIR,$DATA,$REQ,$RES,$ALLOWED)){
  if((Test-Path $d) -and (Test-ReparsePoint $d)){ throw "refusing: $d exists as a reparse point -- delete it (elevated) and re-run" }
  if(-not (Test-Path $d)){ New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
if((Resolve-Path $REQ).Path -notlike (Join-Path $DATA '*')){ throw "requests dir resolves outside $DATA" }
if((Resolve-Path $RES).Path -notlike (Join-Path $DATA '*')){ throw "results dir resolves outside $DATA" }
# clear pre-existing queue children REPARSE-SAFELY: abort on any reparse/dir child (a planted junction would be
# FOLLOWED by a recursive delete and could wipe its target as admin); delete only plain files.
foreach($qd in @($REQ,$RES)){
  foreach($c in @(Get-ChildItem -LiteralPath $qd -Force -EA SilentlyContinue)){
    if((($c.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $c.PSIsContainer){ throw "refusing: pre-existing queue child '$($c.FullName)' is a reparse point or directory -- delete $DATA manually (elevated) and re-run" }
    Remove-Item -LiteralPath $c.FullName -Force -EA SilentlyContinue
  }
}
L "dirs ok (owner-verified; queue children cleared reparse-safely)"

# --- 2. deploy code into the admin-only path (inherits C:\Program Files admin-only ACL on creation) ---
foreach($f in $BROKER_FILES){ Copy-Item -LiteralPath (Join-Path $SRC $f) -Destination (Join-Path $HOME_DIR $f) -Force }
if(-not (Test-Path -LiteralPath $AUDIT)){ New-Item -ItemType File -Path $AUDIT -Force | Out-Null }
L "deployed broker files"

# --- 3. ownership + DACLs. OWNER=Administrators + admin-only DACLs, per-file (NO /T). ---
Icacls $HOME_DIR /setowner "*$SID_ADMINS"
Icacls $HOME_DIR /inheritance:r /grant:r "*${SID_SYSTEM}:(OI)(CI)F" "*${SID_ADMINS}:(OI)(CI)F" "*${SID_USERS}:(OI)(CI)RX"
foreach($f in $BROKER_FILES){
  $fp = Join-Path $HOME_DIR $f
  Icacls $fp /setowner "*$SID_ADMINS"
  Icacls $fp /inheritance:r /grant:r "*${SID_SYSTEM}:F" "*${SID_ADMINS}:F" "*${SID_USERS}:RX"
}
Icacls $ALLOWED /setowner "*$SID_ADMINS"
Icacls $ALLOWED /inheritance:r /grant:r "*${SID_SYSTEM}:(OI)(CI)F" "*${SID_ADMINS}:(OI)(CI)F" "*${SID_USERS}:(OI)(CI)RX"
Icacls $AUDIT /setowner "*$SID_ADMINS"
Icacls $AUDIT /inheritance:r /grant:r "*${SID_SYSTEM}:F" "*${SID_ADMINS}:F"
L "ownership + acls set on code/allowed/audit"

# --- 4. data queue ACLs. requests = CREATE-ONLY for Users; results = Users:RX; data root = traverse+read ---
Icacls $DATA /setowner "*$SID_ADMINS"
Icacls $DATA /inheritance:r /grant:r "*${SID_SYSTEM}:(OI)(CI)F" "*${SID_ADMINS}:(OI)(CI)F" "*${SID_USERS}:(OI)(CI)RX"
Icacls $RES  /setowner "*$SID_ADMINS"
Icacls $RES  /inheritance:r /grant:r "*${SID_SYSTEM}:(OI)(CI)F" "*${SID_ADMINS}:(OI)(CI)F" "*${SID_USERS}:(OI)(CI)RX"
Icacls $REQ  /setowner "*$SID_ADMINS"
# Users grant = WD only (create FILE), NO AD (create subdir/junction), NO (OI)(CI) inheritance: a dropped
# request inherits only SYSTEM:F/Admins:F and cannot be LISTED/read by other non-admins. (Its creator owns it
# and could rewrite its own DACL, but that is harmless -- the attacker already controls the request JSON, and
# the broker reads each request through ONE exclusive no-reparse handle + validates against the allow-list.)
Icacls $REQ  /inheritance:r /grant:r "*${SID_SYSTEM}:(OI)(CI)F" "*${SID_ADMINS}:(OI)(CI)F" "*${SID_USERS}:(WD,REA,RA,RC,S,X)"
L "data queue acls set (requests = create-only)"

# --- 5. verify the DEPLOYED (now admin-only) bytes against the pin -- catches a source swap mid-install ---
if($PIN.Count){
  foreach($f in $BROKER_FILES){
    if($PIN.ContainsKey($f) -and ((Hash (Join-Path $HOME_DIR $f)) -ne $PIN[$f])){ throw "DEPLOYED hash mismatch for $f -- aborting before task registration (source may have been swapped mid-install)" }
  }
  L "deployed bytes hash-verified against pin"
}

# --- 6. FAIL-CLOSED trust-anchor verification BEFORE registering any SYSTEM task ---
$bad = @()
$u = Get-Untrusted $HOME_DIR $true; if($u){ $bad += "$HOME_DIR ($u)" }
foreach($f in $BROKER_FILES){ $u = Get-Untrusted (Join-Path $HOME_DIR $f) $false; if($u){ $bad += "$f ($u)" } }
$u = Get-Untrusted $ALLOWED $true; if($u){ $bad += "allowed ($u)" }
$u = Get-Untrusted $AUDIT $false; if($u){ $bad += "audit.log ($u)" }
foreach($d in @($DATA,$REQ,$RES)){ $u = Get-UnexpectedAce $d; if($u){ $bad += "$d ($u)" } }
if($bad.Count -gt 0){ L ("VERIFY FAILED: " + ($bad -join ' | ')); throw "post-deploy trust-anchor verification FAILED -- SYSTEM tasks NOT registered. If a queue dir shows an 'unexpected ACE', delete C:\ProgramData\AgentElevate and re-run. Fix: $($bad -join ' | ')" }
L "trust-anchor verified admin-only (owner + DACL + non-reparse)"

# --- 7. event sources via the native .NET API (works in both Windows PowerShell 5.1 and PowerShell 7) ---
foreach($s in @('AgentElevate','AgentElevate-Broker')){ try { if(-not [System.Diagnostics.EventLog]::SourceExists($s)){ [System.Diagnostics.EventLog]::CreateEventSource($s,'Application') } } catch { L "event source $s : $_" } }
$missingSrc = @('AgentElevate','AgentElevate-Broker') | Where-Object { try { -not [System.Diagnostics.EventLog]::SourceExists($_) } catch { $true } }
if($missingSrc){ L "WARNING: event source(s) NOT registered ($($missingSrc -join ', ')) -- broker will run POLL-ONLY (up to ~3-min latency); low-latency event trigger disabled. (selfheal will retry post-update.)" } else { L "event sources verified" }

# --- 8. tasks (single source of truth in AgentElevate-tasks.ps1) ---
. (Join-Path $HOME_DIR 'AgentElevate-tasks.ps1')
Register-BrokerTask;   L "registered AgentElevate-Broker"
Register-SelfHealTask; L "registered AgentElevate-SelfHeal"

# --- 9. drain any queued request once via the event trigger ---
try { [System.Diagnostics.EventLog]::WriteEntry('AgentElevate','setup post-install broker kick',[System.Diagnostics.EventLogEntryType]::Information,4001) } catch {}
L "=== done ==="
