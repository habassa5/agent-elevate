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
$ICACLS   = (Join-Path ([Environment]::SystemDirectory) 'icacls.exe')   # API-resolved (GetSystemDirectoryW), not $env:SystemRoot -- a poisoned install env can't redirect to a fake icacls.exe
# Log to the CONSOLE first. Only AFTER $HOME_DIR is created admin-only (section 3) do we ALSO append to
# $HOME_DIR\setup-result.txt. We NEVER write the log into the user-writable source tree: on a symlink-capable
# box, malware could pre-plant _setup-result.txt as a symlink and make this elevated process truncate/append
# through it to a protected file.
$script:LOGFILE = $null
function L($m){ $line = ("{0}  {1}" -f (Get-Date -Format o), $m); Write-Host $line; if($script:LOGFILE){ try { $line | Out-File -FilePath $script:LOGFILE -Append -Encoding utf8 } catch {} } }
L "=== setup-agentelevate $(Get-Date -Format o) ==="

# Broker subsystem -- the complete deployed file set (no keep-awake/notify; that is a separate project).
$BROKER_FILES = @('broker.ps1','broker-policy.json','AgentElevate-tasks.ps1','selfheal.ps1','Invoke-AgentElevate.ps1')

# SHA256 pin of each file (defense-in-depth). Populate with build-broker-manifest.ps1 before deploy. Verified
# on BOTH the source (early) and the DEPLOYED admin-only copy (before registering tasks) -- so a swap of the
# writable source between those points is caught. Empty = pin skipped (the owner/DACL verify is always-on).
$PIN = @{
  'broker.ps1' = '27F2D79BE350B1FDB7D4B5B4A353EE27E46C83DDB68E335D62D5F79AAE9C0E72'
  'broker-policy.json' = '232917403DC9B6190E8E0B321CCC6AEE3C8EEF1E89B577DBE11531B9B3CAE2CE'
  'AgentElevate-tasks.ps1' = '261C1DF1C321997CB4ED77E0201835448E3F23834141EE63CA86F9B6C881EB0B'
  'selfheal.ps1' = '9DB8C9B6B6EA05FDF06C80BE541E340BBBDAD0CC16C3EB10B28350DAB3D57824'
  'Invoke-AgentElevate.ps1' = 'A48BA269C658A932557CAA38D07B90F55F8190BDDF11DB67BB5B2C4122AEEB54'
}

$SID_SYSTEM='S-1-5-18'; $SID_ADMINS='S-1-5-32-544'; $SID_USERS='S-1-5-32-545'; $SID_TI_PFX='S-1-5-80-956008885'; $SID_CREATOR='S-1-3-0'
# Expected Users-ACE rights masks for the queue dirs -- MUST match the icacls grants in section 4. The post-deploy
# verify flags any Users ACE granting rights BEYOND these, so a future typo granting Users:F/Modify fails closed.
$USERS_RX  = [int]([Security.AccessControl.FileSystemRights]'ReadAndExecute,Synchronize')  # DATA + RES  (0x1200A9)
$USERS_REQ = [int]([Security.AccessControl.FileSystemRights]'CreateFiles,ReadExtendedAttributes,Traverse,ReadAttributes,ReadPermissions,Synchronize')  # requests create-only (0x1200AA)
# Expected Users-ACE inheritance per dir: DATA/RES propagate Users:RX to children (OI)(CI); requests must NOT
# (the WD create-grant is dir-only, so a dropped request file does not inherit Users-write).
$INH_CICO  = [int]([Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit')   # DATA + RES
$INH_NONE  = [int]([Security.AccessControl.InheritanceFlags]'None')                              # requests
function Test-ReparsePoint($p){ try { (((Get-Item -LiteralPath $p -Force).Attributes) -band [IO.FileAttributes]::ReparsePoint) -ne 0 } catch { $false } }
function Get-Untrusted($p,$isDir){
  if(-not (Test-Path -LiteralPath $p)){ return 'missing' }
  if(Test-ReparsePoint $p){ return 'reparse point' }
  $acl = $null; try { $acl = Get-Acl -LiteralPath $p } catch { return 'acl-unreadable' }
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
function Get-UnexpectedAce($dir,$usersMask,$usersInherit){
  if(Test-ReparsePoint $dir){ return 'reparse' }
  $acl = $null; try { $acl = Get-Acl -LiteralPath $dir } catch { return 'acl-unreadable' }
  $o = $null; try { $o = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return 'owner unresolved' }
  if(($o -ne $SID_ADMINS) -and ($o -ne $SID_SYSTEM) -and ($o -notlike "$SID_TI_PFX*")){ return "owner $o" }
  $usersSeen = $false; $usersRights = 0
  foreach($a in $acl.Access){
    if($a.AccessControlType -ne 'Allow'){ continue }
    $s = $null; try { $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $s = $null }
    if(-not $s){ return 'unresolvable ACE' }
    if(@($SID_SYSTEM,$SID_ADMINS) -contains $s -or ($s -like "$SID_TI_PFX*")){ continue }     # trusted principals: full rights allowed
    if($s -eq $SID_USERS){
      $usersSeen = $true; $usersRights = $usersRights -bor [int]$a.FileSystemRights
      # the Users ACE must carry EXACTLY the expected inheritance (e.g. requests = NO inherit, so a request FILE
      # can't inherit Users-create); a drift to (OI)(CI) on requests would leak Users rights onto children.
      if([int]$a.InheritanceFlags -ne [int]$usersInherit){ return ("Users ACE inheritance drift (got [$($a.InheritanceFlags)], expected [$usersInherit])") }
      continue
    }
    return "unexpected ACE for $s"
  }
  # require the Users ACE to EXIST with EXACTLY the expected aggregate rights (catches both excess like Users:F
  # AND a missing right that would silently break the queue, e.g. requests missing CreateFiles).
  if(-not $usersSeen){ return 'Users ACE missing' }
  if($usersRights -ne [int]$usersMask){ return ("Users ACE rights not exact (got 0x{0:X}, expected 0x{1:X})" -f $usersRights,[int]$usersMask) }
  return ''
}
# audit.log holds request params + owner SIDs -> must be SYSTEM/Admins-only, NOT even Users-readable. Get-Untrusted
# permits a non-admin READ ACE; this stricter check returns '' iff no Allow ACE exists for any SID outside the
# trusted set. (Mirror of broker.ps1 Test-AuditTight, used on $AUDIT in the post-deploy verify.)
function Test-AuditTight($p){
  $u = Get-Untrusted $p $false; if($u){ return $u }
  $acl = $null; try { $acl = Get-Acl -LiteralPath $p } catch { return 'acl-unreadable' }
  foreach($a in $acl.Access){
    if($a.AccessControlType -ne 'Allow'){ continue }
    $s = $null; try { $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $s = $null }
    if(-not $s){ return 'unresolvable ACE' }
    if(@($SID_SYSTEM,$SID_ADMINS) -contains $s -or ($s -like "$SID_TI_PFX*")){ continue }
    return "non-admin ACE on audit.log ($($a.IdentityReference.Value))"
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
  if($PIN.ContainsKey($f) -and $PIN[$f] -and ((Hash $sp) -ne $PIN[$f])){ throw "SOURCE hash mismatch for $f -- refusing to deploy a possibly-tampered payload" }   # $PIN[$f] non-empty: an empty pin SKIPS (per the comment above)
}
L "source files verified (reparse + $(if($PIN.Count){'hash-pin'}else{'no pin'}))"

# --- 1. directories ---
# SQUAT DEFENSE: C:\ProgramData lets non-admins create subdirectories, so an attacker can pre-create
# C:\ProgramData\AgentElevate (owning it) before setup runs. If the data root already exists but is NOT
# admin-owned, we do NOT auto-reclaim it: a recursive takeown/delete could FOLLOW a planted junction child and
# take/delete its target as admin. Instead we ABORT with reparse-safe `cmd /c rd /s` cleanup guidance (below).
# (DoS defense; never an escalation -- the broker anchor + setup verify both fail-closed on a foreign owner.)
if((Test-Path $DATA) -and -not (Test-OwnerTrusted $DATA)){
  # A non-admin squatted the data root (C:\ProgramData lets Users mkdir). Do NOT auto-reclaim: a recursive
  # takeown/delete would FOLLOW a planted junction child and could take/delete its target as admin. Abort and
  # have the admin remove it DELIBERATELY + reparse-safely (cmd's `rd /s` removes a junction as a link, never
  # recursing into its target). A one-time manual cleanup is the safe trade for not auto-walking attacker dirs.
  throw "a non-admin pre-created $DATA (squat). From an elevated prompt, inspect it, then remove it reparse-safely and re-run setup:  cmd /c rd /s /q `"$DATA`""
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
    # -EA Stop + abort: a pre-existing plain file we CANNOT remove (lock or hostile ACL) must NOT be left behind
    # while we register SYSTEM tasks over a dirty queue. Fail loudly so the admin clears it deliberately.
    try { Remove-Item -LiteralPath $c.FullName -Force -EA Stop } catch { throw "could not remove pre-existing queue child '$($c.FullName)' ($_) -- a lock or ACL is blocking it; clear $DATA manually (elevated) and re-run" }
  }
  if(@(Get-ChildItem -LiteralPath $qd -Force -EA SilentlyContinue).Count -ne 0){ throw "queue dir '$qd' not empty after cleanup -- clear $DATA manually (elevated) and re-run" }
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
# $HOME_DIR is now admin-only (owner=Admins, Users:RX) -> safe to persist the setup log there (admin-only write,
# attacker cannot pre-plant a symlink). Earlier lines were console-only (see the L() note above).
$script:LOGFILE = Join-Path $HOME_DIR 'setup-result.txt'
L "log now persisting to $script:LOGFILE"

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
    if($PIN.ContainsKey($f) -and $PIN[$f] -and ((Hash (Join-Path $HOME_DIR $f)) -ne $PIN[$f])){ throw "DEPLOYED hash mismatch for $f -- aborting before task registration (source may have been swapped mid-install)" }   # empty pin SKIPS
  }
  L "deployed bytes hash-verified against pin"
}

# --- 6. FAIL-CLOSED trust-anchor verification BEFORE registering any SYSTEM task ---
$bad = @()
$u = Get-Untrusted $HOME_DIR $true; if($u){ $bad += "$HOME_DIR ($u)" }
foreach($f in $BROKER_FILES){ $u = Get-Untrusted (Join-Path $HOME_DIR $f) $false; if($u){ $bad += "$f ($u)" } }
$u = Get-Untrusted $ALLOWED $true; if($u){ $bad += "allowed ($u)" }
$u = Test-AuditTight $AUDIT; if($u){ $bad += "audit.log ($u)" }   # stricter: audit.log must be Users-NONE (no read)
foreach($pair in @(@{d=$DATA;m=$USERS_RX;i=$INH_CICO}, @{d=$REQ;m=$USERS_REQ;i=$INH_NONE}, @{d=$RES;m=$USERS_RX;i=$INH_CICO})){ $u = Get-UnexpectedAce $pair.d $pair.m $pair.i; if($u){ $bad += "$($pair.d) ($u)" } }
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
