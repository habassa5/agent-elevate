# AgentElevate elevation broker. Runs as SYSTEM from the admin-only C:\Program Files\AgentElevate\.
# The path ACL (owner = Administrators, Users:RX) is the ONLY trust anchor -- NO signing cert.
# Triggered by Application/AgentElevate EventID 4001 (+ a slow safety poll). Reads JSON request files
# from a Users-writable drop queue, and runs ONLY operations that are (a) enabled in the admin-only
# policy AND (b) whose every parameter is on that op's admin-curated allow-list. Never builds a shell
# string; never runs attacker-supplied code. Every request gets a fail-closed JSON-lines audit entry
# attributed to the OS-set file owner (unforgeable). Keep this file admin-only + reviewed -- it is the
# security boundary. See broker-policy.json for the allow-lists and the deliberate "one UAC = one new
# capability" gate.
$ErrorActionPreference = 'Stop'
$HOME_DIR = 'C:\Program Files\AgentElevate'
$DATA_DIR = 'C:\ProgramData\AgentElevate'
$REQ_DIR  = Join-Path $DATA_DIR 'requests'
$RES_DIR  = Join-Path $DATA_DIR 'results'
$POLICY   = Join-Path $HOME_DIR 'broker-policy.json'
$ALLOWED  = Join-Path $HOME_DIR 'allowed'    # admin-only approved scripts (presence = allow-list)
$AUDIT    = Join-Path $HOME_DIR 'audit.log'  # admin-only; Users have NO access (tamper-evident, lock-proof)
$SELF     = Join-Path $HOME_DIR 'broker.ps1'
$MAX_PER_RUN  = 100                          # anti-flood: bound work per trigger
$MAX_REQ_SIZE = 65536                         # bytes
$STALE_MIN    = 30                            # delete request files older than this (flood/garbage bound)

# ----- well-known SIDs (language-independent) -----
$SID_SYSTEM = 'S-1-5-18'
$SID_ADMINS = 'S-1-5-32-544'
$SID_USERS  = 'S-1-5-32-545'
$SID_TI_PFX = 'S-1-5-80-956008885'           # NT SERVICE\TrustedInstaller (prefix)
$SID_CREATOR= 'S-1-3-0'

# ----- TOCTOU-safe request reader: open ONE exclusive handle, refuse to follow reparse points,
#       read size+content from that single handle. Never re-resolves by path. The guard makes the type
#       definition idempotent (re-running Add-Type for an existing type throws -- matters when dot-sourced). -----
if(-not ('AeReq' -as [type])){
Add-Type @"
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class AeReq {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern SafeFileHandle CreateFileW(string p, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  // Pack=4 matches the native (DWORD-aligned) BY_HANDLE_FILE_INFORMATION; without it the 8-byte longs
  // force 8-byte alignment and nFileSizeHigh/Low read garbage (file appears huge).
  [StructLayout(LayoutKind.Sequential, Pack = 4)]
  struct INFO { public uint attr; public long ct; public long at; public long wt; public uint vsn; public uint hi; public uint lo; public uint links; public uint ihi; public uint ilo; }
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle h, out INFO i);
  public static byte[] ReadExclusive(string path, long maxLen) {
    // GENERIC_READ, share=0 (exclusive), OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT (do NOT follow links)
    SafeFileHandle h = CreateFileW(path, 0x80000000u, 0u, IntPtr.Zero, 3u, 0x00200000u, IntPtr.Zero);
    if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    INFO info;
    if (!GetFileInformationByHandle(h, out info)) { int e = Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
    if ((info.attr & 0x400) != 0) { h.Dispose(); throw new IOException("reparse point"); }   // FILE_ATTRIBUTE_REPARSE_POINT
    if ((info.attr & 0x10)  != 0) { h.Dispose(); throw new IOException("directory"); }        // FILE_ATTRIBUTE_DIRECTORY
    long len = ((long)info.hi << 32) | (uint)info.lo;
    if (len > maxLen) { h.Dispose(); throw new IOException("too large"); }
    FileStream fs = new FileStream(h, FileAccess.Read);
    try {
      byte[] buf = new byte[len];
      int off = 0;
      while (off < len) { int n = fs.Read(buf, off, (int)(len - off)); if (n <= 0) break; off += n; }
      return buf;
    } finally { fs.Dispose(); }
  }
}
"@
}

# ----- admin-only verifier: returns '' if $path is non-reparse, owned by a trusted principal, and has
#       NO write/modify/delete/own ACE for any non-trusted principal; else a human reason. (Proven logic
#       ported from the live keep-awake installer.) -----
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
    if(([int]$a.FileSystemRights -band [int]$wm) -ne 0){ $bad += $a.IdentityReference.Value }
  }
  return ($bad -join '; ')
}

# ----- fail-closed JSON-lines audit. Returns $true ONLY if the durable line was written. Every
#       attacker-controlled field is JSON-encoded (no newline/log injection). Users have no read/write
#       on audit.log, so a non-admin can neither forge nor lock it. -----
function Write-Audit($obj){
  $ok = $false
  try {
    $json = ($obj | ConvertTo-Json -Compress -Depth 8)
    # FileStream with WriteThrough so a committed audit line survives a power loss, not just a process crash.
    $fs = New-Object System.IO.FileStream($AUDIT,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    $sw = New-Object System.IO.StreamWriter($fs,(New-Object System.Text.UTF8Encoding($false)))
    try { $sw.WriteLine($json); $sw.Flush() } finally { $sw.Dispose() }
    $ok = $true
  } catch { $ok = $false }
  try {
    $v = [string]$obj.verdict
    $lvl = if($v -eq 'ALLOW-OK'){'Information'} elseif($v -like 'DENY*' -or $v -eq 'ALLOW-FAIL'){'Warning'} else {'Error'}
    # native .NET API: portable across Windows PowerShell 5.1 + PowerShell 7 (no Write-EventLog dependency)
    [System.Diagnostics.EventLog]::WriteEntry('AgentElevate-Broker',($obj | ConvertTo-Json -Compress -Depth 8),[System.Diagnostics.EventLogEntryType]$lvl,4100)
  } catch {}
  return $ok
}

# ----- strict character validators (defense in depth; the allow-lists are the real gate) -----
function V-PkgId($v){ ($v -is [string]) -and ($v -match '^[A-Za-z0-9][A-Za-z0-9.\-_+]{0,128}$') }
function V-ScriptName($v){
  if($v -isnot [string]){ return $false }
  if($v -notmatch '^[A-Za-z0-9._\-]{1,80}\.ps1$'){ return $false }
  if($v -match '\.\.'){ return $false }
  if(($v -split '\.')[0] -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$'){ return $false }   # reserved DOS device names
  return $true
}
function V-Hostname($v){ ($v -is [string]) -and ($v -match '^[A-Za-z0-9.\-]{1,253}$') }
# octets strictly 0-255, plus a real parse (TryParse is the gate; the regex bounds octet range up front)
function V-IPv4($v){ if($v -isnot [string]){ return $false }; if($v -notmatch '^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$'){ return $false }; $t=[System.Net.IPAddress]::Any; [System.Net.IPAddress]::TryParse($v,[ref]$t) }
function V-EnvName($v){ ($v -is [string]) -and ($v -match '^[A-Za-z_][A-Za-z0-9_]{0,127}$') }
# require an actual integer (or pure-digit string) -- reject 80.9->81 coercion and other non-integer forms
function V-Port($v){ $isInt = ($v -is [int]) -or ($v -is [long]) -or (($v -is [string]) -and ($v -match '^\d+$')); $isInt -and ([long]$v -ge 1) -and ([long]$v -le 65535) }
function Test-PrivateOrLoopback($ip){
  $o = $ip.Split('.') | ForEach-Object { [int]$_ }
  if($o[0] -eq 127){ return $true }                         # loopback (127.0.0.0/8)
  if($o[0] -eq 10){ return $true }                          # RFC1918 10.0.0.0/8
  if($o[0] -eq 192 -and $o[1] -eq 168){ return $true }      # RFC1918 192.168.0.0/16
  if($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31){ return $true } # RFC1918 172.16.0.0/12
  return $false                                             # link-local 169.254/16 deliberately EXCLUDED
}

# Resolve winget by TRUSTED ABSOLUTE PATH (never Get-Command -> never honors a poisoned PATH) and verify
# it is admin-only before running it as SYSTEM.
function Resolve-Winget {
  $cands = @(Resolve-Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" -EA SilentlyContinue | ForEach-Object { $_.Path })
  $wg = $cands | Sort-Object | Select-Object -Last 1
  if(-not $wg){ return $null }
  if(Get-Untrusted $wg $false){ return $null }
  return $wg
}

# Machine env names that steer other elevated processes into attacker code -- hard-denied even if an admin
# mistakenly allow-lists one.
$ENV_DENY = @('Path','PSModulePath','ComSpec','PATHEXT','windir','SystemRoot','SystemDrive','ProgramData',
  'ProgramFiles','ProgramFiles(x86)','CommonProgramFiles','CommonProgramFiles(x86)','__PSLockdownPolicy',
  'PSExecutionPolicyPreference','TEMP','TMP','OS','USERPROFILE','ALLUSERSPROFILE','APPDATA','LOCALAPPDATA','DriverData')
function Test-EnvDenied($name){
  if($ENV_DENY -contains $name){ return $true }                 # -contains is case-insensitive (env names are too)
  if($name -match '^(COMPLUS_|DOTNET_|COR_|CORECLR_)'){ return $true }  # CLR profiler / JIT hijack prefixes
  return $false
}

# ----- operation handlers. Each returns @{ok=$bool; detail=...}; each enforces its policy allow-list. -----
function Op-WingetInstall($p,$node){
  if(-not (V-PkgId $p.id)){ return @{ok=$false; detail='invalid package id'} }
  # $allowedPkgs (NOT $allowed): PowerShell vars are case-insensitive; $allowed would alias $ALLOWED (the path).
  $allowedPkgs = @($node.allowedPackages)
  if($allowedPkgs -notcontains [string]$p.id){ return @{ok=$false; detail="package '$($p.id)' not on allowedPackages"} }
  $wg = Resolve-Winget
  if(-not $wg){ return @{ok=$false; detail='winget not found or not admin-only'} }
  $a = @('install','--id',[string]$p.id,'--exact','--source','winget','--silent','--accept-source-agreements','--accept-package-agreements','--disable-interactivity')
  $proc = Start-Process -FilePath $wg -ArgumentList $a -Wait -PassThru -NoNewWindow
  return @{ok=($proc.ExitCode -eq 0); detail="winget exit $($proc.ExitCode)"}
}
function Op-RunAllowedScript($p){
  if(-not (V-ScriptName $p.name)){ return @{ok=$false; detail='invalid script name'} }
  # the allowed\ dir itself must be admin-only + non-reparse (re-checked here, not just at startup)
  $du = Get-Untrusted $ALLOWED $true
  if($du){ return @{ok=$false; detail="allowed dir not admin-only ($du)"} }
  $path = Join-Path $ALLOWED $p.name
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){ return @{ok=$false; detail='not an approved script'} }
  $resolved = (Resolve-Path -LiteralPath $path).Path
  if([IO.Path]::GetDirectoryName($resolved) -ne (Resolve-Path -LiteralPath $ALLOWED).Path){ return @{ok=$false; detail='path escape'} }
  $su = Get-Untrusted $resolved $false
  if($su){ return @{ok=$false; detail="approved script not admin-only ($su)"} }
  $PSEXE = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  # Call operator (NOT Start-Process -ArgumentList): the script path lives under "C:\Program Files\..."
  # which has a space; -ArgumentList flattens it and powershell sees "-File C:\Program" and fails. The call
  # operator passes $resolved as ONE properly-quoted argument. Still -File (no shell string) -> no injection.
  & $PSEXE -NoProfile -ExecutionPolicy Bypass -File $resolved
  $code = $LASTEXITCODE
  return @{ok=($code -eq 0); detail="script exit $code"}
}
function Op-HostsAdd($p,$node){
  if(-not (V-IPv4 $p.ip) -or -not (V-Hostname $p.host)){ return @{ok=$false; detail='invalid ip/host'} }
  if(@($node.allowedHosts) -notcontains [string]$p.host){ return @{ok=$false; detail="host '$($p.host)' not on allowedHosts"} }
  if(-not (Test-PrivateOrLoopback ([string]$p.ip))){ return @{ok=$false; detail='ip must be loopback or RFC1918 (link-local/public refused)'} }
  $hf = "$env:SystemRoot\System32\drivers\etc\hosts"
  $existing = Get-Content -LiteralPath $hf -EA SilentlyContinue
  # add-if-absent: parse each non-comment line ('IP host [aliases...]') and treat the host as present if it
  # appears in ANY name field, so a second conflicting mapping can't be slipped in.
  foreach($line in $existing){
    $t = ([string]$line).Trim()
    if($t -eq '' -or $t.StartsWith('#')){ continue }
    $fields = $t -split '\s+'
    if($fields.Count -ge 2 -and ($fields[1..($fields.Count-1)] | Where-Object { $_ -ieq [string]$p.host })){ return @{ok=$true; detail='host already present'} }
  }
  Add-Content -LiteralPath $hf -Value ("{0}`t{1}`t# added by AgentElevate broker {2}" -f $p.ip,$p.host,(Get-Date -Format 'yyyy-MM-dd'))
  return @{ok=$true; detail="added $($p.ip) $($p.host)"}
}
function Op-FirewallAllow($p,$node){
  if(-not (V-Port $p.port) -or $p.direction -notin @('Inbound','Outbound') -or $p.protocol -notin @('TCP','UDP')){ return @{ok=$false; detail='invalid firewall params'} }
  # per-rule allow-list: the EXACT {port,protocol,direction} must be admin-curated, so an attacker cannot
  # choose the direction (e.g. open an inbound listener) -- only rules the admin pre-approved are creatable.
  $match = $false
  foreach($r in @($node.allowedRules)){
    if(($null -ne $r) -and ([int]$r.port -eq [int]$p.port) -and ([string]$r.protocol -eq [string]$p.protocol) -and ([string]$r.direction -eq [string]$p.direction)){ $match = $true; break }
  }
  if(-not $match){ return @{ok=$false; detail="rule $($p.direction)/$($p.protocol)/$([int]$p.port) not on allowedRules"} }
  $cap = if($node.maxRules){ [int]$node.maxRules } else { 20 }
  if(@(Get-NetFirewallRule -DisplayName 'AgentElevate-*' -EA SilentlyContinue).Count -ge $cap){ return @{ok=$false; detail="AgentElevate firewall rule cap ($cap) reached"} }
  $name = "AgentElevate-$($p.direction)-$($p.protocol)-$([int]$p.port)"
  if(Get-NetFirewallRule -DisplayName $name -EA SilentlyContinue){ return @{ok=$true; detail="firewall rule $name already present"} }  # idempotent: no duplicate rules
  New-NetFirewallRule -DisplayName $name -Direction $p.direction -Protocol $p.protocol -LocalPort ([int]$p.port) -Action Allow -EA Stop | Out-Null
  return @{ok=$true; detail="firewall rule $name"}
}
function Op-SetMachineEnv($p,$node){
  if(-not (V-EnvName $p.name) -or ($p.value -isnot [string]) -or $p.value.Length -gt 8192){ return @{ok=$false; detail='invalid env name/value'} }
  if(Test-EnvDenied ([string]$p.name)){ return @{ok=$false; detail="env name '$($p.name)' is hard-denied"} }
  if(@($node.allowedEnvVars) -notcontains [string]$p.name){ return @{ok=$false; detail="env name '$($p.name)' not on allowedEnvVars"} }
  [Environment]::SetEnvironmentVariable($p.name,$p.value,'Machine')
  return @{ok=$true; detail="set machine env $($p.name)"}
}

$KNOWN_OPS = @('winget-install','run-allowed-script','hosts-add','firewall-allow','set-machine-env')
function Invoke-Op($op,$p,$node){
  switch($op){
    'winget-install'     { return (Op-WingetInstall $p $node) }
    'run-allowed-script' { return (Op-RunAllowedScript $p) }
    'hosts-add'          { return (Op-HostsAdd $p $node) }
    'firewall-allow'     { return (Op-FirewallAllow $p $node) }
    'set-machine-env'    { return (Op-SetMachineEnv $p $node) }
    default              { return @{ok=$false; detail='unknown operation'} }
  }
}

# ===== STARTUP SELF-INTEGRITY: the broker refuses to process anything unless its own trust anchor is
#       intact (admin-owned, admin-only, non-reparse). This is the runtime half of the ownership fix. =====
$anchorBad = @()
foreach($it in @(@{p=$HOME_DIR;d=$true}, @{p=$SELF;d=$false}, @{p=$POLICY;d=$false}, @{p=$AUDIT;d=$false}, @{p=$ALLOWED;d=$true})){
  $r = Get-Untrusted $it.p $it.d
  if($r){ $anchorBad += ("{0}: {1}" -f $it.p,$r) }
}
foreach($d in @($DATA_DIR,$REQ_DIR,$RES_DIR)){ if(Test-ReparsePoint $d){ $anchorBad += ("{0}: reparse point" -f $d) } }
if($anchorBad.Count -gt 0){
  Write-Audit @{ ts=(Get-Date -Format o); reqId='-'; owner='-'; claimedBy='broker'; op='-'; verdict='ABORT-ANCHOR'; detail=($anchorBad -join ' | ') } | Out-Null
  exit 1
}

# ----- load policy (admin-only). $pol (NOT $policy): $policy would alias $POLICY (the path) case-insensitively. -----
try { $pol = Get-Content -LiteralPath $POLICY -Raw | ConvertFrom-Json }
catch { Write-Audit @{ ts=(Get-Date -Format o); reqId='-'; owner='-'; claimedBy='broker'; op='-'; verdict='ERROR'; detail="policy load failed: $_" } | Out-Null; exit 1 }
$ops = $pol.operations
function Get-OpNode($op){ if($ops -and $ops.PSObject.Properties[$op]){ return $ops.PSObject.Properties[$op].Value } else { return $null } }

# ----- process pending requests (oldest first, capped) -----
$pending = Get-ChildItem -LiteralPath $REQ_DIR -Filter '*.req.json' -File -EA SilentlyContinue | Sort-Object CreationTimeUtc | Select-Object -First $MAX_PER_RUN
foreach($f in $pending){
  $reqFile = $f.FullName
  $reqId = ($f.BaseName -replace '\.req$','')
  if($reqId -notmatch '^[A-Za-z0-9]{1,64}$'){ $reqId = [guid]::NewGuid().ToString('N') }   # malformed name -> fresh id (no result-path collision/traversal)
  $owner = '?'; $who = '?'; $op = '?'; $deleteReq = $true
  try {
    try { $owner = (Get-Acl -LiteralPath $reqFile).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { $owner = 'unknown' }
    $bytes = $null
    try { $bytes = [AeReq]::ReadExclusive($reqFile,$MAX_REQ_SIZE) }
    catch {
      $ageSec = ((Get-Date).ToUniversalTime() - $f.CreationTimeUtc).TotalSeconds
      Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy='?'; op='-'; verdict='DENY-READ'; detail=("$_ (age {0:N0}s)" -f $ageSec) } | Out-Null
      if($ageSec -lt 8){ $deleteReq = $false; continue }   # transient (client mid-write / AV scan) -> leave for retry, don't delete or answer yet
      @{ id=$reqId; ok=$false; detail="request unreadable: $_"; ts=(Get-Date -Format o) } | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $RES_DIR ($reqId + '.res.json')) -Encoding utf8 -EA SilentlyContinue
      continue   # permanent read failure -> client got a deny result; finally deletes the request
    }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF){ $text = $text.Substring(1) }   # tolerate a UTF-8 BOM
    $r = $text | ConvertFrom-Json
    $op = [string]$r.op; $who = [string]$r.by
    $node = Get-OpNode $op
    $result = @{ok=$false; detail=''}
    if($op -notin $KNOWN_OPS){
      $result.detail = 'unknown operation'; Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='DENY-UNKNOWN'; detail=$result.detail } | Out-Null
    } elseif(-not $node -or -not (($node.enabled -is [bool]) -and $node.enabled)){
      # require an ACTUAL JSON boolean true -- a string like "false" (or "true") is truthy in PowerShell and
      # must NOT enable an op; this denies a typo'd/over-permissive policy rather than silently enabling it.
      $result.detail = 'operation not enabled in policy'; Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='DENY-POLICY'; detail=$result.detail } | Out-Null
    } else {
      # FAIL-CLOSED: only run the op if the "about to run" audit line was durably written.
      $ran = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='ALLOW-RUN'; params=$r.params }
      if(-not $ran){
        $result.detail = 'audit write failed; operation denied (fail-closed)'
      } else {
        $result = Invoke-Op $op $r.params $node
        Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict=$(if($result.ok){'ALLOW-OK'}else{'ALLOW-FAIL'}); detail=$result.detail } | Out-Null
      }
    }
    @{ id=$reqId; ok=[bool]$result.ok; detail=[string]$result.detail; ts=(Get-Date -Format o) } | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $RES_DIR ($reqId + '.res.json')) -Encoding utf8
  } catch {
    Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='ERROR'; detail="$_" } | Out-Null
    try { @{ id=$reqId; ok=$false; detail="broker error"; ts=(Get-Date -Format o) } | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $RES_DIR ($reqId + '.res.json')) -Encoding utf8 } catch {}
  } finally {
    if($deleteReq){ Remove-Item -LiteralPath $reqFile -Force -EA SilentlyContinue }
  }
}

# GC: bound the queues. Delete stale request files (flood/garbage) + result files older than 60 min.
Get-ChildItem -LiteralPath $REQ_DIR -Filter '*.req.json' -File -EA SilentlyContinue | Where-Object { $_.CreationTimeUtc -lt (Get-Date).ToUniversalTime().AddMinutes(-$STALE_MIN) } | Remove-Item -Force -EA SilentlyContinue
Get-ChildItem -LiteralPath $RES_DIR -Filter '*.res.json' -File -EA SilentlyContinue | Where-Object { $_.CreationTimeUtc -lt (Get-Date).ToUniversalTime().AddMinutes(-60) } | Remove-Item -Force -EA SilentlyContinue
