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
$FUTURE_TOL_MIN = 2                           # CreationTime is owner-settable; treat > now+this as forged (GC it,
                                              # never execute it). Same-machine honest requests can't be future-dated.

# ----- well-known SIDs (language-independent) -----
$SID_SYSTEM = 'S-1-5-18'
$SID_ADMINS = 'S-1-5-32-544'
$SID_TI_PFX = 'S-1-5-80-956008885'           # NT SERVICE\TrustedInstaller (prefix)
$SID_CREATOR= 'S-1-3-0'                       # CREATOR OWNER (file-owner ACE on a created request)

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
public class AeRead { public byte[] Data; public string Owner; }   // bytes + owner SID, both from ONE validated handle
public static class AeReq {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern SafeFileHandle CreateFileW(string p, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  // Pack=4 matches the native (DWORD-aligned) BY_HANDLE_FILE_INFORMATION; without it the 8-byte longs
  // force 8-byte alignment and nFileSizeHigh/Low read garbage (file appears huge).
  [StructLayout(LayoutKind.Sequential, Pack = 4)]
  struct INFO { public uint attr; public long ct; public long at; public long wt; public uint vsn; public uint hi; public uint lo; public uint links; public uint ihi; public uint ilo; }
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle h, out INFO i);
  [DllImport("advapi32.dll")]
  static extern uint GetSecurityInfo(SafeFileHandle h, int objType, int secInfo, out IntPtr owner, IntPtr grp, IntPtr dacl, IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);
  [DllImport("kernel32.dll")]
  static extern IntPtr LocalFree(IntPtr h);
  // Owner SID string from an ALREADY-VALIDATED handle (no path re-resolve -> no TOCTOU; a hardlink/symlink
  // cannot spoof the owner because we never resolve by path). "?" if it can't be read.
  static string OwnerFromHandle(SafeFileHandle h) {
    IntPtr owner = IntPtr.Zero, sd = IntPtr.Zero;
    uint rc = GetSecurityInfo(h, 1 /*SE_FILE_OBJECT*/, 1 /*OWNER_SECURITY_INFORMATION*/, out owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
    if (rc != 0 || owner == IntPtr.Zero) { if (sd != IntPtr.Zero) LocalFree(sd); return "?"; }
    string s = "?"; IntPtr str;
    if (ConvertSidToStringSidW(owner, out str)) { s = Marshal.PtrToStringUni(str); LocalFree(str); }
    LocalFree(sd);
    return s;
  }
  public static AeRead ReadExclusive(string path, long maxLen) {
    // GENERIC_READ (incl READ_CONTROL for the owner query), share=0 (exclusive), OPEN_EXISTING,
    // FILE_FLAG_OPEN_REPARSE_POINT (do NOT follow links)
    SafeFileHandle h = CreateFileW(path, 0x80000000u, 0u, IntPtr.Zero, 3u, 0x00200000u, IntPtr.Zero);
    if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    INFO info;
    if (!GetFileInformationByHandle(h, out info)) { int e = Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
    if ((info.attr & 0x400) != 0) { h.Dispose(); throw new IOException("reparse point"); }   // FILE_ATTRIBUTE_REPARSE_POINT (symlink/junction)
    if ((info.attr & 0x10)  != 0) { h.Dispose(); throw new IOException("directory"); }        // FILE_ATTRIBUTE_DIRECTORY
    // A HARD LINK (links>1) is not a reparse point and shares the TARGET's security descriptor, so a non-admin
    // could hardlink a request to a trusted-owned file and forge the audit owner. A legit request has links==1.
    if (info.links > 1)          { h.Dispose(); throw new IOException("hard link"); }
    long len = ((long)info.hi << 32) | (uint)info.lo;
    if (len > maxLen) { h.Dispose(); throw new IOException("too large"); }
    string owner = OwnerFromHandle(h);   // from the validated handle, BEFORE the FileStream takes ownership of it
    FileStream fs = new FileStream(h, FileAccess.Read);
    try {
      byte[] buf = new byte[len];
      int off = 0;
      while (off < len) { int n = fs.Read(buf, off, (int)(len - off)); if (n <= 0) break; off += n; }
      return new AeRead { Data = buf, Owner = owner };
    } finally { fs.Dispose(); }
  }
}
"@
}

# ----- admin-only verifier: returns '' if $path is non-reparse, owned by a trusted principal, and has
#       NO write/modify/delete/own ACE for any non-trusted principal; else a human reason. -----
function Test-ReparsePoint($p){ try { (((Get-Item -LiteralPath $p -Force).Attributes) -band [IO.FileAttributes]::ReparsePoint) -ne 0 } catch { $false } }
function Get-Untrusted($p,$isDir){
  if(-not (Test-Path -LiteralPath $p)){ return 'missing' }
  if(Test-ReparsePoint $p){ return 'reparse point' }
  $acl = $null; try { $acl = Get-Acl -LiteralPath $p } catch { return 'acl-unreadable' }   # fail-closed if the ACL can't be read
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
    # include GENERIC_WRITE (0x40000000) + GENERIC_ALL (0x10000000): inherit-only ACEs on DIRECTORIES retain
    # raw generic bits (Windows only maps generic->specific on files at store time), so the specific mask alone
    # would miss a non-admin generic-write/all ACE on a directory.
    if(([int]$a.FileSystemRights -band ([int]$wm -bor 0x40000000 -bor 0x10000000)) -ne 0){ $bad += $a.IdentityReference.Value }
  }
  return ($bad -join '; ')
}
# audit.log holds request params + owner SIDs, so it must be SYSTEM/Admins-only -- NOT even Users-READABLE.
# Get-Untrusted permits a non-admin READ ACE (it only blocks non-admin write); this stricter check returns '' iff
# the file has NO Allow ACE for any SID outside {SYSTEM, Admins, TrustedInstaller}. Used on $AUDIT specifically.
function Test-AuditTight($p){
  $u = Get-Untrusted $p $false; if($u){ return $u }   # owner trusted + non-reparse + no non-admin WRITE
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

# ----- fail-closed JSON-lines audit. Returns $true ONLY if the durable line was written. Every
#       attacker-controlled field is JSON-encoded (no newline/log injection). Users have no read/write
#       on audit.log, so a non-admin can neither forge nor lock it. -----
function Write-Audit($obj){
  $ok = $false
  try {
    $json = ($obj | ConvertTo-Json -Compress -Depth 8)
    # Open the EXISTING audit.log only (FileMode.Open) + WriteThrough. If it is missing -> throw -> fail-closed;
    # never silently re-create it with inherited Users:RX (setup creates it admin-only; startup aborts if gone).
    $fs = New-Object System.IO.FileStream($AUDIT,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    $sw = New-Object System.IO.StreamWriter($fs,(New-Object System.Text.UTF8Encoding($false)))
    try { [void]$fs.Seek(0,[IO.SeekOrigin]::End); $sw.WriteLine($json); $sw.Flush() } finally { $sw.Dispose() }
    $ok = $true
  } catch { $ok = $false }
  try {
    $v = [string]$obj.verdict
    # normal operation (allowed run, its OK terminal, routine GC) = Information; a denial or failed op = Warning;
    # only a broker malfunction/tamper (ERROR, ABORT-ANCHOR) = Error. ALLOW-RUN is NOT an error.
    $lvl = if($v -eq 'ALLOW-OK' -or $v -eq 'ALLOW-RUN' -or $v -eq 'GC-STALE'){'Information'} elseif($v -like 'DENY*' -or $v -eq 'ALLOW-FAIL'){'Warning'} else {'Error'}
    # native .NET API (portable PS 5.1 + 7). Mirror a BOUNDED, fixed-shape record (NOT the raw attacker JSON,
    # whose oversized params could throw >32766 chars and silently suppress the tamper-evident mirror).
    $mirror = @{ ts=$obj.ts; reqId=$obj.reqId; owner=$obj.owner; claimedBy=([string]$obj.claimedBy); op=([string]$obj.op); verdict=$v; detail=([string]$obj.detail) }
    $mmsg = ($mirror | ConvertTo-Json -Compress -Depth 3); if($mmsg.Length -gt 30000){ $mmsg = $mmsg.Substring(0,30000) }
    [System.Diagnostics.EventLog]::WriteEntry('AgentElevate-Broker',$mmsg,[System.Diagnostics.EventLogEntryType]$lvl,4100)
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
# require an actual integer (or pure-digit string) in 1..65535. TryParse (not a [long] cast) so a huge digit
# string returns $false (a clean DENY-PARAM) instead of an overflow EXCEPTION (which would audit as ERROR).
function V-Port($v){
  $n = 0L
  if(($v -is [int]) -or ($v -is [long])){ $n = [long]$v }
  elseif(($v -is [string]) -and ($v -match '^\d+$') -and [long]::TryParse($v,[ref]$n)){ }
  else { return $false }
  ($n -ge 1) -and ($n -le 65535)
}
function Test-PrivateOrLoopback($ip){
  $o = $ip.Split('.') | ForEach-Object { [int]$_ }
  if($o[0] -eq 127){ return $true }                         # loopback (127.0.0.0/8)
  if($o[0] -eq 10){ return $true }                          # RFC1918 10.0.0.0/8
  if($o[0] -eq 192 -and $o[1] -eq 168){ return $true }      # RFC1918 192.168.0.0/16
  if($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31){ return $true } # RFC1918 172.16.0.0/12
  return $false                                             # link-local 169.254/16 deliberately EXCLUDED
}

# Strict request-shape validator (defense against the array-vs-string type-confusion class). A valid request is
# a single JSON OBJECT with a string `op`, an optional string `by`, and an optional object `params`. ConvertFrom-
# Json yields a PSCustomObject for an object and Object[] for an array, and PowerShell silently unwraps a singleton
# array on member access -- so without this gate `{"op":["winget-install"]}` or `[{...}]` would be accepted.
function Test-RequestShape($text,$r){
  # Reject a top-level JSON array at the TEXT level: PowerShell 7's ConvertFrom-Json ENUMERATES a top-level array
  # (so `[{...}]` arrives as its unwrapped element before we can inspect it), while 5.1 returns an Object[]. The
  # text check catches it on BOTH engines; the `$r -is [Array]` check below is the 5.1 backstop.
  if(([string]$text).TrimStart().StartsWith('[')){ return 'request must be a single JSON object, not an array' }
  if($null -eq $r){ return 'null request' }
  if($r -is [System.Array]){ return 'request must be a single JSON object, not an array' }
  if($r -isnot [System.Management.Automation.PSCustomObject]){ return 'request must be a JSON object' }
  if($r.op -isnot [string]){ return 'op must be a string' }
  if(($null -ne $r.by) -and ($r.by -isnot [string])){ return 'by must be a string' }
  if($r.PSObject.Properties['params'] -and ($null -ne $r.params) -and ($r.params -isnot [System.Management.Automation.PSCustomObject])){ return 'params must be a JSON object' }
  return ''
}

# Resolve winget by TRUSTED ABSOLUTE PATH (never Get-Command -> never honors a poisoned PATH) and verify
# it is admin-only before running it as SYSTEM.
function Resolve-Winget {
  $cands = @(Resolve-Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" -EA SilentlyContinue | ForEach-Object { $_.Path })
  # pick the highest VERSION (parsed from the package folder), not a lexicographic path sort (1.9 vs 1.24)
  $wg = $cands | Sort-Object @{ Expression = { $v=[version]'0.0'; if($_ -match 'Microsoft\.DesktopAppInstaller_(\d+(\.\d+){1,3})_'){ [void][version]::TryParse($matches[1],[ref]$v) }; $v } } | Select-Object -Last 1
  if(-not $wg){ return $null }
  if(Get-Untrusted $wg $false){ return $null }
  return $wg
}

# Machine env names that steer other elevated processes into attacker code -- hard-denied even if an admin
# mistakenly allow-lists one.
$ENV_DENY = @('Path','PSModulePath','ComSpec','PATHEXT','windir','SystemRoot','SystemDrive','ProgramData',
  'ProgramFiles','ProgramFiles(x86)','CommonProgramFiles','CommonProgramFiles(x86)','__PSLockdownPolicy',
  'PSExecutionPolicyPreference','TEMP','TMP','OS','USERPROFILE','ALLUSERSPROFILE','APPDATA','LOCALAPPDATA','DriverData',
  # cross-runtime code-loaders: setting these machine-wide steers Java/.NET/Python/Node/Perl/Ruby/native loaders
  'JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JAVA_OPTS','JDK_JAVA_OPTIONS','CLASSPATH','PYTHONPATH','PYTHONSTARTUP',
  'PYTHONHOME','NODE_OPTIONS','NODE_PATH','PERL5LIB','PERL5OPT','RUBYOPT','RUBYLIB','GEM_PATH','LD_PRELOAD',
  'LD_LIBRARY_PATH','GCONV_PATH')
function Test-EnvDenied($name){
  if($ENV_DENY -contains $name){ return $true }                 # -contains is case-insensitive (env names are too)
  if($name -match '^(COMPLUS_|DOTNET_|COR_|CORECLR_|JAVA_|_JAVA|PYTHON|NODE_|PERL5|RUBY)'){ return $true }  # CLR/JVM/Python/Node/etc. loader prefixes
  return $false
}

# ----- PARAM VALIDATION GATE: returns a deny-reason ('' = allowed). The single place the param + allow-list
#       rules live, so the broker can audit a precise DENY-PARAM BEFORE writing ALLOW-RUN. Pure checks only (no
#       side effects); execution-time preconditions that depend on live filesystem state stay in the handler. -----
function Test-OpParams($op,$p,$node){
  switch($op){
    'winget-install' {
      if(-not (V-PkgId $p.id)){ return 'invalid package id' }
      if(@($node.allowedPackages) -notcontains [string]$p.id){ return "package '$($p.id)' not on allowedPackages" }
    }
    'run-allowed-script' {
      if(-not (V-ScriptName $p.name)){ return 'invalid script name' }   # existence + admin-only are execution preconditions (Op-RunAllowedScript)
    }
    'hosts-add' {
      if(-not (V-IPv4 $p.ip) -or -not (V-Hostname $p.host)){ return 'invalid ip/host' }
      if(@($node.allowedHosts) -notcontains [string]$p.host){ return "host '$($p.host)' not on allowedHosts" }
      if(-not (Test-PrivateOrLoopback ([string]$p.ip))){ return 'ip must be loopback or RFC1918 (link-local/public refused)' }
    }
    'firewall-allow' {
      if(-not (V-Port $p.port) -or $p.direction -notin @('Inbound','Outbound') -or $p.protocol -notin @('TCP','UDP')){ return 'invalid firewall params' }
      # per-rule allow-list: the EXACT {port,protocol,direction} must be admin-curated, so an attacker cannot
      # choose the direction (e.g. open an inbound listener) -- only rules the admin pre-approved are creatable.
      $match = $false
      foreach($r in @($node.allowedRules)){ if(($null -ne $r) -and ([int]$r.port -eq [int]$p.port) -and ([string]$r.protocol -eq [string]$p.protocol) -and ([string]$r.direction -eq [string]$p.direction)){ $match = $true; break } }
      if(-not $match){ return "rule $($p.direction)/$($p.protocol)/$([int]$p.port) not on allowedRules" }
    }
    'set-machine-env' {
      if(-not (V-EnvName $p.name) -or ($p.value -isnot [string]) -or $p.value.Length -gt 8192){ return 'invalid env name/value' }
      if(Test-EnvDenied ([string]$p.name)){ return "env name '$($p.name)' is hard-denied" }
      if(@($node.allowedEnvVars) -notcontains [string]$p.name){ return "env name '$($p.name)' not on allowedEnvVars" }
    }
  }
  return ''
}

# ----- operation HANDLERS (execute-only). Test-OpParams has already validated params + allow-list (Invoke-Op
#       re-asserts it as defense-in-depth), so each handler does only the side effect + live-state preconditions.
#       Each returns @{ok=$bool; detail=...}. -----
function Op-WingetInstall($p,$node){
  $wg = Resolve-Winget
  if(-not $wg){ return @{ok=$false; detail='winget not found or not admin-only'} }
  $a = @('install','--id',[string]$p.id,'--exact','--source','winget','--silent','--accept-source-agreements','--accept-package-agreements','--disable-interactivity')
  $proc = Start-Process -FilePath $wg -ArgumentList $a -Wait -PassThru -NoNewWindow
  return @{ok=($proc.ExitCode -eq 0); detail="winget exit $($proc.ExitCode)"}
}
function Op-RunAllowedScript($p){
  # Execution preconditions on LIVE filesystem state (kept here, not in Test-OpParams, so the admin-only check and
  # the execution use the SAME resolved path -- a validate-then-reresolve split would be a TOCTOU).
  $du = Get-Untrusted $ALLOWED $true
  if($du){ return @{ok=$false; detail="allowed dir not admin-only ($du)"} }
  $path = Join-Path $ALLOWED $p.name
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){ return @{ok=$false; detail='not an approved script'} }
  $resolved = (Resolve-Path -LiteralPath $path).Path
  if([IO.Path]::GetDirectoryName($resolved) -ne (Resolve-Path -LiteralPath $ALLOWED).Path){ return @{ok=$false; detail='path escape'} }
  $su = Get-Untrusted $resolved $false
  if($su){ return @{ok=$false; detail="approved script not admin-only ($su)"} }
  $PSEXE = (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')   # API-resolved, not $env:SystemRoot
  # Call operator (NOT Start-Process -ArgumentList): the script path lives under "C:\Program Files\..." which has a
  # space; -ArgumentList flattens it and powershell sees "-File C:\Program" and fails. The call operator passes
  # $resolved as ONE properly-quoted argument. Still -File (no shell string) -> no injection.
  & $PSEXE -NoProfile -ExecutionPolicy Bypass -File $resolved
  $code = $LASTEXITCODE
  return @{ok=($code -eq 0); detail="script exit $code"}
}
function Op-HostsAdd($p,$node){
  $hf = (Join-Path ([Environment]::SystemDirectory) 'drivers\etc\hosts')   # API-resolved, not $env:SystemRoot
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
  $name = "AgentElevate-$($p.direction)-$($p.protocol)-$([int]$p.port)"
  # idempotency BEFORE the cap: an already-present rule returns success even at the cap (re-requesting an existing
  # allowed rule must not fail just because the cap is reached -- the cap only bounds NEW rule creation). VERIFY
  # the existing rule actually matches {direction,protocol,port,Allow} rather than trust the name: a drifted or
  # admin-created same-name rule could differ, and we must not report OK while the intended rule is absent.
  $existing = Get-NetFirewallRule -DisplayName $name -EA SilentlyContinue
  if($existing){
    $pf = $existing | Get-NetFirewallPortFilter -EA SilentlyContinue
    if(([string]$existing.Direction -eq [string]$p.direction) -and ([string]$existing.Action -eq 'Allow') -and $pf -and ([string]$pf.Protocol -eq [string]$p.protocol) -and ("$($pf.LocalPort)" -eq "$([int]$p.port)")){
      return @{ok=$true; detail="firewall rule $name already present"}
    }
    return @{ok=$false; detail="a rule named $name exists but does NOT match the requested direction/protocol/port/Allow"}
  }
  $cap = if($node.PSObject.Properties['maxRules']){ [int]$node.maxRules } else { 20 }   # presence test: maxRules:0 honestly means "no new rules" (Test-PolicyValid already enforces int)
  if(@(Get-NetFirewallRule -DisplayName 'AgentElevate-*' -EA SilentlyContinue).Count -ge $cap){ return @{ok=$false; detail="AgentElevate firewall rule cap ($cap) reached"} }
  New-NetFirewallRule -DisplayName $name -Direction $p.direction -Protocol $p.protocol -LocalPort ([int]$p.port) -Action Allow -EA Stop | Out-Null
  return @{ok=$true; detail="firewall rule $name"}
}
function Op-SetMachineEnv($p,$node){
  [Environment]::SetEnvironmentVariable($p.name,$p.value,'Machine')
  return @{ok=$true; detail="set machine env $($p.name)"}
}

$KNOWN_OPS = @('winget-install','run-allowed-script','hosts-add','firewall-allow','set-machine-env')
function Invoke-Op($op,$p,$node){
  # defense-in-depth: NEVER execute unvalidated params, even though the broker already gated on Test-OpParams
  # for the audit verdict. Single validation source (Test-OpParams), double enforcement.
  $deny = Test-OpParams $op $p $node
  if($deny){ return @{ok=$false; detail="param check failed: $deny"} }
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
# Single-instance lock (declared AFTER the marker so the test loader, which loads only the prefix, never takes
# it). Belt-and-suspenders with the task's MultipleInstances=IgnoreNew: two broker processes can never read+run
# the same request concurrently. SESSION-LOCAL (no 'Global\'): both broker instances run as SYSTEM in session 0
# so the local namespace serializes them, while a non-admin in their own session cannot touch it to DoS the
# broker. The OS releases the mutex when this short-lived process exits, so no explicit release is needed.
$mtx = $null; $haveLock = $true
try { $mtx = New-Object System.Threading.Mutex($false,'AgentElevate-Broker-Singleton') } catch {}
# WaitOne can throw AbandonedMutexException if a prior holder was force-killed (e.g. ExecutionTimeLimit) while
# its handle still overlapped ours -- catching it is correct: WE now own the mutex, so proceed. Without the
# catch, $ErrorActionPreference='Stop' would crash this run before it processed anything.
if($mtx){ try { $haveLock = $mtx.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $haveLock = $true } }
if($mtx -and -not $haveLock){ exit 0 }
$anchorBad = @()
foreach($it in @(@{p=$HOME_DIR;d=$true}, @{p=$SELF;d=$false}, @{p=$POLICY;d=$false}, @{p=$ALLOWED;d=$true})){
  $r = Get-Untrusted $it.p $it.d
  if($r){ $anchorBad += ("{0}: {1}" -f $it.p,$r) }
}
$ra = Test-AuditTight $AUDIT; if($ra){ $anchorBad += ("{0}: {1}" -f $AUDIT,$ra) }   # audit.log = stricter (Users not even readable)
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

# Validate the policy schema once at load so an admin typo fails CLOSED here (audit + exit) instead of
# coercing/throwing mid-operation AFTER an ALLOW-RUN audit line. Only ENABLED ops' allow-lists are checked.
function Test-PolicyValid($opsObj){
  if($null -eq $opsObj){ return 'no operations object' }
  foreach($opName in $KNOWN_OPS){
    $n = if($opsObj.PSObject.Properties[$opName]){ $opsObj.PSObject.Properties[$opName].Value } else { $null }
    if($null -eq $n){ continue }
    if($n.PSObject.Properties['enabled'] -and ($n.enabled -isnot [bool])){ return "$opName.enabled must be a JSON boolean" }
    if(-not (($n.enabled -is [bool]) -and $n.enabled)){ continue }
    switch($opName){
      'winget-install'  { foreach($x in @($n.allowedPackages)){ if($x -isnot [string]){ return 'winget-install.allowedPackages must be strings' } } }
      'hosts-add'       { foreach($x in @($n.allowedHosts)){ if($x -isnot [string]){ return 'hosts-add.allowedHosts must be strings' } } }
      'set-machine-env' { foreach($x in @($n.allowedEnvVars)){ if($x -isnot [string]){ return 'set-machine-env.allowedEnvVars must be strings' } } }
      'firewall-allow'  {
        if($n.PSObject.Properties['maxRules']){
          if(($n.maxRules -isnot [int]) -and ($n.maxRules -isnot [long])){ return 'firewall-allow.maxRules must be an integer' }
          if(([long]$n.maxRules -lt 0) -or ([long]$n.maxRules -gt [int]::MaxValue)){ return 'firewall-allow.maxRules out of range (0..2147483647)' }   # Op casts to [int]; reject an oversized admin typo at LOAD
        }
        foreach($rule in @($n.allowedRules)){
          if(-not (V-Port $rule.port)){ return 'firewall-allow.allowedRules has an invalid port' }
          if($rule.protocol -notin @('TCP','UDP')){ return 'firewall-allow.allowedRules.protocol must be TCP/UDP' }
          if($rule.direction -notin @('Inbound','Outbound')){ return 'firewall-allow.allowedRules.direction must be Inbound/Outbound' }
        }
      }
    }
  }
  return ''
}
$polBad = Test-PolicyValid $ops
if($polBad){ Write-Audit @{ ts=(Get-Date -Format o); reqId='-'; owner='-'; claimedBy='broker'; op='-'; verdict='ERROR'; detail="policy schema invalid: $polBad" } | Out-Null; exit 1 }

# ----- process pending requests (oldest first, capped). EXCLUDE stale (> STALE_MIN, handled only by the audited
#       GC below) and forged-future (> now+FUTURE_TOL, owner-set timestamp) so a stale/future request is never
#       executed and a future stamp can't dodge the age logic -- CreationTimeUtc is attacker-settable. -----
$nowUtc = (Get-Date).ToUniversalTime()
$pending = Get-ChildItem -LiteralPath $REQ_DIR -Filter '*.req.json' -File -EA SilentlyContinue |
  Where-Object { ($_.CreationTimeUtc -ge $nowUtc.AddMinutes(-$STALE_MIN)) -and ($_.CreationTimeUtc -le $nowUtc.AddMinutes($FUTURE_TOL_MIN)) } |
  Sort-Object CreationTimeUtc | Select-Object -First $MAX_PER_RUN
foreach($f in $pending){
  $reqFile = $f.FullName
  $reqId = ($f.BaseName -replace '\.req$','')
  if($reqId -notmatch '^[A-Za-z0-9]{1,64}$'){
    # malformed name -> a DETERMINISTIC safe id from the filename (alnum only, no traversal), so a malformed-name
    # STUCK file still coalesces (same id every run) instead of a fresh GUID per run that defeats the .res.json
    # coalesce marker. (.NET-Fx + Core both: instance ComputeHash, not the Core-only static HashData.)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $reqId = 'bad' + ((($sha.ComputeHash([Text.Encoding]::Unicode.GetBytes($f.Name))) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0,29) }
    finally { $sha.Dispose() }
  }
  $owner = '?'; $who = '?'; $op = '?'; $deleteReq = $true; $auditOk = $true
  try {
    $bytes = $null
    # owner is taken FROM the validated read handle (set on success below); for an unreadable/rejected file it
    # stays '?'. We deliberately do NOT path-Get-Acl here: that would be hardlink/symlink-spoofable to a trusted
    # owner, forging the "unforgeable OS owner" in the audit log.
    try { $rd = [AeReq]::ReadExclusive($reqFile,$MAX_REQ_SIZE); $bytes = $rd.Data; $owner = $rd.Owner }
    catch {
      # COALESCE the audit for a WEDGED request (held open FileShare.None, or an owner-planted DENY-delete ACE):
      # such a file can be neither read (exclusive open fails) nor deleted, so without this it would re-emit a
      # DENY-READ line on EVERY trigger forever (audit flood). Once we have durably denied this reqId (its .res.json
      # exists), skip re-auditing -- the finally still re-attempts the delete, so the instant the lock is released
      # the file is reaped. (A normal request is read+deleted long before this matters; reqIds are GUIDs.)
      $resPath = Join-Path $RES_DIR ($reqId + '.res.json')
      if(Test-Path -LiteralPath $resPath){ continue }
      $ageSec = ((Get-Date).ToUniversalTime() - $f.CreationTimeUtc).TotalSeconds
      $rdOk = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy='?'; op='-'; verdict='DENY-READ'; detail=("$_ (age {0:N0}s)" -f $ageSec) }
      # Keep for retry ONLY if genuinely young (a client mid-write/AV scan) OR the deny was not durably audited.
      # "Young" = ageSec in [-5, 8): the -5 floor tolerates benign sub-second FS-vs-system clock skew but does NOT
      # treat a forged FUTURE CreationTime (large-negative ageSec) as young. Young files write NO deny result yet
      # (so a real transient isn't prematurely denied, and the coalesce marker is set only once it's truly stuck).
      if((($ageSec -ge -5) -and ($ageSec -lt 8)) -or -not $rdOk){ $deleteReq = $false; continue }
      # Permanently unreadable: write the durable deny result ONCE -- this is also the coalesce marker checked above.
      @{ id=$reqId; ok=$false; detail="request unreadable: $_"; ts=(Get-Date -Format o) } | ConvertTo-Json -Compress | Set-Content -LiteralPath $resPath -Encoding utf8 -EA SilentlyContinue
      continue   # permanent read failure, durably audited -> client got a deny result; finally tries to delete the request
    }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF){ $text = $text.Substring(1) }   # tolerate a UTF-8 BOM
    # Parse + shape in ONE malformed bucket: a JSON SYNTAX error and a bad SHAPE (top-level array, non-string op,
    # non-object params -- the array-vs-string type-confusion class) both audit as DENY-MALFORMED, not ERROR, so a
    # malformed request is cleanly distinguished from a broker fault.
    $r = $null; $parseErr = $null
    try { $r = $text | ConvertFrom-Json } catch { $parseErr = "invalid JSON: $_" }
    $result = @{ok=$false; detail=''}
    $shapeBad = if($parseErr){ $parseErr } else { Test-RequestShape $text $r }
    if($shapeBad){
      $op = '-'; $result.detail = "malformed request: $shapeBad"
      $auditOk = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy='?'; op='-'; verdict='DENY-MALFORMED'; detail=$shapeBad }
    } else {
      $op = [string]$r.op; $who = [string]$r.by
      $node = Get-OpNode $op
      if($op -notin $KNOWN_OPS){
        $result.detail = 'unknown operation'; $auditOk = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='DENY-UNKNOWN'; detail=$result.detail }
      } elseif(-not $node -or -not (($node.enabled -is [bool]) -and $node.enabled)){
        # require an ACTUAL JSON boolean true -- a string like "false" (or "true") is truthy in PowerShell and
        # must NOT enable an op; this denies a typo'd/over-permissive policy rather than silently enabling it.
        $result.detail = 'operation not enabled in policy'; $auditOk = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='DENY-POLICY'; detail=$result.detail }
      } elseif($denyParam = (Test-OpParams $op $r.params $node)){
        # PARAM/ALLOW-LIST gate BEFORE ALLOW-RUN: a valid-but-disallowed request (bad param or off-list value) is
        # audited as DENY-PARAM and never runs -- so the audit cleanly distinguishes "denied by policy" from
        # "allowed + executed". (Invoke-Op re-asserts this as defense-in-depth.)
        $result.detail = $denyParam; $auditOk = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='DENY-PARAM'; detail=$denyParam }
      } else {
        # AT-MOST-ONCE claim: REMOVE the request before auditing-intent or running. A normal request is always
        # SYSTEM-deletable (it inherits SYSTEM:F from the queue dir); if removal FAILS, the file owner planted a
        # DENY-delete ACE or holds a lock -- executing such a request would REPLAY it on every trigger, so DENY it
        # instead of running. (-EA Stop: a failed delete must be CAUGHT, never silently ignored -- that silent path
        # was the at-most-once bypass.) A normal request is unaffected.
        # ACCEPTED RESIDUAL: removal is path-based, so a request owner could race-rename the validated file and drop
        # a replacement at this path between the read and here, making us run the validated bytes once + delete the
        # decoy (the renamed original re-runs later). This is NOT an escalation -- it only re-runs an ALREADY allow-
        # listed op that the same attacker could simply submit twice -- so a handle-based delete isn't worth re-
        # destabilizing the validated-read path for. The replay is bounded by the allow-list + the per-run cap.
        $removed = $false; try { Remove-Item -LiteralPath $reqFile -Force -EA Stop; $removed = $true } catch { $removed = $false }
        if(-not $removed){
          $result = @{ok=$false; detail='request not removable pre-run (deny-delete ACE or lock); not executed to prevent replay'}
          $auditOk = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='DENY-UNDELETABLE'; detail=$result.detail }
        } else {
          $deleteReq = $false   # already gone; the finally must not try to delete again
          # FAIL-CLOSED: only run the op if the "about to run" audit line was durably written. ALLOW-RUN means
          # "claimed + about to execute"; a kill/crash/full-disk between here and the terminal ALLOW-OK/ALLOW-FAIL
          # leaves ALLOW-RUN with no terminal line = "claimed, outcome unknown" (the op ran 0 or 1 times, never a
          # replay -- the request is already gone).
          $ran = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='ALLOW-RUN'; params=$r.params }
          if(-not $ran){
            $auditOk = $false; $result.detail = 'audit write failed; operation denied (fail-closed)'
          } else {
            $result = Invoke-Op $op $r.params $node
            $auditOk = Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict=$(if($result.ok){'ALLOW-OK'}else{'ALLOW-FAIL'}); detail=$result.detail }
          }
        }
      }
    }
    # -EA SilentlyContinue (consistent with the other two result writes): the op already ran + was audited + the
    # request was already removed, so a transient result-write failure must NOT throw into the outer catch and
    # re-audit a misleading ERROR. The client tolerates a missing result (times out + may resubmit).
    @{ id=$reqId; ok=[bool]$result.ok; detail=[string]$result.detail; ts=(Get-Date -Format o) } | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $RES_DIR ($reqId + '.res.json')) -Encoding utf8 -EA SilentlyContinue
    if(-not $auditOk){ $deleteReq = $false }   # terminal verdict not durably audited (e.g. full disk) -> keep request for retry; stale-GC backstops
  } catch {
    if(-not (Write-Audit @{ ts=(Get-Date -Format o); reqId=$reqId; owner=$owner; claimedBy=$who; op=$op; verdict='ERROR'; detail="$_" })){ $deleteReq = $false }
    try { @{ id=$reqId; ok=$false; detail="broker error"; ts=(Get-Date -Format o) } | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $RES_DIR ($reqId + '.res.json')) -Encoding utf8 } catch {}
  } finally {
    if($deleteReq){ Remove-Item -LiteralPath $reqFile -Force -EA SilentlyContinue }
  }
}

# GC: bound the queues. AUDIT each stale REQUEST removal before deleting it (a request only survives to
# $STALE_MIN if it was retained by a prior audit/read failure -- removing it silently would lose evidence);
# if the GC audit itself fails, leave the file for the next run rather than delete it unaudited. Result files
# are transient outputs (no audit needed).
foreach($sf in @(Get-ChildItem -LiteralPath $REQ_DIR -Filter '*.req.json' -File -EA SilentlyContinue | Where-Object { ($_.CreationTimeUtc -lt (Get-Date).ToUniversalTime().AddMinutes(-$STALE_MIN)) -or ($_.CreationTimeUtc -gt (Get-Date).ToUniversalTime().AddMinutes($FUTURE_TOL_MIN)) })){
  $sid = ($sf.BaseName -replace '\.req$',''); if($sid -notmatch '^[A-Za-z0-9]{1,64}$'){ $sid = 'stale' }
  # Delete FIRST, then audit GC-STALE ONLY on success. An undeletable stale file (attacker DENY-delete ACE) must
  # NOT emit a GC-STALE line every trigger (audit flood). A silently-persisting undeletable orphan is harmless: it
  # is stale (excluded from $pending) so it is never executed. owner='?' (a stale file was never validate-read; a
  # path-Get-Acl could be hardlink-spoofed) -- the line records the removal, not an attribution.
  $gdel = $false; try { Remove-Item -LiteralPath $sf.FullName -Force -EA Stop; $gdel = $true } catch { $gdel = $false }
  if($gdel){ Write-Audit @{ ts=(Get-Date -Format o); reqId=$sid; owner='?'; claimedBy='?'; op='-'; verdict='GC-STALE'; detail=("removed stale/forged-timestamp unprocessed request") } | Out-Null }
}
Get-ChildItem -LiteralPath $RES_DIR -Filter '*.res.json' -File -EA SilentlyContinue | Where-Object { $_.CreationTimeUtc -lt (Get-Date).ToUniversalTime().AddMinutes(-60) } | Remove-Item -Force -EA SilentlyContinue
