# Unit tests for Write-Audit (the broker's fail-closed JSON-lines audit writer). The REAL function is
# loaded from broker.ps1 via _load-broker.ps1 (no copies). Write-Audit reads the script-scoped $AUDIT for
# its target path and ALSO writes the Application event log via a source ('AgentElevate-Broker') that may not
# exist in a test context -- that inner Write-EventLog is wrapped in try/catch in the function, so it must
# never fail Write-Audit. These tests therefore exercise ONLY the durable file write + return contract.
#
# To target a temp file we override $script:AUDIT BEFORE each call (proven to be the scope Write-Audit reads
# in both Windows PowerShell 5.1 and PowerShell 7). The original value is saved and restored in a finally so
# the live audit path is never touched and no other test is disturbed. Nothing on the live system is mutated.
. (Join-Path $PSScriptRoot '_load-broker.ps1')

# Split a raw audit file into its actual JSON records: physical lines, dropping the single trailing-newline
# empty segment WriteLine produces. An injected log line (the attack) would be a NON-empty segment, so it is
# NOT filtered away -- it would show up in the count and (because it is not a JSON object) fail the brace
# check. Both engines emit \r\n from StreamWriter.WriteLine; \r?\n covers either just in case.
#
# IMPORTANT caller contract: a one-record file makes `return @(...)` UNWRAP to a scalar string (PowerShell
# collapses single-element pipeline output). That is fine ONLY because every caller wraps the call in @()
# -- @('FULLJSON') re-wraps the scalar into a 1-element array, so $lines[0] is the whole record, not its
# first character '{'. For a multi-record file the array passes through unchanged. ALWAYS call as
# @(Get-AuditLines ...). (Do NOT "fix" this with Write-Output -NoEnumerate: that emits the array as a single
# pipeline item, and the caller's @() would then yield a 1-element array CONTAINING the array -- wrong count.)
function Get-AuditLines([string]$path) {
  $raw = Get-Content -LiteralPath $path -Raw
  if ($null -eq $raw) { return @() }
  return @($raw -split "`r?`n" | Where-Object { $_ -ne '' })
}

Describe 'Write-Audit -- log-injection resistance (CRLF in claimedBy)' {
  $saved = $script:AUDIT
  $tmp = Join-Path $env:TEMP ("rc_audit_inj_{0}.log" -f ([guid]::NewGuid().ToString('N')))
  try {
    $script:AUDIT = $tmp
    # A malicious claimedBy: a CRLF followed by a fully-formed FORGED audit record. If Write-Audit wrote the
    # field raw, this would appear as an extra physical line that looks like a genuine ALLOW-OK success.
    $evil = "attacker`r`n{`"ts`":`"2099-01-01`",`"reqId`":`"x`",`"owner`":`"S-1-5-18`",`"claimedBy`":`"broker`",`"op`":`"winget-install`",`"verdict`":`"ALLOW-OK`",`"detail`":`"PWNED`"}"
    # Two calls -> must produce EXACTLY two lines (proves one JSON line per call AND no injected extra line).
    $r1 = Write-Audit @{ ts='t1'; reqId='r1'; owner='o1'; claimedBy=$evil; op='hosts-add'; verdict='DENY-POLICY'; detail='a' }
    $r2 = Write-Audit @{ ts='t2'; reqId='r2'; owner='o2'; claimedBy=$evil; op='hosts-add'; verdict='DENY-POLICY'; detail='b' }
    $lines = @(Get-AuditLines $tmp)

    It 'writes exactly one physical line per call (2 calls => 2 lines)' {
      Assert-Equal $lines.Count 2 'CRLF in claimedBy must not split the record into extra lines'
    }
    It 'every record is a single JSON object (no injected line lacking a leading brace)' {
      $notObj = @($lines | Where-Object { -not $_.StartsWith('{') })
      Assert-Equal $notObj.Count 0 "found $($notObj.Count) line(s) not starting with '{' -- log injection succeeded"
    }
    It 'no record carries the forged ALLOW-OK verdict as its own line' {
      # The forged text only ever appears ESCAPED inside the claimedBy string, never as a standalone record.
      $forged = @($lines | Where-Object { ($_ | ConvertFrom-Json).detail -eq 'PWNED' })
      Assert-Equal $forged.Count 0 'a forged "PWNED" record leaked as a real audit line'
    }
    It 'claimedBy round-trips byte-exact (CRLF preserved as escaped data, not a real newline)' {
      $obj = $lines[0] | ConvertFrom-Json
      Assert-True ($obj.claimedBy -ceq $evil) 'the malicious claimedBy was altered or truncated on the way through'
    }
    It 'the escaped record actually contains a literal backslash-r-backslash-n (the CRLF was escaped, not raw)' {
      # Assert against the on-disk text: the bytes for CR/LF must NOT appear inside the line; the 2-char
      # escape sequence \r \n must. This is what keeps the CRLF on one line.
      Assert-Match $lines[0] '\\r\\n' 'expected an escaped \r\n inside the JSON-encoded field'
      Assert-NoMatch $lines[0] "`r" 'a raw carriage return leaked into the audit line'
    }
    It 'both calls returned $true (durable write succeeded)' {
      Assert-True ($r1 -eq $true -and $r2 -eq $true) 'Write-Audit should report success when the line is written'
    }
  } finally {
    $script:AUDIT = $saved
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

Describe 'Write-Audit -- success contract' {
  $saved = $script:AUDIT
  $tmp = Join-Path $env:TEMP ("rc_audit_ok_{0}.log" -f ([guid]::NewGuid().ToString('N')))
  try {
    $script:AUDIT = $tmp
    $ret = Write-Audit @{ ts='2026-01-01'; reqId='abc'; owner='S-1-5-18'; claimedBy='broker'; op='winget-install'; verdict='ALLOW-OK'; detail='ok' }
    $lines = @(Get-AuditLines $tmp)

    It 'returns $true on a successful durable write' {
      Assert-True ($ret -eq $true) 'Write-Audit must return $true when it durably wrote the line'
    }
    It 'actually created the audit file with exactly one record' {
      Assert-True (Test-Path -LiteralPath $tmp) 'the audit file should exist after a successful write'
      Assert-Equal $lines.Count 1 'a single Write-Audit call should append exactly one line'
    }
    It 'the record round-trips to the same verdict/op (content is real, not empty)' {
      $obj = $lines[0] | ConvertFrom-Json
      Assert-Equal $obj.verdict 'ALLOW-OK' 'verdict not faithfully serialized'
      Assert-Equal $obj.op 'winget-install' 'op not faithfully serialized'
    }
    It 'appends rather than truncates (second call leaves two records)' {
      $ret2 = Write-Audit @{ ts='2026-01-02'; reqId='def'; owner='S-1-5-18'; claimedBy='broker'; op='hosts-add'; verdict='DENY-POLICY'; detail='nope' }
      Assert-True ($ret2 -eq $true) 'second write should also succeed'
      $lines2 = @(Get-AuditLines $tmp)
      Assert-Equal $lines2.Count 2 'audit must be append-only within a session, not overwrite'
    }
  } finally {
    $script:AUDIT = $saved
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

Describe 'Write-Audit -- fail-closed on un-writable / illegal path' {
  $saved = $script:AUDIT
  # A path whose PARENT directory does not exist: StreamWriter throws DirectoryNotFoundException, which the
  # function catches and converts into a $false return (the fail-closed signal the broker depends on to deny
  # an operation when it cannot record it). Using a fresh GUID dir guarantees it does not exist and nothing
  # is created on disk -- verified below.
  $badDir = Join-Path ([IO.Path]::GetPathRoot($env:SystemDrive)) ("AgentElevate_NoExist_{0}" -f ([guid]::NewGuid().ToString('N')))
  $badPath = Join-Path $badDir 'sub\audit.log'
  # A second, independent failure mode: a path containing characters illegal in a Windows filename.
  $illegalPath = Join-Path $env:TEMP ('rc_audit_illegal_<>"|.log')
  try {
    $script:AUDIT = $badPath
    $ret = Write-Audit @{ ts='x'; reqId='r'; owner='o'; claimedBy='broker'; op='hosts-add'; verdict='DENY-READ'; detail='unwritable' }

    It 'returns $false when the durable write throws (missing parent directory)' {
      Assert-False ($ret -eq $true) 'a failed durable write must report $false so the broker can fail closed'
      # ($ret must be exactly $false -- not $null, not 0)
      Assert-True ($ret -eq $false) 'Write-Audit should return the boolean $false, not a falsy non-boolean'
    }
    It 'does not create the missing directory or any audit file as a side effect' {
      # [IO.Directory]::Exists never throws (Test-Path -LiteralPath can throw on illegal paths under 5.1).
      Assert-False ([System.IO.Directory]::Exists($badDir)) 'Write-Audit must not create directories when the path is bad'
    }

    $script:AUDIT = $illegalPath
    $ret2 = Write-Audit @{ ts='x'; reqId='r'; owner='o'; claimedBy='broker'; op='hosts-add'; verdict='DENY-READ'; detail='illegal' }
    It 'returns $false for an illegal filename path' {
      Assert-False ($ret2 -eq $true) 'an illegal target path must also fail closed ($false)'
    }
    It 'leaves no file at the illegal path' {
      # [IO.File]::Exists returns $false (never throws) for a path with illegal characters, in 5.1 and 7.
      Assert-False ([System.IO.File]::Exists($illegalPath)) 'no file should be created for an illegal path'
    }
  } finally {
    $script:AUDIT = $saved
    # Defensive cleanup in case any branch unexpectedly wrote something. Wrapped: an illegal-char path can
    # make Remove-Item throw a TERMINATING binding error that -ErrorAction SilentlyContinue does not catch.
    try { if ([System.IO.File]::Exists($illegalPath)) { Remove-Item -LiteralPath $illegalPath -Force -ErrorAction SilentlyContinue } } catch {}
    try { if ([System.IO.Directory]::Exists($badDir)) { Remove-Item -LiteralPath $badDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
  }
}
