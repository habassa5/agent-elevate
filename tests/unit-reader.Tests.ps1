# Unit tests for [AeReq]::ReadExclusive (broker.ps1) -- the ONE exclusive, reparse-safe handle the
# broker uses to read every queued request. Loaded straight from broker.ps1 via _load-broker.ps1 (no copy),
# so these exercise the REAL native read path. Also covers the broker's UTF-8 BOM decode (broker.ps1 lines
# 268-270). All writes go to a per-test temp dir under $env:TEMP and are removed in finally; nothing on the
# live system is touched.
#
# Engine notes proven empirically on this machine (both powershell.exe 5.1 and pwsh 7):
#  * A directory and a junction (a *directory* reparse point) both fail at CreateFileW with ERROR_ACCESS_DENIED
#    -- ReadExclusive opens with FILE_FLAG_OPEN_REPARSE_POINT but NOT FILE_FLAG_BACKUP_SEMANTICS, so a dir
#    handle never opens; the rejection surfaces as a Win32 "Access is denied" *before* the line-53/54
#    attribute checks. The security property still holds: the call THROWS and reads nothing (it never follows
#    the junction to its target). The IOException("reparse point")/("directory") branches are a backstop for a
#    *file* reparse point, which a medium-IL attacker cannot create without SeCreateSymbolicLinkPrivilege.
#  * [Text.Encoding]::UTF8.GetString does NOT strip a leading BOM on either engine, so the broker's explicit
#    0xFEFF strip is load-bearing: without it ConvertFrom-Json throws on both engines.
. (Join-Path $PSScriptRoot '_load-broker.ps1')

# --- per-file temp sandbox (created/removed by the helpers below) ---
function New-RcTmpDir {
  $d = Join-Path $env:TEMP ('rcreader_' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $d -Force | Out-Null
  $d
}
function Remove-RcTmpDir([string]$d) {
  if ($d -and (Test-Path -LiteralPath $d)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe '[AeReq]::ReadExclusive -- normal read returns exact bytes' {
  $tmp = New-RcTmpDir
  try {
    # A small payload with the awkward bytes (0x00 NUL, 0xFF, 0x0D/0x0A, high byte) so an off-by-one,
    # a truncation, or an encoding round-trip would be caught -- not just clean ASCII.
    $expected = [byte[]]@(0x00, 0x7B, 0x22, 0xFF, 0x0D, 0x0A, 0x41, 0x42, 0x80, 0x7D)
    $p = Join-Path $tmp 'normal.bin'
    [IO.File]::WriteAllBytes($p, $expected)

    $got = [AeReq]::ReadExclusive($p, 1MB)

    It 'returns a byte[]' { Assert-Equal $got.GetType().Name 'Byte[]' }
    It 'returns the exact byte count' { Assert-Equal $got.Length $expected.Length 'length mismatch' }
    It 'returns byte-for-byte identical content' {
      $same = $true
      for ($i = 0; $i -lt $expected.Length; $i++) { if ($got[$i] -ne $expected[$i]) { $same = $false; break } }
      Assert-True $same ('byte mismatch; got=[{0}] expected=[{1}]' -f ($got -join ','), ($expected -join ','))
    }

    # An empty file is a legitimate (if malformed-as-a-request) input: must read cleanly as zero bytes,
    # never trip "too large", and not hang the broker's read loop.
    $pe = Join-Path $tmp 'empty.bin'
    [IO.File]::WriteAllBytes($pe, ([byte[]]@()))
    $gote = [AeReq]::ReadExclusive($pe, 1MB)
    It 'reads an empty file as zero bytes' { Assert-Equal $gote.Length 0 'empty file should be 0 bytes' }
  } finally { Remove-RcTmpDir $tmp }
}

Describe '[AeReq]::ReadExclusive -- rejects a file larger than maxLen' {
  $tmp = New-RcTmpDir
  try {
    $p = Join-Path $tmp 'big.bin'
    [IO.File]::WriteAllBytes($p, (New-Object byte[] 4096))   # 4096 bytes

    # At maxLen just under the size -> rejected with "too large".
    $msg = ''
    try { [AeReq]::ReadExclusive($p, 4095) | Out-Null }
    catch { $msg = $_.Exception.Message }
    It 'throws when size > maxLen' { Assert-NotEqual $msg '' 'expected a throw for oversized file' }
    It 'the rejection reason is "too large"' { Assert-Match $msg 'too large' }

    # Boundary: maxLen exactly == size must SUCCEED (the check is strictly `len > maxLen`), and return all bytes.
    $okAtBoundary = $null
    Assert-NotThrows { $script:okAtBoundary = [AeReq]::ReadExclusive($p, 4096) } 'len == maxLen must be allowed'
    It 'allows size == maxLen (strict greater-than boundary) and returns all bytes' {
      Assert-Equal $script:okAtBoundary.Length 4096 'boundary read should return the full file'
    }
  } finally { Remove-RcTmpDir $tmp }
}

Describe '[AeReq]::ReadExclusive -- rejects a directory' {
  $tmp = New-RcTmpDir
  try {
    $dir = Join-Path $tmp 'adir'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $threw = $false; $msg = ''; $ret = 'SENTINEL'
    try { $ret = [AeReq]::ReadExclusive($dir, 1MB) }
    catch { $threw = $true; $msg = $_.Exception.Message }

    It 'throws on a directory path' { Assert-True $threw 'a directory must not be read as a request' }
    It 'returns no bytes for a directory (never falls through to a successful read)' {
      Assert-Equal $ret 'SENTINEL' 'directory read must not return a value'
    }
    # On this platform the dir handle fails to open (no FILE_FLAG_BACKUP_SEMANTICS) -> "Access is denied".
    # Assert the security-relevant shape of the failure without over-pinning the exact OS wording.
    It 'fails to open the directory handle (access denied, not a content read)' { Assert-Match $msg 'access is denied' }
  } finally { Remove-RcTmpDir $tmp }
}

Describe '[AeReq]::ReadExclusive -- rejects a reparse point (junction)' {
  $tmp = New-RcTmpDir
  try {
    # A real target with a secret payload, and a junction pointing at it. ReadExclusive must NOT follow the
    # junction (FILE_FLAG_OPEN_REPARSE_POINT) -> it must reject the junction and never surface the target bytes.
    $target = Join-Path $tmp 'target'
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    $secretInTarget = [Text.Encoding]::UTF8.GetBytes('TOP-SECRET-SHOULD-NEVER-BE-READ')
    [IO.File]::WriteAllBytes((Join-Path $target 'secret.bin'), $secretInTarget)

    $jx = Join-Path $tmp 'jx'
    New-Item -ItemType Junction -Path $jx -Target $target | Out-Null
    # Sanity: the junction really is a reparse point, so the test is exercising what it claims.
    It 'precondition: the junction is a reparse point' {
      $attrs = (Get-Item -LiteralPath $jx -Force).Attributes
      Assert-True (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'New-Item Junction did not create a reparse point'
    }

    $threw = $false; $msg = ''; $ret = 'SENTINEL'
    try { $ret = [AeReq]::ReadExclusive($jx, 1MB) }
    catch { $threw = $true; $msg = $_.Exception.Message }

    It 'throws on a junction (does not follow the reparse point)' { Assert-True $threw 'a junction must be rejected' }
    It 'returns no bytes for a junction' { Assert-Equal $ret 'SENTINEL' 'junction read must not return a value' }
    It 'rejection reason is access-denied or reparse/directory (never a successful target read)' {
      Assert-Match $msg '(access is denied|reparse point|directory)'
    }
  } finally { Remove-RcTmpDir $tmp }
}

Describe 'broker decode path tolerates a UTF-8 BOM (broker.ps1 lines 268-270)' {
  $tmp = New-RcTmpDir
  try {
    # Write a BOM-prefixed JSON request exactly as a BOM-emitting client would, then read the raw bytes back
    # and replicate the broker's decode: UTF8.GetString -> 0xFEFF strip -> ConvertFrom-Json.
    $json = '{"op":"winget-install","by":"agent","id":"Microsoft.PowerShell"}'
    $bom = ([System.Text.UTF8Encoding]::new($true)).GetPreamble()       # EF BB BF
    $bytes = $bom + [Text.Encoding]::UTF8.GetBytes($json)
    $p = Join-Path $tmp 'bom.req.json'
    [IO.File]::WriteAllBytes($p, $bytes)

    # Read the bytes back through the real reader (and confirm it preserves the BOM bytes verbatim).
    $raw = [AeReq]::ReadExclusive($p, 1MB)
    It 'the file really begins with a UTF-8 BOM (EF BB BF)' {
      Assert-True (($raw.Length -ge 3) -and ($raw[0] -eq 0xEF) -and ($raw[1] -eq 0xBB) -and ($raw[2] -eq 0xBF)) 'missing BOM bytes'
    }

    $text = [Text.Encoding]::UTF8.GetString($raw)
    It 'UTF8.GetString does NOT strip the BOM (so the explicit strip is load-bearing)' {
      Assert-True (($text.Length -gt 0) -and ($text[0] -eq [char]0xFEFF)) 'expected a leading U+FEFF after GetString'
    }

    # Negative control: WITHOUT the strip the parse must fail -- proves the broker's strip line is required,
    # not cosmetic. (Verified to throw on both 5.1 and 7.)
    It 'parsing WITHOUT the BOM strip fails (negative control)' {
      Assert-Throws { $text | ConvertFrom-Json } 'a leading BOM should break ConvertFrom-Json'
    }

    # The broker's actual decode: strip U+FEFF then parse -> must succeed and yield the exact fields.
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    $r = $null
    Assert-NotThrows { $script:r = $text | ConvertFrom-Json } 'BOM-stripped JSON must parse'
    It 'after the strip, ConvertFrom-Json yields op=winget-install' { Assert-Equal $script:r.op 'winget-install' }
    It 'after the strip, ConvertFrom-Json yields by=agent' { Assert-Equal $script:r.by 'agent' }
    It 'after the strip, ConvertFrom-Json yields the package id' { Assert-Equal $script:r.id 'Microsoft.PowerShell' }
  } finally { Remove-RcTmpDir $tmp }
}
