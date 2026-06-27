# Unit tests for Get-Untrusted (broker.ps1) -- the broker's trust-anchor ACL/reparse verifier. Loaded
# straight from broker.ps1 via _load-broker.ps1 (no copies), so these exercise the REAL code. All cases
# run NON-ELEVATED and use positive/negative controls. Nothing here mutates the live system: it reads
# the (deployed, admin-only) broker home read-only and otherwise works in $env:TEMP, cleaning up after.
#
# Get-Untrusted($path,$isDir) returns '' when $path is non-reparse, owned by a trusted principal
# (Administrators / SYSTEM / TrustedInstaller), and has NO write/modify/delete/own ACE for any
# non-trusted principal; otherwise it returns a human-readable reason (e.g. 'missing', 'reparse point',
# "owner <SID>", or '<principal>' for a writable foreign ACE).
. (Join-Path $PSScriptRoot '_load-broker.ps1')

# --- shared temp sandbox for the negative/junction/missing controls (all under $env:TEMP) ---
$script:RcAclTmp = Join-Path $env:TEMP ("rcacltest_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:RcAclTmp -Force | Out-Null

try {

# POSITIVE CONTROL. A non-elevated process CANNOT create a file owned by Administrators, so the control must
# be an existing admin-controlled path. Stock %SystemRoot%\System32 binaries are NOT usable -- they carry
# [RESTRICTED] APPLICATION PACKAGES ACEs that fail SID translation, which Get-Untrusted (fail-closed) reports
# as 'UNRESOLVABLE'. The clean, true positive control is the broker's own deployed home (Administrators-owned,
# Users:RX, no AppContainer ACEs). When AgentElevate is not yet deployed there is no such control, so SKIP.
$brokerHome = 'C:\Program Files\AgentElevate'
$brokerSelf = Join-Path $brokerHome 'broker.ps1'
if (Test-Path -LiteralPath $brokerSelf) {
  Describe 'Get-Untrusted (a) admin-owned, no non-admin write => "" (trusted)' {
    It 'positive control is deployed + Administrators-owned' {
      $owner = (Get-Acl -LiteralPath $brokerSelf).GetOwner([Security.Principal.SecurityIdentifier]).Value
      Assert-Equal $owner 'S-1-5-32-544' 'broker.ps1 must be Administrators-owned for the trusted-path control'
    }
    It 'returns "" for the admin-only broker home directory' {
      Assert-Equal (Get-Untrusted $brokerHome $true) '' 'admin-owned dir with no non-admin write must be trusted'
    }
    It 'returns "" for the admin-only broker.ps1 file' {
      Assert-Equal (Get-Untrusted $brokerSelf $false) '' 'admin-owned file with no non-admin write must be trusted'
    }
  }
} else {
  Write-Host "    [SKIP] Get-Untrusted admin-only positive control (AgentElevate not deployed at $brokerHome)"
}

Describe 'Get-Untrusted (b) current-user-owned temp file => NON-empty reason' {
  # NEGATIVE CONTROL. A file the test creates is owned by the (non-admin) current user, so its owner is
  # neither Administrators nor SYSTEM nor TrustedInstaller -- Get-Untrusted must flag it.
  $f = Join-Path $script:RcAclTmp 'mine.txt'
  Set-Content -LiteralPath $f -Value 'owned-by-me' -Encoding ascii
  $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

  It 'sanity: the temp file is owned by the current (non-admin) user' {
    $owner = (Get-Acl -LiteralPath $f).GetOwner([Security.Principal.SecurityIdentifier]).Value
    Assert-Equal $owner $mySid 'precondition: temp file owned by current user'
    Assert-NotEqual $owner 'S-1-5-32-544' 'precondition: current user is not Administrators'
  }
  It 'returns a NON-empty reason (not trusted)' {
    $r = Get-Untrusted $f $false
    Assert-NotEqual $r '' 'a user-owned file must NOT be reported trusted'
    Assert-True ($r.Length -gt 0) 'reason string must be non-empty'
  }
  It 'the reason names the untrusted owner SID' {
    # owner check fires first for a user-owned, non-reparse file -> reason is "owner <SID>"
    $r = Get-Untrusted $f $false
    Assert-Match $r ([regex]::Escape("owner $mySid")) 'reason should cite the current user owner SID'
  }
}

Describe 'Get-Untrusted (c) directory junction (reparse) => "reparse point"' {
  # Junctions do NOT require SeCreateSymbolicLinkPrivilege (unlike symlinks), so this works non-elevated.
  # The reparse check runs BEFORE the owner/ACL checks, so the result is 'reparse point' regardless of
  # who owns the link or its target.
  $target = Join-Path $script:RcAclTmp 'target'
  New-Item -ItemType Directory -Path $target -Force | Out-Null
  $junc = Join-Path $script:RcAclTmp 'junc'
  New-Item -ItemType Junction -Path $junc -Target $target | Out-Null

  It 'sanity: the junction carries the ReparsePoint attribute' {
    $attrs = (Get-Item -LiteralPath $junc -Force).Attributes
    Assert-True ((($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0)) 'precondition: junc is a reparse point'
  }
  It 'returns exactly "reparse point"' {
    Assert-Equal (Get-Untrusted $junc $true) 'reparse point' 'a reparse point must be refused as such'
  }
  It 'reports reparse even when asked as a non-directory ($isDir=$false)' {
    # $isDir does not gate the reparse decision; the link is flagged either way.
    Assert-Equal (Get-Untrusted $junc $false) 'reparse point' 'reparse decision is independent of $isDir'
  }
}

Describe 'Get-Untrusted (d) missing path => "missing"' {
  $gone = Join-Path $script:RcAclTmp ('does-not-exist_' + [guid]::NewGuid().ToString('N'))

  It 'sanity: the path truly does not exist' {
    Assert-False (Test-Path -LiteralPath $gone) 'precondition: path must be absent'
  }
  It 'returns exactly "missing"' {
    Assert-Equal (Get-Untrusted $gone $false) 'missing' 'a non-existent path must report missing'
  }
  It 'returns "missing" for an absent path inside a non-existent parent too' {
    $deep = Join-Path $gone 'child\leaf.txt'
    Assert-Equal (Get-Untrusted $deep $false) 'missing' 'absent nested path must report missing'
  }
}

}
finally {
  # Always clean up the temp sandbox (junction is removed as a link, never recursing into the target).
  if (Test-Path -LiteralPath $script:RcAclTmp) {
    Remove-Item -LiteralPath $script:RcAclTmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}
