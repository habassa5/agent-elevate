# Functional tests for the broker OPERATION HANDLERS -- DENY / validation branches ONLY. These exercise the
# REAL Op-* functions (loaded from broker.ps1 via _load-broker.ps1, no copies) but ONLY along paths that
# return ok=$false BEFORE any system mutation. They deliberately do NOT cover any allow path: no winget runs,
# no script executes, the hosts file / machine env / firewall are never touched. Every fake policy node is
# built the way the broker really sees it -- a PSCustomObject from ConvertFrom-Json -- so the array-vs-string
# and empty-list semantics under test are the genuine ones (and match PS 5.1 + 7).
. (Join-Path $PSScriptRoot '_load-broker.ps1')

# A policy node exactly as ConvertFrom-Json yields it (matches Get-OpNode's return type at runtime).
function New-Node([string]$json) { $json | ConvertFrom-Json }

Describe 'Op-WingetInstall :: deny branches (never runs winget)' {
  # An empty-allow-list node: even a charset-VALID id must be refused because it is not on allowedPackages,
  # and the refusal happens BEFORE Resolve-Winget, so winget is never invoked.
  $emptyNode = New-Node '{ "enabled": true, "allowedPackages": [] }'
  $otherNode = New-Node '{ "enabled": true, "allowedPackages": ["Some.OtherPackage"] }'

  It 'rejects an invalid package id (charset) -> ok=$false / invalid package id' {
    $r = Op-WingetInstall @{ id = 'evil; rm -rf' } $emptyNode
    Assert-False $r.ok 'space/semicolon id must be denied'
    Assert-Match ([string]$r.detail) 'invalid package id'
  }
  It 'rejects a leading-dash id (flag injection) -> ok=$false / invalid package id' {
    $r = Op-WingetInstall @{ id = '--source' } $otherNode
    Assert-False $r.ok '--source must be denied as an invalid id'
    Assert-Match ([string]$r.detail) 'invalid package id'
  }
  It 'rejects a non-string id (array type-confusion) -> ok=$false / invalid package id' {
    $r = Op-WingetInstall @{ id = @('Microsoft.PowerShell','x') } $otherNode
    Assert-False $r.ok 'array id must be denied'
    Assert-Match ([string]$r.detail) 'invalid package id'
  }
  It 'a charset-valid id NOT on an empty allowedPackages -> ok=$false / not on allowedPackages' {
    $r = Op-WingetInstall @{ id = 'Microsoft.PowerShell' } $emptyNode
    Assert-False $r.ok 'empty allow-list must deny every id'
    Assert-Match ([string]$r.detail) 'not on allowedPackages'
    Assert-Match ([string]$r.detail) 'Microsoft\.PowerShell'   # the offending id is echoed
  }
  It 'a charset-valid id NOT on a non-empty (other) allowedPackages -> ok=$false / not on allowedPackages' {
    $r = Op-WingetInstall @{ id = 'Microsoft.PowerShell' } $otherNode
    Assert-False $r.ok 'id absent from the list must be denied'
    Assert-Match ([string]$r.detail) 'not on allowedPackages'
  }
}

Describe 'Op-RunAllowedScript :: deny branches (never executes a script)' {
  It 'rejects a non-.ps1 name -> ok=$false / invalid script name' {
    $r = Op-RunAllowedScript @{ name = 'evil.txt' }
    Assert-False $r.ok
    Assert-Match ([string]$r.detail) 'invalid script name'
  }
  It 'rejects path traversal in the name -> ok=$false / invalid script name' {
    $r = Op-RunAllowedScript @{ name = '..\evil.ps1' }
    Assert-False $r.ok '.. must never reach the filesystem'
    Assert-Match ([string]$r.detail) 'invalid script name'
  }
  It 'rejects reserved DOS device CON.ps1 -> ok=$false / invalid script name' {
    $r = Op-RunAllowedScript @{ name = 'CON.ps1' }
    Assert-False $r.ok 'CON.ps1 (reserved device) must be denied'
    Assert-Match ([string]$r.detail) 'invalid script name'
  }
  It 'a valid name absent from allowed\ is denied (deployed: not an approved script; not deployed: allowed dir not admin-only)' {
    # V-ScriptName passes, so execution reaches the allowed\ checks. Either way the op DENIES (the security
    # property): if AgentElevate is deployed the admin-only dir exists and the absent leaf is refused; if not
    # deployed the dir is missing and the admin-only-dir gate refuses first. Random name stays absent.
    $name = ('rc_test_{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
    $r = Op-RunAllowedScript @{ name = $name }
    Assert-False $r.ok 'a name not present in allowed\ must be denied'
    Assert-Match ([string]$r.detail) '(not an approved script|allowed dir not admin-only)'
  }
}

Describe 'Op-HostsAdd :: deny branches (never edits the hosts file)' {
  $emptyNode = New-Node '{ "enabled": true, "allowedHosts": [] }'
  $okHostNode = New-Node '{ "enabled": true, "allowedHosts": ["app.internal.test"] }'

  It 'rejects an invalid IP -> ok=$false / invalid ip/host' {
    $r = Op-HostsAdd @{ ip = '999.1.1.1'; host = 'app.internal.test' } $okHostNode
    Assert-False $r.ok '999.x is not a valid octet'
    Assert-Match ([string]$r.detail) 'invalid ip/host'
  }
  It 'rejects a host NOT on allowedHosts -> ok=$false / not on allowedHosts' {
    $r = Op-HostsAdd @{ ip = '10.1.2.3'; host = 'evil.example.com' } $emptyNode
    Assert-False $r.ok 'host absent from allowedHosts must be denied'
    Assert-Match ([string]$r.detail) 'not on allowedHosts'
  }
  It 'an ALLOWED host with a link-local 169.254 IP -> ok=$false / link-local.*refused' {
    # The metadata-service style 169.254 address must be refused even though the host is approved.
    $r = Op-HostsAdd @{ ip = '169.254.169.254'; host = 'app.internal.test' } $okHostNode
    Assert-False $r.ok 'link-local must be refused'
    Assert-Match ([string]$r.detail) 'loopback or RFC1918'
  }
  It 'an ALLOWED host with a PUBLIC 8.8.8.8 IP -> ok=$false / link-local.*refused' {
    $r = Op-HostsAdd @{ ip = '8.8.8.8'; host = 'app.internal.test' } $okHostNode
    Assert-False $r.ok 'a public IP must be refused (no DNS hijack to the internet)'
    Assert-Match ([string]$r.detail) 'loopback or RFC1918'
  }
}

Describe 'Op-SetMachineEnv :: deny branches (never sets a machine env var)' {
  # 'Path' is intentionally placed ON the allow-list to prove the hard denylist still wins.
  $pathAllowedNode = New-Node '{ "enabled": true, "allowedEnvVars": ["Path"] }'
  $emptyNode       = New-Node '{ "enabled": true, "allowedEnvVars": [] }'

  It 'denies Path even when it is allow-listed -> ok=$false / hard-denied' {
    $r = Op-SetMachineEnv @{ name = 'Path'; value = 'C:\evil' } $pathAllowedNode
    Assert-False $r.ok 'Path must be hard-denied regardless of the allow-list'
    Assert-Match ([string]$r.detail) 'hard-denied'
  }
  It 'denies a name NOT on allowedEnvVars -> ok=$false / not on allowedEnvVars' {
    $r = Op-SetMachineEnv @{ name = 'MY_APP_HOME'; value = 'C:\app' } $emptyNode
    Assert-False $r.ok 'a benign name absent from the list must be denied'
    Assert-Match ([string]$r.detail) 'not on allowedEnvVars'
  }
  It 'rejects a non-string value (type-confusion) -> ok=$false / invalid env name/value' {
    $r = Op-SetMachineEnv @{ name = 'MY_APP_HOME'; value = @('a','b') } $emptyNode
    Assert-False $r.ok 'an array value must be denied'
    Assert-Match ([string]$r.detail) 'invalid env name/value'
  }
}

Describe 'Op-FirewallAllow :: deny branches (never creates a rule)' {
  $emptyNode = New-Node '{ "enabled": true, "allowedRules": [], "maxRules": 20 }'

  It 'rejects invalid firewall params (bad protocol) -> ok=$false / invalid firewall params' {
    $r = Op-FirewallAllow @{ port = 443; protocol = 'ICMP'; direction = 'Outbound' } $emptyNode
    Assert-False $r.ok 'ICMP is not an accepted protocol'
    Assert-Match ([string]$r.detail) 'invalid firewall params'
  }
  It 'a well-formed rule NOT on allowedRules -> ok=$false / not on allowedRules' {
    # Valid port/proto/direction, but the empty allow-list means it must be denied BEFORE any rule is made.
    $r = Op-FirewallAllow @{ port = 443; protocol = 'TCP'; direction = 'Inbound' } $emptyNode
    Assert-False $r.ok 'no rule may be created from an empty allowedRules'
    Assert-Match ([string]$r.detail) 'not on allowedRules'
    Assert-Match ([string]$r.detail) 'Inbound/TCP/443'   # the refused rule is echoed back
  }
}
