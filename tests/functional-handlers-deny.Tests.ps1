# Functional tests for the broker's PARAM/ALLOW-LIST GATE (Test-OpParams) + request-shape gate (Test-RequestShape)
# -- the deny/validation paths. Loaded from broker.ps1 via _load-broker.ps1 (no copies), so these exercise the
# REAL validation. Test-OpParams is PURE (no side effects), so every case here is safe: nothing installs, no
# script runs, the hosts file / machine env / firewall are never touched. Each fake policy node is built the way
# the broker really sees it -- a PSCustomObject from ConvertFrom-Json -- so the array-vs-string + empty-list
# semantics under test are the genuine ones (PS 5.1 + 7).
. (Join-Path $PSScriptRoot '_load-broker.ps1')

# A policy node exactly as ConvertFrom-Json yields it (matches Get-OpNode's return type at runtime).
function New-Node([string]$json) { $json | ConvertFrom-Json }

# Test-RequestShape takes the raw TEXT + the parsed object (the text check rejects a top-level array on BOTH
# engines, since PS7's ConvertFrom-Json enumerates a top-level array before $r is formed). Helper mirrors the
# broker's call: parse, then validate.
function Shape([string]$json){ Test-RequestShape $json ($json | ConvertFrom-Json) }
Describe 'Test-RequestShape :: rejects malformed JSON request shapes (array-vs-string type confusion)' {
  It 'accepts a well-formed request object' {
    Assert-Equal (Shape '{ "op":"winget-install", "by":"agent", "params": { "id":"Git.Git" } }') '' 'a valid request object must pass'
  }
  It 'rejects a top-level ARRAY of requests (engine-independent, text-level)' {
    Assert-Match (Shape '[ { "op":"winget-install" } ]') 'array' 'a [{...}] request must be rejected on PS 5.1 AND 7'
  }
  It 'rejects a non-string op (singleton-array unwrap)' {
    Assert-Match (Shape '{ "op":["winget-install"], "params":{} }') 'op must be a string'
  }
  It 'rejects a missing op' {
    Assert-Match (Shape '{ "params":{} }') 'op must be a string'
  }
  It 'rejects a non-object params (array)' {
    Assert-Match (Shape '{ "op":"winget-install", "params":[ { "id":"Git.Git" } ] }') 'params must be a JSON object'
  }
  It 'rejects a non-string by' {
    Assert-Match (Shape '{ "op":"winget-install", "by":123, "params":{} }') 'by must be a string'
  }
}

Describe 'Test-OpParams winget-install :: deny branches (pure; never runs winget)' {
  $emptyNode = New-Node '{ "enabled": true, "allowedPackages": [] }'
  $otherNode = New-Node '{ "enabled": true, "allowedPackages": ["Some.OtherPackage"] }'

  It 'rejects an invalid package id (charset)' {
    Assert-Match (Test-OpParams 'winget-install' @{ id = 'evil; rm -rf' } $emptyNode) 'invalid package id'
  }
  It 'rejects a leading-dash id (flag injection)' {
    Assert-Match (Test-OpParams 'winget-install' @{ id = '--source' } $otherNode) 'invalid package id'
  }
  It 'rejects a non-string id (array type-confusion)' {
    Assert-Match (Test-OpParams 'winget-install' @{ id = @('Microsoft.PowerShell','x') } $otherNode) 'invalid package id'
  }
  It 'a charset-valid id NOT on an empty allowedPackages -> not on allowedPackages (echoes the id)' {
    $d = Test-OpParams 'winget-install' @{ id = 'Microsoft.PowerShell' } $emptyNode
    Assert-Match $d 'not on allowedPackages'
    Assert-Match $d 'Microsoft\.PowerShell'
  }
  It 'a charset-valid id NOT on a non-empty (other) allowedPackages -> not on allowedPackages' {
    Assert-Match (Test-OpParams 'winget-install' @{ id = 'Microsoft.PowerShell' } $otherNode) 'not on allowedPackages'
  }
  It 'an id ON the allow-list PASSES the param gate (returns empty -> would proceed to execute)' {
    Assert-Equal (Test-OpParams 'winget-install' @{ id = 'Some.OtherPackage' } $otherNode) '' 'an allow-listed id must pass the gate'
  }
}

Describe 'run-allowed-script :: deny branches (never executes a script)' {
  # Invalid NAMES are rejected by the pure param gate (Test-OpParams).
  It 'Test-OpParams rejects a non-.ps1 name' { Assert-Match (Test-OpParams 'run-allowed-script' @{ name = 'evil.txt' } $null) 'invalid script name' }
  It 'Test-OpParams rejects path traversal in the name' { Assert-Match (Test-OpParams 'run-allowed-script' @{ name = '..\evil.ps1' } $null) 'invalid script name' }
  It 'Test-OpParams rejects reserved DOS device CON.ps1' { Assert-Match (Test-OpParams 'run-allowed-script' @{ name = 'CON.ps1' } $null) 'invalid script name' }
  # A charset-valid but ABSENT name passes the param gate, then Op-RunAllowedScript denies it as an execution
  # precondition (the leaf doesn't exist / the allowed dir gate) -- safe to call: it returns BEFORE executing.
  It 'Op-RunAllowedScript denies a valid-but-absent name before executing' {
    $name = ('rc_test_{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
    Assert-Equal (Test-OpParams 'run-allowed-script' @{ name = $name } $null) '' 'a valid name passes the param gate'
    $r = Op-RunAllowedScript @{ name = $name }
    Assert-False $r.ok 'a name not present in allowed\ must be denied'
    Assert-Match ([string]$r.detail) '(not an approved script|allowed dir not admin-only)'
  }
}

Describe 'Test-OpParams hosts-add :: deny branches (pure; never edits the hosts file)' {
  $emptyNode = New-Node '{ "enabled": true, "allowedHosts": [] }'
  $okHostNode = New-Node '{ "enabled": true, "allowedHosts": ["app.internal.test"] }'

  It 'rejects an invalid IP' { Assert-Match (Test-OpParams 'hosts-add' @{ ip = '999.1.1.1'; host = 'app.internal.test' } $okHostNode) 'invalid ip/host' }
  It 'rejects a host NOT on allowedHosts' { Assert-Match (Test-OpParams 'hosts-add' @{ ip = '10.1.2.3'; host = 'evil.example.com' } $emptyNode) 'not on allowedHosts' }
  It 'an ALLOWED host with a link-local 169.254 IP is refused' { Assert-Match (Test-OpParams 'hosts-add' @{ ip = '169.254.169.254'; host = 'app.internal.test' } $okHostNode) 'loopback or RFC1918' }
  It 'an ALLOWED host with a PUBLIC 8.8.8.8 IP is refused' { Assert-Match (Test-OpParams 'hosts-add' @{ ip = '8.8.8.8'; host = 'app.internal.test' } $okHostNode) 'loopback or RFC1918' }
}

Describe 'Test-OpParams set-machine-env :: deny branches (pure; never sets a machine env var)' {
  $pathAllowedNode = New-Node '{ "enabled": true, "allowedEnvVars": ["Path"] }'   # Path ON the list proves the hard denylist still wins
  $emptyNode       = New-Node '{ "enabled": true, "allowedEnvVars": [] }'

  It 'denies Path even when it is allow-listed (hard denylist wins)' { Assert-Match (Test-OpParams 'set-machine-env' @{ name = 'Path'; value = 'C:\evil' } $pathAllowedNode) 'hard-denied' }
  It 'denies a name NOT on allowedEnvVars' { Assert-Match (Test-OpParams 'set-machine-env' @{ name = 'MY_APP_HOME'; value = 'C:\app' } $emptyNode) 'not on allowedEnvVars' }
  It 'rejects a non-string value (type-confusion)' { Assert-Match (Test-OpParams 'set-machine-env' @{ name = 'MY_APP_HOME'; value = @('a','b') } $emptyNode) 'invalid env name/value' }
}

Describe 'Test-OpParams firewall-allow :: deny branches (pure; never creates a rule)' {
  $emptyNode = New-Node '{ "enabled": true, "allowedRules": [], "maxRules": 20 }'

  It 'rejects invalid firewall params (bad protocol)' { Assert-Match (Test-OpParams 'firewall-allow' @{ port = 443; protocol = 'ICMP'; direction = 'Outbound' } $emptyNode) 'invalid firewall params' }
  It 'a well-formed rule NOT on allowedRules is denied (echoes the rule)' {
    $d = Test-OpParams 'firewall-allow' @{ port = 443; protocol = 'TCP'; direction = 'Inbound' } $emptyNode
    Assert-Match $d 'not on allowedRules'
    Assert-Match $d 'Inbound/TCP/443'
  }
}
