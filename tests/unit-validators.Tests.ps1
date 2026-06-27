# Unit tests for the broker's parameter validators + range helpers. Loaded definitions come straight from
# broker.ps1 (no copies) via _load-broker.ps1, so these test the REAL code.
. (Join-Path $PSScriptRoot '_load-broker.ps1')

Describe 'V-PkgId (winget package id charset)' {
  It 'accepts a normal id' { Assert-True (V-PkgId 'Microsoft.PowerShell') }
  It 'accepts dots/dashes/underscores/plus' { Assert-True (V-PkgId 'Foo.Bar-baz_qux+1') }
  It 'rejects spaces (no arg-splitting)' { Assert-False (V-PkgId 'Foo Bar') }
  It 'rejects a leading dash (no flag injection)' { Assert-False (V-PkgId '--source') }
  It 'rejects quotes/semicolons' { Assert-False (V-PkgId 'a";b') }
  It 'rejects non-string (array type-confusion)' { Assert-False (V-PkgId @('a','b')) }
  It 'rejects null' { Assert-False (V-PkgId $null) }
}

Describe 'V-ScriptName (approved script name)' {
  It 'accepts a normal .ps1 name' { Assert-True (V-ScriptName 'reset-iis.ps1') }
  It 'rejects a non-.ps1 extension' { Assert-False (V-ScriptName 'evil.txt') }
  It 'rejects path traversal (..)' { Assert-False (V-ScriptName '..\evil.ps1') }
  It 'rejects a separator' { Assert-False (V-ScriptName 'sub\x.ps1') }
  It 'rejects reserved DOS device CON.ps1' { Assert-False (V-ScriptName 'CON.ps1') }
  It 'rejects reserved DOS device nul.ps1 (case-insensitive)' { Assert-False (V-ScriptName 'nul.ps1') }
  It 'rejects COM1.ps1' { Assert-False (V-ScriptName 'COM1.ps1') }
  It 'rejects LPT9.ps1' { Assert-False (V-ScriptName 'LPT9.ps1') }
  It 'accepts a name that merely contains con' { Assert-True (V-ScriptName 'reconfig.ps1') }
  It 'rejects non-string' { Assert-False (V-ScriptName @('a.ps1')) }
}

Describe 'V-IPv4 (octet bounds + parse)' {
  It 'accepts 10.1.2.3' { Assert-True (V-IPv4 '10.1.2.3') }
  It 'accepts 255.255.255.255' { Assert-True (V-IPv4 '255.255.255.255') }
  It 'rejects 256.1.1.1 (octet > 255)' { Assert-False (V-IPv4 '256.1.1.1') }
  It 'rejects 1.2.3 (too few octets)' { Assert-False (V-IPv4 '1.2.3') }
  It 'rejects 999.1.1.1' { Assert-False (V-IPv4 '999.1.1.1') }
  It 'rejects non-string' { Assert-False (V-IPv4 @('1.2.3.4')) }
}

Describe 'Test-PrivateOrLoopback (RFC1918/loopback only; link-local + public refused)' {
  It '127.0.0.1 is loopback' { Assert-True (Test-PrivateOrLoopback '127.0.0.1') }
  It '10.1.2.3 is private' { Assert-True (Test-PrivateOrLoopback '10.1.2.3') }
  It '192.168.1.1 is private' { Assert-True (Test-PrivateOrLoopback '192.168.1.1') }
  It '172.16.0.1 is private' { Assert-True (Test-PrivateOrLoopback '172.16.0.1') }
  It '172.31.255.255 is private' { Assert-True (Test-PrivateOrLoopback '172.31.255.255') }
  It '172.32.0.1 is NOT private (outside /12)' { Assert-False (Test-PrivateOrLoopback '172.32.0.1') }
  It '169.254.169.254 (link-local) is REFUSED' { Assert-False (Test-PrivateOrLoopback '169.254.169.254') }
  It '8.8.8.8 (public) is REFUSED' { Assert-False (Test-PrivateOrLoopback '8.8.8.8') }
}

Describe 'Test-EnvDenied (machine-env hard denylist)' {
  It 'denies Path' { Assert-True (Test-EnvDenied 'Path') }
  It 'denies PATH (case-insensitive)' { Assert-True (Test-EnvDenied 'PATH') }
  It 'denies PSModulePath' { Assert-True (Test-EnvDenied 'PSModulePath') }
  It 'denies __PSLockdownPolicy' { Assert-True (Test-EnvDenied '__PSLockdownPolicy') }
  It 'denies COMPLUS_ prefix' { Assert-True (Test-EnvDenied 'COMPLUS_ProfilerEnabled') }
  It 'denies DOTNET_ prefix' { Assert-True (Test-EnvDenied 'DOTNET_STARTUP_HOOKS') }
  It 'denies ComSpec' { Assert-True (Test-EnvDenied 'ComSpec') }
  It 'denies JAVA_TOOL_OPTIONS (cross-runtime loader)' { Assert-True (Test-EnvDenied 'JAVA_TOOL_OPTIONS') }
  It 'denies PYTHONPATH (cross-runtime loader)' { Assert-True (Test-EnvDenied 'PYTHONPATH') }
  It 'denies NODE_OPTIONS (cross-runtime loader)' { Assert-True (Test-EnvDenied 'NODE_OPTIONS') }
  It 'denies CLASSPATH' { Assert-True (Test-EnvDenied 'CLASSPATH') }
  It 'denies LD_PRELOAD' { Assert-True (Test-EnvDenied 'LD_PRELOAD') }
  It 'allows a benign app var' { Assert-False (Test-EnvDenied 'MY_APP_HOME') }
}

Describe 'V-EnvName / V-Hostname / V-Port' {
  It 'V-EnvName accepts a normal name' { Assert-True (V-EnvName 'MY_VAR1') }
  It 'V-EnvName rejects a leading digit' { Assert-False (V-EnvName '1BAD') }
  It 'V-EnvName rejects spaces' { Assert-False (V-EnvName 'a b') }
  It 'V-Hostname accepts a dotted host' { Assert-True (V-Hostname 'app.internal.test') }
  It 'V-Hostname rejects a space' { Assert-False (V-Hostname 'a b') }
  It 'V-Port accepts 443' { Assert-True (V-Port 443) }
  It 'V-Port rejects 0' { Assert-False (V-Port 0) }
  It 'V-Port rejects 70000' { Assert-False (V-Port 70000) }
}
