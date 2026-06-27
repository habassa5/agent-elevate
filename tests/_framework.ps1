# Tiny dependency-free test framework for the AgentElevate broker suite (works in Windows PowerShell 5.1 AND
# PowerShell 7; no Pester required). Dot-sourced by run-tests.ps1 BEFORE each *.Tests.ps1. Test files call
# Describe/It + the Assert-* helpers; the runner tallies $global:RC_TESTS.
if (-not $global:RC_TESTS) { $global:RC_TESTS = @{ pass = 0; fail = 0; failures = @() } }
function Reset-RcTests { $global:RC_TESTS = @{ pass = 0; fail = 0; failures = @() } }
function Describe([string]$name, [scriptblock]$body) { $global:RC_CTX = $name; & $body }
function It([string]$name, [scriptblock]$body) {
  try { & $body; $global:RC_TESTS.pass++ }
  catch { $global:RC_TESTS.fail++; $global:RC_TESTS.failures += ("[{0}] {1} :: {2}" -f $global:RC_CTX, $name, $_.Exception.Message) }
}
function Assert-True($cond, [string]$msg = '') { if (-not $cond) { throw "expected TRUE; $msg" } }
function Assert-False($cond, [string]$msg = '') { if ($cond) { throw "expected FALSE; $msg" } }
function Assert-Equal($actual, $expected, [string]$msg = '') { if ("$actual" -ne "$expected") { throw "expected '$expected' got '$actual'; $msg" } }
function Assert-NotEqual($actual, $notExpected, [string]$msg = '') { if ("$actual" -eq "$notExpected") { throw "expected NOT '$notExpected'; $msg" } }
function Assert-Match([string]$s, [string]$pattern, [string]$msg = '') { if ($s -notmatch $pattern) { throw "'$s' did not match /$pattern/; $msg" } }
function Assert-NoMatch([string]$s, [string]$pattern, [string]$msg = '') { if ($s -match $pattern) { throw "'$s' unexpectedly matched /$pattern/; $msg" } }
function Assert-Throws([scriptblock]$body, [string]$msg = '') { $threw = $false; try { & $body } catch { $threw = $true }; if (-not $threw) { throw "expected an exception; $msg" } }
function Assert-NotThrows([scriptblock]$body, [string]$msg = '') { try { & $body } catch { throw "unexpected exception ($($_.Exception.Message)); $msg" } }
