# AgentElevate broker test runner. Discovers + runs every *.Tests.ps1 in this directory using the tiny
# framework in _framework.ps1. Exit code = number of failed tests (0 = all green). Run under BOTH engines:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1     (Windows PowerShell 5.1)
#   pwsh          -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1      (PowerShell 7)
# A test file may dot-source _load-broker.ps1 (broker internals) and/or use only the Assert-* helpers.
[CmdletBinding()]
param([string]$Filter = '*')
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here '_framework.ps1')
Reset-RcTests
$eng = "PowerShell $($PSVersionTable.PSVersion)"
Write-Host "==================== AgentElevate test run on $eng ===================="
$files = Get-ChildItem -LiteralPath $here -Filter '*.Tests.ps1' -File | Where-Object { $_.Name -like "$Filter*" -or $Filter -eq '*' } | Sort-Object Name
if (-not $files) { Write-Host "no *.Tests.ps1 files found in $here"; exit 0 }
foreach ($f in $files) {
  $before = $global:RC_TESTS.pass + $global:RC_TESTS.fail
  try { . $f.FullName }
  catch { $global:RC_TESTS.fail++; $global:RC_TESTS.failures += ("[LOAD] {0} :: {1}" -f $f.Name, $_.Exception.Message) }
  $after = $global:RC_TESTS.pass + $global:RC_TESTS.fail
  Write-Host ("  {0,-40} {1} case(s)" -f $f.Name, ($after - $before))
}
Write-Host "------------------------------------------------------------------"
Write-Host ("PASS: {0}   FAIL: {1}   ({2})" -f $global:RC_TESTS.pass, $global:RC_TESTS.fail, $eng)
if ($global:RC_TESTS.fail -gt 0) {
  Write-Host "FAILURES:"
  $global:RC_TESTS.failures | ForEach-Object { Write-Host ("  - " + $_) }
}
Write-Host "=================================================================="
exit $global:RC_TESTS.fail
