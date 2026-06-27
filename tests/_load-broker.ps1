# Loads the broker's internal functions + constants + the AeReq Add-Type into the scope that
# DOT-SOURCES this file, WITHOUT running the broker's side-effecting body. Everything in broker.ps1 before
# the "STARTUP SELF-INTEGRITY" marker is pure definitions (constants, Add-Type, functions); splitting there
# gives a clean, no-side-effect load. A test does `. $PSScriptRoot\_load-broker.ps1` then calls V-PkgId /
# Get-Untrusted / [AeReq]::ReadExclusive / etc. directly. This keeps broker.ps1 free of any test hooks.
#
# IMPORTANT: this must run at TOP LEVEL (not wrapped in a function) so the dot-source chain lands the
# definitions in the test's scope.
$RC_REPO = Split-Path $PSScriptRoot -Parent
$RC_BROKER_PATH = Join-Path $RC_REPO 'broker.ps1'
# Load once per session: re-running Add-Type for AeReq throws "type already exists", and re-defining the
# functions is wasteful. The guard makes the loader idempotent across multiple *.Tests.ps1 in one run.
if (-not (Get-Command 'V-PkgId' -EA SilentlyContinue) -or -not ('AeReq' -as [type])) {
  $__src = Get-Content -LiteralPath $RC_BROKER_PATH -Raw
  $__marker = '# ===== STARTUP SELF-INTEGRITY'
  $__idx = $__src.IndexOf($__marker)
  if ($__idx -lt 0) { throw "STARTUP SELF-INTEGRITY marker not found in $RC_BROKER_PATH (broker structure changed -- update _load-broker.ps1)" }
  . ([scriptblock]::Create($__src.Substring(0, $__idx)))
}
if (-not (Get-Command 'Get-RepoFile' -EA SilentlyContinue)) { function Get-RepoFile([string]$name) { Join-Path $RC_REPO $name } }
