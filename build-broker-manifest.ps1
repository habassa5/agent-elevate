# build-broker-manifest.ps1 -- compute the SHA256 pin for each broker payload file and inject it into the
# $PIN block of setup-agentelevate.ps1. Run NON-elevated after the payloads are final (e.g. after the council
# signs off) and before deploying. Re-run any time you edit a pinned file. The pin is defense-in-depth:
# it lets setup-agentelevate.ps1 refuse to deploy a payload whose bytes don't match what was reviewed.
$ErrorActionPreference = 'Stop'
$here  = 'C:\dev\agent-elevate'
$setup = Join-Path $here 'setup-agentelevate.ps1'
$files = @('broker.ps1','broker-policy.json','AgentElevate-tasks.ps1','selfheal.ps1','Invoke-AgentElevate.ps1')

$lines = @('$PIN = @{')
foreach($f in $files){
  $h = (Get-FileHash -LiteralPath (Join-Path $here $f) -Algorithm SHA256).Hash
  $lines += ("  '{0}' = '{1}'" -f $f, $h)
}
$lines += '}'
$block = ($lines -join "`r`n")

$txt = Get-Content -LiteralPath $setup -Raw
# replace the existing $PIN = @{ ... } block (handles both the empty placeholder and a populated one).
# Use a MatchEvaluator so '$' in the hash block is never treated as a regex substitution token.
$pattern = '(?s)\$PIN = @\{.*?\}'
if($txt -notmatch $pattern){ throw 'could not find a $PIN = @{ ... } block in setup-agentelevate.ps1' }
$txt = [regex]::Replace($txt, $pattern, { param($m) $block }, 1)
[IO.File]::WriteAllText($setup, $txt, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Injected SHA256 pins into setup-agentelevate.ps1:"
$block | Write-Host
