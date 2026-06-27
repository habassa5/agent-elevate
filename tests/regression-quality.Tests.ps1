# Static regression / quality guards over the AgentElevate broker source tree. NO broker functions are
# executed and NOTHING on the live system is mutated -- every check parses/tokenizes/hashes the files
# on disk only. Runs under BOTH Windows PowerShell 5.1 and PowerShell 7. Uses the tiny framework in
# _framework.ps1 (Describe/It/Assert-*) via run-tests.ps1.
#
# What each Describe guards (all are real bugs that already bit this codebase or its class):
#   (a) case-insensitive PowerShell variable collisions  -> the $REQ/$req silent-clobber bug
#   (b) the "# ===== STARTUP SELF-INTEGRITY" marker       -> the _load-broker.ps1 split contract
#   (c) Op-RunAllowedScript invokes powershell via the call operator with $resolved, NOT
#       Start-Process -ArgumentList                        -> the "C:\Program Files" space-path break
#   (d) all 5 .ps1 files + broker-policy.json parse clean  -> no shipped syntax/JSON error
#   (e) deployed C:\Program Files\AgentElevate files == repo    -> drift between source and what runs as SYSTEM

$RC_REPO = Split-Path $PSScriptRoot -Parent
# The 5 PowerShell sources under review (the broker subsystem). setup-agentelevate.ps1 is the installer and is
# deliberately NOT one of the files copied to the deployed dir (see $BROKER_FILES in setup-agentelevate.ps1).
$RC_PS_FILES = @('broker.ps1','setup-agentelevate.ps1','Invoke-AgentElevate.ps1','selfheal.ps1','AgentElevate-tasks.ps1')

function Get-RepoSrc([string]$name) {
  $p = Join-Path $RC_REPO $name
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "source file missing: $p" }
  Get-Content -LiteralPath $p -Raw
}

# ---- (a) case-insensitive variable-collision scan -----------------------------------------------------
# PowerShell variable names are CASE-INSENSITIVE: $REQ and $req are the SAME variable. A mixed-casing
# pair is therefore an aliasing accident waiting to silently clobber state (exactly the $req-over-$REQ
# bug that mis-routed every request). Tokenize each file and assert that no lowercased variable name maps
# to more than one distinct original casing. We group on the FULL token content (keeping any scope/drive
# prefix such as 'script:' or 'env:') because $env:Path and a bare $Path are genuinely different
# variables -- stripping the prefix would invent false collisions.
Describe 'No case-insensitive PowerShell variable collisions (the $REQ/$req class of bug)' {
  foreach ($file in $RC_PS_FILES) {
    It "$file has no variable name used with two different casings" {
      $src = Get-RepoSrc $file
      $perr = $null
      $tokens = [System.Management.Automation.PSParser]::Tokenize($src, [ref]$perr)
      Assert-True ($tokens.Count -gt 0) "$file tokenized to zero tokens (parser problem)"
      $names = $tokens | Where-Object { $_.Type -eq 'Variable' } | ForEach-Object { $_.Content }
      Assert-True ($names.Count -gt 0) "$file has no variable tokens (unexpected)"
      $groups = $names | Group-Object { $_.ToLowerInvariant() }
      $collisions = @()
      foreach ($g in $groups) {
        # -CaseSensitive is REQUIRED: a bare Sort-Object -Unique is case-INSENSITIVE and would collapse
        # 'REQ' and 'req' into one entry -- silently hiding the very collision we are hunting for.
        $distinct = @($g.Group | Sort-Object -Unique -CaseSensitive)
        if ($distinct.Count -gt 1) { $collisions += ("`${0} => {1}" -f $g.Name, ($distinct -join ', ')) }
      }
      Assert-Equal $collisions.Count 0 "case-insensitive variable collision(s) in ${file}: $($collisions -join ' | ')"
    }
  }

  It 'the scan is real: a crafted $REQ/$req snippet IS flagged as a collision (guards against a no-op test)' {
    # Positive control -- if the detection logic ever silently broke, this would start failing.
    $bad = '$REQ = "C:\queue"; $req = "body"; Set-Content $REQ $req'
    $perr = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($bad, [ref]$perr)
    $names = $tokens | Where-Object { $_.Type -eq 'Variable' } | ForEach-Object { $_.Content }
    $groups = $names | Group-Object { $_.ToLowerInvariant() }
    $hit = @($groups | Where-Object { (@($_.Group | Sort-Object -Unique -CaseSensitive)).Count -gt 1 })
    Assert-True ($hit.Count -ge 1) 'detector failed to flag the deliberate $REQ/$req collision'
    Assert-Match $hit[0].Name '^req$' 'the flagged collision should be the req name'
  }

  It 'the scan does NOT flag prefix-distinct vars ($env:Path vs $Path are different variables)' {
    # Negative control -- keeping the scope/drive prefix must NOT create a false positive.
    $okSrc = '$Path = "x"; $env:Path = "y"'
    $perr = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($okSrc, [ref]$perr)
    $names = $tokens | Where-Object { $_.Type -eq 'Variable' } | ForEach-Object { $_.Content }
    $groups = $names | Group-Object { $_.ToLowerInvariant() }
    $hit = @($groups | Where-Object { (@($_.Group | Sort-Object -Unique -CaseSensitive)).Count -gt 1 })
    Assert-Equal $hit.Count 0 'prefix-distinct variables were wrongly flagged as a collision'
  }
}

# ---- (b) loader contract: the STARTUP SELF-INTEGRITY marker --------------------------------------------
# _load-broker.ps1 splits broker.ps1 at this exact marker to load the pure definitions WITHOUT running the
# side-effecting startup body. If the marker text drifts, every broker unit test breaks. Pin it here.
Describe 'broker.ps1 keeps the loader-contract marker' {
  It 'contains the exact "# ===== STARTUP SELF-INTEGRITY" marker' {
    $src = Get-RepoSrc 'broker.ps1'
    Assert-True ($src.Contains('# ===== STARTUP SELF-INTEGRITY')) 'STARTUP SELF-INTEGRITY marker missing -- _load-broker.ps1 split contract broken'
  }
  It 'has all pure definitions BEFORE the marker (Add-Type AeReq + key functions precede it)' {
    $src = Get-RepoSrc 'broker.ps1'
    $idx = $src.IndexOf('# ===== STARTUP SELF-INTEGRITY')
    Assert-True ($idx -gt 0) 'marker not found'
    $head = $src.Substring(0, $idx)
    # The loader dot-sources only $head; these must live there or the broker unit tests cannot load.
    Assert-Match $head 'public static class AeReq' 'AeReq Add-Type must precede the marker'
    Assert-Match $head 'function\s+V-PkgId'       'V-PkgId must precede the marker'
    Assert-Match $head 'function\s+Op-RunAllowedScript' 'Op-RunAllowedScript must precede the marker'
  }
}

# ---- (c) Op-RunAllowedScript must use the call operator, not Start-Process -ArgumentList ---------------
# The approved-script path lives under "C:\Program Files\..." (a space). Start-Process -ArgumentList
# flattens the args and powershell.exe then sees "-File C:\Program" -> fails. The fix invokes powershell
# via the call operator (&) passing $resolved as ONE argument. Scan ONLY the function body so a Start-Process
# elsewhere in the file can't mask a regression here.
Describe 'Op-RunAllowedScript invokes powershell safely (space-in-path guard)' {
  # Extract the function body via the language AST (robust to formatting), with a regex fallback.
  $brokerPath = Join-Path $RC_REPO 'broker.ps1'
  $perr = $null; $ptok = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($brokerPath, [ref]$ptok, [ref]$perr)
  $fnAst = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Op-RunAllowedScript' }, $true)
  $fnText = if ($fnAst) { $fnAst.Extent.Text } else {
    $raw = Get-Content -LiteralPath $brokerPath -Raw
    if ($raw -match '(?s)function\s+Op-RunAllowedScript.*?\n\}') { $Matches[0] } else { '' }
  }
  # CODE-ONLY view of the function: strip Comment tokens so prose like "(NOT Start-Process -ArgumentList)"
  # in the explanatory comment cannot false-match the negative assertion below. We scan executable code,
  # not documentation. NOTE: PSParser Variable tokens drop the '$' sigil (.Content of $resolved is
  # 'resolved'), so we re-add it for Variable tokens to keep the reconstructed code faithful (and to let
  # '\$resolved' patterns match).
  $cerr = $null
  $fnCodeTokens = [System.Management.Automation.PSParser]::Tokenize($fnText, [ref]$cerr) | Where-Object { $_.Type -ne 'Comment' }
  $fnCode = ($fnCodeTokens | ForEach-Object { if ($_.Type -eq 'Variable') { '$' + $_.Content } else { $_.Content } }) -join ' '

  It 'the Op-RunAllowedScript function body was located' {
    Assert-True ([bool]$fnAst) 'AST did not find function Op-RunAllowedScript'
    Assert-True ($fnText.Length -gt 0) 'Op-RunAllowedScript body text is empty'
    Assert-True ($fnCode.Length -gt 0) 'Op-RunAllowedScript code-token projection is empty'
  }
  It 'invokes powershell via the call operator with $resolved (& $PSEXE ... -File $resolved)' {
    # The actual invocation (code tokens, comments removed): & $PSEXE -NoProfile -ExecutionPolicy Bypass -File $resolved
    Assert-Match $fnCode '&\s*\$PSEXE\b' 'call operator on $PSEXE not found in code'
    Assert-Match $fnCode '-File\s+\$resolved\b' '-File $resolved (single quoted argument) not found in code'
  }
  It 'does NOT launch the approved script via Start-Process -ArgumentList (the space-path bug)' {
    # No Start-Process and no -ArgumentList in the EXECUTABLE code of this function (comment prose excluded).
    Assert-NoMatch $fnCode 'Start-Process' 'Op-RunAllowedScript code must not call Start-Process'
    Assert-NoMatch $fnCode '-ArgumentList' 'Op-RunAllowedScript code must not use -ArgumentList'
  }
}

# ---- (d) every shipped source parses cleanly ----------------------------------------------------------
# A shipped syntax error or malformed JSON would fail closed at runtime (broker exits / policy load throws),
# so catch it statically. Use the language Parser for .ps1 (collects ALL parse errors) and ConvertFrom-Json
# for the policy.
Describe 'All source files parse without errors' {
  foreach ($file in $RC_PS_FILES) {
    It "$file parses with zero Parser errors" {
      $p = Join-Path $RC_REPO $file
      $tok = $null; $errs = $null
      [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tok, [ref]$errs)
      $errCount = @($errs).Count
      $detail = if ($errCount -gt 0) { ($errs | ForEach-Object { $_.Message }) -join ' | ' } else { '' }
      Assert-Equal $errCount 0 "${file} parse errors: $detail"
    }
  }
  It 'broker-policy.json is valid JSON with the expected operation nodes' {
    $jp = Join-Path $RC_REPO 'broker-policy.json'
    Assert-True (Test-Path -LiteralPath $jp -PathType Leaf) 'broker-policy.json missing'
    $raw = Get-Content -LiteralPath $jp -Raw
    $obj = $null
    Assert-NotThrows { $script:__pol = $raw | ConvertFrom-Json } 'broker-policy.json failed to parse as JSON'
    $obj = $script:__pol
    Assert-True ($null -ne $obj.operations) 'policy has no .operations object'
    # The 5 known ops the broker switch dispatches must all be present (keeps policy + code in lockstep).
    foreach ($op in @('winget-install','run-allowed-script','hosts-add','firewall-allow','set-machine-env')) {
      Assert-True ($null -ne $obj.operations.PSObject.Properties[$op]) "policy missing operation node '$op'"
    }
  }
}

# ---- (e) deployed files (if present) match the repo source --------------------------------------------
# The broker runs as SYSTEM from C:\Program Files\AgentElevate. If a deployed file drifts from the reviewed repo
# copy, what actually runs is NOT what was reviewed. Hash-compare every file that setup-agentelevate.ps1 deploys.
# setup-agentelevate.ps1 itself is NOT deployed (installer-only), so it is excluded. If the broker isn't deployed
# on this machine, skip gracefully (single passing It) rather than fail.
Describe 'Deployed broker files match the repo source (SHA-256) when deployed' {
  $deployDir = 'C:\Program Files\AgentElevate'
  # Files the installer copies to the deployed dir (see $BROKER_FILES in setup-agentelevate.ps1) -- excludes the
  # installer and includes the policy json.
  $deployedSet = @('broker.ps1','broker-policy.json','AgentElevate-tasks.ps1','selfheal.ps1','Invoke-AgentElevate.ps1')
  $isDeployed = Test-Path -LiteralPath (Join-Path $deployDir 'broker.ps1') -PathType Leaf

  if (-not $isDeployed) {
    It 'broker not deployed on this machine -- deployed-vs-repo hash check skipped' {
      Assert-False $isDeployed 'broker.ps1 not present under C:\Program Files\AgentElevate (skip)'
    }
  } else {
    It 'setup-agentelevate.ps1 is correctly NOT deployed (installer is not a runtime file)' {
      # Sanity: confirms our exclusion is right -- if this ever appears deployed, the model changed.
      Assert-False (Test-Path -LiteralPath (Join-Path $deployDir 'setup-agentelevate.ps1') -PathType Leaf) `
        'setup-agentelevate.ps1 unexpectedly found in the deployed dir'
    }
    foreach ($file in $deployedSet) {
      It "$file deployed copy SHA-256 == repo copy" {
        $repoPath = Join-Path $RC_REPO $file
        $depPath  = Join-Path $deployDir $file
        Assert-True (Test-Path -LiteralPath $repoPath -PathType Leaf) "repo $file missing"
        Assert-True (Test-Path -LiteralPath $depPath  -PathType Leaf) "deployed $file missing"
        $repoHash = (Get-FileHash -LiteralPath $repoPath -Algorithm SHA256).Hash
        $depHash  = (Get-FileHash -LiteralPath $depPath  -Algorithm SHA256).Hash
        Assert-Equal $depHash $repoHash "$file deployed copy differs from repo (deployed=$depHash repo=$repoHash) -- redeploy via setup-agentelevate.ps1"
      }
    }
  }
}
