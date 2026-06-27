# Tests for the self-heal drift baseline -- the highest-risk surface the AgentElevate rename touched. The
# deployed task arguments now contain a SPACE ('C:\Program Files\AgentElevate\...'); if selfheal's drift
# check were brittle about quote/space normalization it would re-register + RESTART the broker on EVERY
# trigger (startup, each Windows-Update, daily). These tests pin (1) the two arg templates stay identical,
# and (2) the deployed-path argument survives a real Task Scheduler round-trip and still matches. Non-elevated,
# self-contained, cleaned up; nothing on the live system is left behind.
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'AgentElevate-tasks.ps1')   # defines _AE-Action, Get-AEExpectedAction, $script:AE_HOME (no side effects at load)

Describe 'Get-AEExpectedAction == _AE-Action (selfheal drift baseline stays in sync with the real action)' {
  foreach ($file in 'broker.ps1','selfheal.ps1') {
    It "$file : expected-action Argument equals the action _AE-Action would register" {
      $exp = Get-AEExpectedAction $file
      $act = _AE-Action $file
      Assert-Equal $exp.Execute  $act.Execute  "$file Execute must match (two separate literals must not desync)"
      Assert-Equal $exp.Argument $act.Arguments "$file Argument must match -- a desync would make selfheal thrash-restart the broker"
    }
  }
}

# Round-trip the action through a REAL throwaway task (registered as the current user, Limited -> no elevation)
# and assert selfheal's -like containment match holds against what Task Scheduler stores+returns.
$expFile = Join-Path 'C:\Program Files\AgentElevate' 'broker.ps1'
$tn = 'AgentElevate-TEST-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$registered = $false
try {
  $act = _AE-Action 'broker.ps1'
  $pr  = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
  $tr  = New-ScheduledTaskTrigger -AtLogOn
  Register-ScheduledTask -TaskName $tn -Action $act -Trigger $tr -Principal $pr -Force -ErrorAction Stop | Out-Null
  $registered = $true
} catch { }

if ($registered) {
  try {
    $live = (Get-ScheduledTask -TaskName $tn).Actions[0]
    Describe 'Test-TaskHealth arg-match survives the Task Scheduler round-trip (space-path regression)' {
      It 'the round-tripped Arguments still contain the -File broker path' {
        Assert-Match ([string]$live.Arguments) ([regex]::Escape($expFile)) 'the deployed space-path -File arg must survive round-trip'
      }
      It 'the -like "*<brokerPath>*" containment match is TRUE (no false drift on a healthy task)' {
        Assert-True ((([string]$live.Arguments) -like "*$expFile*")) 'selfheal target match must not false-positive on the space path'
      }
      It 'the round-tripped Execute equals the expected powershell.exe' {
        Assert-Equal $live.Execute (Get-AEExpectedAction 'broker.ps1').Execute 'exe must round-trip unchanged'
      }
    }
  } finally {
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
  }
} else {
  Write-Host "    [SKIP] Test-TaskHealth round-trip (could not register a throwaway task in this context)"
}
