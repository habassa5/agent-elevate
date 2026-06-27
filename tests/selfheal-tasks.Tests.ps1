# Tests for the self-heal drift baseline -- the highest-risk surface the AgentElevate rename touched. The
# deployed task arguments now contain a SPACE ('C:\Program Files\AgentElevate\...'); if selfheal's drift
# check were brittle about quote/space normalization it would re-register + RESTART the broker on EVERY
# trigger (startup, each Windows-Update, daily). These tests pin (1) the two arg templates stay identical,
# and (2) the deployed-path argument survives a real Task Scheduler round-trip and still matches. Non-elevated,
# self-contained, cleaned up; nothing on the live system is left behind.
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'AgentElevate-tasks.ps1')   # defines _AE-Action, Get-AEExpectedAction, $script:AE_HOME (no side effects at load)

# Mirror selfheal's CommandLineToArgvW tokenizer (selfheal.ps1 [AeArgv]) so these tests exercise the SAME
# Windows arg-parsing contract its drift check uses. (selfheal.ps1 has no load-split marker, so we can't dot-
# source it without running it; this is the identical API.)
if (-not ('AeArgvTest' -as [type])) {
  Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class AeArgvTest {
  [DllImport("shell32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CommandLineToArgvW(string cmd, out int n);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  public static string[] Parse(string cmd) {
    int n; IntPtr p = CommandLineToArgvW("ae " + cmd, out n);
    if (p == IntPtr.Zero) return null;
    try { string[] r = new string[n > 0 ? n - 1 : 0]; for (int i = 1; i < n; i++) r[i-1] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, i * IntPtr.Size)); return r; }
    finally { LocalFree(p); }
  }
}
"@
}
function Tok-Argv($s){ @([AeArgvTest]::Parse([string]$s)) }
function Argv-Equal($a,$b){ ($a.Count -eq $b.Count) -and (0 -eq @(0..([Math]::Max($a.Count,1)-1) | Where-Object { $_ -lt $a.Count -and $a[$_] -ne $b[$_] }).Count) }

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

# Pins the trigger-count contract at its SINGLE SOURCE (Get-AE*Triggers, used by BOTH Register-*Task and selfheal's
# derived tc). If a future edit adds/removes a trigger, this fails -- forcing a deliberate reconciliation instead
# of a silent heal-time thrash.
Describe 'trigger-list contract (Get-AE*Triggers) stays at the count selfheal derives' {
  It 'Get-AEBrokerTriggers builds exactly 3 triggers (event 4001 + AtStartup + 3-min poll)' {
    Assert-Equal (@(Get-AEBrokerTriggers).Count) 3 'broker trigger count changed -- reconcile deliberately'
  }
  It 'Get-AESelfHealTriggers builds exactly 3 triggers (AtStartup + WU-event-19 + daily)' {
    Assert-Equal (@(Get-AESelfHealTriggers).Count) 3 'selfheal trigger count changed -- reconcile deliberately'
  }
}

# Pins selfheal's NEW tokenized arg-VECTOR match (replaces the substring/flag-presence checks). The expected
# vector is the real Get-AEExpectedAction argument; drift variants must tokenize differently.
Describe 'selfheal arg-vector match is EXACT (token-for-token), rejecting injection + look-alikes' {
  $expArg = (Get-AEExpectedAction 'broker.ps1').Argument
  $expTok = Tok-Argv $expArg
  It 'the expected argument tokenizes to a stable 7-token vector ending in the broker path' {
    Assert-Equal $expTok.Count 7 'expected arg should be 7 tokens'
    Assert-Equal $expTok[6] (Join-Path 'C:\Program Files\AgentElevate' 'broker.ps1') 'last token is the -File path'
  }
  It 'an injected -Command produces a DIFFERENT token vector (drift)' {
    $inj = Tok-Argv '-NoProfile -ExecutionPolicy Bypass -Command calc -File "C:\Program Files\AgentElevate\broker.ps1"'
    Assert-False (Argv-Equal $expTok $inj) 'an injected -Command must be detected as drift'
  }
  It 'a broker.ps1.bak look-alike produces a DIFFERENT token vector (drift)' {
    $bak = Tok-Argv ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f (Join-Path 'C:\Program Files\AgentElevate' 'broker.ps1.bak'))
    Assert-False (Argv-Equal $expTok $bak) 'a .bak target must be detected as drift'
  }
  It 'an unquoted space-path produces a DIFFERENT (longer) token vector (drift)' {
    $unq = Tok-Argv '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Program Files\AgentElevate\broker.ps1'
    Assert-False (Argv-Equal $expTok $unq) 'an unquoted space-path must be detected as drift'
  }
  It 'the identical expected argument matches itself (no false drift)' {
    Assert-True (Argv-Equal $expTok (Tok-Argv $expArg)) 'identical args must match'
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
      It 'the round-tripped args tokenize to EXACTLY the expected vector (no false drift on the space path)' {
        $expTok  = Tok-Argv (Get-AEExpectedAction 'broker.ps1').Argument
        $liveTok = Tok-Argv ([string]$live.Arguments)
        Assert-True (Argv-Equal $expTok $liveTok) ("round-tripped args must match expected token-for-token; live=[{0}] exp=[{1}]" -f ($liveTok -join ' | '), ($expTok -join ' | '))
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
