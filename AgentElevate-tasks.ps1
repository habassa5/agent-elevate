# AgentElevate task definitions -- the single source of truth for the broker's two SYSTEM tasks. Dot-sourced
# by setup-agentelevate.ps1 (install) and selfheal.ps1 (restore-missing-or-drifted). Admin-only. Every task
# runs FIXED code from the admin-only C:\Program Files\AgentElevate\ -- that path's ACL + Administrators
# ownership is the trust anchor (NO signing cert). This project is JUST the elevation broker: it does not
# touch power/sleep/lock settings, Wi-Fi, or any keep-awake/Remote-Control concern.
$script:AE_HOME = 'C:\Program Files\AgentElevate'
$script:AE_PS   = (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')   # API-resolved, not $env:SystemRoot

function _AE-Action([string]$file) {
  New-ScheduledTaskAction -Execute $script:AE_PS -Argument ("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"{0}`"" -f (Join-Path $script:AE_HOME $file))
}
function _AE-EventTrigger([string]$logPath, [string]$provider, [int]$eventId) {
  $cls = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
  $t = New-CimInstance -CimClass $cls -ClientOnly
  $t.Enabled = $true
  $t.Subscription = "<QueryList><Query Id='0' Path='$logPath'><Select Path='$logPath'>*[System[Provider[@Name='$provider'] and (EventID=$eventId)]]</Select></Query></QueryList>"
  $t
}

# Trigger lists are the SINGLE SOURCE OF TRUTH for both registration AND selfheal's drift count (selfheal asserts
# exactly this many triggers). Exposed as functions so a test pins the count and a future change can't silently
# desync selfheal's tc baseline (which would thrash-re-register the task on every heal).
function Get-AEBrokerTriggers {
  @(
    (_AE-EventTrigger 'Application' 'AgentElevate' 4001),                                   # low-latency event signal
    (New-ScheduledTaskTrigger -AtStartup),                                                  # drain queue after reboot
    (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 3) -RepetitionDuration (New-TimeSpan -Days 3650))  # 3-min safety poll
  )
}
function Get-AESelfHealTriggers {
  @(
    (New-ScheduledTaskTrigger -AtStartup),
    (_AE-EventTrigger 'System' 'Microsoft-Windows-WindowsUpdateClient' 19),                 # post-Windows-Update
    (New-ScheduledTaskTrigger -Daily -At (Get-Date '3:19am'))
  )
}

# The broker: event-triggered (low latency) on AgentElevate EventID 4001, plus AtStartup + a 3-min safety poll.
function Register-BrokerTask {
  $a  = _AE-Action 'broker.ps1'
  $p  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $s  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -Hidden
  Register-ScheduledTask -TaskName 'AgentElevate-Broker' -Action $a -Trigger (Get-AEBrokerTriggers) -Principal $p -Settings $s -Description 'AgentElevate elevation broker (SYSTEM, admin-only path, allow-listed parameterized ops)' -Force | Out-Null
}

# Self-heal: restore the broker tasks if a Windows update / drift removes or breaks them. FIXED logic, no input.
function Register-SelfHealTask {
  $a  = _AE-Action 'selfheal.ps1'
  $p  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $s  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -Hidden
  Register-ScheduledTask -TaskName 'AgentElevate-SelfHeal' -Action $a -Trigger (Get-AESelfHealTriggers) -Principal $p -Settings $s -Description 'AgentElevate self-heal (SYSTEM, admin-only, restore missing-or-drifted broker tasks)' -Force | Out-Null
}

# Expected action for drift detection (selfheal compares the live task against this).
function Get-AEExpectedAction([string]$file) {
  @{ Execute = $script:AE_PS; Argument = ("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"{0}`"" -f (Join-Path $script:AE_HOME $file)) }
}
