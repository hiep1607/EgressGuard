param(
    [ValidateRange(1, 120)][int]$DurationMinutes = 10,
    [string]$DotNetPath
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $DotNetPath) {
    $temporarySdk = Join-Path $env:TEMP 'EgressGuard-dotnet8\dotnet.exe'
    $DotNetPath = if (Test-Path -LiteralPath $temporarySdk) { $temporarySdk } else { (Get-Command dotnet -ErrorAction Stop).Source }
}
$serviceDll = Join-Path $root 'src\EgressGuard.Service\bin\Release\net8.0-windows\EgressGuard.Service.dll'
$uiDll = Join-Path $root 'src\EgressGuard.UI\bin\Release\net8.0-windows\EgressGuard.UI.dll'
$serverDll = Join-Path $root 'tools\EgressGuard.TestServer\bin\Release\net8.0-windows\EgressGuard.TestServer.dll'
$simulatorDll = Join-Path $root 'tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.dll'
$cliDll = Join-Path $root 'src\EgressGuard.Cli\bin\Release\net8.0-windows\EgressGuard.Cli.dll'
foreach ($path in @($DotNetPath,$serviceDll,$uiDll,$serverDll,$simulatorDll,$cliDll)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Build output not found: $path" }
}

$soakDirectory = Join-Path $root 'artifacts\soak'
$runsDirectory = Join-Path $soakDirectory 'runs'
$startedAtUtc = [DateTimeOffset]::UtcNow
$runId = $startedAtUtc.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N')
$runDirectory = Join-Path $runsDirectory $runId
$dataDirectory = Join-Path $runDirectory 'data'
New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
$previousDataDirectory = $env:EGRESSGUARD_DATA_DIR
$env:EGRESSGUARD_DATA_DIR = $dataDirectory
$deadline = (Get-Date).AddMinutes($DurationMinutes)
$failures = [System.Collections.Generic.List[string]]::new()
$ownedProcessIds = [System.Collections.Generic.HashSet[int]]::new()
$service = $null
$server = $null
$ui = $null
$cycles = 0
$serviceMemory = [System.Collections.Generic.List[double]]::new()
$uiMemory = [System.Collections.Generic.List[double]]::new()
$serviceCpu = [System.Collections.Generic.List[double]]::new()
$uiCpu = [System.Collections.Generic.List[double]]::new()
$sampleState = @{}
$uiOpenCount = 0
$uiCloseCount = 0
$serviceRestartCount = 0
$ipcStatusChecks = 0
$normalTrafficRuns = 0
$burstTrafficRuns = 0
$beaconTrafficRuns = 0

function Register-SoakProcess($Process) {
    [void]$ownedProcessIds.Add($Process.Id)
    return $Process
}
function Start-SoakService {
    Register-SoakProcess (Start-Process -FilePath $DotNetPath -ArgumentList ('"' + $serviceDll + '"') -WindowStyle Hidden -PassThru)
}
function Stop-SoakProcess($Process, [string]$Role) {
    if (-not $Process) { return }
    if ($Process.HasExited) {
        [void]$ownedProcessIds.Remove($Process.Id)
        return
    }
    if (-not $ownedProcessIds.Contains($Process.Id)) {
        $failures.Add("Refused to stop unowned $Role process $($Process.Id).")
        return
    }

    try {
        [void]$Process.CloseMainWindow()
        if (-not $Process.WaitForExit(5000)) {
            Stop-Process -Id $Process.Id -Force -ErrorAction Stop
            if (-not $Process.WaitForExit(5000)) {
                $failures.Add("Owned $Role process $($Process.Id) did not exit after forced stop.")
                return
            }
        }
        [void]$ownedProcessIds.Remove($Process.Id)
    }
    catch {
        $stopFailure = $_.Exception.Message
        try {
            $Process.Refresh()
            if ($Process.HasExited) {
                [void]$ownedProcessIds.Remove($Process.Id)
                return
            }
        }
        catch {
            [void]$ownedProcessIds.Remove($Process.Id)
            return
        }
        $failures.Add("Failed to stop owned $Role process $($Process.Id): $stopFailure")
    }
}
function Measure-SoakProcess([string]$Name, $Process, $MemorySamples, $CpuSamples) {
    if (-not $Process -or $Process.HasExited) { return }
    $Process.Refresh()
    $now = Get-Date
    $cpuSeconds = $Process.TotalProcessorTime.TotalSeconds
    $MemorySamples.Add($Process.WorkingSet64 / 1MB)
    $previous = $sampleState[$Name]
    if ($previous -and $previous.ProcessId -eq $Process.Id) {
        $elapsedSeconds = ($now - $previous.Timestamp).TotalSeconds
        if ($elapsedSeconds -gt 0) {
            $cpuPercent = 100 * ($cpuSeconds - $previous.CpuSeconds) / $elapsedSeconds / [Environment]::ProcessorCount
            $CpuSamples.Add([math]::Max(0, $cpuPercent))
        }
    }
    $sampleState[$Name] = [pscustomobject]@{ ProcessId = $Process.Id; Timestamp = $now; CpuSeconds = $cpuSeconds }
}

try {
    $service = Start-SoakService
    $server = Register-SoakProcess (Start-Process -FilePath $DotNetPath -ArgumentList @($serverDll,'--protocol','tcp','--port','5050','--duration-seconds',($DurationMinutes * 60 + 30)) -WindowStyle Hidden -PassThru)
    Start-Sleep -Seconds 3
    while ((Get-Date) -lt $deadline) {
        $cycles++
        try {
            if (-not $ui -or $ui.HasExited) {
                $ui = Register-SoakProcess (Start-Process -FilePath $DotNetPath -ArgumentList ('"' + $uiDll + '"') -PassThru)
                $uiOpenCount++
            }
            & $DotNetPath $simulatorDll --protocol tcp --port 5050 --mode small --bytes 1024 --hold-seconds 0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Normal simulator run failed.' }
            $normalTrafficRuns++
            & $DotNetPath $simulatorDll --protocol tcp --port 5050 --mode burst --bytes 262144 --hold-seconds 0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Burst simulator run failed.' }
            $burstTrafficRuns++
            & $DotNetPath $simulatorDll --protocol tcp --port 5050 --connect-only --hold-seconds 0 --connections 3 --connection-interval-ms 500 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Beacon simulator run failed.' }
            $beaconTrafficRuns++
            & $DotNetPath $cliDll service status | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Pipe status request failed.' }
            $ipcStatusChecks++
            Measure-SoakProcess 'Service' $service $serviceMemory $serviceCpu
            Measure-SoakProcess 'UI' $ui $uiMemory $uiCpu
            if (($cycles % 3) -eq 0) {
                Stop-SoakProcess $ui 'UI'
                $ui = $null
                $uiCloseCount++
            }
            if (($cycles % 5) -eq 0) {
                Stop-SoakProcess $service 'service'
                $service = Start-SoakService
                $serviceRestartCount++
                Start-Sleep -Seconds 3
            }
        }
        catch {
            $failures.Add($_.Exception.Message)
        }
    }
}
catch {
    $failures.Add("Fatal soak failure: $($_.Exception.Message)")
}
finally {
    Stop-SoakProcess $ui 'UI'
    Stop-SoakProcess $service 'service'
    Stop-SoakProcess $server 'test server'
    if ($null -eq $previousDataDirectory) {
        Remove-Item Env:EGRESSGUARD_DATA_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:EGRESSGUARD_DATA_DIR = $previousDataDirectory
    }
}

$databasePath = Join-Path $dataDirectory 'egressguard.db'
$databaseLockReleased = $false
if (Test-Path -LiteralPath $databasePath) {
    try {
        $stream = [System.IO.File]::Open($databasePath, 'Open', 'ReadWrite', 'None')
        $stream.Dispose()
        $databaseLockReleased = $true
    }
    catch {
        $failures.Add("Database remained locked after cleanup: $($_.Exception.Message)")
    }
}
else {
    $failures.Add('Soak database was not created.')
}
$processInspectionSucceeded = $false
$remainingProcesses = $null
try {
    [void](Get-Command Get-CimInstance -ErrorAction Stop)
    $remainingProcesses = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Where-Object {
        $ownedProcessIds.Contains([int]$_.ProcessId)
    }).Count
    $processInspectionSucceeded = $true
}
catch {
    $failures.Add("Process cleanup inspection failed: $($_.Exception.Message)")
}

$firewallInspectionSucceeded = $false
$remainingOwnedRules = $null
try {
    [void](Get-Command Get-NetFirewallRule -ErrorAction Stop)
    $remainingOwnedRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
        $_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'
    }).Count
    $firewallInspectionSucceeded = $true
}
catch {
    $failures.Add("Firewall cleanup inspection failed: $($_.Exception.Message)")
}

if ($processInspectionSucceeded -and $remainingProcesses -ne 0) { $failures.Add("$remainingProcesses owned soak process(es) remained after cleanup.") }
if ($firewallInspectionSucceeded -and $remainingOwnedRules -ne 0) { $failures.Add("$remainingOwnedRules EgressGuard-owned firewall rule(s) remained after cleanup.") }

$summary = [pscustomobject]@{
    RunId = $runId
    StartedAtUtc = $startedAtUtc.ToString('O')
    CompletedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    DurationMinutes = $DurationMinutes
    Cycles = $cycles
    Failures = $failures.Count
    FailureMessages = @($failures)
    NormalTrafficRuns = $normalTrafficRuns
    BurstTrafficRuns = $burstTrafficRuns
    BeaconTrafficRuns = $beaconTrafficRuns
    IpcStatusChecks = $ipcStatusChecks
    ServiceRestarts = $serviceRestartCount
    UiOpenCount = $uiOpenCount
    UiCloseCount = $uiCloseCount
    ServiceCpuAveragePercent = if ($serviceCpu.Count) { [math]::Round(($serviceCpu | Measure-Object -Average).Average,3) } else { $null }
    ServiceCpuPeakPercent = if ($serviceCpu.Count) { [math]::Round(($serviceCpu | Measure-Object -Maximum).Maximum,3) } else { $null }
    UiCpuAveragePercent = if ($uiCpu.Count) { [math]::Round(($uiCpu | Measure-Object -Average).Average,3) } else { $null }
    UiCpuPeakPercent = if ($uiCpu.Count) { [math]::Round(($uiCpu | Measure-Object -Maximum).Maximum,3) } else { $null }
    ServiceRamInitialMb = if ($serviceMemory.Count) { [math]::Round($serviceMemory[0],1) } else { $null }
    ServiceRamFinalMb = if ($serviceMemory.Count) { [math]::Round($serviceMemory[$serviceMemory.Count - 1],1) } else { $null }
    ServiceRamMinimumMb = if ($serviceMemory.Count) { [math]::Round(($serviceMemory | Measure-Object -Minimum).Minimum,1) } else { $null }
    ServiceRamMaximumMb = if ($serviceMemory.Count) { [math]::Round(($serviceMemory | Measure-Object -Maximum).Maximum,1) } else { $null }
    UiRamInitialMb = if ($uiMemory.Count) { [math]::Round($uiMemory[0],1) } else { $null }
    UiRamFinalMb = if ($uiMemory.Count) { [math]::Round($uiMemory[$uiMemory.Count - 1],1) } else { $null }
    UiRamMinimumMb = if ($uiMemory.Count) { [math]::Round(($uiMemory | Measure-Object -Minimum).Minimum,1) } else { $null }
    UiRamMaximumMb = if ($uiMemory.Count) { [math]::Round(($uiMemory | Measure-Object -Maximum).Maximum,1) } else { $null }
    DatabaseLockReleased = $databaseLockReleased
    ProcessInspectionSucceeded = $processInspectionSucceeded
    RemainingProcesses = $remainingProcesses
    FirewallInspectionSucceeded = $firewallInspectionSucceeded
    RemainingOwnedFirewallRules = $remainingOwnedRules
}
$summaryJson = $summary | ConvertTo-Json -Depth 4
$summaryJson | Set-Content -LiteralPath (Join-Path $runDirectory 'summary.json') -Encoding utf8
$summaryJson | Set-Content -LiteralPath (Join-Path $soakDirectory 'latest-summary.json') -Encoding utf8
$summary
if ($failures.Count -gt 0) { exit 1 }
