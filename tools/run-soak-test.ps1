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
New-Item -ItemType Directory -Path $soakDirectory -Force | Out-Null
$previousDataDirectory = $env:EGRESSGUARD_DATA_DIR
$env:EGRESSGUARD_DATA_DIR = Join-Path $soakDirectory 'data'
$deadline = (Get-Date).AddMinutes($DurationMinutes)
$service = $null
$server = $null
$ui = $null
$cycles = 0
$failures = [System.Collections.Generic.List[string]]::new()
$serviceMemory = [System.Collections.Generic.List[double]]::new()

function Start-SoakService { Start-Process -FilePath $DotNetPath -ArgumentList ('"' + $serviceDll + '"') -WindowStyle Hidden -PassThru }
function Stop-SoakProcess($Process) {
    if ($Process -and -not $Process.HasExited) {
        [void]$Process.CloseMainWindow()
        if (-not $Process.WaitForExit(5000)) { Stop-Process -Id $Process.Id }
    }
}

try {
    $service = Start-SoakService
    $server = Start-Process -FilePath $DotNetPath -ArgumentList @($serverDll,'--protocol','tcp','--port','5050','--duration-seconds',($DurationMinutes * 60 + 30)) -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 3
    while ((Get-Date) -lt $deadline) {
        $cycles++
        try {
            if (-not $ui -or $ui.HasExited) { $ui = Start-Process -FilePath $DotNetPath -ArgumentList ('"' + $uiDll + '"') -PassThru }
            & $DotNetPath $simulatorDll --protocol tcp --port 5050 --mode small --bytes 1024 --hold-seconds 0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Normal simulator run failed.' }
            & $DotNetPath $simulatorDll --protocol tcp --port 5050 --mode burst --bytes 262144 --hold-seconds 0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Burst simulator run failed.' }
            & $DotNetPath $simulatorDll --protocol tcp --port 5050 --connect-only --hold-seconds 0 --connections 3 --connection-interval-ms 500 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Beacon simulator run failed.' }
            & $DotNetPath $cliDll service status | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Pipe status request failed.' }
            $serviceMemory.Add((Get-Process -Id $service.Id).WorkingSet64 / 1MB)
            if (($cycles % 3) -eq 0) { Stop-SoakProcess $ui; $ui = $null }
            if (($cycles % 5) -eq 0) {
                Stop-SoakProcess $service
                $service = Start-SoakService
                Start-Sleep -Seconds 3
            }
        }
        catch {
            $failures.Add($_.Exception.Message)
        }
    }
}
finally {
    Stop-SoakProcess $ui
    Stop-SoakProcess $service
    Stop-SoakProcess $server
    $env:EGRESSGUARD_DATA_DIR = $previousDataDirectory
}

$summary = [pscustomobject]@{
    StartedAt = $deadline.AddMinutes(-$DurationMinutes).ToString('O')
    DurationMinutes = $DurationMinutes
    Cycles = $cycles
    Failures = $failures.Count
    FailureMessages = @($failures)
    ServiceRamMinimumMb = if ($serviceMemory.Count) { [math]::Round(($serviceMemory | Measure-Object -Minimum).Minimum,1) } else { $null }
    ServiceRamMaximumMb = if ($serviceMemory.Count) { [math]::Round(($serviceMemory | Measure-Object -Maximum).Maximum,1) } else { $null }
}
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $soakDirectory 'latest-summary.json') -Encoding utf8
$summary
if ($failures.Count -gt 0) { exit 1 }
