param(
    [Parameter(Mandatory = $true)][int]$UiProcessId,
    [Parameter(Mandatory = $true)][int]$ServiceProcessId,
    [ValidateRange(5, 300)][int]$DurationSeconds = 30,
    [string]$Label = 'measurement'
)

$ErrorActionPreference = 'Stop'
$logicalProcessors = [Environment]::ProcessorCount
$processes = @{
    UI = Get-Process -Id $UiProcessId
    Service = Get-Process -Id $ServiceProcessId
}
$previousCpu = @{}
$samples = @{ UI = @(); Service = @() }
foreach ($name in $processes.Keys) { $previousCpu[$name] = $processes[$name].TotalProcessorTime.TotalSeconds }

for ($sample = 0; $sample -lt $DurationSeconds; $sample++) {
    Start-Sleep -Seconds 1
    foreach ($name in @('UI','Service')) {
        $processes[$name] = Get-Process -Id $processes[$name].Id
        $currentCpu = $processes[$name].TotalProcessorTime.TotalSeconds
        $samples[$name] += [pscustomobject]@{
            CpuPercent = (($currentCpu - $previousCpu[$name]) / $logicalProcessors) * 100
            RamMb = $processes[$name].WorkingSet64 / 1MB
        }
        $previousCpu[$name] = $currentCpu
    }
}

foreach ($name in @('UI','Service')) {
    [pscustomobject]@{
        Label = $Label
        Process = $name
        DurationSeconds = $DurationSeconds
        CpuAveragePercent = [math]::Round(($samples[$name] | Measure-Object CpuPercent -Average).Average, 3)
        CpuPeakPercent = [math]::Round(($samples[$name] | Measure-Object CpuPercent -Maximum).Maximum, 3)
        RamAverageMb = [math]::Round(($samples[$name] | Measure-Object RamMb -Average).Average, 1)
        RamPeakMb = [math]::Round(($samples[$name] | Measure-Object RamMb -Maximum).Maximum, 1)
    }
}
