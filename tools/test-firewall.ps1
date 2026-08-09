param(
    [string]$SimulatorPath,
    [string]$AlternateSimulatorPath,
    [string]$PublicAddress = '1.1.1.1',
    [int]$PublicPort = 443,
    [string]$DotNetPath
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an Administrator PowerShell terminal.'
}

$egRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$cli = Join-Path $egRoot 'src\EgressGuard.Cli\bin\Release\net8.0-windows\EgressGuard.Cli.dll'
if (-not $DotNetPath) {
    $temporarySdk = Join-Path $env:TEMP 'EgressGuard-dotnet8\dotnet.exe'
    $DotNetPath = if (Test-Path -LiteralPath $temporarySdk) { $temporarySdk } else { (Get-Command dotnet -ErrorAction Stop).Source }
}
if (-not $SimulatorPath) {
    $SimulatorPath = Join-Path $egRoot 'tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.exe'
}
$SimulatorPath = (Resolve-Path -LiteralPath $SimulatorPath).Path
foreach ($path in @($DotNetPath, $cli, $SimulatorPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required file not found: $path" }
}
if ((Split-Path -Leaf $SimulatorPath) -ne 'EgressGuard.Simulator.exe') {
    throw 'SimulatorPath must identify EgressGuard.Simulator.exe.'
}

function Invoke-Cli([string[]]$Arguments) {
    & $DotNetPath $cli @Arguments
    if ($LASTEXITCODE -ne 0) { throw "CLI failed: $($Arguments -join ' ')" }
}

function Invoke-Probe([string]$Path) {
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $probeOutput = & $Path --host $PublicAddress --port $PublicPort --connect-only --hold-seconds 0 2>&1
        $exitCode = $LASTEXITCODE
        $probeOutput | ForEach-Object { Write-Host $_ }
        return $exitCode
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
}

$before = $null
$during = $null
$after = $null
try {
    $before = Invoke-Probe $SimulatorPath
    if ($before -ne 0) { throw 'Public baseline probe failed before applying the block rule.' }

    Invoke-Cli @('service', 'block', '--path', $SimulatorPath)
    Invoke-Cli @('service', 'block', '--path', $SimulatorPath)
    $owned = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
        $_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'
    })
    if ($owned.Count -ne 1) { throw "Duplicate/ownership check failed; expected 1 rule, found $($owned.Count)." }

    $during = Invoke-Probe $SimulatorPath
    if ($during -eq 0) { throw 'Simulator still reached the public destination while its block rule was active.' }

    if ($AlternateSimulatorPath) {
        $alternate = (Resolve-Path -LiteralPath $AlternateSimulatorPath).Path
        if ((Invoke-Probe $alternate) -ne 0) { throw 'Same-name executable at another path was unexpectedly blocked.' }
    }

    $chromePublicConnections = @(Get-Process chrome,msedge -ErrorAction SilentlyContinue | ForEach-Object {
        Get-NetTCPConnection -OwningProcess $_.Id -State Established -ErrorAction SilentlyContinue
    } | Where-Object { $_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::') }).Count
    if ($chromePublicConnections -eq 0) { Write-Warning 'No established Chrome/Edge public connection was available as browser evidence.' }
}
finally {
    try { Invoke-Cli @('service', 'reset-rules') } catch { Write-Warning $_ }
}

$after = Invoke-Probe $SimulatorPath
$remaining = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'
}).Count
if ($after -ne 0 -or $remaining -ne 0) { throw 'Firewall rollback verification failed.' }

[pscustomobject]@{
    PublicDestination = "$PublicAddress`:$PublicPort"
    BeforeBlockExit = $before
    DuringBlockExit = $during
    AfterUndoExit = $after
    BrowserPublicConnections = $chromePublicConnections
    RemainingOwnedRules = $remaining
}
