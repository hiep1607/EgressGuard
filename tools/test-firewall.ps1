$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an Administrator PowerShell terminal.'
}

$egRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$egCli = Join-Path $egRoot 'src\EgressGuard.Cli\bin\Release\net8.0-windows\EgressGuard.Cli.exe'
$egSimulator = Join-Path $egRoot 'tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.exe'
$egServer = Join-Path $egRoot 'tools\EgressGuard.TestServer\bin\Release\net8.0-windows\EgressGuard.TestServer.exe'

foreach ($path in @($egCli, $egSimulator, $egServer)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Build output not found: $path" }
}

$server = $null
try {
    $server = Start-Process -FilePath $egServer -ArgumentList @('--protocol','tcp','--port','5050','--duration-seconds','40') -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 1
    & $egSimulator --protocol tcp --port 5050 --mode small --bytes 512 --hold-seconds 0
    if ($LASTEXITCODE -ne 0) { throw 'Baseline Simulator connection failed before applying a rule.' }

    & $egCli service block --path $egSimulator
    & $egSimulator --protocol tcp --port 5050 --mode small --bytes 512 --hold-seconds 0
    if ($LASTEXITCODE -eq 0) { throw 'Simulator still connected. The target Windows policy may exempt loopback traffic.' }

    Write-Host 'Simulator was blocked. Verify Chrome/Edge still has Internet, then press Enter.'
    Read-Host
}
finally {
    try { & $egCli service reset-rules } catch { Write-Warning $_ }
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id }
}

& $egSimulator --protocol tcp --port 5050 --mode small --bytes 512 --hold-seconds 0
Get-NetFirewallRule -DisplayName 'EgressGuard-MVP-*' -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Enabled, Direction, Action, Description
