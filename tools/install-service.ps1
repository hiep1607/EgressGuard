param(
    [Parameter(Mandatory = $true)]
    [string]$PublishedDirectory
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an Administrator PowerShell terminal.'
}

$serviceName = 'EgressGuard.Service'
$executable = Join-Path (Resolve-Path -LiteralPath $PublishedDirectory).Path 'EgressGuard.Service.exe'
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Published service executable not found: $executable"
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Service $serviceName already exists. Uninstall it explicitly before reinstalling."
}

sc.exe create $serviceName binPath= ('"' + $executable + '"') start= auto DisplayName= 'EgressGuard Service' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/none/0 | Out-Null
sc.exe failureflag $serviceName 1 | Out-Null
Start-Service -Name $serviceName
Write-Host "Installed and started $serviceName"
