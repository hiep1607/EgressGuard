$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an Administrator PowerShell terminal.'
}

$serviceName = 'EgressGuard.Service'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
}

Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like 'EgressGuard-MVP-*' -and
        $_.Description -like 'Owned by EgressGuard MVP;*'
    } |
    Remove-NetFirewallRule

Write-Host 'Service removed and EgressGuard-owned MVP firewall rules reset.'
