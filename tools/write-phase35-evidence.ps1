param(
    [Parameter(Mandatory = $true)][string]$SoakSummaryPath,
    [Parameter(Mandatory = $true)][string]$TestedCommit,
    [Parameter(Mandatory = $true)][string]$Branch,
    [Parameter(Mandatory = $true)][string]$DotNetSdkVersion,
    [Parameter(Mandatory = $true)][string]$DotNetRuntimeVersion,
    [Parameter(Mandatory = $true)][int]$BuildWarnings,
    [Parameter(Mandatory = $true)][int]$BuildErrors,
    [Parameter(Mandatory = $true)][int]$TestPassed,
    [Parameter(Mandatory = $true)][int]$TestFailed,
    [Parameter(Mandatory = $true)][int]$FormatExitCode,
    [Parameter(Mandatory = $true)][bool]$ScmVerified,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ServiceExeSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ServiceDllSha256,
    [string]$GitHubActionsUrl,
    [string[]]$NotVerified = @(),
    [string[]]$Blocked = @(),
    [string]$OutputPath = 'docs\evidence\phase-3.5-validation.json'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$summary = Get-Content -Raw -LiteralPath (Resolve-Path -LiteralPath $SoakSummaryPath) | ConvertFrom-Json
$requiredSummaryProperties = @(
    'StartedAtUtc', 'DurationMinutes', 'Cycles', 'Failures',
    'ServiceCpuAveragePercent', 'ServiceCpuPeakPercent', 'UiCpuAveragePercent', 'UiCpuPeakPercent',
    'ServiceRamInitialMb', 'ServiceRamFinalMb', 'ServiceRamMinimumMb', 'ServiceRamMaximumMb',
    'UiRamInitialMb', 'UiRamFinalMb', 'UiRamMinimumMb', 'UiRamMaximumMb',
    'ServiceRestarts', 'UiOpenCount', 'UiCloseCount', 'IpcStatusChecks',
    'DatabaseLockReleased', 'ProcessInspectionSucceeded', 'RemainingProcesses',
    'FirewallInspectionSucceeded', 'RemainingOwnedFirewallRules'
)
foreach ($property in $requiredSummaryProperties) {
    if ($null -eq $summary.PSObject.Properties[$property]) {
        throw "Soak summary is missing required property: $property"
    }
}

if (-not $summary.ProcessInspectionSucceeded -or -not $summary.FirewallInspectionSucceeded) {
    throw 'Refusing to create evidence from a soak run whose cleanup inspection did not succeed.'
}

$evidence = [ordered]@{
    SchemaVersion = 1
    GeneratedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    Source = [ordered]@{
        TestedCommit = $TestedCommit
        Branch = $Branch
    }
    DotNet = [ordered]@{
        SdkVersion = $DotNetSdkVersion
        RuntimeVersion = $DotNetRuntimeVersion
    }
    Validation = [ordered]@{
        BuildWarnings = $BuildWarnings
        BuildErrors = $BuildErrors
        TestsPassed = $TestPassed
        TestsFailed = $TestFailed
        FormatExitCode = $FormatExitCode
    }
    Soak = [ordered]@{
        StartedAtUtc = $summary.StartedAtUtc
        DurationMinutes = $summary.DurationMinutes
        Cycles = $summary.Cycles
        Failures = $summary.Failures
        ServiceCpuAveragePercent = $summary.ServiceCpuAveragePercent
        ServiceCpuPeakPercent = $summary.ServiceCpuPeakPercent
        UiCpuAveragePercent = $summary.UiCpuAveragePercent
        UiCpuPeakPercent = $summary.UiCpuPeakPercent
        ServiceRamInitialMb = $summary.ServiceRamInitialMb
        ServiceRamFinalMb = $summary.ServiceRamFinalMb
        ServiceRamMinimumMb = $summary.ServiceRamMinimumMb
        ServiceRamMaximumMb = $summary.ServiceRamMaximumMb
        UiRamInitialMb = $summary.UiRamInitialMb
        UiRamFinalMb = $summary.UiRamFinalMb
        UiRamMinimumMb = $summary.UiRamMinimumMb
        UiRamMaximumMb = $summary.UiRamMaximumMb
        ServiceRestarts = $summary.ServiceRestarts
        UiOpenCount = $summary.UiOpenCount
        UiCloseCount = $summary.UiCloseCount
        IpcStatusChecks = $summary.IpcStatusChecks
        DatabaseLockReleased = $summary.DatabaseLockReleased
        ProcessInspectionSucceeded = $summary.ProcessInspectionSucceeded
        RemainingProcesses = $summary.RemainingProcesses
        FirewallInspectionSucceeded = $summary.FirewallInspectionSucceeded
        RemainingOwnedFirewallRules = $summary.RemainingOwnedFirewallRules
    }
    Scm = [ordered]@{
        Status = if ($ScmVerified) { 'Verified' } else { 'Not verified' }
        ServiceExeSha256 = $ServiceExeSha256.ToUpperInvariant()
        ServiceDllSha256 = $ServiceDllSha256.ToUpperInvariant()
    }
    GitHubActionsUrl = if ([string]::IsNullOrWhiteSpace($GitHubActionsUrl)) { $null } else { $GitHubActionsUrl }
    Remaining = [ordered]@{
        NotVerified = @($NotVerified)
        Blocked = @($Blocked)
    }
}

$json = $evidence | ConvertTo-Json -Depth 6
$forbiddenPatterns = @(
    'C:\\Users\\',
    '(?i)github_pat_|gho_|Bearer\s+[A-Za-z0-9._-]+',
    '(?i)BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY',
    '\b10\.(?:\d{1,3}\.){2}\d{1,3}\b',
    '\b192\.168\.(?:\d{1,3}\.)\d{1,3}\b',
    '\b172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}\b'
)
foreach ($pattern in $forbiddenPatterns) {
    if ($json -match $pattern) {
        throw "Refusing to write evidence containing forbidden data matching: $pattern"
    }
}

$evidenceRoot = [IO.Path]::GetFullPath((Join-Path $root 'docs\evidence'))
$resolvedOutput = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputPath))
}
if (-not $resolvedOutput.StartsWith($evidenceRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Evidence output must stay under docs\evidence.'
}

New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
$json | Set-Content -LiteralPath $resolvedOutput -Encoding utf8
Write-Output $resolvedOutput
