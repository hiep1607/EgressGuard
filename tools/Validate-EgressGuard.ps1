#requires -Version 5.1
<#
.SYNOPSIS
    Single-command EgressGuard validation used locally and by GitHub Actions.

.DESCRIPTION
    Runs, in order: dotnet tool restore, locked solution restore, format
    verification (never rewrites files), Release build, the executable test
    suite, the vulnerable-package audit, git diff --check, a display-only
    git status --short, and structural/secret checks for AGENT_HANDOFF.md.

    The script stops at the first failing step and exits with that step's
    exit code. It determines the repository root from its own location,
    requires no administrator rights, changes no firewall, Defender,
    registry, service or user data state, writes nothing into the
    repository, and never uses Invoke-Expression or command lines composed
    from untrusted data. Matched secret values are never printed.

.PARAMETER RequireClean
    Fails when tracked repository files changed during validation. Files
    ignored through .gitignore (for example build output) do not fail the
    run because git status excludes them.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\Validate-EgressGuard.ps1 -RequireClean
#>

[CmdletBinding()]
param(
    [switch]$RequireClean
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot

$script:StepResults = New-Object System.Collections.Generic.List[string]
$script:FailedStepName = ''
$script:FailedStepCode = 0

function Write-SummaryAndExit {
    param([int]$ExitCode)

    Write-Host ''
    Write-Host '==================== validation summary ===================='
    foreach ($entry in $script:StepResults) {
        Write-Host $entry
    }
    Write-Host '============================================================'
    if ($script:FailedStepName -ne '') {
        Write-Host ('RESULT: FAILED - step "' + $script:FailedStepName + '" exited with code ' + $script:FailedStepCode)
    }
    else {
        Write-Host 'RESULT: PASSED - all validation steps succeeded.'
    }
    exit $ExitCode
}

function Invoke-ValidationStep {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host ''
    Write-Host ('[step] ' + $Name)
    & $Action
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        $script:StepResults.Add(('ok   ' + $Name + ' (exit 0)'))
        Write-Host ('[ok  ] ' + $Name)
    }
    else {
        $script:StepResults.Add(('FAIL ' + $Name + ' (exit ' + $code + ')'))
        $script:FailedStepName = $Name
        $script:FailedStepCode = $code
        Write-Host ('[fail] ' + $Name + ' exited with code ' + $code + '; stopping.')
        Write-SummaryAndExit -ExitCode $code
    }
}

function Get-AgentHandoffViolations {
    $issues = New-Object System.Collections.Generic.List[string]
    $handoffPath = Join-Path -Path $repoRoot -ChildPath 'AGENT_HANDOFF.md'
    if (-not (Test-Path -LiteralPath $handoffPath -PathType Leaf)) {
        [void]$issues.Add('AGENT_HANDOFF.md is missing from the repository root.')
        return ,$issues.ToArray()
    }

    $fileItem = Get-Item -LiteralPath $handoffPath
    if ($fileItem.Length -gt 12288) {
        [void]$issues.Add(('File size ' + $fileItem.Length + ' bytes exceeds the 12288 byte limit.'))
    }

    $lines = [System.IO.File]::ReadAllLines($handoffPath)
    if ($lines.Count -gt 180) {
        [void]$issues.Add(('File has ' + $lines.Count + ' lines; the limit is 180.'))
    }

    $sessionCount = 0
    foreach ($line in $lines) {
        if ($line -match '^### Session') {
            $sessionCount++
        }
    }
    if ($sessionCount -gt 5) {
        [void]$issues.Add(('Found ' + $sessionCount + ' session headings; keep at most 5 completed sessions.'))
    }

    $text = [System.IO.File]::ReadAllText($handoffPath)
    if ($text -notmatch '## Current snapshot') {
        [void]$issues.Add('Missing required section "## Current snapshot".')
    }
    if ($text -notmatch '## Recent sessions') {
        [void]$issues.Add('Missing required section "## Recent sessions".')
    }

    $secretChecks = @(
        @{ Name = 'private key block'; Pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
        @{ Name = 'GitHub token'; Pattern = '\bgh[pousr]_[A-Za-z0-9]{20,}' },
        @{ Name = 'GitHub fine-grained token'; Pattern = '\bgithub_pat_[A-Za-z0-9_]{20,}' },
        @{ Name = 'AWS access key id'; Pattern = '\bAKIA[0-9A-Z]{16}\b' },
        @{ Name = 'hard-coded credential assignment'; Pattern = '(?i)\b(password|passwd|api[_-]?key|client[_-]?secret)\s*[:=]\s*["'']?[^\s"'':=]{8,}' }
    )
    for ($index = 0; $index -lt $lines.Count; $index++) {
        foreach ($check in $secretChecks) {
            if ($lines[$index] -match $check.Pattern) {
                [void]$issues.Add(('Line ' + ($index + 1) + ': possible secret detected (' + $check.Name + '); value withheld.'))
                break
            }
        }
    }

    return ,$issues.ToArray()
}

Write-Host ('Repository root: ' + $repoRoot)

Invoke-ValidationStep -Name 'dotnet tool restore' -Action { dotnet tool restore }
Invoke-ValidationStep -Name 'restore solution (locked mode)' -Action { dotnet restore EgressGuard.sln --locked-mode }
Invoke-ValidationStep -Name 'verify formatting (no rewrite)' -Action { dotnet format EgressGuard.sln --verify-no-changes --no-restore }
Invoke-ValidationStep -Name 'build Release' -Action { dotnet build EgressGuard.sln -c Release --no-restore }
Invoke-ValidationStep -Name 'run executable test suite' -Action { dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build }
Invoke-ValidationStep -Name 'vulnerable package audit' -Action { dotnet list EgressGuard.sln package --vulnerable --include-transitive }
Invoke-ValidationStep -Name 'git diff --check' -Action { git diff --check }

Write-Host ''
Write-Host '[step] git status --short (display only)'
$statusOutput = @(git status --short)
if ($statusOutput.Count -eq 0) {
    Write-Host '[ok  ] git status --short reported no entries'
    $script:StepResults.Add('ok   git status --short (0 entries)')
}
else {
    foreach ($statusLine in $statusOutput) {
        Write-Host ('       ' + $statusLine)
    }
    $script:StepResults.Add(('ok   git status --short (' + $statusOutput.Count + ' entries, display only)'))
}

Invoke-ValidationStep -Name 'agent handoff file validation' -Action {
    $violations = Get-AgentHandoffViolations
    if ($violations.Count -gt 0) {
        foreach ($violation in $violations) {
            Write-Host ('[!]   ' + $violation)
        }
        $global:LASTEXITCODE = 1
    }
    else {
        Write-Host '[ok  ] AGENT_HANDOFF.md exists, within limits, no secret patterns found'
        $global:LASTEXITCODE = 0
    }
}

if ($RequireClean) {
    $trackedChanges = @(git status --porcelain | Where-Object { $_ -notmatch '^\?\?' })
    if ($trackedChanges.Count -gt 0) {
        Write-Host ''
        Write-Host '[fail] -RequireClean: unexpected tracked changes appeared during validation:'
        foreach ($change in $trackedChanges) {
            Write-Host ('       ' + $change)
        }
        $script:StepResults.Add(('FAIL -RequireClean (' + $trackedChanges.Count + ' tracked change(s))'))
        $script:FailedStepName = '-RequireClean tracked-change check'
        $script:FailedStepCode = 10
        Write-SummaryAndExit -ExitCode 10
    }
    $script:StepResults.Add('ok   -RequireClean (no tracked changes appeared)')
    Write-Host ''
    Write-Host '[ok  ] -RequireClean: no tracked changes appeared during validation'
}

Write-SummaryAndExit -ExitCode 0