[CmdletBinding()]
param(
    [int]$ReadyTimeoutSeconds = 20
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$serviceProject = Join-Path $repoRoot "src\EgressGuard.Service\EgressGuard.Service.csproj"
$uiProject = Join-Path $repoRoot "src\EgressGuard.UI\EgressGuard.UI.csproj"
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue

if ($null -eq $dotnet) {
    throw "dotnet was not found on PATH. Install the required .NET SDK first."
}

foreach ($project in @($serviceProject, $uiProject)) {
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
        throw "Required project was not found: $project"
    }
}

if ($ReadyTimeoutSeconds -lt 1 -or $ReadyTimeoutSeconds -gt 300) {
    throw "ReadyTimeoutSeconds must be between 1 and 300 seconds."
}

$dataRoot = Join-Path $repoRoot ".local\egressguard-$PID"
$null = New-Item -ItemType Directory -Path $dataRoot -Force
$pipeName = "EgressGuard.Local.$PID"
$serviceLog = Join-Path $dataRoot "service.out.log"
$serviceErrorLog = Join-Path $dataRoot "service.error.log"
$uiLog = Join-Path $dataRoot "ui.out.log"
$uiErrorLog = Join-Path $dataRoot "ui.error.log"
$ownedProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$exitCode = 0
$previousDataRoot = [Environment]::GetEnvironmentVariable("EGRESSGUARD_DATA_DIR", "Process")
$previousPipeName = [Environment]::GetEnvironmentVariable("EGRESSGUARD_PIPE_NAME", "Process")

function Get-DescendantProcesses {
    param([int]$RootProcessId)

    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $byParent = @{}
    foreach ($item in $all) {
        $parent = [int]$item.ParentProcessId
        if (-not $byParent.ContainsKey($parent)) {
            $byParent[$parent] = [System.Collections.Generic.List[object]]::new()
        }
        $byParent[$parent].Add($item)
    }

    $queue = [System.Collections.Generic.Queue[int]]::new()
    $queue.Enqueue($RootProcessId)
    $result = [System.Collections.Generic.List[object]]::new()
    while ($queue.Count -gt 0) {
        $parentId = $queue.Dequeue()
        foreach ($child in @($byParent[$parentId])) {
            $result.Add($child)
            $queue.Enqueue([int]$child.ProcessId)
        }
    }
    return $result
}

function Stop-OwnedProcessTree {
    param([System.Diagnostics.Process]$Root)

    if ($null -eq $Root) { return }
    # Resolve descendants before stopping the root so only this script's tree
    # is addressed. No service, firewall, registry, or security policy command
    # is used here.
    $descendants = @(Get-DescendantProcesses -RootProcessId $Root.Id)
    foreach ($child in @($descendants | Sort-Object { $_.ProcessId } -Descending)) {
        try {
            $process = [System.Diagnostics.Process]::GetProcessById([int]$child.ProcessId)
            if (-not $process.HasExited) {
                $process.Kill($true)
                $process.WaitForExit(5000)
            }
            $process.Dispose()
        } catch [ArgumentException] { }
          catch [System.ComponentModel.Win32Exception] { }
    }

    try {
        if (-not $Root.HasExited) {
            $Root.Kill($true)
            $Root.WaitForExit(5000)
        }
    } catch [InvalidOperationException] { }
      catch [System.ComponentModel.Win32Exception] { }
}

function Wait-ForLocalPipe {
    param(
        [string]$Name,
        [System.Diagnostics.Process]$Service,
        [int]$TimeoutSeconds
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if ($Service.HasExited) {
            throw "Service process exited before its local pipe became ready (code $($Service.ExitCode))."
        }

        $client = [System.IO.Pipes.NamedPipeClientStream]::new(".", $Name, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
        try {
            $client.Connect(250)
            return
        } catch [TimeoutException] {
        } catch [System.IO.IOException] {
        } finally {
            $client.Dispose()
        }
    }
    throw "Timed out after $TimeoutSeconds seconds waiting for local Service pipe '$Name'."
}

try {
    $env:EGRESSGUARD_DATA_DIR = $dataRoot
    $env:EGRESSGUARD_PIPE_NAME = $pipeName
    $serviceArguments = @(
        "run", "--project", $serviceProject, "--configuration", "Release", "--no-launch-profile"
    )
    $service = Start-Process -FilePath $dotnet.Source -ArgumentList $serviceArguments -WorkingDirectory $repoRoot `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput $serviceLog -RedirectStandardError $serviceErrorLog
    $ownedProcesses.Add($service)

    Wait-ForLocalPipe -Name $pipeName -Service $service -TimeoutSeconds $ReadyTimeoutSeconds

    $uiArguments = @(
        "run", "--project", $uiProject, "--configuration", "Release", "--no-launch-profile"
    )
    $ui = Start-Process -FilePath $dotnet.Source -ArgumentList $uiArguments -WorkingDirectory $repoRoot `
        -PassThru -RedirectStandardOutput $uiLog -RedirectStandardError $uiErrorLog
    $ownedProcesses.Add($ui)
    $ui.WaitForExit()
    $exitCode = $ui.ExitCode
} catch {
    Write-Error $_
    $exitCode = 1
} finally {
    foreach ($process in @($ownedProcesses | Select-Object -Reverse)) {
        Stop-OwnedProcessTree -Root $process
        $process.Dispose()
    }
    if ($null -eq $previousDataRoot) { Remove-Item Env:EGRESSGUARD_DATA_DIR -ErrorAction SilentlyContinue }
    else { $env:EGRESSGUARD_DATA_DIR = $previousDataRoot }
    if ($null -eq $previousPipeName) { Remove-Item Env:EGRESSGUARD_PIPE_NAME -ErrorAction SilentlyContinue }
    else { $env:EGRESSGUARD_PIPE_NAME = $previousPipeName }
}

exit $exitCode
