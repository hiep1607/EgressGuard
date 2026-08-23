[CmdletBinding()]
param(
    [int]$ReadyTimeoutSeconds = 20
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$solution = Join-Path $repoRoot "EgressGuard.sln"
$serviceProject = Join-Path $repoRoot "src\EgressGuard.Service\EgressGuard.Service.csproj"
$uiProject = Join-Path $repoRoot "src\EgressGuard.UI\EgressGuard.UI.csproj"
$serviceDll = Join-Path $repoRoot "src\EgressGuard.Service\bin\Release\net8.0-windows\EgressGuard.Service.dll"
$uiDll = Join-Path $repoRoot "src\EgressGuard.UI\bin\Release\net8.0-windows\EgressGuard.UI.dll"
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue

if ($null -eq $dotnet) {
    throw "dotnet was not found on PATH. Install the required .NET SDK first."
}

foreach ($project in @($solution, $serviceProject, $uiProject)) {
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
        throw "Required project was not found: $project"
    }
}

if ($ReadyTimeoutSeconds -lt 1 -or $ReadyTimeoutSeconds -gt 300) {
    throw "ReadyTimeoutSeconds must be between 1 and 300 seconds."
}

& $dotnet.Source build $solution --configuration Release --nologo -nodeReuse:false -p:UseSharedCompilation=false
$buildExitCode = $LASTEXITCODE
if ($buildExitCode -ne 0) {
    throw "Local Release build failed with exit code $buildExitCode."
}

foreach ($applicationDll in @($serviceDll, $uiDll)) {
    if (-not (Test-Path -LiteralPath $applicationDll -PathType Leaf)) {
        throw "Required build output was not found: $applicationDll"
    }
}

$dataRoot = Join-Path $repoRoot ".local\egressguard-$PID"
$null = New-Item -ItemType Directory -Path $dataRoot -Force
$pipeName = "EgressGuard.Local.$PID"
$ownedProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$exitCode = 0
$previousDataRoot = [Environment]::GetEnvironmentVariable("EGRESSGUARD_DATA_DIR", "Process")
$previousPipeName = [Environment]::GetEnvironmentVariable("EGRESSGUARD_PIPE_NAME", "Process")

function Stop-OwnedProcess {
    param([System.Diagnostics.Process]$Root)

    if ($null -eq $Root) { return }
    try {
        if ($Root.HasExited) { return }
        $Root.Kill()
        if (-not $Root.WaitForExit(5000)) {
            Write-Warning "Timed out waiting for owned process $($Root.Id) to exit."
        }
    } catch [InvalidOperationException] { }
      catch [System.ComponentModel.Win32Exception] { }
      finally { $Root.Dispose() }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    # Start-Process in Windows PowerShell 5.1 joins ArgumentList arrays into
    # one string. Build the command line explicitly so --project receives one
    # quoted argument even when the repository path contains spaces. Double
    # backslashes before a closing quote and escape embedded quotes according
    # to the Windows command-line parsing rules.
    $escaped = $Value -replace '(\\*)"', '$1$1\\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
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
    $serviceArguments = Quote-ProcessArgument $serviceDll
    $service = Start-Process -FilePath $dotnet.Source -ArgumentList $serviceArguments -WorkingDirectory $repoRoot `
        -WindowStyle Hidden -PassThru
    $ownedProcesses.Add($service)

    Wait-ForLocalPipe -Name $pipeName -Service $service -TimeoutSeconds $ReadyTimeoutSeconds

    $uiArguments = Quote-ProcessArgument $uiDll
    $ui = Start-Process -FilePath $dotnet.Source -ArgumentList $uiArguments -WorkingDirectory $repoRoot `
        -PassThru
    $ownedProcesses.Add($ui)
    $ui.WaitForExit()
    $exitCode = $ui.ExitCode
    if ($exitCode -ne 0) {
        throw "UI process exited with code $exitCode."
    }
} catch {
    Write-Error $_
    $exitCode = 1
} finally {
    for ($index = $ownedProcesses.Count - 1; $index -ge 0; $index--) {
        Stop-OwnedProcess -Root $ownedProcesses[$index]
    }
    if ($null -eq $previousDataRoot) { Remove-Item Env:EGRESSGUARD_DATA_DIR -ErrorAction SilentlyContinue }
    else { $env:EGRESSGUARD_DATA_DIR = $previousDataRoot }
    if ($null -eq $previousPipeName) { Remove-Item Env:EGRESSGUARD_PIPE_NAME -ErrorAction SilentlyContinue }
    else { $env:EGRESSGUARD_PIPE_NAME = $previousPipeName }
}

exit $exitCode
