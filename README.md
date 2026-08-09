# EgressGuard

EgressGuard is a Windows, local-first outbound connection monitor. It maps TCP/UDP endpoints to process identity, stores local history in SQLite, assesses explainable risk, and manages only firewall rules carrying the EgressGuard ownership marker.

The repository implements Phases 0–3. It does **not** include ETW file correlation, packet payload capture, TLS interception, a driver, cloud telemetry, process killing, or malware execution.

## Components

```text
src/
├─ EgressGuard.Core/         domain model, baseline, risk and policy
├─ EgressGuard.Windows/      IP Helper, process, Authenticode and firewall adapters
├─ EgressGuard.Persistence/  SQLite schema and repositories
├─ EgressGuard.Protocol/     framed Named Pipe request and event clients
├─ EgressGuard.Service/      sensor, bounded queues, event fan-out and IPC
├─ EgressGuard.UI/           WPF dashboard, live/detail/alerts/rules/settings and tray
└─ EgressGuard.Cli/          diagnostics and service commands
```

## Build and test

Windows 11 x64 and the .NET 8 SDK are required.

```powershell
dotnet build EgressGuard.sln -c Release
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build
dotnet format EgressGuard.sln --verify-no-changes --no-restore
```

## Development run

```powershell
$env:EGRESSGUARD_DATA_DIR = Join-Path $env:LOCALAPPDATA 'EgressGuard-Dev'
.\src\EgressGuard.Service\bin\Release\net8.0-windows\EgressGuard.Service.exe
.\src\EgressGuard.UI\bin\Release\net8.0-windows\EgressGuard.UI.exe
```

Closing the UI releases its request pipe, event pipe, timer and cancellation source. It does not stop the service. The tray provides Open Dashboard, current protection/service state, and Exit UI.

## Safe synthetic traffic

```powershell
.\tools\EgressGuard.TestServer\bin\Release\net8.0-windows\EgressGuard.TestServer.exe --protocol both --port 5050
.\tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.exe --protocol tcp --port 5050 --mode small --bytes 5120 --hold-seconds 5
```

For a harmless public enforcement probe with no payload:

```powershell
.\EgressGuard.Simulator.exe --host 1.1.1.1 --port 443 --connect-only --hold-seconds 0
```

## Windows Service

Administrator PowerShell:

```powershell
dotnet publish .\src\EgressGuard.Service\EgressGuard.Service.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
.\tools\install-service.ps1 -PublishedDirectory .\src\EgressGuard.Service\bin\Release\net8.0-windows\win-x64\publish
sc.exe qfailure EgressGuard.Service
.\tools\uninstall-service.ps1
```

Framework-dependent deployment requires a machine-wide .NET 8 runtime visible to LocalSystem. The installer now rolls back the SCM entry if configuration or start fails. This workstation had no registered runtime; a self-contained acceptance build initially ran, while a later rebuilt unsigned service was blocked by the workstation's Application Control policy. See [acceptance-report.md](docs/acceptance-report.md).

## Firewall acceptance

The service and calling client must both have the required administrator context. The script uses a public TCP connect-only probe, always resets owned rules in `finally`, and never changes a firewall profile.

```powershell
.\tools\test-firewall.ps1 `
  -SimulatorPath 'D:\path with spaces\EgressGuard.Simulator.exe' `
  -AlternateSimulatorPath 'D:\other path\EgressGuard.Simulator.exe'
```

Rules are path-bound by Windows Firewall. EgressGuard verifies SHA-256 immediately before creation and policy matching includes path plus hash, but Windows Firewall cannot keep enforcing the hash after the file is replaced. Refresh identity and recreate the rule after executable changes.

## Reports

- [Architecture](docs/architecture.md)
- [Testing](docs/testing.md)
- [Privacy](docs/privacy.md)
- [Acceptance](docs/acceptance-report.md)
- [Performance](docs/performance-report.md)
- [Administrator checklist](docs/windows-admin-checklist.md)

Phase 4/ETW is intentionally not implemented. The final SCM restart and soak gates remain open, so the project is not yet declared ready for Phase 4.
