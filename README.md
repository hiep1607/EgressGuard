# EgressGuard

> Development prototype. Do not deploy on production systems in its current state.

EgressGuard is a Windows, local-first outbound connection monitor. It maps TCP/UDP endpoints to process identity, stores local history in SQLite, evaluates explainable risk, and manages only Windows Firewall rules carrying the EgressGuard ownership marker.

EgressGuard does **not** claim to prevent 100% of data exfiltration. The current prototype has no ETW file correlation, packet payload capture, TLS interception, driver, cloud telemetry, process killing, or malware execution. See the [threat model](docs/threat-model.md) and [acceptance report](docs/acceptance-report.md) before evaluating its security properties.

## Architecture

```text
Windows IP Helper + process metadata
  → Service sensor / risk / policy
  ├─→ SQLite persistence
  └─→ bounded sequenced Named Pipe events
       → WPF UI batched incremental updates
```

Projects live under `src/`; safe traffic generators and bounded acceptance scripts live under `tools/`. Details are in [architecture.md](docs/architecture.md).

## Requirements

- Windows 11 x64
- .NET 8 SDK
- Administrator PowerShell only for explicitly documented firewall or SCM acceptance

Never disable Windows Defender Firewall or use a blanket outbound block for development tests.

## Build, test, and format

```powershell
dotnet tool restore
dotnet restore --locked-mode
dotnet build EgressGuard.sln -c Release --no-restore
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build
dotnet format EgressGuard.sln --verify-no-changes --no-restore
```

The test project uses a custom executable runner, not `dotnet test`.

## Run locally

Terminal 1:

```powershell
$env:EGRESSGUARD_DATA_DIR = Join-Path $env:LOCALAPPDATA 'EgressGuard-Dev'
dotnet run --project src\EgressGuard.Service\EgressGuard.Service.csproj -c Release
```

Terminal 2:

```powershell
dotnet run --project src\EgressGuard.UI\EgressGuard.UI.csproj -c Release
```

Safe local traffic:

```powershell
dotnet run --project tools\EgressGuard.TestServer\EgressGuard.TestServer.csproj -c Release -- --protocol both --port 5050
dotnet run --project tools\EgressGuard.Simulator\EgressGuard.Simulator.csproj -c Release -- --protocol tcp --port 5050 --mode small --bytes 5120 --hold-seconds 5
```

Closing the UI does not stop the service. The Simulator generates bytes in memory and never reads user documents or credentials.

## Administrator operations

Service installation and real firewall acceptance are separate, opt-in Administrator tasks:

- [Windows administrator checklist](docs/windows-admin-checklist.md)
- [Testing guide](docs/testing.md)

Every firewall test must have cleanup. The Phase 3.5 framework-dependent service publish ran through SCM on the acceptance workstation, but it remains unsigned and is not a production-approved artifact. Never bypass Windows Application Control policy.

Firewall PowerShell mutations have finite timeouts and owned process-tree cleanup. An interrupted create is reconciled against the exact rule identity and ownership marker before cancellation is returned to the caller.

The soak harness creates an isolated run/database directory for every invocation and treats a failed process or firewall cleanup inspection as a test failure. Sanitized, reviewable evidence is published separately for [Phase 3.5](docs/evidence/phase-3.5-validation.json) and [Phase 3.5.1](docs/evidence/phase-3.5.1-validation.json); runtime artifacts remain ignored.

## Current limitations

- Phases 1–3 have verified final SCM restart/reconnect and a 30-minute soak. Real reboot acceptance, DPI 100%/150% QA, direct tray interaction and production signing/approval remain open; do not begin Phase 4/ETW yet.
- Windows Firewall enforcement is path-based; EgressGuard verifies SHA-256 before rule creation and in policy matching, but executable replacement requires identity refresh and rule recreation.
- UDP owner tables do not expose a remote peer.
- No release, installer, signing pipeline, or production support commitment exists yet.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Privacy](docs/privacy.md)
- [Testing](docs/testing.md)
- [Development environment](docs/development-environment.md)
- [Release process](docs/release-process.md)
- [Acceptance](docs/acceptance-report.md)
- [Performance](docs/performance-report.md)

License status: [no license selected; all rights reserved](LICENSE-DECISION.md).
