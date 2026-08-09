# Development environment

## Current baseline

- Windows 11 x64
- Git for Windows and GitHub CLI
- .NET 8 SDK selected by `global.json`
- PowerShell 7
- VS Code with official C# Dev Kit and GitHub Actions extensions
- Project-local `dotnet-counters` and `dotnet-trace` restored from `.config/dotnet-tools.json`

Use project-local tools instead of global installations:

```powershell
dotnet tool restore
dotnet tool run dotnet-counters -- --help
dotnet tool run dotnet-trace -- --help
```

## Deferred tooling

Do not install these for current user-mode Phases 1–3 work:

- Windows Driver Kit: only when an approved driver phase has architecture, signing and VM test plans.
- Additional Windows SDK/native WFP components: only when native WFP development is explicitly approved.
- Sysinternals Suite: useful for a dedicated operational-diagnostics exercise; not required to build.
- Windows Performance Recorder/Analyzer: add when short process-counter profiling cannot explain a measured regression.
- Wireshark/Npcap: add only for an approved packet-analysis task with privacy controls; never required by current tests.
- Driver Verifier tooling: only inside a disposable driver-test VM.
- Dedicated Windows VM: mandatory before experimental driver/kernel work or destructive security-policy testing.

## Workflow

Keep `main` buildable. Use `feature/`, `fix/`, or `agent/` branches and pull requests for material changes. Run locked restore, build, tests and format before review. Do not install or test experimental drivers on the primary workstation.
