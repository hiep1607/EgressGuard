# Phases 1–3 acceptance report

Date: 2026-08-09. Host: Windows 11 x64. Session administrator: yes.

| Area | Status | Evidence |
|---|---|---|
| Git checkpoint | Verified on Windows | Local commit `f773eb3 checkpoint: phases 1-3 implementation`; no remote/push. |
| Release build | Verified on Windows | 0 warnings, 0 errors after hardening. |
| Event architecture | Integration tested | Real Named Pipe subscription, reconnect, sequence, bounded overflow/resync and slow-client tests. |
| Authenticode | Unit tested / Verified on Windows | Embedded-signed .NET host, catalog-signed `cmd.exe`, unsigned apphost, tampered signed file and missing file. |
| Firewall IPv4 | Verified on Windows | `1.1.1.1:443` connect-only: exit 0 before, exit 2 during block, exit 0 after undo. |
| Firewall isolation | Verified on Windows | Same filename at another path exit 0; Chrome public 443/5228 connections remained established. |
| Firewall cleanup | Verified on Windows | Duplicate produced one rule; external deletion and repeated reset left 0 rules. |
| Firewall IPv6 | Not verified | Both blocked and alternate binaries reported no route. |
| Hash replacement | Unit tested / platform limitation | Pre-create mismatch is rejected; Windows Firewall remains path-based after creation. |
| Crash exactly between firewall and DB commit | Not verified | Exception rollback is implemented; process-kill timing was not injected. |
| SCM framework-dependent publish | Failed (environment) | Publish succeeded; start failed because LocalSystem could not find a registered .NET 8 runtime. |
| SCM self-contained initial run | Verified on Windows | Install/start/recovery/status/UI connection/UI-close independence/flow capture/uninstall succeeded. |
| SCM final rebuilt binary | Failed (environment policy) | SCM event 7000: Application Control policy blocked the unsigned rebuilt executable; installer removed the failed SCM entry. |
| Visual QA | Integration tested | Six tabs captured through UI Automation; 641-row burst, empty Rules, long database path and IPv6 rows inspected. |
| CPU target | Verified on Windows | UI idle 0.017%, normal 0.043%, burst 0.054%, minimized 0.026% average. |
| Soak | Integration tested | 2 minutes, 40 normal/burst/beacon/UI/IPC cycles, 0 failures; service RAM 56.2–78.0 MB. |

## Firewall acceptance details

- Exact target: a self-contained `EgressGuard.Simulator.exe` under a path containing spaces.
- Rule: outbound Block, profile Any, exact program path, EgressGuard prefix and ownership description.
- No firewall profile/default was changed and Windows Defender Firewall was not disabled.
- Public probe sent no bytes. Localhost was not the sole evidence.
- UI/service/Test Server were unaffected outside the expected Simulator process path.

## SCM cleanup result

After each failed install, `install-service.ps1` deleted the partial service. Final inspection found no `EgressGuard.Service` SCM entry and no owned firewall rule. Application Control settings were not modified.

## Decision

Phases 1–3 are materially hardened but **not fully accepted**. Do not begin Phase 4/ETW until the final service binary is allowed through the organization's signing/Application Control process, stop/restart/reconnect is rerun, and forced multi-DPI QA passes. A short soak passed; a longer pre-release soak is still recommended.
