# Phases 1–3 acceptance report

Date: 2026-08-09. Host: Windows 11 x64. Session administrator: yes.
Tested source baseline: `0c12bbd8fffe13426344d701c665198bf31f4e9a`, followed by the Phase 3.5 changes on `hardening/phase-3-5-acceptance`.

Status vocabulary in this report is deliberate: `Verified` means exercised on the current Windows host, `Integration tested` means exercised without the full production boundary, `Not verified` means no real test was performed, and `Blocked` requires owner or administrator action.

| Area | Status | Evidence |
|---|---|---|
| Locked restore | Verified | .NET SDK 8.0.423; locked restore completed. |
| Release build | Verified | 0 warnings, 0 errors. |
| Executable tests | Verified | 23/23 passed. |
| Format verification | Verified | `dotnet format --verify-no-changes --no-restore` exited 0. |
| Event architecture | Integration tested | Real Named Pipe subscription, reconnect, sequence, bounded overflow/resync and slow-client tests passed. |
| Authenticode behavior | Verified | Embedded-signed .NET host, catalog-signed Windows binary, unsigned apphost, tampered signed file and missing file are covered. |
| Firewall IPv4 and ownership | Verified | Earlier public connect-only acceptance passed; the Phase 3.5 SCM and soak cleanup both found zero owned rules. |
| Firewall IPv6 | Not verified | The workstation still has no usable IPv6 route for a public block/undo test. |
| Final framework-dependent publish | Verified | Immutable publish under `%TEMP%\EgressGuard-Phase35-final1\service`; .NET 8 runtime 8.0.29 is installed machine-wide. |
| Final service executable identity | Verified | `EgressGuard.Service.exe` SHA-256 `0B48EFFA32B593AE4402590097D317CE02ECC864FD8865DA61137DB3613FA558`; hash was unchanged after SCM acceptance. |
| Final managed service identity | Verified | `EgressGuard.Service.dll` SHA-256 `76EB90545497985DE98682DB389E4A9C930E343587E9F6C6D776A8F2AAE1AECB`; hash was unchanged after SCM acceptance. |
| Application Control execution | Verified | The exact final framework-dependent publish ran interactively and through SCM as `LocalSystem`; no new EgressGuard Code Integrity event was recorded. |
| Production signing/approval | Blocked – requires owner/administrator action | The final executable is `NotSigned`; no eligible code-signing certificate with a private key was present in CurrentUser or LocalMachine stores. No policy bypass or certificate creation was attempted. |
| SCM install/start/recovery | Verified | Service reached `Running`, start type `Automatic`; recovery resets after 86400 seconds and restarts after 5 seconds, then 15 seconds. |
| UI/service independence | Verified | UI reported online; closing UI left the service `Running`. |
| SCM stop/start and UI reconnect | Verified | UI displayed `Service disconnected · reconnecting`, then returned to `Service online · Monitor · dropped 0` and remained responsive. |
| Flow collection after restart | Verified | Safe local traffic produced service status `Active=146`, `Dropped=0` after reconnect. |
| SCM uninstall and cleanup | Verified | Final inspection: zero SCM service, service/UI processes and EgressGuard-owned firewall rules. |
| Reboot acceptance | Not verified | No reboot was authorized or performed. |
| DPI 125% | Verified | All six tabs were selected and visually inspected; maximize/minimize remained responsive. Dashboard and Live Connections rendered many rows including IPv6, Connection Detail rendered a selected row, Rules rendered empty, and a 215-character database path wrapped without overlap. |
| DPI 100% and 150% | Not verified | The active display was 120 DPI (125%). Display scaling was not changed because a real scale change can disrupt the user session and was not separately authorized. |
| Tray interaction | Not verified | The real `NotifyIcon` construction/disposal path ran during UI open/close cycles, but the shell icon and context menu were not independently discoverable through UI Automation. |
| Visual contrast regression | Verified | Fixed light-on-light ComboBox text and Alerts DataGrid rows; post-fix screenshots at 125% show readable text and selection surfaces. Screenshots remain temporary and are not committed. |
| Thirty-minute soak | Verified | 595 cycles, 0 failures; 595 normal, burst and beacon runs; 595 IPC checks; 119 service restarts; 199 UI opens and 198 scheduled closes. |
| Soak resource/cleanup checks | Verified | Service RAM 56.4 MB initial, 78.9 MB final, 56.2–82.1 MB observed; UI RAM 134.8 MB initial, 154.4 MB final, 134.6–189.1 MB observed. Database exclusive-open check passed after shutdown; zero process and rule leftovers. |

## SCM and Application Control notes

The accepted service was the framework-dependent publish, not a substituted binary. Event 7045 recorded installation as an auto-start user-mode service under `LocalSystem`. The final executable and managed DLL hashes were checked before and after the lifecycle.

Two self-contained preparation attempts were not accepted as final artifacts. `publish --no-restore -r win-x64` first reported `NETSDK1047`; RID-specific locked restore then reported `NU1004` because the existing lock files do not declare `win-x64`. The valid framework-dependent route was used instead because .NET 8 is machine-wide. No lock file was weakened or regenerated outside locked mode.

The first final SCM automation attempt was rejected by the PowerShell parser before changing state. A second helper attempt installed and started the service but failed in UI text collection; its `finally` cleanup removed the service and left zero processes/rules. The corrected full rerun produced the verified results above.

Production signing remains blocked even though the current host permits this framework-dependent publish. The owner must provide an organization-approved certificate/signing service or an explicit Application Control approval process. After approval, rerun:

```powershell
Get-AuthenticodeSignature <final-publish>\EgressGuard.Service.exe
Get-FileHash -Algorithm SHA256 <final-publish>\EgressGuard.Service.exe
.\tools\install-service.ps1 -PublishedDirectory <final-publish>
sc.exe qfailure EgressGuard.Service
.\tools\uninstall-service.ps1
```

## Soak interpretation

The 30-minute run completed with exit code 0. It exercised normal, burst and beacon traffic, UI open/close, status IPC and process-level service restart/reconnect. Automated tests separately cover database contention and event sequence/gap/overflow/resync semantics. The soak verified that the database lock was released after shutdown; it did not inject a live SQLite lock or a forced event-sequence gap during the 30-minute run.

Service and UI processes were deliberately restarted, so initial/final RAM values span different process instances and are not a single-process leak measurement. CPU values in the performance report are normalized by logical processor count and represent active churn workload, not idle CPU.

## Remaining manual acceptance

- Reboot acceptance: `Not verified`. Follow `docs/windows-admin-checklist.md`; do not reboot automatically.
- DPI 100% and 150%: `Not verified`. Set each real display scale, sign out/restart applications if Windows requests it, and repeat the six-tab, tray, long-path, IPv6, empty-state and resize checks.
- Tray icon/context menu: `Not verified` for direct user interaction.
- Production signing/organizational approval: `Blocked – requires owner/administrator action`.

## Decision

Phases 1–3 now have verified final SCM lifecycle and a verified 30-minute soak, but Phase 3.5 is not fully closed. **Do not begin Phase 4/ETW yet.** Real reboot acceptance, DPI 100% and 150% visual QA, and direct tray interaction remain open. Production signing/approval must also be resolved before any release claim.
