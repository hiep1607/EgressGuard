# Phases 1–3 acceptance report

Date: 2026-08-09. Host: Windows 11 x64. Session administrator: yes.
Tested source baseline: `0c12bbd8fffe13426344d701c665198bf31f4e9a`, followed by the Phase 3.5 changes on `hardening/phase-3-5-acceptance`.
The Phase 3.5 30-minute-soak evidence remains [`docs/evidence/phase-3.5-validation.json`](evidence/phase-3.5-validation.json) and identifies tested commit `c7273caac1106d54d5b327bfde20b13c7c2187f3`. It must not be interpreted as a 30-minute run on the later Phase 3.5.1 source.
Phase 3.5.1 targeted-test, real-firewall-integration and smoke evidence is recorded separately in [`docs/evidence/phase-3.5.1-validation.json`](evidence/phase-3.5.1-validation.json).

Status vocabulary in this report is deliberate: `Verified` means exercised on the current Windows host, `Integration tested` means exercised without the full production boundary, `Not verified` means no real test was performed, and `Blocked` requires owner or administrator action.

| Area | Status | Evidence |
|---|---|---|
| Locked restore | Verified | .NET SDK 8.0.423; locked restore completed. |
| Release build | Verified | 0 warnings, 0 errors. |
| Executable tests | Verified | The complete suite passed 35/35, including the explicit Named Pipe ACL regression, IPC lifecycle, graceful cancellation, process-tree cleanup, complete firewall semantics, exact-rule reconciliation, concurrency and automatic firewall rollback regressions. |
| Format verification | Verified | `dotnet format --verify-no-changes --no-restore` exited 0. |
| Event architecture | Integration tested | Real Named Pipe subscription, reconnect, sequence, bounded overflow/resync and slow-client tests passed. The real-service test now uses a per-run pipe and a subscription acknowledgement instead of a fixed readiness delay. |
| Authenticode behavior | Verified | Embedded-signed .NET host, catalog-signed Windows binary, unsigned apphost, tampered signed file and missing file are covered. |
| Firewall IPv4 and ownership | Verified | Earlier public connect-only acceptance passed; the Phase 3.5 SCM and soak cleanup both found zero owned rules. |
| Automatic firewall persistence rollback | Verified | Tests cover create-success/database-failure rollback, cancellation after create, pre-existing-rule preservation, foreign-rule preservation, and separate logging of original plus rollback failures. |
| Phase 3.5.1 PowerShell cancellation safety | Verified | Deterministic tests cover cancellation before start, cancellation/timeout after start, owned tree termination, unrelated PowerShell preservation, exact-rule reconciliation and concurrent duplicate requests. Real Administrator integration cancelled after a unique rule was created and left zero child processes/rules. |
| Firewall IPv6 | Not verified | The workstation still has no usable IPv6 route for a public block/undo test. |
| Final framework-dependent publish | Verified | Fresh immutable publish under an isolated `%TEMP%` directory; .NET 8 runtime 8.0.29 is installed machine-wide. |
| Final service executable identity | Verified for its recorded checkpoint | `EgressGuard.Service.exe` SHA-256 `2B6D057BD3F189AC6A186CA6B7D2AED759422390ADD6596195CA3D1FC64737F5`; hash was unchanged after its SCM acceptance. This is not the current PR-head artifact. |
| Final managed service identity | Verified for its recorded checkpoint | `EgressGuard.Service.dll` SHA-256 `67503DCCB540CDCEDF7AD7F16551B5F4116A7A491A06212BFDACD78419A8671F`; hash was unchanged after its SCM acceptance. This is not the current PR-head artifact. |
| Application Control execution | Verified | The exact final framework-dependent publish ran interactively and through SCM as `LocalSystem`; no new EgressGuard Code Integrity event was recorded. |
| Production signing/approval | Blocked – requires owner/administrator action | The final executable is `NotSigned`; no eligible code-signing certificate with a private key was present in CurrentUser or LocalMachine stores. No policy bypass or certificate creation was attempted. |
| SCM install/start/recovery | Verified | Service reached `Running`, start type `Automatic`; recovery resets after 86400 seconds and restarts after 5 seconds, then 15 seconds. |
| UI/service independence | Verified | UI reported online; closing UI left the service `Running`. |
| SCM stop/start and UI reconnect | Verified | UI displayed `Service disconnected · reconnecting`, then returned to `Service online · Monitor · dropped 0` and remained responsive. |
| Flow collection after restart | Verified | Safe local traffic produced service status `Active=146`, `Dropped=0` after reconnect. |
| SCM uninstall and cleanup | Verified | Final inspection: zero SCM service, service/UI processes and EgressGuard-owned firewall rules. |
| Reboot acceptance | Verified | The corrected exact artifact from `2cf39c48c57853fedbfede2c9cf82704c5cf9b08` auto-started after reboot, retained all six hashes and completed UI/IPC/Simulator acceptance. The earlier `fbf98b2...` attempt remains recorded as failed. |
| DPI 125% | Verified | All six tabs were selected and visually inspected; maximize/minimize remained responsive. Dashboard and Live Connections rendered many rows including IPv6, Connection Detail rendered a selected row, Rules rendered empty, and a 215-character database path wrapped without overlap. |
| DPI 100% | Verified | At real 96 DPI/100%, all three Live Connections filter ComboBoxes remained readable in normal, dropdown, hover/focus and selected states, with explicit disabled-state colors. Long Authenticode/publisher content wrapped at normal and 900×560 sizes. Alerts, Settings, all six tabs and minimize/restore/maximize showed no regression. |
| DPI 150% | Verified | The primary monitor and rebuilt UI both measured 144 DPI/150%. All six tabs, ComboBox states, long publisher wrapping/tooltip, 900×560 DIP, maximize/minimize/restore and regression surfaces passed after reducing the default window height from 720 to 640 DIP so its title bar remains on-screen. |
| Tray interaction | Verified | The real hidden-icons button exposed exactly one `EgressGuard` icon. Right-click displayed `Open Dashboard`, `Mode: Monitor`, live service status and `Exit UI`; Open Dashboard restored the window, and both Exit UI/window close disposed the icon and process while the service remained Running. |
| Visual contrast regression | Verified | Fixed light-on-light ComboBox text and Alerts DataGrid rows; post-fix screenshots at 125% show readable text and selection surfaces. Screenshots remain temporary and are not committed. |
| Thirty-minute soak | Verified | Fresh isolated run `20260809T141839100Z-a33cfce431bd4ba1bf54c0de7348a8ea`: 585 cycles, 0 failures; 585 normal, burst and beacon runs; 585 IPC checks; 117 service restarts; 195 UI opens and 195 closes. |
| Soak resource/cleanup checks | Verified | Service RAM 55.5 MB initial, 79.1 MB final, 55.5–86.4 MB observed; UI RAM 135.3 MB initial, 157.9 MB final, 134.5–196.3 MB observed. Database exclusive-open check passed; process and firewall inspections succeeded; zero process and rule leftovers. |

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

The hardened harness uses a unique timestamp/GUID run directory and database. Process and owned-firewall-rule queries must both complete with `-ErrorAction Stop`; inspection failure produces a failed run and a null count rather than a misleading zero. Forced process cleanup is restricted to process IDs registered by the current soak run and verifies termination with a second timeout.

An initial hardened 30-minute diagnostic run correctly failed because its ownership set retained historical PIDs that Windows later reused. No EgressGuard process remained. The harness was corrected to remove a PID as soon as the owned process exit is confirmed, a 1-minute 20-cycle regression run passed, and the fresh 30-minute result reported above then passed. The failed diagnostic run is not used as acceptance evidence.

Service and UI processes were deliberately restarted, so initial/final RAM values span different process instances and are not a single-process leak measurement. CPU values in the performance report are normalized by logical processor count and represent active churn workload, not idle CPU.

## Phase 3.5.1 validation

Phase 3.5.1 changes only the PowerShell/firewall mutation runner and the service create/persist transaction path; it does not change the soak harness, sensor, IPC protocol, UI lifecycle or reconnect implementation. The default executable suite passed 32/32. An Administrator-only real firewall integration delayed PowerShell immediately after a uniquely named owned rule was created, cancelled the operation, and verified exact-rule removal, owned child-process cleanup and survival of an unrelated PowerShell process.

A fresh 2-minute smoke run `20260809T153826754Z-44c3679c3f324a6c9a5b528ecf4f05d9` completed 40 traffic/IPC cycles, 8 service restarts, 14 UI opens, 13 scheduled closes and 0 failures. The database lock was released; both strict inspections succeeded with zero EgressGuard process and zero owned firewall rule. A separate post-smoke inspection also found zero SCM service, UI/service process, test-owned PowerShell process and owned rule.

The 30-minute soak was not repeated because neither the soak harness nor lifecycle/reconnect behavior changed. Targeted process-tree tests, the real firewall cancellation integration and the 2-minute lifecycle smoke cover the Phase 3.5.1 risk. The earlier 30-minute evidence remains scoped only to tested commit `c7273caac1106d54d5b327bfde20b13c7c2187f3`.

## Post-merge pre-reboot checkpoint

Source commit `c7689c4ba33dcfb9809163173a7e82a655a8c8ea` was rebuilt on branch `acceptance/post-merge-windows`. Locked restore and format verification passed; the Release build completed with 0 warnings and 0 errors, all 34 executable tests passed, and the vulnerable dependency audit was clean. The 30-minute soak was not repeated.

A fresh framework-dependent service artifact was published to a new isolated runtime directory. `EgressGuard.Service.exe` SHA-256 is `CE8CE2AEB3C67508966B0FA5F0244232FA645D5270C74625E468842CE0DEF8E7`; `EgressGuard.Service.dll` SHA-256 is `E16A797BEB0170C93EEF2C8182435ABE8785A9954AF76FC752EBAFD62A86679E`. Both files are `NotSigned`; read-only inspection found no eligible code-signing certificate with a private key, so production signing remains blocked pending owner/administrator action.

Before the manual reboot, SCM reported the service `Running`, automatic start, `LocalSystem`, the expected artifact path, recovery restarts after 5 and 15 seconds, and failure actions enabled for non-crash failures. The UI connected and displayed `Service online · Monitor · dropped 0`; a graceful UI close left the service running and no UI process. No firewall rule was created for reboot preparation. At that checkpoint, the sanitized continuation state in [`docs/evidence/post-merge-acceptance-state.json`](evidence/post-merge-acceptance-state.json) was `AwaitingManualReboot`, and reboot acceptance correctly remained `NotVerified` until the recorded boot time advanced and the post-boot checklist passed.

## Post-merge reboot acceptance

The recorded Windows boot time advanced to `2026-08-09T16:39:28.5000000Z`. Before any service-control mutation in the post-boot session, `EgressGuard.Service` already existed and was `Running`; start mode remained automatic, account remained `LocalSystem`, failure recovery remained 5/15 seconds, and non-crash failure actions remained enabled. The installed EXE/DLL hashes still matched the pre-reboot checkpoint. No EgressGuard-related Code Integrity event and no SCM 7000/7009 event appeared after boot.

The UI connected without hanging and displayed the service-online state. Its startup successfully read flows, rules and alerts through service IPC, exercising the live database after boot. A bounded Simulator TCP connection to the loopback-only test server appeared through service IPC; both fixtures exited with code 0. Closing the UI left the service running, with zero UI process and zero EgressGuard-owned firewall rule. This reboot evidence is `Verified` only for commit `c7689c4ba33dcfb9809163173a7e82a655a8c8ea` and the associated EXE/DLL hashes recorded in the state file. PR #2 changed service/protocol/UI code after that checkpoint, so its current-head reboot status is `NotVerified`.

## Remaining manual acceptance

The post-reboot system DPI probe reported 120 DPI (125% scale), matching the previously accepted level. This is the original scale that must be restored after the 100% and 150% visual checks. The continuation checkpoint was set to `AwaitingManualDpi100`; no registry or display-setting mutation was performed automatically.

At real 96 DPI/100% scale, UI Automation selected all six tabs and a live connection. The two defects found on the first pass were corrected in XAML: the implicit ComboBox style now supplies readable selected-content/item colors for normal, hover, selected and disabled states, while Connection Detail constrains horizontal layout and wraps the Signature value with a full-value tooltip. Direct retesting showed readable Live Connections filters and complete Authenticode/publisher content at normal and 900×560 sizes. Alerts, Settings, all six tabs and minimize/restore/maximize remained usable. Temporary screenshots were deleted and not committed.

The first post-fix gate exposed an independent flaky test harness issue in `Service pipe reconnect and event subscription`. The test service shared the production pipe name, started event generation after a fixed 500 ms delay without proving subscription readiness, and consumed its bounded event/lifetime budget before readiness on a busy host. The harness now gives every service-test process a unique pipe name, waits for the real subscription acknowledgement, and supports exact-name targeted execution. The targeted lifecycle test passed 5/5 consecutive runs, followed by a 34/34 full suite; locked restore, format verification, Release build with 0 warnings/errors and vulnerable-package audit also passed. Cleanup found no test process, test pipe, temporary service database or EgressGuard-owned firewall rule.

- Previous reboot acceptance: `Verified` for commit `c7689c4...` and its recorded artifact hashes. The real post-merge artifact auto-started and completed the post-boot service/UI/database/Simulator checklist.
- DPI 100%: `Verified`. The Live Connections ComboBox contrast and Connection Detail publisher wrapping fixes passed direct retesting at real 96 DPI/100%.
- DPI 150%: `Verified`. The primary monitor and UI measured 144 DPI; all required layouts and window states passed after the default-height correction.
- Tray icon/context menu: `Verified` through direct hidden-icons, right-click, menu invocation, restore and disposal interaction.
- Corrected final-artifact reboot: `Verified` for product-source commit `2cf39c48c57853fedbfede2c9cf82704c5cf9b08` and its six recorded hashes. Later evidence-only commits do not change that artifact.
- Production signing/organizational approval: `Blocked – requires owner/administrator action`.

## DPI 150% and tray acceptance

The primary monitor and newly launched WPF window both reported 144 DPI/150%. The initial `1180×720` DIP normal window occupied 1770×1080 physical pixels and was centered at Y=-36, placing its entire title bar above the screen. The only source correction in this checkpoint changes the default height to 640 DIP while retaining the 900×560 DIP minimum. The rebuilt window then opened at 1770×960 physical pixels with Y=24 and a fully accessible title bar.

Dashboard, Live Connections, Connection Detail, Alerts, Rules and Settings were selected directly. The three Live Connections filters remained readable in selected, dropdown and hover/focus states; no safe disabled transition exists in the running UI, but the explicit disabled palette remains in the accepted style. A real RiotClientServices connection supplied a 239-character Authenticode/publisher value that wrapped without horizontal overflow at normal, maximized and 900×560 DIP sizes; its tooltip exposed the complete value. Alerts retained readable contrast, Rules rendered its empty state and Settings remained legible. Minimize, maximize and restore completed without hangs.

Windows hidden icons exposed one `EgressGuard` button. Direct right-click produced `Open Dashboard`, disabled `Mode: Monitor`, disabled `Service online · Monitor · dropped 0`, and `Exit UI`. Open Dashboard restored the minimized window. Exit UI and a separate window-close cycle each terminated the UI, removed the tray icon, left no orphan UI process and left `EgressGuard.Service` Running. No firewall rule was created. Temporary QA screenshots were deleted and are not acceptance artifacts.

## Final-artifact reboot failure and IPC ACL correction

The first final-artifact reboot attempt used commit `fbf98b23a999952c689fc3357b1cce97c2d54068`. Windows boot time advanced from `2026-08-09T16:39:28.5000000Z` to `2026-08-10T05:12:24.5000000Z`, and before any service-control mutation the exact artifact had auto-started as `LocalSystem`. Its six recorded hashes, automatic start, 5/15-second recovery configuration and image path all matched. No EgressGuard Code Integrity event, SCM 7000/7009 event or owned firewall rule appeared after boot.

Functional acceptance failed because both UI and CLI received `UnauthorizedAccessException` while connecting to `EgressGuard.Service.v1`. The service created its named pipe with the creator's default DACL, which did not provide an explicit cross-session rule for the interactive client after boot. That artifact's reboot status is `Failed` and it must not be accepted or relabeled with new hashes.

The correction creates a protected pipe DACL with FullControl for the service identity, `LocalSystem` and `Administrators`, plus ReadWrite for the Windows `INTERACTIVE` SID. It does not grant `Everyone` or `Authenticated Users`; mutating requests still require the existing administrator impersonation check. A new ACL regression test verifies the exact identities and rights. Locked restore, format verification, a zero-warning Release build, all 35 executable tests and vulnerable-package audit passed. A validation publish installed as `LocalSystem`; CLI status/flows and the framework-dependent UI then connected successfully at 120 DPI, and closing UI left the service Running. This is pre-reboot validation only and does not restore reboot acceptance.

The corrected final artifact was then rebuilt from exact commit `2cf39c48c57853fedbfede2c9cf82704c5cf9b08` and installed from a stable non-temporary directory. Windows boot time advanced from `2026-08-10T05:12:24.5000000Z` to `2026-08-10T09:40:30.5000000Z`. Before any service-control mutation, SCM reported the service already `Running`, `Automatic` and `LocalSystem`; its image path, six hashes, 5/15-second recovery actions, 86400-second reset period and non-crash failure flag all matched. No related Code Integrity event, SCM 7000/7009 event or owned firewall rule appeared after boot.

At 120 DPI/125%, the UI connected without hanging and displayed `Service online · Monitor · dropped 0`. Dashboard, Live Connections, Rules and Alerts were selected directly; minimize and restore returned `Minimized` and `Normal`. A bounded Simulator connection to the loopback Test Server on port 54325 appeared through service IPC. Closing UI left the service Running, with zero UI/test process and zero owned firewall rule. Current-head reboot acceptance is therefore `Verified` for the exact `2cf39c4...` artifact and recorded hashes. Any following documentation-only commit does not alter the tested product source or artifact.

## Decision

Phases 1–3 now have verified DPI 100%, DPI 150%, direct tray interaction, soak evidence and corrected final-artifact reboot acceptance. The failed `fbf98b2...` artifact remains explicitly rejected; the accepted artifact is tied to exact source commit `2cf39c4...` and its recorded hashes. The checkpoint is `ReadyForIndependentReview`. **Do not begin Phase 4/ETW or merge Draft PR #2 before independent review.** Production signing/Application Control approval remains blocked and must be resolved before any release claim.
