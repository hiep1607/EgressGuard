# Testing

## One-command validation

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\Validate-EgressGuard.ps1 -RequireClean
```

`tools/Validate-EgressGuard.ps1` is the single entry point used locally and by CI. It runs, in order: `dotnet tool restore`, locked solution restore, format verification (never rewrites files), Release build, the executable test suite, the vulnerable-package audit and `git diff --check`; it then displays `git status --short`, validates `AGENT_HANDOFF.md` against its size/line/session limits and common secret patterns, and finally enforces `-RequireClean`. It stops at the first failing step and exits with that step's exit code. The script locates the repository root from its own location, needs no administrator rights, changes no firewall/Defender/registry/service state, writes nothing into the repository, avoids `Invoke-Expression`, and never prints matched secret values.

`-RequireClean` fails the run when tracked files change during validation; gitignored build output does not count. CI always passes this switch.

This command does not replace the opt-in Administrator Windows integration scenarios described below; those still require elevation and separate execution.

CI (`.github/workflows/ci.yml`) invokes this script for pushes to `main` and for **every** pull request regardless of base branch, so stacked feature-branch PRs are checked too. A concurrency group cancels superseded runs of the same pull request. Existing pull requests only pick up this configuration once their branch contains the workflow change or their base branch includes it, because `pull_request` workflows resolve from the merge ref. Do not claim a green CI result for any configuration until a real run of it completes successfully.

## Commands

```powershell
dotnet build EgressGuard.sln -c Release
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --test "Service pipe reconnect and event subscription"
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --firewall-cancellation-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --etw-file-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --etw-orphan-reclaim-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --etw-lifecycle-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --etw-lifecycle-smoke
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --file-correlation-service-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --raw-buffer-benchmark
dotnet format EgressGuard.sln --verify-no-changes --no-restore
.\tools\run-performance-test.ps1 -UiProcessId <pid> -ServiceProcessId <pid> -DurationSeconds 30
.\tools\run-soak-test.ps1 -DurationMinutes 30
```

The custom runner is retained: it has deterministic Windows integration setup and returns a CI-compatible exit code. `--test <exact-test-name>` runs one default-suite test for targeted regression loops. Migrating frameworks would not currently add enough isolation to justify the rewrite.

## Automated coverage

The 62-test default suite retains all prior regressions and adds file-correlation coverage for exact process identity/window matching, normalized system-root boundary filtering without user-path false positives, read-only admission before a network identity exists, hard-bounded/expiring ETW callback coalescing, newest-signal raw dedupe, real pre-flow promotion through the sensor interest path, retention and per-process/global raw-buffer bounds, out-of-order expiration under dual indexes, sensor-side PID-reuse generation rejection, a hard-bounded/TTL process-interest cache, exact-identity indexed pending promotion with deterministic structural work counters and orphan-free global eviction, promoted-event correlation cleanup through a bounded timestamp index, out-of-order delivery, hard-bounded dedupe and safe eviction, multiple files/flows, evidence caps, coalesced final dropped-count publication, exact ETW ownership, 10-cycle ETW lifecycle cleanup with a cancellation race, retention, self-storage exclusion, disabled/AccessDenied lifecycle safety, complete multi-flow SQLite batches, live UI refresh cancellation/throttling, configured-pipe request/event handshakes, schema v3/Clear history, and bounded backward-compatible IPC. The ACL regression still combines every explicit allow rule for the `INTERACTIVE` SID and requires exactly `ReadWrite | Synchronize`, rejecting any additional ownership, permission-changing, deletion, instance-creation or system-security rights.

The real ETW/service commands are opt-in and require Administrator. The first observes a synthetic file. The orphan test kills a child controller and proves exact protected-marker reclaim. The full lifecycle test performs 10 exact start/stop cycles, including a cancellation race; `--etw-lifecycle-smoke` provides a bounded three-cycle post-change check without replacing the 10-cycle acceptance evidence. Both verify each cycle has removed its exact session and marker before the next begins. The service test creates a loopback Simulator flow, proves the `.egfixture` read happened before that flow, reads correlations over IPC, verifies the server received zero bytes and SQLite contains no raw fixture path, then requires normal service exit to leave zero exact session/marker before recovery. Failure-path recovery still uses only the validated exact marker and cannot change a recorded failure into a pass. Default CI uses fakes and never changes system auditing or policy.

The real-service IPC test assigns a unique Named Pipe name to each service process through `EGRESSGUARD_PIPE_NAME`, passes that name explicitly to its clients, and waits for the server's subscription acknowledgement before creating the controlled TCP flow. Default UI request/event clients now resolve the same override, covered by real Named Pipe handshake/subscription regression; the production pipe remains `EgressGuard.Service.v1` when no override is supplied.

The complete-semantics tests execute the production PowerShell exact-rule predicate against mocked NetSecurity cmdlets. One verifies a full match, including case-insensitive values and numeric TCP normalization; the table-driven mismatch test changes remote address, remote port, protocol and enabled state independently and verifies no create, reconciliation delete or database save occurs.

The firewall cancellation integration command is intentionally opt-in and requires an Administrator token. It uses a unique rule ID and the test executable, delays the owned PowerShell immediately after `New-NetFirewallRule`, cancels, and verifies exact-rule reconciliation, zero owned child processes/rules, and survival of an unrelated PowerShell process. Cleanup runs in `finally`; CI runs only the non-mutating default suite.

Access-denied Authenticode is not automated because a reliable fixture requires ACL mutation and can produce machine-specific behavior. The verifier maps access/I/O failures to `VerificationUnavailable`.

## Windows integration evidence

- Public IPv4 connect-only probe to `1.1.1.1:443`: success before block, socket access denied while blocked, success after undo.
- Same-name binary at a different path remained connected.
- Duplicate request left exactly one owned rule.
- Chrome retained established public TCP connections while the Simulator rule was active.
- External rule deletion followed by two resets was idempotent; zero owned rules remained.
- Phase 3.5.1 real cancellation integration created a uniquely named owned test rule, cancelled while its PowerShell was delayed after creation, reconciled and removed that exact rule, left an unrelated PowerShell running, and finished with zero owned child processes or firewall rules.
- IPv6 was not verifiable because the workstation had no IPv6 route.
- UI Automation at the host's real 125% scale selected and rendered Dashboard, Live Connections, Connection Detail, Alerts, Rules and Settings. Multi-row and IPv6 data, empty Rules, a selected connection, a 215-character database path, minimize and maximize were exercised. ComboBox and Alerts DataGrid contrast defects found during Phase 3.5 QA were fixed and visually rechecked.
- Focused Phase 4 visual QA used isolated development service/UI instances at real 100% (96 DPI) and 150% (144 DPI), then restored the host to 125% (120 DPI). The service stayed `Running` with `FileSensor=Running` and `dropped 0`; protected/redacted correlation items rendered, the full protected-file hash tooltip was observed at both test scales, the 100% window resized to 900×560 with vertical-only scrolling, and the 150% layout remained readable. The loopback fixture test server recorded zero transmitted bytes. No installed service or registry setting was changed.
- True subscription was exercised over the real service pipe and preserved sequence order.
- The bounded soak ran 2 minutes/40 cycles with normal, burst, beacon, UI open/close and IPC checks: 0 failures; service RAM 56.2–78.0 MB.
- The fresh Phase 3.5 soak ran 30 minutes/585 cycles with 0 failures, 117 service restarts, 195 UI opens/closes and 585 IPC checks. Service RAM remained within 55.5–86.4 MB and UI RAM within 134.5–196.3 MB across deliberately restarted process instances. The database lock was released; both cleanup inspections succeeded and found zero process or owned firewall rule.

- Phase 3.5.1 ran the 32/32 default suite plus the opt-in real firewall cancellation integration. Its fresh 2-minute smoke completed 40 traffic/IPC cycles, 8 service restarts and 0 failures; database lock release and both strict cleanup inspections passed with zero EgressGuard process, test-owned PowerShell process or owned firewall rule. The prior 30-minute soak was not relabeled or reused as Phase 3.5.1 evidence.

## Phase 3.5 limitations

- DPI 100% and 150% are now verified by the focused Phase 4 acceptance; the host was restored to 125% afterward without reboot.
- Direct tray icon/context-menu interaction was verified in the final-artifact acceptance; the real `NotifyIcon` lifecycle also executed during UI open/close testing.
- No additional reboot was performed for this focused Phase 4 visual check; the prior reboot acceptance remains recorded separately as verified.
- The 30-minute soak checked IPC reconnect and database lock release. Database contention and event sequence/gap/overflow/resync remain covered by the automated suite rather than by forced fault injection during the soak.
- Every soak run now uses its own timestamp/GUID run directory and database. Cleanup reports process/firewall inspection success separately; a failed inspection is a failed soak and is never represented as a zero-leftover result.

See the acceptance and performance reports for limitations and exact measurements.
