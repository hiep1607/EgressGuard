# Testing

## Commands

```powershell
dotnet build EgressGuard.sln -c Release
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --test "Service pipe reconnect and event subscription"
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --firewall-cancellation-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --etw-file-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --etw-orphan-reclaim-integration
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build -- --file-correlation-service-integration
dotnet format EgressGuard.sln --verify-no-changes --no-restore
.\tools\run-performance-test.ps1 -UiProcessId <pid> -ServiceProcessId <pid> -DurationSeconds 30
.\tools\run-soak-test.ps1 -DurationMinutes 30
```

The custom runner is retained: it has deterministic Windows integration setup and returns a CI-compatible exit code. `--test <exact-test-name>` runs one default-suite test for targeted regression loops. Migrating frameworks would not currently add enough isolation to justify the rewrite.

## Automated coverage

The 50-test default suite retains all prior regressions and adds file-correlation coverage for exact process identity/window matching, sensor-side PID-reuse rejection, out-of-order delivery, hard-bounded dedupe and safe eviction, multiple files/flows, evidence caps, bounded overflow/drop/status notifications, exact ETW ownership, retention, self-storage exclusion, disabled/AccessDenied lifecycle safety, complete multi-flow SQLite batches, live UI refresh cancellation/throttling, schema v3/Clear history, and bounded backward-compatible IPC. The ACL regression still combines every explicit allow rule for the `INTERACTIVE` SID and requires exactly `ReadWrite | Synchronize`, rejecting any additional ownership, permission-changing, deletion, instance-creation or system-security rights.

The three real ETW/service commands are opt-in and require Administrator. The first observes a synthetic file. The orphan test kills a child controller and proves exact protected-marker reclaim with final cleanup. The service test creates a loopback Simulator flow, reads correlations over IPC, verifies the server received zero bytes and SQLite contains no raw fixture path, then removes every fixture. Default CI uses fakes and never changes system auditing or policy.

The real-service IPC test assigns a unique Named Pipe name to each service process through `EGRESSGUARD_PIPE_NAME`, passes that name explicitly to both clients, and waits for the server's subscription acknowledgement before creating the controlled TCP flow. This prevents an installed service from competing for a shared pipe and removes the fixed-delay readiness race. The default production pipe remains `EgressGuard.Service.v1` when no override is supplied.

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
- True subscription was exercised over the real service pipe and preserved sequence order.
- The bounded soak ran 2 minutes/40 cycles with normal, burst, beacon, UI open/close and IPC checks: 0 failures; service RAM 56.2–78.0 MB.
- The fresh Phase 3.5 soak ran 30 minutes/585 cycles with 0 failures, 117 service restarts, 195 UI opens/closes and 585 IPC checks. Service RAM remained within 55.5–86.4 MB and UI RAM within 134.5–196.3 MB across deliberately restarted process instances. The database lock was released; both cleanup inspections succeeded and found zero process or owned firewall rule.

- Phase 3.5.1 ran the 32/32 default suite plus the opt-in real firewall cancellation integration. Its fresh 2-minute smoke completed 40 traffic/IPC cycles, 8 service restarts and 0 failures; database lock release and both strict cleanup inspections passed with zero EgressGuard process, test-owned PowerShell process or owned firewall rule. The prior 30-minute soak was not relabeled or reused as Phase 3.5.1 evidence.

## Phase 3.5 limitations

- DPI 100% and 150% were not verified because the active display was 125% and no disruptive display-scale change was authorized.
- Direct tray icon/context-menu interaction was not verified; the real `NotifyIcon` lifecycle did execute during UI open/close testing.
- No reboot was performed.
- The 30-minute soak checked IPC reconnect and database lock release. Database contention and event sequence/gap/overflow/resync remain covered by the automated suite rather than by forced fault injection during the soak.
- Every soak run now uses its own timestamp/GUID run directory and database. Cleanup reports process/firewall inspection success separately; a failed inspection is a failed soak and is never represented as a zero-leftover result.

See the acceptance and performance reports for limitations and exact measurements.
