# Testing

## Commands

```powershell
dotnet build EgressGuard.sln -c Release
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build
dotnet format EgressGuard.sln --verify-no-changes --no-restore
.\tools\run-performance-test.ps1 -UiProcessId <pid> -ServiceProcessId <pid> -DurationSeconds 30
.\tools\run-soak-test.ps1 -DurationMinutes 30
```

The custom runner is retained: it has deterministic Windows integration setup and returns a CI-compatible exit code. Migrating frameworks would not currently add enough isolation to justify the rewrite.

## Automated coverage

The suite covers process identity/churn, TCP IPv4/IPv6, UDP owner PID, flow sensing, executable cache invalidation, Authenticode status/HRESULT mapping, embedded and catalog signatures, tampered and missing files, firewall path/hash guards, risk/policy/baseline, SQLite schema/persistence/locking, graceful service cancellation, automatic-rule persistence rollback and rollback-failure logging, framing/oversize/disconnect, event ordering/gap/overflow/slow client, flow add/update/remove, and a real service Named Pipe reconnect/event subscription.

Access-denied Authenticode is not automated because a reliable fixture requires ACL mutation and can produce machine-specific behavior. The verifier maps access/I/O failures to `VerificationUnavailable`.

## Windows integration evidence

- Public IPv4 connect-only probe to `1.1.1.1:443`: success before block, socket access denied while blocked, success after undo.
- Same-name binary at a different path remained connected.
- Duplicate request left exactly one owned rule.
- Chrome retained established public TCP connections while the Simulator rule was active.
- External rule deletion followed by two resets was idempotent; zero owned rules remained.
- IPv6 was not verifiable because the workstation had no IPv6 route.
- UI Automation at the host's real 125% scale selected and rendered Dashboard, Live Connections, Connection Detail, Alerts, Rules and Settings. Multi-row and IPv6 data, empty Rules, a selected connection, a 215-character database path, minimize and maximize were exercised. ComboBox and Alerts DataGrid contrast defects found during Phase 3.5 QA were fixed and visually rechecked.
- True subscription was exercised over the real service pipe and preserved sequence order.
- The bounded soak ran 2 minutes/40 cycles with normal, burst, beacon, UI open/close and IPC checks: 0 failures; service RAM 56.2–78.0 MB.
- The fresh Phase 3.5 soak ran 30 minutes/585 cycles with 0 failures, 117 service restarts, 195 UI opens/closes and 585 IPC checks. Service RAM remained within 55.5–86.4 MB and UI RAM within 134.5–196.3 MB across deliberately restarted process instances. The database lock was released; both cleanup inspections succeeded and found zero process or owned firewall rule.

## Phase 3.5 limitations

- DPI 100% and 150% were not verified because the active display was 125% and no disruptive display-scale change was authorized.
- Direct tray icon/context-menu interaction was not verified; the real `NotifyIcon` lifecycle did execute during UI open/close testing.
- No reboot was performed.
- The 30-minute soak checked IPC reconnect and database lock release. Database contention and event sequence/gap/overflow/resync remain covered by the automated suite rather than by forced fault injection during the soak.
- Every soak run now uses its own timestamp/GUID run directory and database. Cleanup reports process/firewall inspection success separately; a failed inspection is a failed soak and is never represented as a zero-leftover result.

See the acceptance and performance reports for limitations and exact measurements.
