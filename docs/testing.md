# Testing

## Commands

```powershell
dotnet build EgressGuard.sln -c Release
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build
dotnet format EgressGuard.sln --verify-no-changes --no-restore
.\tools\run-performance-test.ps1 -UiProcessId <pid> -ServiceProcessId <pid> -DurationSeconds 30
.\tools\run-soak-test.ps1 -DurationMinutes 10
```

The custom runner is retained: it has deterministic Windows integration setup and returns a CI-compatible exit code. Migrating frameworks would not currently add enough isolation to justify the rewrite.

## Automated coverage

The suite covers process identity/churn, TCP IPv4/IPv6, UDP owner PID, flow sensing, executable cache invalidation, Authenticode status/HRESULT mapping, embedded and catalog signatures, tampered and missing files, firewall path/hash guards, risk/policy/baseline, SQLite schema/persistence/locking, framing/oversize/disconnect, event ordering/gap/overflow/slow client, flow add/update/remove, and a real service Named Pipe reconnect/event subscription.

Access-denied Authenticode is not automated because a reliable fixture requires ACL mutation and can produce machine-specific behavior. The verifier maps access/I/O failures to `VerificationUnavailable`.

## Windows integration evidence

- Public IPv4 connect-only probe to `1.1.1.1:443`: success before block, socket access denied while blocked, success after undo.
- Same-name binary at a different path remained connected.
- Duplicate request left exactly one owned rule.
- Chrome retained established public TCP connections while the Simulator rule was active.
- External rule deletion followed by two resets was idempotent; zero owned rules remained.
- IPv6 was not verifiable because the workstation had no IPv6 route.
- UI Automation selected and rendered Dashboard, Live Connections, Connection Detail, Alerts, Rules and Settings. A 641-row burst snapshot rendered responsively; selected-row and ComboBox contrast defects found during QA were fixed.
- True subscription was exercised over the real service pipe and preserved sequence order.
- The bounded soak ran 2 minutes/40 cycles with normal, burst, beacon, UI open/close and IPC checks: 0 failures; service RAM 56.2–78.0 MB.

See the acceptance and performance reports for limitations and exact measurements.
