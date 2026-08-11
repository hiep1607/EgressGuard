# Phase 4 plan: ETW file-to-network temporal correlation

Phase 4 is observe-only. Related file activity is evidence that the same process identity touched a file near a flow; it does not prove that file contents were transmitted and never changes risk, policy, or firewall enforcement.

## Sensor and permissions

- `IFileActivitySensor` lives in Core; the Windows implementation lives in `EgressGuard.Windows`.
- Use Microsoft's `Microsoft.Diagnostics.Tracing.TraceEvent` package and the Windows kernel File I/O provider. The opt-in real sensor normally requires an elevated service token; `AccessDenied` and unavailable providers degrade safely.
- Each real-time session has an unpredictable exact name, `EgressGuard.FileActivity.v2-{128-bit nonce}`. A protected ownership marker records that exact nonce/name plus controller PID and start time. Restart reclaims a session only when the marker validates exactly and the recorded controller identity is dead. It never stops by prefix, touches a foreign session, or changes the shared NT Kernel Logger.
- Graceful cancellation has a finite wait. Unexpected ETW failures become `Failed`/`ProviderUnavailable`; network monitoring continues.

## Volume, correlation, and retention

- ETW callbacks use `TryWrite` into a bounded channel and never wait. Overflow atomically increments the exact dropped-event counter and exposes `OverflowDegraded`; a separate capacity-one status channel coalesces notifications, so drops cannot create a task or notification storm.
- Normalize paths, reject incomplete operations, exclude the EgressGuard data/log/artifact roots early, and deduplicate identical process/path/operation events in a short window.
- Keep a short bounded staging window because ETW cannot reliably filter by only processes that will soon create a flow. Cleanup and capacity eviction remove the matching dedupe entry only when it still represents that event. Both event and dedupe state therefore have the same hard maximum.
- Sensor projection resolves `(PID, ProcessStartTime)` and drops an event timestamped before the resolved process start, or whenever identity cannot be verified. This prevents a delayed raw event from being assigned to a reused PID.
- The deterministic Core engine matches exact `(PID, ProcessStartTime)` from 30 seconds before through 5 seconds after flow first-seen, tolerates out-of-order delivery, and returns at most 20 evidence items per flow.
- Confidence is rule-based (`High` for Read/Open/Create close to the flow, otherwise `Medium`/`Low`) and every reason states the operation and signed time delta.

## Privacy

- Never read file content, packet payload, TLS plaintext, credentials, clipboard, keystrokes, cookies, or tokens. No telemetry leaves the machine.
- Raw paths exist only in the short-lived in-memory sensor event. Persisted/display evidence uses a redacted filename plus a salted local SHA-256 path identifier and extension.
- Persist only selected correlations, not raw ETW events. Retention is 30 days by default; Clear history deletes correlations too. Test/report evidence uses synthetic paths only.

## Schema, IPC, UI, and simulator

- SQLite schema v3 adds bounded `file_correlations` rows with parameterized writes, flow/time indexes, cascade cleanup, retention, and bounded reads. Persistence writes every item in the already-bounded batch; it does not truncate later flows with `Take(100)`.
- Compatible IPC adds `GetFileCorrelations`; service status gains optional file-sensor fields with defaults so older payloads remain readable. Correlation replies are capped and stay under the 1 MiB framing limit.
- Connection Detail adds a bounded, wrapping `Related file activity` list with empty/degraded states, tooltips, sensor status, and the explicit non-transmission warning. `FlowUpdated` triggers a capacity-one, at-most-once-per-second refresh for the selected flow; selection changes cancel stale work and only one IPC request can run.
- Simulator `--file-correlation-test` creates and reads a synthetic temporary file, then connects only to loopback without sending file bytes, and removes the file in `finally`.

## Checkpoints and tests

- A: models, interfaces, pure engine; window, PID reuse, out-of-order, dedupe, multiple files/flows tests.
- B: bounded sensor pipeline, state transitions, exclusion, overflow/drop, cancellation, fake sensor, and opt-in Administrator ETW integration.
- C: orchestration, schema v3, retention/Clear history, bounded IPC serialization.
- D: UI, simulator, local functional checks, 3–5 minute performance smoke, and reports.

Default CI uses fakes and requires neither Administrator nor policy changes. The real ETW integration is explicit and never alters Windows auditing, Application Control, Named Pipe ACLs, or firewall configuration.

## Initial performance budget

- ETW callback never blocks; bounded staging capacity 4,096 events.
- Correlation evidence is capped at 20 rows per flow; database queries are capped at 100.
- Idle service CPU increase target: at most about 1%; normal service/UI target: below 3% each.
- No continuous RAM growth; overflow is visible through state and counters rather than hidden.

## Known limitations

- Temporal correlation does not prove upload or identify bytes on the wire.
- Events may be missed on overflow, provider differences, late process identity resolution, or insufficient permission.
- File paths are sensitive; redaction reduces but cannot eliminate metadata sensitivity.
- Protected marker integrity assumes the service identity, `SYSTEM`, and local Administrators are trusted. An Administrator can still tamper with ETW state and is outside this local ownership boundary.
- The 2026-08-11 smoke exceeded the initial service CPU budget with the optional kernel File I/O sensor enabled. Performance acceptance remains failed until that overhead is reduced and remeasured.
