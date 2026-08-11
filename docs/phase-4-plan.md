# Phase 4 plan: ETW file-to-network temporal correlation

Phase 4 is observe-only. Related file activity is evidence that the same process identity touched a file near a flow; it does not prove that file contents were transmitted and never changes risk, policy, or firewall enforcement.

## Sensor and permissions

- `IFileActivitySensor` lives in Core; the Windows implementation lives in `EgressGuard.Windows`.
- Use Microsoft's `Microsoft.Diagnostics.Tracing.TraceEvent` package and the Windows kernel File I/O provider. The opt-in real sensor normally requires an elevated service token; `AccessDenied` and unavailable providers degrade safely.
- Each real-time session is named `EgressGuard.FileActivity.v1-{service PID}`. The sensor disposes/stops only the session instance it created. It never opens, stops, or changes another application's session or the shared NT Kernel Logger.
- Graceful cancellation has a finite wait. Unexpected ETW failures become `Failed`/`ProviderUnavailable`; network monitoring continues.

## Volume, correlation, and retention

- ETW callbacks use `TryWrite` into a bounded channel and never wait. Overflow increments a dropped-event counter and exposes `OverflowDegraded`.
- Normalize paths, reject incomplete operations, exclude the EgressGuard data/log/artifact roots early, and deduplicate identical process/path/operation events in a short window.
- Keep a short bounded staging window because ETW cannot reliably filter by only processes that will soon create a flow. Cleanup removes expired events; memory has a hard event capacity.
- The deterministic Core engine matches exact `(PID, ProcessStartTime)` from 30 seconds before through 5 seconds after flow first-seen, tolerates out-of-order delivery, and returns at most 20 evidence items per flow.
- Confidence is rule-based (`High` for Read/Open/Create close to the flow, otherwise `Medium`/`Low`) and every reason states the operation and signed time delta.

## Privacy

- Never read file content, packet payload, TLS plaintext, credentials, clipboard, keystrokes, cookies, or tokens. No telemetry leaves the machine.
- Raw paths exist only in the short-lived in-memory sensor event. Persisted/display evidence uses a redacted filename plus a salted local SHA-256 path identifier and extension.
- Persist only selected correlations, not raw ETW events. Retention is 30 days by default; Clear history deletes correlations too. Test/report evidence uses synthetic paths only.

## Schema, IPC, UI, and simulator

- SQLite schema v3 adds bounded `file_correlations` rows with parameterized writes, flow/time indexes, cascade cleanup, retention, and bounded reads.
- Compatible IPC adds `GetFileCorrelations`; service status gains optional file-sensor fields with defaults so older payloads remain readable. Correlation replies are capped and stay under the 1 MiB framing limit.
- Connection Detail adds a bounded, wrapping `Related file activity` list with empty/degraded states, tooltips, sensor status, and the explicit non-transmission warning.
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
- Crash-only cleanup of a Windows ETW session is platform-dependent; service restart uses a new process-owned name and never stops an unproven foreign session.
