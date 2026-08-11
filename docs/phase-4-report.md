# Phase 4 implementation report

Date: 2026-08-11. Status vocabulary: `Unit tested`, `Integration tested`, `Verified`, `Not verified`, and `Blocked` are intentionally distinct.

| Area | Status | Evidence |
|---|---|---|
| Pure temporal correlation | Unit tested | Exact `(PID, ProcessStartTime)`, configurable -30/+5 second window, out-of-order input, dedupe, multiple files/flows, evidence cap, overflow counter, retention, and EgressGuard storage exclusion. |
| Windows ETW sensor | Verified | Microsoft TraceEvent kernel File I/O collector observed a synthetic temporary file under an Administrator token. The process-owned session started and stopped with bounded cleanup; fake/buffer tests cover degraded states and overflow. |
| Service degradation | Integration tested | Disabled and controlled AccessDenied sensors leave the network coordinator running and shut down cleanly. |
| SQLite v3 | Integration tested | Idempotent migration, parameterized selected-evidence write/read, bounded query, indexes, retention, foreign key, and Clear history deletion. |
| IPC | Unit tested | Optional status fields and bounded `GetFileCorrelations`; legacy status without Phase 4 fields deserializes. Existing framing remains capped at 1 MiB. |
| UI | Build verified; visual QA Not verified | Connection Detail includes wrapping/virtualized bounded related-activity rows, empty/degraded states, tooltips, sensor status, and non-transmission warning at the existing 900×560 minimum. DPI 100/125/150 needs manual confirmation on this head. |
| Simulator | Build verified; functional ETW path Not verified | `--file-correlation-test` reads a synthetic temporary file, makes a loopback connect-only flow, sends no file bytes, and deletes the fixture. |
| Performance | Not verified | A 3–5 minute real ETW/service/UI smoke is still required; bounded memory is structurally enforced and dropped events are surfaced. |
| Production signing/Application Control | Blocked | Unchanged from Phases 1–3.5; this is not a production release. |

## Architecture and privacy

The sensor emits timestamp, exact process identity, operation, normalized path, extension, provider, sequence and validity, but never opens file content. The deterministic engine selects related events and persists only a salted path hash, redacted display identifier, extension, timestamps, delta, confidence and reason. No packet content, HTTPS plaintext, credential, clipboard, keystroke, cookie/token, or external telemetry is collected.

The feature is observe-only and disabled by default. File evidence never raises risk, creates a firewall rule, or activates enforcement. Raw events live in a 4,096-item short-retention buffer; correlations are capped at 20 per flow and stored under the normal 30-day local retention. Users can remove them with Clear history.

## Provider, ownership, and dependency

The Windows sensor uses `Microsoft.Diagnostics.Tracing.TraceEvent` 3.2.5, owned by Microsoft, because it provides maintained kernel File I/O ETW parsing/session control without a custom unsafe P/Invoke layer. A session is named `EgressGuard.FileActivity.v1-{PID}`. The sensor retains the created session object, sets `StopOnDispose`, and stops/disposes only that object. It never stops a same-named or foreign session and never changes the shared kernel logger, auditing, firewall, Named Pipe ACL, or Application Control policy.

## Limitations and remaining acceptance

- Temporal correlation does not prove upload or identify transmitted contents.
- Overflow, provider variation, permission failure, late identity lookup, or very short processes can cause missed events.
- File metadata is sensitive even after redaction; evidence stays local and bounded.
- Real elevated ETW integration is `Verified`. Safe loopback end-to-end UI correlation, 3–5 minute CPU/RAM smoke, dropped-event measurement, and manual DPI visual QA remain `Not verified` until completed on this head.
- Unexpected process termination can leave cleanup behavior dependent on Windows ETW; restart uses a new process-owned name and does not delete an unproven foreign session.
