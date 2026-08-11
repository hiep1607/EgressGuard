# Phase 4 implementation report

Date: 2026-08-11. Status vocabulary: `Unit tested`, `Integration tested`, `Verified`, `Not verified`, and `Blocked` are intentionally distinct.

| Area | Status | Evidence |
|---|---|---|
| Pure temporal correlation | Unit tested | Exact `(PID, ProcessStartTime)`, configurable -30/+5 second window, out-of-order input, a dedupe hard bound equal to event capacity, safe same-key eviction, multiple files/flows, evidence cap, overflow counter, retention, and storage exclusion. |
| Windows ETW sensor | Verified | The elevated Microsoft TraceEvent collector observed the synthetic fixture. Projection rejected events older than process start. A 20,000-event/capacity-one regression proved exact drops and bounded notifications. |
| ETW crash ownership | Verified | The Administrator child-process integration killed the controller, observed the orphan, reclaimed only the exact nonce session authorized by its protected marker, left a foreign session untouched, and ended with zero EgressGuard session. |
| Service degradation | Integration tested | Disabled and controlled AccessDenied sensors leave the network coordinator running and shut down cleanly. |
| SQLite v3 | Integration tested | Idempotent migration, parameterized write/read of every already-bounded item, 10 flows × 20 correlations without later-flow truncation, duplicate-ID idempotence, bounded query, indexes, retention, foreign key, and Clear history deletion. |
| IPC | Unit tested | Optional status fields and bounded `GetFileCorrelations`; legacy status without Phase 4 fields deserializes. Existing framing remains capped at 1 MiB. |
| UI | Verified at 125%; 100%/150% Not verified | UI Automation and screenshots covered all six tabs, selected/empty Related file activity, long values, scrollbar, disabled/degraded presentation, 900×560, maximize/minimize/normal, tray lifecycle, and UI-close/service-survival. No clipping, overlap, or contrast defect was observed. The live sensor degraded before a stable `Running` screenshot; that presentation and tooltip appearance still require manual confirmation. |
| Simulator/service IPC | Verified | The real service observed the synthetic file and loopback Simulator flow, returned correlation through IPC, persisted only protected/redacted identifiers, and the test server recorded zero transmitted bytes. Fixtures and sessions were cleaned. |
| Performance | Failed | At 125% on 12 logical CPUs: 180-second churn measured UI 0.342% CPU/182.7 MB average and service 17.2%/96.8 MB; a 60-second idle window measured UI 0.017%/195.8 MB and service 1.756%/94.4 MB. RAM did not grow continuously, but service exceeded the ~1% idle and <3% normal budgets. Overflow was visible (560 drops); bounded-state tests and session cleanup passed. |
| Production signing/Application Control | Blocked | Unchanged from Phases 1–3.5; this is not a production release. |

## Architecture and privacy

The sensor emits timestamp, exact process identity, operation, normalized path, extension, provider, sequence and validity, but never opens file content. The deterministic engine selects related events and persists only a salted path hash, redacted display identifier, extension, timestamps, delta, confidence and reason. No packet content, HTTPS plaintext, credential, clipboard, keystroke, cookie/token, or external telemetry is collected.

The feature is observe-only and disabled by default. File evidence never raises risk, creates a firewall rule, or activates enforcement. Raw events and dedupe keys each have a hard 4,096-item bound; correlations are capped at 20 per flow and stored under the normal 30-day local retention. Persistence writes the complete already-bounded correlation enumeration instead of silently taking only its first 100 items. Users can remove evidence with Clear history.

## Provider, ownership, and dependency

The Windows sensor uses `Microsoft.Diagnostics.Tracing.TraceEvent` 3.2.5, owned by Microsoft, because it provides maintained kernel File I/O ETW parsing/session control without a custom unsafe P/Invoke layer. A session is named `EgressGuard.FileActivity.v2-{nonce}`. Its marker directory has protected ACLs for the controller identity, `SYSTEM`, and Administrators. The marker must exactly match version, nonce, session, PID, and start time; a live owner blocks a second controller, while a dead verified owner permits stopping only that exact session. Missing/invalid markers never authorize prefix cleanup. Local Administrators remain inside the trust boundary.

## Limitations and remaining acceptance

- Temporal correlation does not prove upload or identify transmitted contents.
- Overflow, provider variation, permission failure, late identity lookup, or very short processes can cause missed events.
- File metadata is sensitive even after redaction; evidence stays local and bounded.
- Real ETW, crash/reclaim, service IPC, zero-byte loopback, raw-path redaction, and 125% UI integration are `Verified`. Phase 4 UI at 100%/150%, a stable direct `Running` sensor presentation, and tooltip appearance remain `Not verified`.
- Performance is `Failed`, not hidden: the service exceeded the initial CPU budget. The Draft PR is not production-ready until this is resolved and independently re-reviewed.
