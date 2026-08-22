# Architecture

## Dependency direction

```text
UI ───────────────→ Protocol → Core
Service → Protocol/Persistence/Windows → Core
CLI → Protocol/Windows/Core
Persistence → Core
Windows → Core
```

UI never opens SQLite or changes Windows Firewall directly. Mutations cross the Named Pipe and the service verifies the impersonated client is an administrator.

## Runtime data and event path

```text
IP Helper + process snapshot
  → WindowsFlowSensor
  → FlowCoordinator → RiskEngine / PolicyEngine
Windows kernel File I/O ETW (optional)
  → non-blocking bounded raw staging (4,096; cheap path checks)
  → dual-index recent raw buffer (4,096 global / 256 per PID / 35-second retention)
  → exact PID/start-time promotion when a network flow appears
  → FileCorrelationEngine (-30/+5 seconds; max 20 evidence rows)
  → FlowCoordinator (descriptive evidence only; no risk/policy input)
  ├─→ bounded persistence queue (2,048) → SQLite
  └─→ ServiceState transitions
       → EventHub sequence + per-client bounded channel (512)
       → Named Pipe subscription
       → UI SequencedEventBuffer (4,096)
       → 250 ms dispatcher batch
       → incremental ObservableCollection update
       → selected correlation refresh (capacity 1; at most 1/second)
```

Snapshots are used only for initial connection, reconnect, manual refresh, queue overflow or a sequence gap. A slow subscriber cannot block the sensor: its channel is drained, a `ResyncRequired` marker is queued, and further events are skipped until reconnect. Disconnected subscriptions are removed from `EventHub`.

Event kinds are `FlowAdded`, `FlowUpdated`, `FlowRemoved`, `AlertRaised`, `ServiceStatusChanged`, and `ResyncRequired`. DataGrid row/column virtualization and recycling are enabled.

## Identity and persistence

- Process identity: `(PID, ProcessStartTime)`.
- TCP flow: process identity, protocol/IP version, local and remote endpoints.
- UDP flow: process identity, protocol/IP version and local endpoint; Windows owner tables do not expose a remote peer.
- Executable cache: normalized path, file size and last-write time; the cached record includes SHA-256.
- SQLite schema version 3 adds selected, redacted `file_correlations`; raw ETW events are never persisted. WAL, foreign keys, parameterized SQL, transactions, busy timeout and retention remain enabled, and Clear history removes correlation evidence.

## Phase 4 file correlation

`IFileActivitySensor` is a Core boundary. `EtwFileActivitySensor` is the Windows implementation backed by Microsoft's TraceEvent library and kernel File I/O keywords. ETW callbacks do only cheap PID/path/operation checks and `TryWrite` a raw event; they never call `Process.GetProcessById` or `Process.StartTime` for system-wide File I/O. Low-value system files are recognized only beneath normalized Windows, Program Files and Program Files (x86) roots with case-insensitive directory-boundary matching; a user directory that merely contains one of those names remains eligible. A bounded recent raw buffer retains events that occur before a network flow. Each buffered entry is linked into a global eviction list and a PID-specific list, so global and per-PID eviction/removal are O(1); promotion walks only that PID's entries. Out-of-order-safe expiration scans the bounded global list at most once per second during ingestion and is forced immediately before promotion, replacing the former full scan on every event. When `FlowCoordinator` supplies exact current network process identities through `IFileActivityInterestSink`, matching events at or after that generation's start time are synchronously promoted, so the -30/+5-second window works for the first flow as well as later flows. The bounded promoted handoff uses a global eviction list plus an exact `(PID, ProcessStartTime)` index, so an interest drains only its own entries without a process-by-event scan; both indexes are removed together on drain or global eviction. The exact interest cache is a separate bounded LRU/TTL structure. A capacity-one status signal channel publishes changed dropped counts at most once per second and flushes the final total at stop. Session names are `EgressGuard.FileActivity.v2-{nonce}`. A protected exact-identity marker permits restart to reclaim only a dead EgressGuard controller's exact session; missing, invalid, live-owner, foreign and shared sessions are never stopped.

Both request and event Named Pipe clients resolve the optional `EGRESSGUARD_PIPE_NAME` override when no explicit name is supplied. The production default remains `EgressGuard.Service.v1`; the override permits isolated UI/service integration without competing with an installed service.

The connection-detail UI presents only the protected file identifier's redacted label, operation, activity time, before/after delta, confidence and fixed correlation reason. It offers `All`, `Read / open` and `Write / rename / delete` views and always states that temporal/process correlation does not prove transmission. The displayed dropped-event count is the saturating total from the bounded ETW handoff and Core correlation buffers; status detail crossing the service boundary is fixed text rather than provider exception data.

The pure engine matches exact `(PID, ProcessStartTime)` and a configurable temporal window, handles out-of-order events, deduplicates short repeats, expires old events, and gives event, timestamp-index and dedupe state the same hard capacity. Insertion order remains a linked list for deterministic capacity eviction; a timestamp-sorted index lets cleanup inspect only the oldest candidates and expired entries instead of scanning the full buffer on every promoted event. Eviction removes both indexes and removes a dedupe key only when it still represents that exact timestamp. Stored paths are salted SHA-256 identifiers with redacted display identifiers; an extension is retained only when it is 2–16 ASCII characters consisting of a leading dot and alphanumeric suffix. Persistence, Named Pipe and UI boundaries reapply the projection so malformed or legacy values cannot become raw path output. Correlation is descriptive evidence only: it never changes risk, policy, or firewall state and does not prove file transmission.

## Authenticode

`AuthenticodeVerifier` calls `WinVerifyTrust` with no UI and cache-only URL retrieval. It verifies embedded signatures and falls back to Windows Catalog lookup for catalog-signed system binaries. Status is one of `Unsigned`, `Valid`, `Invalid`, `Untrusted`, `Expired`, `Revoked`, `Unknown`, or `VerificationUnavailable`.

Publisher subject is display metadata only. Risk treats only `Unsigned` as unsigned; `Unknown` and `VerificationUnavailable` are not auto-block signals. Network revocation lookup is not performed on the UI or sensor path.

## Firewall ownership and safety

Owned rule names are `EgressGuard-MVP-{guid}` and descriptions start with `Owned by EgressGuard MVP;`. The full ownership description records rule ID, executable SHA-256/path, action, remote address/port, protocol and enabled state. Create validates administrator context, absolute path, protected-system policy and current SHA-256 before comparing that description and the live Windows Firewall application, address and port filters plus direction, action, enabled state and `Any` profile. Post-create validation uses the same comparison and removes the newly created rule on failure. A database failure after firewall creation triggers rule deletion.

PowerShell firewall operations use a finite internal timeout. Once an owned child starts, stdout, stderr and exit are observed together; cancellation, timeout or I/O failure terminates only that process tree and waits for cleanup with an independent timeout. Create preflight, post-create validation and indeterminate-create reconciliation share one exact-rule predicate. It canonicalizes unrestricted address/port values to `Any`, treats TCP as `TCP`/`Tcp`/`6` and UDP as `UDP`/`Udp`/`17`, and compares paths and textual values case-insensitively. A matching rule newly created by the failed request is removed; any same-name semantic mismatch is neither changed nor deleted. Caller cancellation is rethrown after cleanup.

Automatic-policy and manual-IPC creates share one transaction gate across duplicate recheck, firewall creation, database persistence and rollback. This prevents a concurrent request from adopting a rule while its creating request can still roll it back. Equivalent enabled rules are deduplicated inside that gate. Delete/reset match both the prefix and ownership marker. System32 executables are not automatically blocked. Windows Firewall ultimately enforces program path, so replacement-after-creation remains a platform limitation; policy matching still requires the stored hash.
