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
  → FlowCoordinator / RiskEngine / PolicyEngine
  ├─→ bounded persistence queue (2,048) → SQLite
  └─→ ServiceState transitions
       → EventHub sequence + per-client bounded channel (512)
       → Named Pipe subscription
       → UI SequencedEventBuffer (4,096)
       → 250 ms dispatcher batch
       → incremental ObservableCollection update
```

Snapshots are used only for initial connection, reconnect, manual refresh, queue overflow or a sequence gap. A slow subscriber cannot block the sensor: its channel is drained, a `ResyncRequired` marker is queued, and further events are skipped until reconnect. Disconnected subscriptions are removed from `EventHub`.

Event kinds are `FlowAdded`, `FlowUpdated`, `FlowRemoved`, `AlertRaised`, `ServiceStatusChanged`, and `ResyncRequired`. DataGrid row/column virtualization and recycling are enabled.

## Identity and persistence

- Process identity: `(PID, ProcessStartTime)`.
- TCP flow: process identity, protocol/IP version, local and remote endpoints.
- UDP flow: process identity, protocol/IP version and local endpoint; Windows owner tables do not expose a remote peer.
- Executable cache: normalized path, file size and last-write time; the cached record includes SHA-256.
- SQLite schema version 2 adds `signature_status`. WAL, foreign keys, parameterized SQL, transactions, busy timeout and retention remain enabled.

## Authenticode

`AuthenticodeVerifier` calls `WinVerifyTrust` with no UI and cache-only URL retrieval. It verifies embedded signatures and falls back to Windows Catalog lookup for catalog-signed system binaries. Status is one of `Unsigned`, `Valid`, `Invalid`, `Untrusted`, `Expired`, `Revoked`, `Unknown`, or `VerificationUnavailable`.

Publisher subject is display metadata only. Risk treats only `Unsigned` as unsigned; `Unknown` and `VerificationUnavailable` are not auto-block signals. Network revocation lookup is not performed on the UI or sensor path.

## Firewall ownership and safety

Owned rule names are `EgressGuard-MVP-{guid}` and descriptions start with `Owned by EgressGuard MVP;`. Create validates administrator context, absolute path, protected-system policy, current SHA-256, ownership, direction, action and application path. Post-create validation removes the new rule on failure. A database failure after firewall creation triggers rule deletion.

Equivalent enabled rules are deduplicated at the service boundary. Delete/reset match both the prefix and ownership marker. System32 executables are not automatically blocked. Windows Firewall ultimately enforces program path, so replacement-after-creation remains a platform limitation; policy matching still requires the stored hash.
