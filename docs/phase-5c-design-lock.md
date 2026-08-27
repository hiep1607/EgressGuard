# Phase 5C minifilter design lock

Status: Gate 1 design; `GATE 1 REVIEW REQUIRED`. Gate 2B remains `LAB APPROVAL REQUIRED`.

This design is file-only. It does not authorize any driver work on the current unapproved commit. After independent Gate 1 approval, Gate 2A authorizes source creation, x64 compilation, driver code analysis and pure-logic testing only. Packaging/signing remains prohibited until the controlled transition prerequisites are met; installation/loading and Windows security changes remain prohibited until every Gate 2B condition in `docs/phase-5c-lab-prerequisites.md` is met.

## Scope and claim boundary

Phase 5C will prove a metadata-only Windows file-system minifilter in five ordered gates:

1. approve this design and the isolated, recoverable kernel-lab plan;
2. Gate 2A: create, compile and analyze source without creating an installable package or running a driver;
3. Gate 2B: after the controlled package/signing transition, register the exact returned Microsoft-signed observe-only minifilter and always pass I/O through in the approved VM;
4. Gate 3: prove exact process/file identity and mutation semantics using synthetic files; and
5. Gate 4: pend only eligible IRP-based non-paging reads in a bounded cancel-safe queue.

Phase 5C does not implement WFP, inspect network traffic, change Windows Firewall, call the Phase 5B decision UI, persist allow rules, install a product, or claim to prevent a real upload. It neither reads nor hashes file content. Memory-mapped, paging and Fast I/O reads remain explicitly outside verified coverage.

All Gate 2B-4 driver execution occurs only inside the independently approved VM. Gate 2A may use a temporary GitHub-hosted Windows runner for build and static analysis under the locked no-package/no-install/no-load contract. Development and ordinary .NET validation may run on the host, but no driver command may target the host.

## Preserved Phase 5B contracts

The integrated Phase 5B source at `7523c42e7894ae4e8c9ed436a0936984ae46945f` remains authoritative for user-mode concepts:

- contract version `1`;
- protocol-visible process identity `(PID, ProcessStartTime)`;
- a kernel-only process generation in addition to, never instead of, the protocol identity;
- `FileVersionIdentity` as volume/file/version metadata, never a content hash;
- NTFS-only prototype behavior;
- unsupported/uncertain paths fail open with critical evidence;
- gate/read deadline at most two seconds;
- pending-read bounds of 4 per exact subject and 64 global;
- exact terminal completion and idempotence; and
- no raw path or file content in service/UI messages.

Phase 5C introduces a kernel wire record only for the lab. It does not change Phase 5B Core, Protocol, Service, UI, simulator or 1 MiB Named Pipe framing.

## Component boundary

```text
Synthetic process in approved VM
  -> local fixed NTFS synthetic volume
  -> EgressGuard minifilter callbacks
       -> kernel-derived process generation
       -> metadata-only file identity/version projection
       -> bounded fixed-record queue
       -> one driver-owned emitter path
  -> protected Filter Manager communication port
  -> lab collector / contract tests

Every Gate 2B operation: pass through immediately.
Gate 4 eligible reads: bounded FltCbdq pending, then exactly one completion.
Anything unsupported, uncertain, full, disconnected or expired: pass through + exact counter.
```

There is no network component in this architecture.

## Planned source ownership

No path in this table exists at Gate 1. After Gate 1 approval it is the allowlist for Gate 2A and later gates, subject to the per-row restriction.

| Planned path | Responsibility |
|---|---|
| `drivers/EgressGuard.Minifilter/EgressGuard.Minifilter.vcxproj` | x64 WDK minifilter build only |
| `drivers/EgressGuard.Minifilter/EgressGuard.Minifilter.inf` | Gate 2A may contain only a non-installable structural template with an unresolved altitude token; the controlled transition may complete it only with the Microsoft-assigned altitude |
| `drivers/EgressGuard.Minifilter/Driver.c` | `DriverEntry`, registration, start and unload ordering |
| `drivers/EgressGuard.Minifilter/Filter.c` | instance setup/teardown and create/read callbacks |
| `drivers/EgressGuard.Minifilter/Identity.c` | kernel-derived process and metadata-only file identity |
| `drivers/EgressGuard.Minifilter/MetadataQueue.c` | fixed-capacity queue and exact overflow counters |
| `drivers/EgressGuard.Minifilter/PendingReads.c` | Gate 4 `FltCbdq`, deadline and one-owner completion |
| `drivers/EgressGuard.Minifilter/Communication.c` | protected one-client Filter Manager port and wire validation |
| `drivers/EgressGuard.Minifilter/Contracts.h` | fixed-width version-1 wire structures, enums and compile-time size checks |
| `drivers/EgressGuard.Minifilter/Ownership.h` | exact names, GUIDs, pool tags and cleanup counters |
| `tests/EgressGuard.DriverContracts/*` | user-mode contract parser, deterministic state/race tests and lab runner |
| `docs/phase-5c-report.md` | sanitized exact-artifact evidence and honest limitations |
| `EgressGuard.sln` | only the approved addition of the contract-test project |

No Core, Protocol, Service, UI, persistence, Windows/firewall implementation, simulator or product installer is planned for Phase 5C. A later Gate 2A PR may add a build-only workflow after separate review, but that workflow may never package, install or load the driver.

## Registration and lifecycle

The future minifilter is a Filter Manager minifilter, not a legacy file-system filter.

Startup order:

1. Validate compile-time/runtime constants; create the load generation; initialize the stopping/connection state, exact counters, fixed metadata ring, fixed pending/tombstone pools, shutdown events and all driver-owned locks. No callback-visible state remains uninitialized after this step.
2. Call `FltRegisterFilter` with explicit create/read and lifecycle callbacks and retain the returned `PFLT_FILTER`.
3. Using only that returned filter pointer, build/free the default security descriptor around `FltCreateCommunicationPort` and create the server port with maximum connection count `1`.
4. Register process-exit notification and start the single bounded emitter plus shared watchdog/completion worker. Each successful registration/start is recorded in the lifecycle state.
5. Call `FltStartFiltering` last. Every callback-visible state and worker must already be ready because Filter Manager may present I/O and attachment notifications before this call returns.

Any startup failure enters the same stopping state as normal unload and unwinds only completed steps in exact reverse order. A failure after `FltRegisterFilter` closes any created ports, stops any started worker, removes any registered process callback, drains owned entries, calls `FltUnregisterFilter` exactly once and only then frees global pools. A failed `FltStartFiltering` follows this path as required by Filter Manager. The result leaves no registered filter, port, callback, worker or pool allocation.

Normal unload and every partial-start cleanup share one idempotent stop routine; only the completed-step bitmap changes. Its order is:

1. Atomically transition `Running -> Stopping`; repeated callers observe `Stopping/Stopped`, admit no new queue/pending work and do not start a second cleanup.
2. Close the communication server port and atomically detach/close the client port. Closing the server alone is insufficient because it prevents new connections but does not close an existing client.
3. Disable every per-instance cancel-safe queue with `FltCbdqDisable` so cancellation and removal use the locked drain path.
4. Atomically claim and either fail-open-continue or cancel-complete every held operation exactly once, then drain metadata records as shutdown drops without waiting indefinitely.
5. Signal/join the shared watchdog and emitter, then remove the process-exit callback. No worker or callback may retain a driver-owned entry after this point.
6. Release every callback-data, file-object, process, instance and client-connection reference owned by EgressGuard and prove their owned counters are zero.
7. Call `FltUnregisterFilter` exactly once. This call, not a preceding explicit detach loop, initiates teardown of all attached instances and invokes their teardown callbacks.
8. After `FltUnregisterFilter` and all teardown callbacks complete, free global ring/pools/locks/events and assert every owned depth, allocation, port, worker and reference counter is zero.

`FilterUnloadCallback` is mandatory. Explicit instance teardown uses the same one-owner drain primitive, but normal driver unload never enumerates/detaches instances before `FltUnregisterFilter`. Cleanup never targets an object outside the exact identifiers in the lab prerequisites.

Microsoft lifecycle references:

- [Filter Manager concepts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)
- [Loading and unloading a minifilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/loading-and-unloading)
- [FltRegisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltregisterfilter)
- [FltCreateCommunicationPort](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatecommunicationport)
- [FltStartFiltering](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/initiating-filtering)
- [FltUnregisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter)

## Volume admission

`InstanceSetupCallback` performs bounded, local classification only. It performs no IPC, waits or thread synchronization.

Attachment is accepted only when all are true:

- `VolumeFilesystemType == FLT_FSTYPE_NTFS`;
- `VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM`;
- the storage stack is local and fixed, not remote or removable;
- the mount-manager volume GUID from `FltGetVolumeGuidName(FltObjects->Volume, ...)` exactly equals the owner-approved synthetic-volume GUID; and
- the instance is the single EgressGuard default instance at the Microsoft-assigned altitude.

The authoritative kernel/wire volume identity is the tuple `(VolumeGuid, VolumeSerialNumber)`: `VolumeGuid` is the GUID parsed from the exact `\??\Volume{GUID}` returned by `FltGetVolumeGuidName`, and `VolumeSerialNumber` is the `uint32` returned in `FILE_FS_VOLUME_INFORMATION` by `FltQueryVolumeInformation(..., FileFsVolumeInformation)` after attachment at `PASSIVE_LEVEL`. Until both values are available and equal the frozen tuple, all callbacks pass through. A serial mismatch after provisional GUID attachment makes the instance ineligible, increments `Eg5cVolumeIdentityMismatchPassThrough` once and requests normal Filter Manager teardown; no read is ever pended on it.

Before Gate 2B, the lab owner records an out-of-band mapping from the exact synthetic VHDX object/checkpoint identity to the guest's mount-manager volume GUID and NTFS serial, then independently rechecks that tuple after restoring the clean checkpoint. The driver compares only that approved binary tuple. Drive letter `T:`, label `EG5C_SYNTHETIC`, a device path or a file path is never sufficient authority and none is serialized as identity.

Every other case returns `STATUS_FLT_DO_NOT_ATTACH`, so file I/O naturally passes through. A fixed reason enum increments one monotonic warning counter at the volume-admission attempt:

| Reason enum | Condition |
|---|---|
| `Eg5cVolumeRefsPassThrough` | ReFS |
| `Eg5cVolumeRemotePassThrough` | network/remote volume |
| `Eg5cVolumeRemovablePassThrough` | removable media |
| `Eg5cVolumeNotApprovedPassThrough` | local volume not equal to the approved synthetic VHDX |
| `Eg5cVolumeIdentityMismatchPassThrough` | GUID matched provisionally but the NTFS serial was missing or different |
| `Eg5cVolumeUnsupportedPassThrough` | any other filesystem/device type or uncertain classification |

No unsupported volume is silently treated as NTFS and no per-file enforcement claim is made for a volume to which the instance is not attached.

Microsoft references:

- [FltGetVolumeGuidName](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetvolumeguidname)
- [FltQueryVolumeInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryvolumeinformation)

## Callback matrix

| Operation/context | Gate 2B | Gate 4 | Evidence |
|---|---|---|---|
| `IRP_MJ_CREATE` pre-operation | Pass through; capture only cheap kernel requestor metadata needed for post-create | Pass through; never pended | callback counter/reason only |
| Successful `IRP_MJ_CREATE` post-operation | At safe context, form bounded metadata record; original I/O result unchanged | Same | metadata projection or explicit drop counter |
| IRP-based, non-paging `IRP_MJ_READ` | Form metadata record when safe; always pass through | Eligible only after every admission check; otherwise pass through | record or fixed fail-open reason |
| Paging/synchronous-paging read | Pass through | Never pend | `Eg5cPagingReadPassThrough` |
| Fast I/O read | Pass through | Never pend | `Eg5cFastIoPassThrough` |
| Memory-mapped access | No coverage claim | Never pend | report as not verified |
| Unsafe IRQL/context or missing requestor | Pass through | Never pend | `Eg5cUnsafeContextPassThrough` or `Eg5cIdentityUnavailablePassThrough` |
| Write/truncate/delete/rename | No write callback and no content access | No write callback | a later open/read re-queries version metadata |

The filter registers no network, registry, process-token, packet or file-write enforcement callback. Process lifecycle notification is used solely to invalidate exact process generations and complete their pending reads.

## Process identity

The callback derives identity from `PFLT_CALLBACK_DATA`, never from a user-mode message:

1. Call `FltGetRequestorProcess(Data)` and `FltGetRequestorProcessId(Data)` and keep an owned process reference whenever the identity must outlive the callback.
2. Reject a null requestor, PID zero or PID greater than `INT32_MAX` as uncertain and pass through.
3. Call `PsGetProcessStartKey(Process)` and require a nonzero `ULONGLONG`. This is the primary in-kernel generation discriminator and is never supplied by user mode.
4. Call `PsGetProcessCreateTimeQuadPart(Process)` and require a positive signed 64-bit value. Serialize it unchanged as `ProcessCreateTimeFileTimeUtc`: 100-nanosecond intervals since `1601-01-01T00:00:00Z`.
5. Keep `(PID, start key, creation time)` together in every queue/pending key.
6. Revalidate the process generation at metadata publication and before any Gate 4 completion that would claim a current subject.
7. On process exit, terminalize only entries with the exact generation. A reused PID cannot inherit an old entry.

The collector maps the wire value to the existing Phase 5B identity only as `DateTimeOffset.FromFileTime(ProcessCreateTimeFileTimeUtc).ToUniversalTime()` and requires a lossless round trip to the original signed 64-bit FILETIME. The resulting UTC value is `ProcessIdentity.StartTime`; no local-time interpretation or millisecond truncation is allowed. The wire PID must be positive and representable by the existing Core `int` PID. `ProcessStartKey` remains kernel-only generation evidence and never replaces `(PID, StartTime)` at the Core boundary.

If the requestor pointer, PID, start key, creation FILETIME or lossless conversion is missing/invalid, or if a later recheck differs, the operation passes through and exactly one corresponding saturating counter is incremented: `Eg5cProcessPointerUnavailablePassThrough`, `Eg5cProcessIdInvalidPassThrough`, `Eg5cProcessStartKeyUnavailablePassThrough`, `Eg5cProcessCreateTimeInvalidPassThrough` or `Eg5cProcessGenerationChangedPassThrough`. One event selects the first failing check in that order; it never increments multiple reason counters.

Microsoft references:

- [FltGetRequestorProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetrequestorprocess)
- [FltGetRequestorProcessId](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetrequestorprocessid)
- [PsGetProcessStartKey](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessstartkey)
- [PsGetProcessCreateTimeQuadPart](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart)

## File identity and version

Two concepts remain separate:

- `FileObjectIdentity`: approved volume identity plus filesystem file ID. Rename and same-volume move preserve this identity. Hard links expose the same underlying file identity.
- `FileVersionEvidence`: creation, last-write and change times; end-of-file size; optional USN when safely available. A change in any present field creates a different version.

Rules:

- Path equality is never identity.
- A path is used only inside the driver to confirm the synthetic-root scope and derive a redacted basename; it is callback-local and then discarded.
- Delete/recreate at the same path must produce a different object identity or creation evidence and always a different version.
- Same-volume rename/move retains object identity even if version evidence changes.
- A hard link has the same object identity; a different display basename cannot create a separate authority.
- Truncate/write must be observed on the next safe open/read as changed size/time/USN evidence.
- Missing/ambiguous file ID, volume identity or required version evidence is fail-open with a fixed warning.
- The driver never reads, copies, scans, hashes or logs file bytes.
- The future trusted collector derives only the frozen `meta-v1` digest of the 80-byte metadata block; it is named a file-version metadata token, never a content hash. The driver itself performs no hash.

Every callback evaluates uncertainty in this fixed first-failure order: stopping/sequence state, volume tuple, I/O kind/context, process pointer/PID/start key/create time, file ID, file-version fields, receiver readiness, per-subject cap, global cap and queue insertion. The first failed check passes the operation through and increments exactly its one saturating reason counter; later checks are not evaluated for counters. Missing or unverifiable evidence can therefore never create zero or multiple reason increments for one admission attempt.

Gate 3 does not claim paging, cache-manager, section synchronization or memory-mapped coverage.

## Version-1 kernel wire contract

The driver/collector contract is independent of Named Pipe framing. Version 1 is a packed, fixed-width, little-endian ABI: both C and the independent user-mode parser use `#pragma pack(push, 1)` equivalents, no implicit alignment, no pointers, handles, flexible arrays or compiler-dependent `bool`. All integer fields are unsigned unless explicitly marked `int32`/`int64`.

### Byte order, generations and sequence exhaustion

Every integer uses little-endian byte order. A GUID uses the Windows in-memory/`Guid.ToByteArray()` layout: `Data1`, `Data2` and `Data3` are little-endian and the eight `Data4` bytes retain order. Therefore contract ID `2118132e-6271-4c66-af32-661a9f61fcea` is exactly:

```text
2e 13 18 21 71 62 66 4c af 32 66 1a 9f 61 fc ea
```

`BootInstance` is the existing trusted Service boot GUID, generated once per Service start and supplied in the 64-byte connect context. `MinifilterGeneration` is a nonzero GUID created with `ExUuidCreate` once during each successful driver load and maps directly to the existing Core `MinifilterGeneration`. `ReceiverSessionId` is a nonzero GUID created by the collector for each connection. None may be reused after restart/reconnect.

Driver/collector `MessageSequence`, `OperationSequence` and `DispositionSequence` start at `1`, increase by one in their documented scope, are limited to `INT64_MAX` for lossless mapping to existing Core `long` fields and never wrap. Driver `ConnectionGeneration` starts at `1` and is limited to `UINT64_MAX`. Before an increment would exceed its limit, the driver enters `SequenceExhausted`, clears readiness, fail-open-releases every held read and admits no new held read; the lab run fails and requires unload/rebuild review. Reconnect never resets driver sequence, operation sequence, counters or `MinifilterGeneration`.

### Connection context and common header

The user-mode `FilterConnectCommunicationPort` context is exactly 64 bytes:

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | `SizeBytes` | `64` |
| 4 | 2 | `Version` | `1` |
| 6 | 2 | `Reserved0` | zero |
| 8 | 16 | `ContractId` | exact wire-contract GUID |
| 24 | 16 | `BootInstance` | nonzero trusted Service boot GUID |
| 40 | 4 | `Flags` | zero in version 1 |
| 44 | 20 | `Reserved1` | all zero |

Every message begins with this exact 64-byte `EG5C_WIRE_HEADER`:

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | `SizeBytes` | exact type size below |
| 4 | 2 | `Version` | `1` |
| 6 | 2 | `MessageType` | closed enum below |
| 8 | 16 | `ContractId` | exact wire-contract GUID |
| 24 | 16 | `MinifilterGeneration` | exact current nonzero generation |
| 40 | 8 | `MessageSequence` | `1..INT64_MAX`, monotonic in sender direction |
| 48 | 8 | `ConnectionGeneration` | current nonzero driver-assigned connection generation |
| 56 | 4 | `Flags` | zero in version 1 |
| 60 | 4 | `Reserved0` | zero |

The only message-type values and sizes are:

| Code | Message | Direction | Exact bytes |
|---:|---|---|---:|
| `0x0001` | `MetadataEvent` | driver to collector | 320 |
| `0x0002` | `StatusSnapshot` | driver to collector | 512 |
| `0x0003` | `PendingRead` | driver to collector | 384 |
| `0x0004` | `ReadCompletion` | driver to collector | 384 |
| `0x8001` | `ReceiverReady` | collector to driver | 128 |
| `0x8002` | `ReadDisposition` | collector to driver | 320 |

Wrong-direction codes are invalid. No record may be shorter, longer or interpreted by a prefix.

### Closed enum and flag values

| Enum | Values |
|---|---|
| `MetadataOperation` | `OpenCreate=1`, `Read=2` |
| `ReceiverState` | `Disconnected=0`, `ConnectedNotReady=1`, `Ready=2`, `Stopping=3`, `SequenceExhausted=4` |
| `FileVersionFlags` | `HasUsn=0x00000001`; all other bits invalid |
| `FileReadDispositionKind` | `ReleaseAfterGateArmed=0`, `FailOpenRelease=1`, `Cancel=2` (exactly the current Core values) |
| `FileReadCompletionResult` | `Released=0`, `FailedOpen=1`, `Canceled=2` (exactly the current Core values) |
| `CompletionMode` | `ContinueToFileSystem=1`, `CompleteCanceled=2` |
| `TerminalReason` | `None=0`, `ValidRelease=1`, `ExplicitFailOpen=2`, `WindowsCanceled=3`, `ProcessExited=4`, `DeadlineExpired=5`, `ReceiverDisconnected=6`, `VolumeTeardown=7`, `DriverStopping=8`, `QueueCapacity=9`, `IdentityUncertain=10`, `SendFailed=11`, `SequenceExhausted=12`, `ExplicitCancel=13` |
| `PassThroughReason` | `None=0`, `ReFs=1`, `RemoteVolume=2`, `RemovableVolume=3`, `UnapprovedVolume=4`, `VolumeIdentityMismatch=5`, `UnsupportedVolume=6`, `PagingRead=7`, `FastIoRead=8`, `UnsafeContext=9`, `ProcessPointerUnavailable=10`, `ProcessIdInvalid=11`, `ProcessStartKeyUnavailable=12`, `ProcessCreateTimeInvalid=13`, `ProcessGenerationChanged=14`, `FileIdentityUnavailable=15`, `FileVersionUnavailable=16`, `MetadataQueueFull=17`, `ReceiverUnavailable=18`, `PendingCapacity=19`, `DeadlineExpired=20`, `InvalidControl=21`, `DriverStopping=22`, `SequenceExhausted=23`, `LabelRedacted=24` |
| `CounterFamily` | `PassThrough=1`, `Terminal=2` |

All common `Flags`, `ReceiverReady.ReadyFlags`, `ReadDisposition.ControlFlags` and `PendingRead.PendingFlags` are zero in version 1. Enum values not listed, unknown bits and a `TerminalReason.None` where a terminal reason is required are rejected.

### Shared identity blocks

`EG5C_PROCESS_IDENTITY_WIRE` is exactly 24 bytes:

| Relative offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | `ProcessId` | `1..INT32_MAX` |
| 4 | 4 | `Reserved0` | zero |
| 8 | 8 | `ProcessStartKey` | nonzero kernel value |
| 16 | 8 | `ProcessCreateTimeFileTimeUtc` (`int64`) | positive, losslessly convertible FILETIME |

`EG5C_FILE_VERSION_WIRE` is exactly 80 bytes:

| Relative offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 16 | `VolumeGuid` | exact approved mount-manager GUID |
| 16 | 4 | `VolumeSerialNumber` | exact approved NTFS serial |
| 20 | 4 | `FileVersionFlags` | only `HasUsn` allowed |
| 24 | 16 | `FileId` | nonzero 128-bit `FILE_ID_INFORMATION.FileId.Identifier` |
| 40 | 8 | `CreationTimeFileTimeUtc` (`int64`) | positive |
| 48 | 8 | `LastWriteTimeFileTimeUtc` (`int64`) | positive |
| 56 | 8 | `ChangeTimeFileTimeUtc` (`int64`) | positive |
| 64 | 8 | `EndOfFile` (`int64`) | nonnegative |
| 72 | 8 | `Usn` (`int64`) | positive iff `HasUsn`; otherwise zero |

The redacted label encoding is identical wherever present: `uint16 LabelLength` is `1..96`, followed by a 96-byte field. Exactly `LabelLength` bytes use `[A-Za-z0-9 ._()-]`; every remaining byte is zero. `/`, `\`, `:`, `.` and `..` as whole labels are invalid. An original basename that cannot be represented becomes the literal `redacted` and increments exactly one redaction counter; no raw Unicode/path bytes enter the wire.

### Type layouts

`MetadataEvent` (320 bytes):

| Offset | Width | Field |
|---:|---:|---|
| 0 | 64 | common header |
| 64 | 2 | `MetadataOperation` |
| 66 | 2 | `PassThroughReason` |
| 68 | 2 | `LabelLength` |
| 70 | 2 | `Reserved1` = 0 |
| 72 | 24 | process identity block |
| 96 | 80 | file-version block |
| 176 | 96 | zero-padded label |
| 272 | 8 | selected reason counter value |
| 280 | 8 | global metadata-dropped count |
| 288 | 32 | `ReservedTail` = 0 |

`StatusSnapshot` (512 bytes):

| Offset | Width | Field |
|---:|---:|---|
| 0 | 64 | common header |
| 64 | 2 | `ReceiverState` |
| 66 | 2 | `ReasonCounterCount`, `0..40` |
| 68 | 2 | pending depth, `0..64` |
| 70 | 2 | pending high-water mark, `0..64` |
| 72 | 2 | metadata depth, `0..1024` |
| 74 | 2 | metadata high-water mark, `0..1024` |
| 76 | 4 | `Reserved1` = 0 |
| 80 | 8 | current EgressGuard-owned allocated bytes, `0..1 MiB` |
| 88 | 8 | metadata delivered count |
| 96 | 8 | metadata dropped count |
| 104 | 8 | read-terminal count |
| 112 | 400 | 40 fixed 10-byte counter entries |

Each counter entry is `uint8 CounterFamily`, `uint8 ReasonCode`, `uint64 Value`. The code must be a non-`None` member of the selected `PassThroughReason` or `TerminalReason` family. The first `ReasonCounterCount` entries are unique and ascending by `(family, reason)`; unused entries are all zero. Forty entries cover all 24 pass-through and 13 terminal reasons with three reserved slots while retaining the exact 512-byte record. A state snapshot is exactly one `StatusSnapshot`, never a variable page: maximum count is one record, maximum size is 512 bytes, and it reports counts/high-water marks rather than enumerating live operation IDs. One initial snapshot is sent after connect and before readiness; later requests may each produce at most one snapshot.

`PendingRead` (384 bytes):

| Offset | Width | Field |
|---:|---:|---|
| 0 | 64 | common header |
| 64 | 16 | `BootInstance` |
| 80 | 16 | `ReceiverSessionId` |
| 96 | 16 | `OperationId` (Core `IntentId`) |
| 112 | 24 | process identity block |
| 136 | 80 | file-version block |
| 216 | 8 | `OperationSequence`, `1..INT64_MAX` |
| 224 | 8 | hold-start `KeQueryInterruptTimePrecise` units (100 ns) |
| 232 | 8 | hold-deadline units; start + `20,000,000` |
| 240 | 2 | `LabelLength` |
| 242 | 2 | `Reserved1` = 0 |
| 244 | 4 | `PendingFlags` = 0 |
| 248 | 96 | zero-padded label |
| 344 | 40 | `ReservedTail` = 0 |

`ReceiverReady` (128 bytes):

| Offset | Width | Field |
|---:|---:|---|
| 0 | 64 | common header for the current connection |
| 64 | 16 | exact connect-context `BootInstance` |
| 80 | 16 | new nonzero `ReceiverSessionId` |
| 96 | 8 | sequence of the validated initial `StatusSnapshot` |
| 104 | 4 | `ReadyFlags` = 0 |
| 108 | 20 | `ReservedTail` = 0 |

`ReadDisposition` (320 bytes):

| Offset | Width | Field |
|---:|---:|---|
| 0 | 64 | common header |
| 64 | 16 | `BootInstance` |
| 80 | 16 | `ReceiverSessionId` |
| 96 | 16 | `OperationId` |
| 112 | 24 | process identity block |
| 136 | 80 | file-version block |
| 216 | 8 | `OperationSequence` |
| 224 | 8 | `DispositionSequence`, `1..INT64_MAX` |
| 232 | 2 | `FileReadDispositionKind` |
| 234 | 2 | required `TerminalReason` |
| 236 | 2 | `GateAckPresent`, exactly `0` or `1` |
| 238 | 2 | `Reserved1` = 0 |
| 240 | 16 | `GateAckId` |
| 256 | 4 | `ControlFlags` = 0 |
| 260 | 60 | `ReservedTail` = 0 |

`ReleaseAfterGateArmed` requires `GateAckPresent=1` and a nonzero `GateAckId`; the other dispositions require `GateAckPresent=0` and 16 zero GUID bytes. The complete tuple `(BootInstance, MinifilterGeneration, ConnectionGeneration, ReceiverSessionId, OperationId, process block, file block, OperationSequence, DispositionSequence)` must match the live entry exactly.

The disposition/reason one-of is exact: `ReleaseAfterGateArmed` requires `ValidRelease`, `FailOpenRelease` requires `ExplicitFailOpen`, and `Cancel` requires `ExplicitCancel`. Driver-originated causes such as `WindowsCanceled`, disconnect, expiry or teardown never arrive as a collector `ReadDisposition`; the driver selects them only while winning its own terminal claim.

`ReadCompletion` (384 bytes):

| Offset | Width | Field |
|---:|---:|---|
| 0 | 64 | common header |
| 64 | 16 | `BootInstance` |
| 80 | 16 | `ReceiverSessionId` |
| 96 | 16 | nonzero `CompletionId` |
| 112 | 16 | `OperationId` |
| 128 | 24 | process identity block |
| 152 | 80 | file-version block |
| 232 | 8 | `OperationSequence` |
| 240 | 8 | `DispositionSequence` |
| 248 | 2 | `FileReadDispositionKind` |
| 250 | 2 | `FileReadCompletionResult` |
| 252 | 2 | `TerminalReason` |
| 254 | 2 | `CompletionMode` |
| 256 | 16 | `GateAckId`, zero when absent |
| 272 | 4 | `NtStatus` (`int32`) |
| 276 | 4 | `Reserved1` = 0 |
| 280 | 8 | `Information` |
| 288 | 8 | selected terminal-reason counter value |
| 296 | 88 | `ReservedTail` = 0 |

For `ContinueToFileSystem`, `NtStatus` and `Information` are zero sentinels meaning "no final filesystem result exists yet"; they never assert a successful zero-byte read. For `CompleteCanceled`, `NtStatus` is exactly `STATUS_CANCELLED (0xC0000120)` and `Information` is zero.

### Projection to existing Core types

No Core or Protocol shape change is required. The future trusted collector performs this closed projection:

- `MetadataOperation.OpenCreate/Read` maps to existing `FileActivityOperation.OpenCreate/Read`.
- `ProcessIdentity` is `(checked((int)ProcessId), DateTimeOffset.FromFileTime(ProcessCreateTimeFileTimeUtc).ToUniversalTime())`; `ProcessStartKey` remains an additional kernel binding.
- `FileVersionIdentity.VolumeId` is `volume:` plus the lower-case `N` form of `VolumeGuid`; `FileId` is `file:` plus 32 lower-case hex characters in the exact `FILE_ID_128.Identifier` byte order.
- File creation/write/change FILETIMEs are losslessly converted with `DateTimeOffset.FromFileTime(...).ToUniversalTime()`, `EndOfFile` becomes `SizeBytes`, and `Usn` is nullable according to `HasUsn`.
- `FileVersionIdentity.VersionToken` is `meta-v1:` plus lower-case SHA-256 of the exact 80-byte `EG5C_FILE_VERSION_WIRE`. It is explicitly a metadata-version token, never a content hash.
- `OperationId`, `BootInstance` and `OperationSequence` map to `FileReadIntent.IntentId`, `BootInstance` and `Sequence`. At receipt, Service creates its own trusted monotonic `ReadWindow` of at most 2,000 ms; the kernel's earlier/equal deadline remains independently authoritative, so clock-domain skew can only fail open sooner.
- `ReadDisposition` maps only from a constructor-valid existing `FileReadDisposition`; the wire drops no authority-bearing identity listed in the exact tuple above.
- `ReadCompletion.CompletionId`, operation/process/file/disposition fields, result and `MinifilterGeneration` map directly to `FileReadCompletionAck`; its `MonotonicSequence` is the checked positive `ReadCompletion.MessageSequence`.

`TerminalReason` maps to fixed Core `ReasonCode` text: `ValidRelease=read-released`, `ExplicitFailOpen=read-fail-open-explicit`, `WindowsCanceled=read-canceled`, `ProcessExited=read-fail-open-process-exited`, `DeadlineExpired=read-fail-open-deadline`, `ReceiverDisconnected=read-fail-open-receiver-disconnected`, `VolumeTeardown=read-fail-open-volume-teardown`, `DriverStopping=read-fail-open-driver-stopping`, `QueueCapacity=read-fail-open-capacity`, `IdentityUncertain=read-fail-open-identity`, `SendFailed=read-fail-open-send`, `SequenceExhausted=read-fail-open-sequence`, and `ExplicitCancel=read-canceled-explicit`. No free-form kernel string crosses the boundary.

The existing Core accepts `ReleaseAfterGateArmed/Released` as the successful arm-release completion. A `FailedOpen` or `Canceled` completion cannot be mistaken for that success; it drives/reports a terminal non-success path. Thus all three existing enum outcomes and bindings are representable without broadening authority or changing Core/Protocol.

### Compile-time and allocation proof

`Contracts.h` must contain `C_ASSERT`/`static_assert` checks for every exact `sizeof` above, `sizeof(EG5C_WIRE_HEADER)==64`, `sizeof(EG5C_PROCESS_IDENTITY_WIRE)==24`, `sizeof(EG5C_FILE_VERSION_WIRE)==80`, and every listed `FIELD_OFFSET`. The user-mode parser has equivalent size/offset tests against independently declared layouts and golden byte fixtures for each message and enum.

The largest record is the 512-byte status snapshot. The fixed metadata ring remains `1,024 * 512 = 524,288` bytes, the pending pool remains `64 * 1,024 = 65,536` bytes, and 64 completion tombstones at 128 bytes consume 8,192 bytes. Two 512-byte worker scratch records bring these explicit fixed buffers to 599,040 bytes, leaving 449,536 bytes inside the frozen 1 MiB driver-owned allocation ceiling for bounded instance/port/lock/bookkeeping state. Metadata ring plus all its bookkeeping must still fit the separate 640 KiB queue ceiling.

No record contains a raw/full path, file content, content hash, command line, user name/SID, access token, security descriptor, network endpoint, packet field, certificate, key or variable collection. Metadata PIDs are kernel-derived. A collector control record only echoes the exact driver-issued process block for binding and can never assert or replace process authority. Unknown version/type/direction/flag/size, nonzero reserved/padding bytes, malformed GUID/enum/identity/time/label/count or an inconsistent optional field is rejected before state lookup and increments exactly one invalid-control or invalid-record counter without retry loops or widening interpretation.

## Communication security

The minifilter uses a Filter Manager communication port named exactly `\EgressGuardMinifilterPort.v1`.

- Build the default security descriptor with `FltBuildDefaultSecurityDescriptor`, which limits access to system/administrator principals.
- Accept exactly one connection.
- Gate 2B is driver-to-collector metadata only; the collector has no mutation/decision authority. `ReadDisposition` is rejected until Gate 4 is explicitly enabled on the exact tested artifact.
- The connect callback validates the exact 64-byte context, ACL principal and sole-client limit, allocates no unbounded state, assigns a new nonzero `ConnectionGeneration` and enters `ConnectedNotReady`.
- The driver sends one 512-byte initial `StatusSnapshot`. Only after the collector validates it and sends an exact `ReceiverReady` bound to that snapshot, boot instance, minifilter generation and connection generation does the driver atomically enter `Ready` for that receiver session.
- Copy and validate every user buffer completely before any live-state lookup. Probe/copy faults, wrong direction, malformed size or nonzero reserved bytes increment exactly one invalid-control counter and cannot change readiness or pending state.
- Closing either endpoint atomically clears `Ready` before any drain work. The disconnect callback closes the driver client port and invokes the one-owner fail-open drain for entries bound to the lost receiver session. The next successful connect, and only that connect, increments `ConnectionGeneration` before publishing its initial snapshot.
- No reconnect can reset counters, sequence or boot generation.
- No secrets are sent or stored. Port ACL and endpoint identity are authorization, not a reason to skip field validation.

Microsoft references:

- [Communication between user mode and minifilters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode)
- [FltBuildDefaultSecurityDescriptor](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltbuilddefaultsecuritydescriptor)

## Metadata queue and fail-open behavior

The metadata queue is a fixed ring of 1,024 records allocated during startup. Record storage is at most 512 KiB and total queue allocation, including bookkeeping, must not exceed 640 KiB. Callbacks never allocate queue nodes, block on the service or create work items.

All allocations carrying the EgressGuard pool tags are tracked against one frozen 1 MiB global ceiling, including the metadata ring, pending-entry pool, instance/port state and bounded bookkeeping. Filter Manager-owned allocations are not hidden inside that counter; their references are tracked separately and must also return to zero. Allocation pressure never expands either limit and always takes the corresponding pass-through path.

One long-lived emitter path removes records in FIFO order and performs port sends with a 250 ms maximum wait. There is no thread/work item per event.

For each record:

- successful admission increments queued exactly once;
- successful delivery increments delivered exactly once;
- full queue passes the file operation through and increments overflow exactly once;
- disconnected/timeout delivery discards that record and increments disconnected/drop exactly once;
- unload drains remaining records as shutdown drops exactly once; and
- counters never decrease or wrap; at `uint64` maximum they saturate and expose a saturation flag.

Alert delivery is not required for I/O completion. A later connection receives a bounded status snapshot of counters and fixed reason enums. Failure to observe metadata never delays or fails the original Gate 2B operation.

## Gate 4 bounded pending model

Gate 4 may start only after Gate 3 passes on the exact driver artifact.

For the per-subject cap, the kernel structural subject is exactly the 24-byte process identity block `(ProcessId, ProcessStartKey, ProcessCreateTimeFileTimeUtc)`, compared byte-for-byte. This is intentionally at least as restrictive as user-mode grouping: one exact process generation may hold at most four reads across all files/app projections, and PID reuse cannot share the prior count.

Eligibility requires all of:

- approved local fixed NTFS synthetic volume and synthetic root;
- IRP-based `IRP_MJ_READ`;
- no paging/synchronous-paging/Fast I/O flag;
- safe Filter Manager callback context and IRQL;
- exact current process generation and complete file identity/version;
- exactly one ACL-valid collector connection in `Ready`, with current boot/minifilter/connection/receiver-session binding;
- fewer than 4 pending reads for that exact subject;
- fewer than 64 pending reads globally; and
- successful insertion into a per-instance cancel-safe `FltCbdq`.

Anything else passes through immediately with one fixed reason/counter. If no receiver is connected or the connection is only `ConnectedNotReady`, the operation is not held. At cap, the 5th subject read and 65th global read are not inserted and cannot evict a live operation.

Each entry is at most 1 KiB and is allocated from a fixed 64-entry pool. The entry contains no file bytes or raw path. One shared watchdog/completion path services all entries; no entry owns a thread or unbounded work item.

The driver uses an atomic lifecycle:

```text
Pending -> ClaimedByExactlyOneReason -> Completing -> Completed
```

Only the winner of the atomic claim may remove/complete the callback data and release references. Other concurrent reasons observe the terminal result and cause no side effect.

The driver pends only after the entry is fully bound to `(BootInstance, MinifilterGeneration, ConnectionGeneration, ReceiverSessionId, OperationId, process identity, file version, OperationSequence)`. The emitter prioritizes unsent `PendingRead` records over ordinary metadata. A 250 ms send timeout/failure or disconnect atomically claims the entry for fail-open release. No callback thread waits on user mode.

Each terminal cause has one locked outcome:

| Cause | Disposition/result | Filter Manager action | I/O status/information |
|---|---|---|---|
| valid current `ReleaseAfterGateArmed` with exact gate acknowledgement | `ReleaseAfterGateArmed` / `Released` | `FltCompletePendedPreOperation(Data, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL)` | not final; downstream filesystem performs the read |
| valid explicit `FailOpenRelease` | `FailOpenRelease` / `FailedOpen` | `FltCompletePendedPreOperation(Data, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL)` | not final; downstream filesystem performs the read |
| deadline at/after 2,000 ms | `FailOpenRelease` / `FailedOpen` | continue to filesystem | not final |
| exact process-generation exit, receiver disconnect/stop, instance/volume teardown or driver stop | `FailOpenRelease` / `FailedOpen` | continue to filesystem | not final |
| Windows I/O cancellation, or a valid exact `Cancel` that wins first | `Cancel` / `Canceled` | set `Data->IoStatus.Status=STATUS_CANCELLED`, `Information=0`, call `FltCompletePendedPreOperation(Data, FLT_PREOP_COMPLETE, NULL)` | `STATUS_CANCELLED`, 0 bytes |

The continue/fail-open branches never use `FLT_PREOP_COMPLETE` and never synthesize `STATUS_SUCCESS`/zero bytes. The cancellation branch never continues the canceled operation. If cancellation races another cause, the atomic claim decides one row: a cancellation winner completes canceled; any already-won release makes the cancellation callback a no-op. This maps without changing current Core/Protocol: wire enum values are identical to `FileReadDispositionKind`; `Released`, `FailedOpen` and `Canceled` are identical to `FileReadCompletionResult`; `ReadCompletion` carries the existing binding fields and current `MinifilterGeneration`.

A `ReadDisposition` must match every locked field and the next valid collector message/disposition sequence. A stale boot, minifilter generation, connection, receiver session, operation ID, process, file version or sequence is rejected and increments exactly one `InvalidControl` reason; it cannot claim or alter the live entry. An exact duplicate of an accepted disposition returns/re-emits the retained completion tombstone and has no second completion/release. The same identifier or sequence with different bytes is invalid. After a tombstone ages out of the fixed 64-entry ring, a replay is simply unknown/stale and still cannot affect live state.

Deadline equality is expired and fail-open. Queue capacity, readiness loss, publication failure and shutdown uncertainty are fail-open. No path can wait indefinitely.

The model follows Microsoft's `FltCbdqInitialize`/`FltCbdqInsertIo` cancel-safe queue guidance. Tests must prove callback-data, file-object, process and instance references return to zero.

Reference: [Processing I/O operations](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/processing-i-o-operations).

## Deterministic test design

Host-safe contract tests may validate pure parsing/state logic. Every actual minifilter, installation, volume and Driver Verifier test runs only in the approved VM.

No race verdict uses `Thread.Sleep`, `Task.Delay` or timing luck. Tests use kernel/user events, explicit barriers, injected monotonic test clocks where the code is pure, and observable queue-depth transitions.

### Gate 2A tests

- `Release|x64` WDK compile succeeds on the frozen temporary Windows runner with warnings as errors.
- Driver code analysis, CodeQL, banned-API/privacy scans and every `C_ASSERT`/`static_assert` size/offset check pass.
- An independent user-mode parser accepts golden bytes for all six messages and rejects every wrong size, offset, enum, flag, GUID byte order, reserved byte and label boundary.
- Pure state tests cover sequence increment/exhaustion, one-owner terminal claims, stale/duplicate controls and all capacity boundaries without loading a driver.
- Workflow inspection proves no complete INF/catalog/package, binary artifact upload, install/load/service/Verifier/security command or primary-workstation target.
- The ephemeral `.sys` digest is recorded in sanitized output and the binary/intermediates disappear with the worker.

### Gate 2B tests

- Driver registration/start/unload and exact-owned reinstall using the returned Microsoft-signed package.
- Failure injection after each startup step proves reverse cleanup; `FltCreateCommunicationPort` is never called before `FltRegisterFilter`, `FltStartFiltering` is last, and unload calls `FltUnregisterFilter` once without a preceding detach loop.
- One Filter Manager client allowed; second rejected.
- Connect context, version, type, direction, exact size (including zero-length/truncated/oversized input), GUID layout, flag, reserved-field and every boundary length accepted/rejected deterministically.
- The initial snapshot plus exact `ReceiverReady` is required before state becomes ready; malformed/stale readiness never enables holding.
- Open/read callback pass-through leaves original status/information unchanged.
- 1,024 metadata records admitted; record 1,025 fails open and increments exactly one overflow.
- Disconnected and send-timeout paths remain pass-through and bounded.
- The approved `(VolumeGuid, VolumeSerialNumber)` tuple attaches/becomes eligible; label/path equality cannot authorize it. ReFS, remote, removable, wrong GUID, wrong serial and unknown types pass through with one exact reason.
- Source/record privacy scans prove no raw path/content/content-hash field.
- Unload returns queue, ports, workers, callbacks, allocations and Filter Manager references to zero.

### Gate 3 tests

All files are generated under the synthetic root:

- same-volume rename and move preserve object identity;
- hard links share object identity;
- truncate and write change version evidence;
- delete/recreate at the same name is a new object/version;
- equal path does not imply equal file;
- process exit invalidates its generation;
- forced PID reuse fixture cannot inherit prior authority;
- stale version records are rejected;
- uncertain identity passes through and warns;
- NTFS is supported and ReFS/remote/removable/other types are explicit pass-through; and
- instrumentation/source inspection proves zero content reads/hashes.

Reports must call a derived token a metadata-version token, not a content hash, and must state paging/memory-mapped coverage is not verified.

### Gate 4 tests

- cancel versus disposition at an explicit barrier;
- disconnect before admission proves immediate pass-through and no pending entry;
- disconnect after insertion but before/after `PendingRead` publication proves one fail-open continuation and zero leaked entry;
- stale boot/minifilter/connection/receiver/operation/process/file/sequence controls cannot mutate a live read;
- an exact duplicate disposition returns the same tombstone and never completes twice; same ID/sequence with changed bytes is rejected;
- process exit versus disposition;
- instance/volume teardown;
- service disconnect/stop;
- driver unload;
- deadline immediately before, exactly at and after 2,000 ms;
- explicit allow and explicit fail-open both continue the original read to the filesystem, never synthesize a successful zero-byte result;
- Windows cancellation produces exactly `STATUS_CANCELLED` and zero information;
- every listed terminal reason produces its one locked disposition/result/completion mode and exactly one reason counter;
- deterministic barriers cover cancellation against each other terminal cause, with one winner and one completion;
- 4 reads per byte-equal process-generation subject across different files and fail-open 5th; a reused PID/start-key/time mismatch has a separate subject but no inherited authority;
- 64 reads global and fail-open 65th;
- concurrent multi-read completion with one owner each;
- duplicate disposition/completion;
- no live-entry eviction at cap;
- final pending depth and every owned reference/resource equal zero; and
- VM restore after an injected failed run.

A bugcheck, hang, incomplete read, verifier violation, leaked reference or nonzero final resource is a failed run followed by restore, never PASS.

## Driver verification and lab evidence

The exact Release x64 artifact is validated in this order:

1. Gate 2A temporary-runner repository Release build and at least the existing 143 tests;
2. Gate 2A exact WDK source build, code analysis, CodeQL, pure contract tests and ephemeral digest/deletion evidence;
3. Gate 2B clean-checkpoint restore and security-state verification;
4. rebuild from the exact Gate 2A source commit with the Microsoft altitude, create the controlled package and submit that digest;
5. INF validation with WDK `InfVerif` and Microsoft signature verification of the returned exact package with `signtool verify /v /kp`;
6. exact-owned install/load/stop/unload/uninstall/reinstall only in the approved VM;
7. Driver Verifier targeting only `EgressGuard.Minifilter.sys`;
8. File System Filter Verification targeting only that driver;
9. Gate 2B/3/4 matrices;
10. zero-resource and ownership inspection;
11. source/Git privacy and artifact scan; and
12. final clean-checkpoint restore and host-unchanged evidence.

On Windows 11, the minimal filter-specific verifier set uses I/O Verification and File System Filter Verification; the broader standard profile may also be run against only the EgressGuard binary. `ntoskrnl` and unrelated drivers are never selected.

References:

- [File System Filter Verification](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/file-system-filter-verification)
- [Tools for minifilter development and testing](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/development-and-testing-tools)
- [Selecting drivers to be verified](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/selecting-drivers-to-be-verified)

Raw build logs, ETL, dumps, certificates, keys, binaries, Driver Store exports, setup logs and real paths remain outside Git. The report records only exact commit/artifact hashes, sanitized VM/checkpoint identifiers, commands, counters and verdicts.

## Safety-to-source/test mapping

The paths are planned Gate 2A-4 paths, not files authorized by Gate 1.

| Safety requirement | Planned source | Planned deterministic/lab evidence |
|---|---|---|
| Gate 2A build-only boundary | project, non-installable INF template, build workflow | source compiles/analyzes; no package/artifact upload/install/load command |
| Register with Filter Manager, demand start | `Driver.c`, Gate 2B INF | startup failure barriers and registration/load/unload/reinstall |
| Correct register/port/start/unregister order | `Driver.c`, `Communication.c` | injected failure after each step; no pre-unregister detach loop |
| Observe only create/read at Gate 2B | `Filter.c` | original callback status/information unchanged |
| NTFS approved volume only | `Filter.c`, `Ownership.h` | NTFS attach plus five pass-through reason cases |
| Kernel-derived exact process generation | `Identity.c` | process exit and PID-reuse barriers |
| Metadata-only file identity/version | `Identity.c`, `Contracts.h` | rename/link/mutate/recreate matrix and privacy scan |
| No raw path/content outside driver | `Identity.c`, `Contracts.h`, `Communication.c` | reflection/source/wire scan, maximum record fixture |
| Version/length/enum/count validation | `Contracts.h`, `Communication.c` | invalid and boundary corpus for every field |
| Restricted one-ready-client port | `Communication.c` | LocalSystem/admin connection plus snapshot/ready succeeds; unauthorized/second/stale ready rejected |
| Bounded nonblocking metadata queue | `MetadataQueue.c` | 1,024/cap+1, disconnect, timeout, exact counters |
| No event-specific threads/work | `MetadataQueue.c`, `Driver.c` | worker-count invariant under flood |
| Exact-owned cleanup | `Ownership.h`, `Driver.c`, INF | unload/uninstall affects only allowlisted IDs; all counters zero |
| File identity independent of path | `Identity.c` | rename/move/delete-recreate tests |
| Hard links share identity | `Identity.c` | two names, one file ID |
| Version mutation invalidation | `Identity.c` | size/write/change/USN cases |
| Unsupported uncertainty fails open | `Filter.c`, `Identity.c` | injected missing metadata and unsupported volumes |
| `FltCbdq` cancel-safe pending | `PendingReads.c` | disconnect-before/after, cancel/decision/teardown barriers and exact filesystem action |
| 4 subject / 64 global | `PendingReads.c` | exact cap and cap+1 without eviction |
| 2-second equality deadline | `PendingReads.c` | before/equal/after injected clock cases |
| One completion owner | `PendingReads.c` | concurrent terminal reasons, duplicate calls |
| Zero teardown resources | all driver modules | queue/ref/port/thread/allocation counters zero |
| Driver Verifier scope only EgressGuard | lab runbook/report | exact verifier selection and clean result |
| No network work in Phase 5C | project/source allowlist | no WFP/firewall/network driver symbols or projects |

## Gate transitions

### Gate 1 exit

Requires a different qualified Windows kernel/security reviewer to approve this exact design, the frozen Gate 2A toolchain/runner and the explicit no-package/no-install/no-load boundary. Gate 1 does not require a built artifact, Microsoft signing, an assigned altitude or a runtime-ready VM. Until this review is recorded: commit only the two Phase 5C design documents, keep the PR Draft and report `GATE 1 REVIEW REQUIRED`.

### Gate 2A exit

Requires source at the approved allowlist, exact x64 WDK compile, driver code analysis, CodeQL, pure contract/race tests, compile-time layout checks and privacy/bounds scans on a temporary Windows runner. Evidence records source/tool versions and ephemeral output digest/deletion. Gate 2A fails if it creates a complete INF/catalog/installable package, uploads a binary product, installs/registers/loads a driver, changes Windows security or targets the primary workstation.

### Gate 2B entry and exit

The controlled transition from 2A to 2B requires the named lab owner/reviewer, exact VM/build/security state, clean checkpoint and restore drill, isolated synthetic VHDX identity, crash/debug ownership, Microsoft-assigned altitude and approved Partner Center route. It rebuilds/packages/submits the candidate outside Git and authorizes no installation or execution. Gate 2B begins only after the exact package has returned Microsoft-signed and passes INF/signature digest verification. Rebuilding any package file invalidates that signature evidence and returns the work to the transition.

Gate 2B exits only after the observe-only callback, connection/readiness, wire/bounds/privacy, startup-failure, exact-owned install/reinstall/unload, Driver Verifier/Filter Verifier and zero-owned-cleanup matrices pass on that exact signed VM artifact. No pending read is allowed in Gate 2B.

### Gate 3 exit

Requires every identity/mutation case on synthetic files to pass with honest unsupported-coverage wording and no content read/hash.

### Gate 4 exit

Requires every bounded pending/cancellation/deadline/teardown test to pass, no bugcheck/hang, and all owned resources zero before and after reinstall/rollback.

After Gate 4, a different Sol High must review the exact full diff and evidence. The implementation author cannot issue the independent final verdict.

## Mandatory stop conditions

Stop as `BLOCKED` if any of these occurs:

- Gate 1 independent approval is missing before Gate 2A source begins;
- Gate 2A attempts to package, install, register, load or execute a driver, or retain/upload its `.sys` as a product;
- lab, altitude, recovery or transition approval is missing when controlled packaging would begin, or returned signing/runtime approval is missing when Gate 2B execution would begin;
- source/install/test would touch the primary workstation;
- Secure Boot, HVCI, Application Control or another Windows protection must be weakened;
- a non-approved or unsupported volume is attached or pended;
- identity falls back to PID-only or path equality;
- content/path/personal/signing data enters a record, log or Git;
- a queue/allocation/wait/thread becomes unbounded;
- an operation can complete twice or remain pending indefinitely;
- a bugcheck, deadlock, hang, incomplete read, verifier finding or resource leak occurs;
- a fixed limit is changed after observing a test; or
- implementation crosses into WFP/network Phase 5D.

## Independent review record

| Field | Value |
|---|---|
| Design commit | `PENDING` |
| Reviewer | `PENDING - must differ from author` |
| Review date | `PENDING` |
| Gate 2A build-only boundary verdict | `PENDING` |
| Gate 2B lab prerequisite verdict | `PENDING` |
| Design/safety verdict | `PENDING` |
| Findings | `PENDING` |

The current author records no PASS verdict. Gate 1 remains `GATE 1 REVIEW REQUIRED`; Gate 2B remains `LAB APPROVAL REQUIRED`.
