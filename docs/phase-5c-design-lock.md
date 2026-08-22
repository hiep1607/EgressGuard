# Phase 5C minifilter design lock

Status: Gate 1 design; `LAB APPROVAL REQUIRED`.

This design is file-only and VM-only. It does not authorize creation of `drivers/`, driver build/sign/install/load, or Windows security changes until `docs/phase-5c-lab-prerequisites.md` is independently approved for an exact lab artifact.

## Scope and claim boundary

Phase 5C will prove a metadata-only Windows file-system minifilter in four ordered gates:

1. approve an isolated, recoverable kernel lab and this design;
2. register an observe-only minifilter that always passes I/O through;
3. prove exact process/file identity and mutation semantics using synthetic files; and
4. pend only eligible IRP-based non-paging reads in a bounded cancel-safe queue.

Phase 5C does not implement WFP, inspect network traffic, change Windows Firewall, call the Phase 5B decision UI, persist allow rules, install a product, or claim to prevent a real upload. It neither reads nor hashes file content. Memory-mapped, paging and Fast I/O reads remain explicitly outside verified coverage.

All Gate 2-4 execution occurs only inside the independently approved VM. Development and ordinary .NET validation may run on the host, but no driver command may target the host.

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

Every Gate 2 operation: pass through immediately.
Gate 4 eligible reads: bounded FltCbdq pending, then exactly one completion.
Anything unsupported, uncertain, full, disconnected or expired: pass through + exact counter.
```

There is no network component in this architecture.

## Planned source ownership

No path in this table exists at Gate 1. It is the allowlist for later approved gates.

| Planned path | Responsibility |
|---|---|
| `drivers/EgressGuard.Minifilter/EgressGuard.Minifilter.vcxproj` | x64 WDK minifilter build only |
| `drivers/EgressGuard.Minifilter/EgressGuard.Minifilter.inf` | demand-start package, Microsoft-assigned altitude only |
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

No Core, Protocol, Service, UI, persistence, Windows/firewall implementation, simulator, product installer, workflow or package lock is planned for Phase 5C.

## Registration and lifecycle

The future minifilter is a Filter Manager minifilter, not a legacy file-system filter.

Startup order:

1. Validate compile-time/runtime contract constants and initialize exact resource counters.
2. Allocate the fixed metadata ring and fixed pending-entry pool.
3. Initialize the single shutdown event, emitter path and shared watchdog/completion path.
4. Build the default communication-port security descriptor for system/administrator access.
5. Create the server port with maximum connection count `1`.
6. Register process-exit notification.
7. Call `FltRegisterFilter` with explicit create/read and lifecycle callbacks.
8. Start the bounded worker paths.
9. Call `FltStartFiltering` last.

Any startup failure unwinds only completed EgressGuard-owned steps in reverse order and leaves no registered filter, port, callback, worker or pool allocation.

Normal unload order:

1. Atomically reject new queue/pending admission.
2. Close the communication server/client ports.
3. Drain metadata records as dropped/disconnected without waiting indefinitely.
4. Fail-open complete every pending operation exactly once.
5. Stop the shared watchdog and emitter paths.
6. Remove the process-exit callback.
7. Tear down instances and release every Filter Manager reference.
8. Call `FltUnregisterFilter`.
9. Free fixed pools and assert all owned depths/references/workers are zero.

`FilterUnloadCallback` is mandatory. Explicit detach and volume teardown use the same idempotent drain primitive. Cleanup never targets an object outside the exact identifiers in the lab prerequisites.

Microsoft lifecycle references:

- [Filter Manager concepts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)
- [Loading and unloading a minifilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/loading-and-unloading)

## Volume admission

`InstanceSetupCallback` performs bounded, local classification only. It performs no IPC, waits or thread synchronization.

Attachment is accepted only when all are true:

- `VolumeFilesystemType == FLT_FSTYPE_NTFS`;
- `VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM`;
- the storage stack is local and fixed, not remote or removable;
- the volume identity exactly equals the owner-approved synthetic VHDX identity; and
- the instance is the single EgressGuard default instance at the Microsoft-assigned altitude.

Every other case returns `STATUS_FLT_DO_NOT_ATTACH`, so file I/O naturally passes through. A fixed reason enum increments one monotonic warning counter at the volume-admission attempt:

| Reason enum | Condition |
|---|---|
| `Eg5cVolumeRefsPassThrough` | ReFS |
| `Eg5cVolumeRemotePassThrough` | network/remote volume |
| `Eg5cVolumeRemovablePassThrough` | removable media |
| `Eg5cVolumeNotApprovedPassThrough` | local volume not equal to the approved synthetic VHDX |
| `Eg5cVolumeUnsupportedPassThrough` | any other filesystem/device type or uncertain classification |

No unsupported volume is silently treated as NTFS and no per-file enforcement claim is made for a volume to which the instance is not attached.

## Callback matrix

| Operation/context | Gate 2 | Gate 4 | Evidence |
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

1. Obtain the requestor process and PID with Filter Manager requestor APIs.
2. Reject a null requestor or PID zero as uncertain and pass through.
3. Record the kernel process start key as the primary in-kernel generation discriminator.
4. Record the process creation time for mapping to Phase 5B `ProcessIdentity.StartTime`.
5. Keep `(PID, start key, creation time)` together in every queue/pending key.
6. Revalidate the process generation at metadata publication and before any Gate 4 completion that would claim a current subject.
7. On process exit, terminalize only entries with the exact generation. A reused PID cannot inherit an old entry.

The wire PID must be positive and representable by the existing Core `int` PID. The start key never comes from the collector/service and is never accepted as a user assertion.

Microsoft references:

- [FltGetRequestorProcessId](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetrequestorprocessid)
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
- If a metadata digest/HMAC is added by a later trusted service, it must be named a file-version metadata token, never a content hash.

Gate 3 does not claim paging, cache-manager, section synchronization or memory-mapped coverage.

## Version-1 kernel wire contract

The driver/collector contract is independent of Named Pipe framing. It uses fixed-width little-endian structures with no pointers, handles, flexible arrays or compiler-dependent booleans.

Every record begins with:

- `uint32 SizeBytes`;
- `uint16 Version` equal to `1`;
- `uint16 MessageType` from a closed enum;
- `GUID ContractId` equal to `2118132e-6271-4c66-af32-661a9f61fcea`;
- `uint64 BootGeneration`;
- `uint64 Sequence`, strictly increasing and nonzero; and
- `uint32 Flags` whose unknown bits are rejected.

The metadata payload contains only:

- operation enum `OpenCreate` or `Read`;
- positive PID, process start key and process creation time;
- approved volume identifier and 128-bit file ID;
- creation, last-write and change times;
- end-of-file size;
- optional USN plus a presence flag;
- redacted file label, ASCII, 1-96 bytes; and
- fixed volume/operation/reason enums and exact monotonic counters.

No record contains a raw/full path, file content, content hash, command line, user name/SID, access token, security descriptor, caller-supplied PID, network endpoint, packet field, certificate, key or variable unbounded collection.

Validation occurs both in kernel and in the lab collector:

- exact version, contract ID, message type and structure size;
- maximum record size 512 bytes and exact type-specific size;
- all reserved fields zero;
- closed enums/flags only;
- positive PID and nonzero process generation/sequence;
- times, size and optional-USN invariants;
- ASCII label length and no `:`, `/`, `\`, root, `.` or `..` path syntax; and
- saturation-safe counters.

Unknown version/type/flag/size is rejected by the collector and counted by the driver without retry loops or widening interpretation.

## Communication security

The minifilter uses a Filter Manager communication port named exactly `\EgressGuardMinifilterPort.v1`.

- Build the default security descriptor with `FltBuildDefaultSecurityDescriptor`, which limits access to system/administrator principals.
- Accept exactly one connection.
- Gate 2 is driver-to-collector metadata only; the collector has no mutation/decision authority.
- Copy and validate every user buffer before use. Gate 4 control messages, if later approved, use a separate closed message enum, exact lengths and driver-owned current state.
- Closing either endpoint transitions to disconnected; callbacks continue pass-through and queue/drop counters remain bounded.
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

Alert delivery is not required for I/O completion. A later connection receives a bounded status snapshot of counters and fixed reason enums. Failure to observe metadata never delays or fails the original Gate 2 operation.

## Gate 4 bounded pending model

Gate 4 may start only after Gate 3 passes on the exact driver artifact.

Eligibility requires all of:

- approved local fixed NTFS synthetic volume and synthetic root;
- IRP-based `IRP_MJ_READ`;
- no paging/synchronous-paging/Fast I/O flag;
- safe Filter Manager callback context and IRQL;
- exact current process generation and complete file identity/version;
- fewer than 4 pending reads for that exact subject;
- fewer than 64 pending reads globally; and
- successful insertion into a per-instance cancel-safe `FltCbdq`.

Anything else passes through immediately with one fixed reason/counter. At cap, the 5th subject read and 65th global read are not inserted and cannot evict a live operation.

Each entry is at most 1 KiB and is allocated from a fixed 64-entry pool. The entry contains no file bytes or raw path. One shared watchdog/completion path services all entries; no entry owns a thread or unbounded work item.

The driver uses an atomic lifecycle:

```text
Pending -> ClaimedByExactlyOneReason -> Completing -> Completed
```

Only the winner of the atomic claim may remove/complete the callback data and release references. Other concurrent reasons observe the terminal result and cause no side effect.

Terminal reasons are:

- valid current acknowledgement/disposition;
- explicit allow disposition;
- I/O cancellation;
- exact process-generation exit;
- instance/volume teardown;
- service disconnect/stop;
- driver unload; and
- deadline at or after exactly 2,000 ms.

Deadline equality is expired and fail-open. Queue capacity and shutdown failures are fail-open. Duplicate dispositions are idempotent. No path can wait indefinitely.

The model follows Microsoft's `FltCbdqInitialize`/`FltCbdqInsertIo` cancel-safe queue guidance. Tests must prove callback-data, file-object, process and instance references return to zero.

Reference: [Processing I/O operations](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/processing-i-o-operations).

## Deterministic test design

Host-safe contract tests may validate pure parsing/state logic. Every actual minifilter, installation, volume and Driver Verifier test runs only in the approved VM.

No race verdict uses `Thread.Sleep`, `Task.Delay` or timing luck. Tests use kernel/user events, explicit barriers, injected monotonic test clocks where the code is pure, and observable queue-depth transitions.

### Gate 2 tests

- Driver registration/start/unload and exact-owned reinstall.
- One Filter Manager client allowed; second rejected.
- Version, type, flag, reserved-field and every boundary length accepted/rejected deterministically.
- Open/read callback pass-through leaves original status/information unchanged.
- 1,024 metadata records admitted; record 1,025 fails open and increments exactly one overflow.
- Disconnected and send-timeout paths remain pass-through and bounded.
- NTFS approved volume attaches; ReFS, remote, removable, unapproved NTFS and unknown types do not attach and expose fixed reason counters.
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
- process exit versus disposition;
- instance/volume teardown;
- service disconnect/stop;
- driver unload;
- deadline immediately before, exactly at and after 2,000 ms;
- 4 reads per subject and fail-open 5th;
- 64 reads global and fail-open 65th;
- concurrent multi-read completion with one owner each;
- duplicate disposition/completion;
- no live-entry eviction at cap;
- final pending depth and every owned reference/resource equal zero; and
- VM restore after an injected failed run.

A bugcheck, hang, incomplete read, verifier violation, leaked reference or nonzero final resource is a failed run followed by restore, never PASS.

## Driver verification and lab evidence

The exact Release x64 artifact is validated in this order:

1. clean-checkpoint restore and security-state verification;
2. repository Release build and at least the existing 143 tests;
3. exact WDK driver build;
4. INF validation with WDK `InfVerif`;
5. Microsoft signature verification with `signtool verify /v /kp`;
6. exact-owned install/load/stop/unload/uninstall/reinstall;
7. Driver Verifier targeting only `EgressGuard.Minifilter.sys`;
8. File System Filter Verification targeting only that driver;
9. Gate 2/3/4 matrices;
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

The paths are planned Gate 2-4 paths, not files authorized by Gate 1.

| Safety requirement | Planned source | Planned deterministic/lab evidence |
|---|---|---|
| Register with Filter Manager, demand start | `Driver.c`, INF | registration/load/unload/reinstall |
| Observe only create/read at Gate 2 | `Filter.c` | original callback status/information unchanged |
| NTFS approved volume only | `Filter.c`, `Ownership.h` | NTFS attach plus five pass-through reason cases |
| Kernel-derived exact process generation | `Identity.c` | process exit and PID-reuse barriers |
| Metadata-only file identity/version | `Identity.c`, `Contracts.h` | rename/link/mutate/recreate matrix and privacy scan |
| No raw path/content outside driver | `Identity.c`, `Contracts.h`, `Communication.c` | reflection/source/wire scan, maximum record fixture |
| Version/length/enum/count validation | `Contracts.h`, `Communication.c` | invalid and boundary corpus for every field |
| Restricted one-client port | `Communication.c` | LocalSystem/admin client succeeds; unauthorized/second client rejected |
| Bounded nonblocking metadata queue | `MetadataQueue.c` | 1,024/cap+1, disconnect, timeout, exact counters |
| No event-specific threads/work | `MetadataQueue.c`, `Driver.c` | worker-count invariant under flood |
| Exact-owned cleanup | `Ownership.h`, `Driver.c`, INF | unload/uninstall affects only allowlisted IDs; all counters zero |
| File identity independent of path | `Identity.c` | rename/move/delete-recreate tests |
| Hard links share identity | `Identity.c` | two names, one file ID |
| Version mutation invalidation | `Identity.c` | size/write/change/USN cases |
| Unsupported uncertainty fails open | `Filter.c`, `Identity.c` | injected missing metadata and unsupported volumes |
| `FltCbdq` cancel-safe pending | `PendingReads.c` | cancel/decision/teardown barriers |
| 4 subject / 64 global | `PendingReads.c` | exact cap and cap+1 without eviction |
| 2-second equality deadline | `PendingReads.c` | before/equal/after injected clock cases |
| One completion owner | `PendingReads.c` | concurrent terminal reasons, duplicate calls |
| Zero teardown resources | all driver modules | queue/ref/port/thread/allocation counters zero |
| Driver Verifier scope only EgressGuard | lab runbook/report | exact verifier selection and clean result |
| No network work in Phase 5C | project/source allowlist | no WFP/firewall/network driver symbols or projects |

## Gate transitions

### Gate 1 exit

Requires all prerequisite rows approved by the VM/security owner and a different qualified Windows kernel reviewer on the exact Gate 1 commit. Until then: commit only the two Phase 5C design documents, open a Draft PR and report `LAB APPROVAL REQUIRED`.

### Gate 2 exit

Requires observe-only source plus real approved-VM evidence: Microsoft-signed exact artifact, INF/signature checks, pass-through callback tests, bounds/privacy tests, Driver Verifier/Filter Verifier and zero-owned cleanup. No pending read is allowed in Gate 2.

### Gate 3 exit

Requires every identity/mutation case on synthetic files to pass with honest unsupported-coverage wording and no content read/hash.

### Gate 4 exit

Requires every bounded pending/cancellation/deadline/teardown test to pass, no bugcheck/hang, and all owned resources zero before and after reinstall/rollback.

After Gate 4, a different Sol High must review the exact full diff and evidence. The implementation author cannot issue the independent final verdict.

## Mandatory stop conditions

Stop as `BLOCKED` if any of these occurs:

- lab, signing, altitude, recovery or independent approval is missing;
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
| Lab prerequisite verdict | `PENDING` |
| Design/safety verdict | `PENDING` |
| Findings | `PENDING` |

The current author records no PASS verdict. Gate 1 remains `LAB APPROVAL REQUIRED`.
