# Phase 5C isolated minifilter lab prerequisites

Status: `GATE 1 REVIEW REQUIRED`; Gate 2B remains `LAB APPROVAL REQUIRED`.

This document is not approval to create or run a driver. After a different qualified reviewer approves Gate 1 on an exact commit, Gate 2A may create source, compile it and run build-time analysis under the non-runtime restrictions below. Signing, altitude, packaging and lab execution are not prerequisites for Gate 2A and do not block that build-only work.

Baseline source commit: `7523c42e7894ae4e8c9ed436a0936984ae46945f`.

## Gate decision

Phase 5C uses five ordered gates with a deliberate build/runtime split:

| Gate | Permitted work | Entry condition | Explicit prohibition |
|---|---|---|---|
| 1 | Review this design and the safety/lab plan | Documentation only | No driver source, build, package, install or load |
| 2A | Create source, compile x64, run driver code analysis/CodeQL and pure-logic tests | Gate 1 approved on the exact commit | No complete INF, installable package, install, service registration or driver load |
| 2B | Install and execute only the exact rebuilt, packaged candidate returned Microsoft-signed | External lab rows approved, Microsoft altitude assigned and exact returned package signature/digest verified | No execution on GitHub runners or the primary workstation |
| 3 | Prove exact file/volume/process identity with synthetic data | Gate 2B observe-only matrix passes on the exact signed artifact | No read pending |
| 4 | Prove bounded, cancel-safe read hold/release | Gate 3 identity matrix passes on the same artifact | No network/WFP scope |

The current branch is blocked at Gate 1 because no different qualified Windows kernel reviewer has approved this exact design. The missing runtime-lab, altitude and signing rows below are hard blockers for Gate 2B, but they are not blockers for Gate 2A after Gate 1 approval. This removes the former circular condition in which source was needed to obtain signing but source creation was forbidden until signing already existed.

| Prerequisite | Required value or evidence | Required before | Current state |
|---|---|---|---|
| Independent design/security reviewer | A different qualified Windows kernel reviewer, identified by durable handle, reviewing the exact Gate 1 commit and the Gate 2A restrictions | Gate 2A | `MISSING` |
| Frozen build environment | Exact supported Visual Studio/SDK/WDK versions and a build-only runner with no install/load step | Gate 2A | `CANDIDATE ONLY` |
| Lab owner | Named human or team with authority over the disposable VM and recovery procedure | Gate 2B | `MISSING` |
| Hypervisor and VM | Dedicated Generation 2 x64 Windows VM; not a developer workstation; no unrelated workloads or personal data | Gate 2B | `UNAPPROVED` |
| Guest OS | Exact Windows edition, release, full build and x64 architecture captured from the approved VM | Gate 2B | `MISSING` |
| Clean recovery point | Hypervisor checkpoint/image identifier, creation time and immutable parent/image identity | Gate 2B | `MISSING` |
| Restore proof | Dated drill restoring that exact recovery point, booting successfully and showing the expected clean state | Gate 2B | `NOT RUN` |
| Network isolation | Private lab network; no route to personal networks; no host personal-folder sharing | Gate 2B | `UNVERIFIED` |
| Signing route and returned artifact | Organization-approved Partner Center attestation or WHCP/HLK route plus the exact returned Microsoft-signed package/digest | Gate 2B | `MISSING` |
| Secure Boot | Enabled before driver load and unchanged throughout the accepted run | Gate 2B runtime | `UNVERIFIED` |
| Application Control/HVCI | Existing policy and Memory Integrity recorded and left enabled/unchanged | Gate 2B runtime | `UNVERIFIED` |
| Filter altitude | Microsoft-assigned altitude and allocation evidence for this product/filter | Gate 2A-to-2B packaging transition | `MISSING` |
| Crash capture | Kernel dump configuration and debugger/recovery owner; dumps stored outside Git | Gate 2B runtime | `UNAPPROVED` |
| Synthetic corpus | Dedicated test VHDX and directory containing only generated files | Gate 2B runtime | `NOT CREATED` |

Until Gate 1 is approved, the branch remains documentation-only. Once Gate 1 is approved, Gate 2A may add only the planned source/build-test paths from the design lock. Gate 2A must not create a complete installable INF or catalog, register an SCM service, modify the Driver Store, call `fltmc`, load a `.sys`, change boot/security policy or target any Windows system for driver execution.

An unsigned `.sys` produced by Gate 2A is an ephemeral analysis output only: it exists only in the temporary Windows build worker, is hashed for the sanitized build result, is not committed or published as a product/artifact, and is deleted with the worker. Without a Microsoft-assigned altitude, any INF-like source is limited to a clearly non-installable structural template whose altitude token is unresolved and whose build cannot produce a package.

## Proposed lab profile awaiting owner approval

The owner and independent reviewer must either approve this profile verbatim or replace it with an equally isolated profile before Gate 2B runtime. Gate 2A does not use this VM.

- Hypervisor: Hyper-V Generation 2 VM with x64 virtual processors, virtual TPM 2.0, UEFI firmware and Secure Boot.
- Guest: Windows 11 Enterprise x64. The release, edition ID, full `CurrentBuildNumber.UBR`, installation media digest and patch level must be recorded from the actual VM; no guessed build is accepted.
- Purpose: EgressGuard Phase 5C file-only minifilter lab. The VM must run no personal applications and hold no real user documents.
- Storage: one OS VHDX and one dedicated fixed-size synthetic-data VHDX. Only the approved local fixed NTFS data volume may receive a filter instance.
- Synthetic root: `T:\EgressGuardLab\SyntheticFiles`. Every file under it is generated specifically for the lab. No test may traverse outside this root.
- Network: a dedicated private Hyper-V switch with no route to the host's personal network and no default Internet route during driver execution. Tool/package provisioning occurs before the clean checkpoint through an owner-controlled process.
- Integration services: Enhanced Session drive redirection, clipboard, host folder sharing, OneDrive and other personal-data synchronization are disabled for the lab VM.
- Host boundary: the development host may edit source and inspect sanitized text evidence, but it must never install, load, verify under Driver Verifier, or execute the minifilter.

Required VM evidence before approval:

1. VM name and immutable VM identifier.
2. Named owner and independent reviewer.
3. Hypervisor/version and Generation 2/x64/vTPM evidence.
4. Exact Windows edition, release and full build.
5. Secure Boot, Memory Integrity/HVCI and Application Control state.
6. Network-switch identity and proof that host folders, clipboard and personal-data synchronization are unavailable.
7. OS VHDX and synthetic VHDX identifiers without exposing a personal path.
8. Clean checkpoint ID and creation timestamp.
9. Successful restore-drill timestamp and post-restore state check.

Screenshots, exported VM configuration, event logs and system dumps remain in the protected lab evidence store. Git may contain only sanitized identifiers and pass/fail summaries.

## Frozen toolchain candidate

The following Microsoft toolchain is the Gate 1 candidate. Gate 2A requires an exact version transcript from its temporary Windows build worker. Gate 2B requires the same evidence from the approved VM; a silent update changes the evidence target, requires a new clean checkpoint and invalidates artifact comparison.

| Component | Frozen candidate |
|---|---|
| Visual Studio | Visual Studio 2022 `17.14.37`, build `17.14.37516.0`, stable/current channel |
| Workloads/components | Desktop development with C++; MSVC v143 x64 Spectre-mitigated libraries; Windows Driver Kit Visual Studio component |
| Windows SDK | `10.0.26100.6584` |
| Windows Driver Kit | `10.0.26100.6584`, x64 target |
| Windows Debugging Tools | Debugging Tools for Windows from SDK `10.0.26100.6584` |
| Build configuration | `Release|x64`; compiler warnings treated as errors; no preview WDK/SDK |

The SDK and WDK build numbers must match. The approved build transcript must record `MSBuild.exe -version`, `cl.exe /Bv`, SDK/WDK directories and hashes of the offline installers/layout manifest. Installers and generated logs are evidence-store artifacts, not repository files.

Gate 2A may run on a temporary GitHub-hosted Windows runner only to:

1. compile `Release|x64` with the WDK;
2. run driver code analysis, CodeQL and compile-time contract assertions;
3. run tests that are pure user-mode logic and never install or open a minifilter port;
4. record the source commit, tool versions, diagnostics and SHA-256 of the ephemeral output; and
5. delete all `.sys`, object, package and analysis intermediates when the job ends, with no binary artifact upload.

The Gate 2A workflow must contain no INF/package installation, `pnputil`, `sc create`, `fltmc`, `FilterLoad`, Driver Verifier configuration, reboot or security-policy command. Neither a GitHub runner nor the user's primary workstation may install or execute the driver.

Microsoft references:

- [Download the Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [Supported and other WDK versions](https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads)
- [Windows SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads)
- [Visual Studio 2022 release history](https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-history)

## Signing route

Signing is not a Gate 1 or Gate 2A prerequisite. Gate 2A intentionally proves that source can compile and be analyzed without making an installable package. After Gate 2A passes and Microsoft assigns the exact altitude, the organization may perform a controlled Gate 2A-to-2B transition outside the repository: reconstruct the candidate, create the complete INF/catalog, submit that exact package and wait for the Microsoft-signed return. This transition is not Gate 2A and authorizes no installation or execution. Gate 2B does not begin until the returned package and digest are verified.

The only accepted runtime route is a Microsoft-signed package returned by Partner Center through an organization-owned attestation or WHCP/HLK submission. The signing owner must provide a sanitized submission ID, certification type, source commit, unsigned input-package digest, returned-package digest and successful Microsoft signature verification for the exact artifact.

Gate 2B is blocked until the organization has:

- a registered Windows Hardware Developer Program account;
- an organization-controlled, valid EV certificate associated with that account;
- approved key custody and signing operators outside this repository;
- a completed Partner Center submission for the exact candidate package; and
- a returned Microsoft-signed package whose catalog and binary validate with `signtool verify /v /kp`.

Every rebuild of any file in the package creates a new artifact: its previous signature evidence is invalid, it must receive a new digest and Partner Center submission, and it cannot be installed or loaded until the newly returned package verifies. A Gate 2A ephemeral `.sys` is never promoted directly to a runtime product.

The repository must never contain a PFX, private key, certificate export, signing token, Partner Center credential or signed package. Self-signed test certificates, `TESTSIGNING`, disabling Secure Boot, clearing UEFI keys and bypassing Application Control are not accepted alternatives. The agent must not perform or automate any of those actions.

Microsoft references:

- [Driver code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Partner Center for Windows Hardware](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/)
- [Attestation sign Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation)
- [Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)

## Minifilter altitude

No numeric altitude is reserved or guessed. Gate 2A may compile source without an altitude, but it must not create a complete/installable INF. The controlled Gate 2A-to-2B packaging transition requires the exact altitude allocated by Microsoft for `EgressGuard.Minifilter.sys`; until allocation evidence exists, no complete INF/catalog/package may be produced and the filter must not be registered or loaded.

The organization owner must send the Microsoft altitude request with:

- company and long-lived contact alias;
- product name `EgressGuard`;
- filter filename `EgressGuard.Minifilter.sys`;
- filter type `FileSystem`;
- start type `Demand`;
- description: metadata-only file open/read observation with a later bounded, fail-open, cancel-safe pre-read lab path; no content inspection;
- requested load-order group selected with Microsoft, with `FSFilter Activity Monitor` only a candidate, not an allocation; and
- an altitude value treated as valid only after Microsoft responds.

Microsoft states that the first altitude is allocated by Microsoft and that processing can take up to 30 business days. Evidence is the sanitized request date/reference and Microsoft's response; email addresses and message bodies are not committed.

References:

- [Request a filter altitude identifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request)
- [Load order groups and altitudes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)

## Security-state lock

The independent reviewer must record these values before the clean checkpoint and verify them again after final rollback:

- Secure Boot: `On`.
- Memory Integrity/HVCI: existing state remains `On`; a failure to load under it is a failed prerequisite, not authority to disable it.
- Windows Defender/Application Control/WDAC policy: exact policy IDs and enforcement mode recorded; no bypass or audit-only downgrade introduced for the lab.
- Defender antivirus and firewall profiles: unchanged by Phase 5C.
- Driver load policy: no `TESTSIGNING`, no `NOINTEGRITYCHECKS`, no UEFI key changes.
- BitLocker/device encryption: handled only by the lab owner; Phase 5C automation does not modify it.

Any request to weaken these controls ends the run as `BLOCKED`.

## Recovery point and restore drill

The clean checkpoint is created only after the approved OS, security state, toolchain and isolated synthetic VHDX are provisioned, and before any EgressGuard driver package is installed.

Required drill:

1. Record the VM ID, checkpoint ID, parent image identity and security state.
2. Create a harmless marker in the synthetic root.
3. Restore the checkpoint through the hypervisor owner workflow.
4. Boot the VM and prove the marker is absent.
5. Confirm Secure Boot, HVCI/Application Control, network isolation and tool versions still match.
6. Confirm `fltmc filters`, `fltmc instances`, SCM and the Driver Store contain no EgressGuard Phase 5C artifact.
7. Record the drill result outside Git and place only the sanitized IDs, timestamp and verdict in this document after approval.

After any bugcheck, hang, incomplete read, cleanup mismatch or verifier violation, stop the test, preserve the dump outside Git, restore this checkpoint and mark that run failed. A successful reboot without rollback is not recovery proof.

## Crash capture and debugger ownership

The VM must be configured by the lab owner for a kernel memory dump on its OS disk with sufficient page file. Dumps, WinDbg workspaces and raw debugger output remain in the protected lab evidence store and are never committed.

The approved runbook must name:

- the debugger/recovery owner;
- dump type and in-VM location;
- dedicated debugger/controller VM or isolated endpoint;
- symbol source/cache policy with no repository output;
- post-bugcheck collection and checkpoint-restore sequence; and
- sanitized fields permitted in `docs/phase-5c-report.md`: exact commit/artifact digest, stop code, faulting module, test case, timestamp and final failed verdict.

No crash dump or kernel log may be copied into this repository.

## EgressGuard-owned identifiers

Cleanup is allowlist-only. These identifiers are reserved for the future Phase 5C implementation and may not be broadened with wildcard deletion:

| Kind | Exact identifier |
|---|---|
| SCM service/filter name | `EgressGuardMinifilterLab` |
| Driver binary | `EgressGuard.Minifilter.sys` |
| Driver package INF | `EgressGuard.Minifilter.inf` |
| Default instance | `EgressGuard.Minifilter.Instance` |
| Communication port | `\EgressGuardMinifilterPort.v1` |
| Package ownership ID | `53ced30c-daeb-4209-be44-d148509d0149` |
| Wire-contract ID | `2118132e-6271-4c66-af32-661a9f61fcea` |
| Cleanup-manifest ID | `d0e4fb9b-05f6-470f-8d02-de4a63e9ca24` |
| Synthetic-corpus ID | `9deb50c1-012b-4bdc-94e0-f4df48836a1c` |
| Pool tags | `5CgE`, `5CqE`, `5CpE` |
| Synthetic VHDX label | `EG5C_SYNTHETIC` |
| Synthetic root | `T:\EgressGuardLab\SyntheticFiles` |

The standard Microsoft file-system-filter setup class GUID is not EgressGuard-owned and must never be used as a cleanup selector.

## Install, stop, uninstall and rollback contract

The future runbook may act only on an exact artifact digest and the identifiers above. It must capture the published OEM INF name at installation and use that exact name for removal; it must not remove every minifilter, every Activity Monitor class package or another vendor's service.

Normal cleanup order is:

1. Stop new lab input and close the single service communication client.
2. Prove pending depth is zero, or invoke the driver's fail-open drain and prove every entry terminal once.
3. `fltmc unload EgressGuardMinifilterLab` and verify the exact filter/instance are absent.
4. Stop/delete only SCM service `EgressGuardMinifilterLab` if it remains.
5. Remove only the captured EgressGuard OEM INF through `pnputil`.
6. Verify the exact communication port is closed and all owned resource counters are zero.
7. Reboot the VM, verify no EgressGuard filter/service/package remains, then restore the clean checkpoint.
8. Recheck the clean security state and prove the development host was not changed.

If unload, pending drain or ownership proof fails, do not force broad deletion. Mark the run `BLOCKED` and restore the VM.

## Frozen resource and time prerequisites

These bounds are fixed before any driver measurement and may not be increased after observing a test result:

| Resource | Frozen bound |
|---|---:|
| Connect context / common wire header | 64 bytes each |
| Version-1 wire records | Metadata 320; status 512; pending read 384; read completion 384; receiver ready 128; disposition 320 bytes |
| Maximum wire record | 512 bytes; no variable/flexible record |
| Driver-to-service metadata queue | 1,024 records global |
| Metadata queue reserved storage | 512 KiB records; 640 KiB total allocation ceiling including queue bookkeeping |
| All driver-owned pool allocation | 1 MiB global across the three EgressGuard pool tags; Filter Manager-owned memory is reported separately |
| Communication clients | 1 LocalSystem/administrator client |
| Driver-to-service send timeout | 250 ms per attempt, on the single emitter thread only |
| Status snapshot | Exactly one 512-byte record; at most 40 fixed counter entries |
| Reason counters | Closed pass-through/terminal enums; monotonic `uint64` saturation |
| Pending reads, exact subject | 4 |
| Pending reads, global | 64 |
| Pending-read deadline | 2,000 ms; equality is expired/fail-open |
| Pending-entry storage | 1 KiB maximum each; 64 KiB total entry ceiling |
| Completion tombstones | 64 entries, 128 bytes each, 8 KiB total |
| Core-mapped sequences | `1..INT64_MAX`, no wrap; exhaustion fail-opens and stops admission |
| Worker model | One long-lived emitter and one shared watchdog/completion path; zero per-event threads |
| Raw path lifetime | Callback-local only; never queued, messaged, logged or persisted |
| Redacted file label | 1-96 bytes in `[A-Za-z0-9 ._()-]`, then zero padding to 96 bytes |

Queue exhaustion, unavailable service, identity uncertainty and unsupported I/O/volume paths always pass through and increment exactly one applicable monotonic counter. No bound may be tuned upward to make a test pass.

## Gate approval records

Gate 1 is intentionally independent of Microsoft signing, altitude and runtime-lab readiness. This separation allows an approved Gate 2A build to create the artifact needed for later packaging/signing without authorizing installation or execution.

### Gate 1 and Gate 2A entry

| Field | Value |
|---|---|
| Gate 1 design commit | `PENDING` |
| Independent Windows kernel/security reviewer | `PENDING` |
| Review date | `PENDING` |
| Frozen Gate 2A toolchain/runner | `PENDING` |
| Build-only/no-install review verdict | `PENDING` |
| Independent Gate 1 verdict | `PENDING` |

### Gate 2B packaging/runtime entry

| Field | Value |
|---|---|
| Exact Gate 2A source commit | `PENDING` |
| Lab owner | `PENDING` |
| VM and exact OS build | `PENDING` |
| Clean checkpoint ID | `PENDING` |
| Restore drill | `PENDING` |
| Microsoft altitude evidence | `PENDING` |
| Signing route approval | `PENDING` |
| Exact returned Microsoft-signed package digest | `PENDING` |
| Security-state verdict | `PENDING` |
| Independent Gate 2B runtime verdict | `PENDING` |

Only a different qualified reviewer may approve Gate 1/Gate 2A entry. Only that reviewer together with the named VM/security owner may approve Gate 2B runtime. The document author cannot self-approve either record.
