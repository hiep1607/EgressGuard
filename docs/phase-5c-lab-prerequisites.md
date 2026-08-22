# Phase 5C isolated minifilter lab prerequisites

Status: `LAB APPROVAL REQUIRED`. This document records the required lab contract; it is not approval to create, build, sign, install, load, or test a driver.

Baseline source commit: `7523c42e7894ae4e8c9ed436a0936984ae46945f`.

## Gate decision

Phase 5C kernel work is blocked at Gate 1. The request and repository do not contain authoritative evidence for the VM owner and exact guest build, a clean checkpoint and successful restore drill, an accepted signing route, current Secure Boot/Application Control state, or a Microsoft-assigned minifilter altitude. Those values cannot be inferred or approved by the author of this document.

While any required row below is not `Approved`, the branch must contain no `drivers` directory, no driver binary/package/certificate/key, and no command or automation that installs or loads a driver.

| Prerequisite | Required value or evidence | Current state |
|---|---|---|
| Lab owner | Named human or team with authority over the disposable VM and recovery procedure | `MISSING` |
| Independent security reviewer | A different qualified Windows kernel reviewer, identified by durable handle, reviewing the exact Gate 1 commit | `MISSING` |
| Hypervisor and VM | Dedicated Generation 2 x64 Windows VM; not a developer workstation; no unrelated workloads or personal data | `UNAPPROVED` |
| Guest OS | Exact Windows edition, release, full build and x64 architecture captured from the approved VM | `MISSING` |
| Clean recovery point | Hypervisor checkpoint/image identifier, creation time and immutable parent/image identity | `MISSING` |
| Restore proof | Dated drill restoring that exact recovery point, booting successfully and showing the expected clean state | `NOT RUN` |
| Network isolation | Private lab network; no route to personal networks; no host personal-folder sharing | `UNVERIFIED` |
| Signing | Microsoft-signed lab package obtained through an approved Partner Center attestation or WHCP/HLK route | `MISSING` |
| Secure Boot | Enabled before driver load and unchanged throughout the accepted run | `UNVERIFIED` |
| Application Control/HVCI | Existing policy and Memory Integrity recorded and left enabled/unchanged | `UNVERIFIED` |
| Filter altitude | Microsoft-assigned altitude and allocation evidence for this product/filter | `MISSING` |
| Crash capture | Kernel dump configuration and debugger/recovery owner; dumps stored outside Git | `UNAPPROVED` |
| Synthetic corpus | Dedicated test VHDX and directory containing only generated files | `NOT CREATED` |

The missing rows are hard prerequisites, not documentation TODOs that implementation may bypass.

## Proposed lab profile awaiting owner approval

The owner and independent reviewer must either approve this profile verbatim or replace it with an equally isolated profile before Gate 2.

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

The following Microsoft toolchain is the Gate 1 candidate. Gate 2 requires evidence from the approved VM that these exact versions are installed; a silent update changes the evidence target and requires a new clean checkpoint.

| Component | Frozen candidate |
|---|---|
| Visual Studio | Visual Studio 2022 `17.14.37`, build `17.14.37516.0`, stable/current channel |
| Workloads/components | Desktop development with C++; MSVC v143 x64 Spectre-mitigated libraries; Windows Driver Kit Visual Studio component |
| Windows SDK | `10.0.26100.6584` |
| Windows Driver Kit | `10.0.26100.6584`, x64 target |
| Windows Debugging Tools | Debugging Tools for Windows from SDK `10.0.26100.6584` |
| Build configuration | `Release|x64`; compiler warnings treated as errors; no preview WDK/SDK |

The SDK and WDK build numbers must match. The approved build transcript must record `MSBuild.exe -version`, `cl.exe /Bv`, SDK/WDK directories and hashes of the offline installers/layout manifest. Installers and generated logs are evidence-store artifacts, not repository files.

Microsoft references:

- [Download the Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [Supported and other WDK versions](https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads)
- [Windows SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads)
- [Visual Studio 2022 release history](https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-history)

## Signing route

The only accepted route for this lab is a Microsoft-signed package returned by Partner Center through an organization-owned attestation or WHCP/HLK submission. The signing owner must provide a sanitized submission ID, certification type, returned-package digest and successful Microsoft signature verification for the exact artifact.

Gate 2 is blocked until the organization has:

- a registered Windows Hardware Developer Program account;
- an organization-controlled, valid EV certificate associated with that account;
- approved key custody and signing operators outside this repository;
- a completed Partner Center submission for the exact candidate package; and
- a returned Microsoft-signed package whose catalog and binary validate with `signtool verify /v /kp`.

The repository must never contain a PFX, private key, certificate export, signing token, Partner Center credential or signed package. Self-signed test certificates, `TESTSIGNING`, disabling Secure Boot, clearing UEFI keys and bypassing Application Control are not accepted alternatives. The agent must not perform or automate any of those actions.

Microsoft references:

- [Driver code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Partner Center for Windows Hardware](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/)
- [Attestation sign Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation)
- [Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)

## Minifilter altitude

No numeric altitude is reserved or guessed. Gate 2 requires the exact altitude allocated by Microsoft for `EgressGuard.Minifilter.sys`. Until allocation evidence exists, an INF must not be created and the filter must not be registered or loaded.

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
| Metadata record wire size | 512 bytes maximum, fixed-width header and bounded payload |
| Driver-to-service metadata queue | 1,024 records global |
| Metadata queue reserved storage | 512 KiB records; 640 KiB total allocation ceiling including queue bookkeeping |
| All driver-owned pool allocation | 1 MiB global across the three EgressGuard pool tags; Filter Manager-owned memory is reported separately |
| Communication clients | 1 LocalSystem/administrator client |
| Driver-to-service send timeout | 250 ms per attempt, on the single emitter thread only |
| Unsupported-volume warning reasons | Fixed enum; monotonic counters bounded to `uint64` saturation |
| Pending reads, exact subject | 4 |
| Pending reads, global | 64 |
| Pending-read deadline | 2,000 ms; equality is expired/fail-open |
| Pending-entry storage | 1 KiB maximum each; 64 KiB total entry ceiling |
| Worker model | One long-lived emitter and one shared watchdog/completion path; zero per-event threads |
| Raw path lifetime | Callback-local only; never queued, messaged, logged or persisted |
| Redacted file label | 96 ASCII characters maximum |

Queue exhaustion, unavailable service, identity uncertainty and unsupported I/O/volume paths always pass through and increment exactly one applicable monotonic counter. No bound may be tuned upward to make a test pass.

## Gate 1 approval record

This section remains intentionally incomplete until external evidence exists.

| Field | Value |
|---|---|
| Gate 1 commit | `PENDING` |
| Lab owner | `PENDING` |
| Independent reviewer | `PENDING` |
| Review date | `PENDING` |
| VM and exact OS build | `PENDING` |
| Clean checkpoint ID | `PENDING` |
| Restore drill | `PENDING` |
| Signing submission/evidence | `PENDING` |
| Microsoft altitude | `PENDING` |
| Security-state verdict | `PENDING` |
| Independent verdict | `PENDING` |

Only a different qualified reviewer and the VM/security owner may change the verdict to `Approved`. The document author cannot self-approve.
