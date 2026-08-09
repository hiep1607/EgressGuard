# Windows administrator checklist

Run in Administrator PowerShell. Do not disable Firewall or Application Control.

1. Install a supported machine-wide .NET 8 runtime, or sign/approve the exact self-contained service binary according to organizational policy.
2. Build/test/format and publish the final immutable binary.
3. Inspect existing owned rules and service:

   ```powershell
   Get-Service EgressGuard.Service -ErrorAction SilentlyContinue
   Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'}
   ```

4. Install, inspect recovery, stop/start, and verify CLI/UI reconnect:

   ```powershell
   .\tools\install-service.ps1 -PublishedDirectory <final-publish-directory>
   sc.exe qfailure EgressGuard.Service
   Stop-Service EgressGuard.Service
   Start-Service EgressGuard.Service
   ```

5. Run `tools\test-firewall.ps1` with two self-contained Simulator paths.
6. Run `tools\run-soak-test.ps1 -DurationMinutes 30`. Confirm both cleanup inspection success fields are `true`; a missing or failed process/firewall query is not a zero-leftover result. Each run writes an isolated database and summary below `artifacts\soak\runs\<timestamp-guid>`.
7. Uninstall and verify no process/service/rule remains:

   ```powershell
   .\tools\uninstall-service.ps1
   Get-Service EgressGuard.Service -ErrorAction SilentlyContinue
   Get-Process EgressGuard.Service -ErrorAction SilentlyContinue
   ```

## Reboot checklist (manual; no automatic reboot)

- Reboot Windows.
- Confirm service reaches Running automatically and recovery configuration remains.
- Open UI and confirm initial snapshot plus event updates.
- Close UI and confirm service continues collecting.
- Stop/start service and confirm UI shows disconnect then reconnects without hanging.
- Re-run an owned-rule create/undo and verify zero orphaned rules.

## Phase 3.5 status (2026-08-09)

- `Verified`: framework-dependent final publish ran through SCM as `LocalSystem` with machine-wide .NET 8.0.29.
- `Verified`: executable SHA-256 `2B6D057BD3F189AC6A186CA6B7D2AED759422390ADD6596195CA3D1FC64737F5`; managed service DLL SHA-256 `67503DCCB540CDCEDF7AD7F16551B5F4116A7A491A06212BFDACD78419A8671F`.
- `Verified`: automatic start, recovery delays 5/15 seconds, UI-close independence, stop/disconnect, start/reconnect, post-restart flow collection and uninstall cleanup.
- `Verified`: fresh isolated 30-minute soak, 585 cycles, 0 failures, database lock released; process/firewall inspections succeeded with zero residual processes/rules.
- `Not verified`: real reboot, DPI 100%, DPI 150% and direct tray context-menu interaction.
- `Blocked – requires owner/administrator action`: production code signing or organizational Application Control approval. The tested executable is unsigned even though the current host allowed it.

After an approved signature or binary approval is available, verify the signature and re-run the exact artifact:

```powershell
Get-AuthenticodeSignature <final-publish>\EgressGuard.Service.exe
Get-FileHash -Algorithm SHA256 <final-publish>\EgressGuard.Service.exe
.\tools\install-service.ps1 -PublishedDirectory <final-publish>
sc.exe qfailure EgressGuard.Service
```

Do not mark reboot or the remaining DPI levels as passed until they are exercised on the real host. After the owner authorizes a reboot, execute the reboot checklist above and finish with:

```powershell
.\tools\uninstall-service.ps1
Get-Service EgressGuard.Service -ErrorAction SilentlyContinue
Get-Process EgressGuard.Service,EgressGuard.UI -ErrorAction SilentlyContinue
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object {$_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'}
```
