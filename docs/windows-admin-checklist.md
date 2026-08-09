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
6. Run `tools\run-soak-test.ps1 -DurationMinutes 30`.
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
