# Kiểm thử

## Lệnh

```powershell
dotnet build EgressGuard.sln -c Release
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build
dotnet format EgressGuard.sln --verify-no-changes --no-restore
```

## Automated tests đã chạy

19/19 pass trên Windows build `10.0.26200`:

- PID + start-time identity và process churn.
- Port/endpoints, SHA/signature cache, simulator-only Stage 0 guard.
- Controlled TCP IPv4, TCP IPv6, UDP owner PID và WindowsFlowSensor mapping.
- Risk Low/Medium/High/Critical, clamp và determinism.
- User block/allow conflict và system safety priority.
- Baseline minimum samples, blocked-flow exclusion và reset.
- SQLite migration idempotence, flow/alert/baseline persistence, retention/clear và lock behavior.
- Protocol roundtrip, 1 MiB rejection, disconnect.
- Worker Service Named Pipe disconnect/reconnect; service vẫn sống giữa clients.

## Integration đã chạy

- Service console → IPC status/snapshot.
- UI process launch; sau khi UI dừng, service vẫn status `Running=True`.
- Service CPU khoảng 1.5%, working set khoảng 69 MB trong sample 6 giây.
- UI CPU khoảng 8.46%, working set khoảng 168 MB trong hidden-process sample; CPU chưa đạt mục tiêu 3% và phép đo chưa thay thế profiler/visual QA.

## Chưa chạy do thiếu Administrator token

- Create/delete/enable/disable/reset Windows Firewall rule thật.
- Rule rollback/drift trên firewall thật.
- SCM install/recovery/uninstall.
- Chrome/Edge unaffected test.

Chạy `tools\test-firewall.ps1`, `tools\install-service.ps1` và `tools\uninstall-service.ps1` trong Administrator PowerShell. Script firewall luôn reset owned rules trong `finally`.

## Manual UI checklist

1. Mở Service và UI; kiểm tra Dashboard/Live/Detail/Alerts/Rules/Settings.
2. Chạy Simulator burst/beacon; kiểm tra batch update và search/filter/sort.
3. Đóng/mở UI; lịch sử/rules/baseline còn trong SQLite.
4. Chuyển Monitor/Learning/Protect bằng client Administrator.
5. Xác nhận alert dùng diễn đạt thận trọng và reason evidence đúng.
