# EgressGuard

EgressGuard là ứng dụng Windows local-first quan sát outbound connection theo process, lưu lịch sử cục bộ, đánh giá rủi ro bằng rule có thể giải thích và quản lý Windows Firewall rule thuộc riêng EgressGuard.

Repository hiện triển khai phạm vi Giai đoạn 0–3. Không có ETW file monitoring, packet payload capture, HTTPS decryption, driver, AI/ML, cloud, malware thật, quarantine hay process killing.

## Thành phần

```text
src/
├─ EgressGuard.Core/         domain model, baseline, risk và policy
├─ EgressGuard.Windows/      IP Helper/process/firewall adapters
├─ EgressGuard.Persistence/  SQLite migrations và repositories
├─ EgressGuard.Protocol/     versioned Named Pipe messages/framing
├─ EgressGuard.Service/      Worker Service, sensor loop, queue, IPC
├─ EgressGuard.UI/           WPF dashboard/live/detail/alerts/rules/settings
└─ EgressGuard.Cli/          Stage 0 watcher và service diagnostics
```

`Core` assembly không compile Windows-specific Stage 0 adapters; các source compatibility file còn ở thư mục cũ được link và compile bởi `EgressGuard.Windows` để tránh viết lại phần đã kiểm thử.

## Dependency

- `Microsoft.Data.Sqlite 8.0.29`: raw parameterized SQL, không dùng Entity Framework.
- `Microsoft.Extensions.Hosting 8.0.1` và `Microsoft.Extensions.Hosting.WindowsServices 8.0.1`: Worker Service và Windows SCM lifetime.
- Không có MVVM framework hoặc dependency UI bên thứ ba.

## Build và test

Yêu cầu Windows 11 x64 và .NET 8 SDK.

```powershell
dotnet build EgressGuard.sln --configuration Release
dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj --configuration Release --no-build
dotnet format EgressGuard.sln --verify-no-changes --no-restore
```

## Chạy development mode

Terminal 1:

```powershell
$env:EGRESSGUARD_DATA_DIR = Join-Path $env:LOCALAPPDATA 'EgressGuard-Dev'
.\src\EgressGuard.Service\bin\Release\net8.0-windows\EgressGuard.Service.exe
```

Terminal 2:

```powershell
.\src\EgressGuard.UI\bin\Release\net8.0-windows\EgressGuard.UI.exe
```

Chẩn đoán không cần UI:

```powershell
.\src\EgressGuard.Cli\bin\Release\net8.0-windows\EgressGuard.Cli.exe service status
.\src\EgressGuard.Cli\bin\Release\net8.0-windows\EgressGuard.Cli.exe service flows
```

Đóng UI không dừng service. Mode mặc định là `Learning`; mode đã chọn được lưu trong SQLite.

## Test Server và Simulator

```powershell
.\tools\EgressGuard.TestServer\bin\Release\net8.0-windows\EgressGuard.TestServer.exe --protocol both --port 5050
.\tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.exe --protocol tcp --port 5050 --mode small --bytes 5120 --hold-seconds 15
```

Burst và beacon/nhiều connection:

```powershell
.\tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.exe --protocol tcp --port 5050 --mode burst --bytes 10485760 --hold-seconds 0
.\tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.exe --protocol tcp --port 5050 --mode small --bytes 512 --hold-seconds 0 --connections 20 --connection-interval-ms 1000
```

Tất cả payload được sinh trong RAM và chỉ gửi tới localhost. UDP remote hiển thị `*:*` vì `GetExtendedUdpTable` chỉ cung cấp local bound endpoint/PID.

## Publish, cài và gỡ service

Administrator PowerShell:

```powershell
dotnet publish .\src\EgressGuard.Service\EgressGuard.Service.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
.\tools\install-service.ps1 -PublishedDirectory .\src\EgressGuard.Service\bin\Release\net8.0-windows\win-x64\publish
Get-Service EgressGuard.Service
```

Gỡ service và owned rules:

```powershell
.\tools\uninstall-service.ps1
```

Script cài đặt cấu hình automatic start và recovery restart. Script gỡ chỉ xóa service exact-name và firewall rule có đúng prefix + ownership marker.

## Firewall commands

Service phải chạy elevated; client gửi lệnh phải có Administrator identity.

```powershell
$cli = '.\src\EgressGuard.Cli\bin\Release\net8.0-windows\EgressGuard.Cli.exe'
$simulator = (Resolve-Path '.\tools\EgressGuard.Simulator\bin\Release\net8.0-windows\EgressGuard.Simulator.exe').Path
& $cli service block --path $simulator
& $cli service allow --path $simulator
& $cli service reset-rules
```

Nghiệm thu có rollback:

```powershell
.\tools\test-firewall.ps1
```

Kiểm tra thủ công Chrome/Edge vẫn có Internet trong khi Simulator bị block.

Reset khẩn cấp chỉ các MVP rule thuộc EgressGuard:

```powershell
Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Where-Object {$_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'} |
  Remove-NetFirewallRule
```

## Tài liệu

- [Kiến trúc](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Quyền riêng tư](docs/privacy.md)
- [Kiểm thử](docs/testing.md)
- [Báo cáo Giai đoạn 1](docs/phase-1-report.md)
- [Báo cáo Giai đoạn 2](docs/phase-2-report.md)
- [Báo cáo Giai đoạn 3](docs/phase-3-report.md)

## Trạng thái hiện tại

Build sạch và 19/19 automated tests pass trên Windows hiện tại. TCP IPv4/IPv6, UDP PID mapping, SQLite, risk/policy/baseline và service IPC reconnect đã được chạy thật. Firewall mutation, SCM install/uninstall và ảnh hưởng loopback vẫn cần terminal Administrator. UI launch/service independence đã kiểm tra; visual QA tương tác và CPU target chưa đạt đầy đủ. Không chuyển sang Giai đoạn 4 trước khi hoàn tất các mục này.
