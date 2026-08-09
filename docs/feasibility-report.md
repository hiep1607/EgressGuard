# Báo cáo chứng minh khả thi — EgressGuard Giai đoạn 0

**Ngày kiểm tra:** 2026-08-09  
**Nền tảng kiểm tra:** Windows x64, OS build `10.0.26200`  
**SDK kiểm tra:** .NET SDK `8.0.423`, runtime `8.0.29`

## 1. Kết quả đã làm được

- Tạo solution .NET 8 gồm Core, CLI, Simulator, local Test Server và test harness.
- Thu thập TCP/UDP IPv4/IPv6 owner tables bằng Windows IP Helper API.
- Thu thập PID, process name, executable path khi được phép, start time và parent PID.
- Identity nội bộ dùng `PID + ProcessStartTime`.
- Ghép endpoint với process snapshot và hiển thị trong console có refresh cấu hình được, `--once`, process filter và `Ctrl+C` clean shutdown.
- Tính SHA-256, cache theo full path + size + last-write time.
- Test Server chỉ bind `127.0.0.1`, nhận TCP/UDP và chỉ log byte count.
- Simulator chỉ sinh dữ liệu ngẫu nhiên trong RAM, hỗ trợ small chunks và burst, TCP/UDP, không đọc file người dùng.
- Firewall adapter chỉ nhận executable đúng tên `EgressGuard.Simulator.exe`; rule cố định có prefix `EgressGuard-Prototype-`, idempotent, có status/unblock và ownership marker.
- Build Release thành công với 0 warning và 0 error.
- 6/6 automated tests thành công.

## 2. API Windows đã dùng

- `GetExtendedTcpTable` với `TCP_TABLE_OWNER_PID_ALL` cho IPv4 và IPv6.
- `GetExtendedUdpTable` với `UDP_TABLE_OWNER_PID` cho IPv4 và IPv6.
- `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW` để lấy parent PID.
- `System.Diagnostics.Process` để lấy name, start time và executable path khi quyền cho phép.
- PowerShell `NetSecurity`: `Get-NetFirewallRule`, `Get-NetFirewallApplicationFilter`, `New-NetFirewallRule`, `Remove-NetFirewallRule`.
- `WindowsIdentity`/`WindowsPrincipal` để từ chối thay đổi firewall khi không elevated.

P/Invoke nằm riêng trong Core. Firewall gọi một PowerShell script cố định; rule name/path được truyền qua environment variable, không ghép dữ liệu đầu vào vào command string.

## 3. Kết quả kiểm thử

### Build

```text
dotnet build EgressGuard.sln --configuration Release --nologo
Build succeeded.
0 Warning(s)
0 Error(s)
```

### Automated tests

```text
PASS  Process identity includes start time
PASS  Native port conversion
PASS  Endpoint formatting
PASS  Executable metadata hashes and caches
PASS  Firewall path validation is simulator-only
PASS  Controlled TCP connection maps to current process
6/6 tests passed.
```

### TCP kiểm soát với executable Simulator

CLI quan sát thực tế:

```text
PID     PROCESS                 PROTOCOL   LOCAL              REMOTE             STATE
26832   EgressGuard.Simulator   TCP/IPv4   127.0.0.1:59653    127.0.0.1:5050     ESTABLISHED
```

Process detail hiển thị đúng executable, process start time, parent PID và SHA-256. Server nhận đúng 2.048 byte dữ liệu giả và không log payload.

### UDP kiểm soát

```text
PID     PROCESS                 PROTOCOL   LOCAL              REMOTE   STATE
18684   EgressGuard.Simulator   UDP/IPv4   0.0.0.0:56328      *:*      -
```

Đây là kết quả đúng với owner-PID UDP table: API cung cấp local bound endpoint/PID, không cung cấp remote peer.

### Firewall

- `firewall status`: chạy thành công, xác nhận không có rule prototype tồn tại.
- Phiên kiểm tra hiện tại không elevated (`Administrator: False`). Theo yêu cầu an toàn, code không tự nâng quyền và không tạo/xóa rule.
- Vì vậy block/unblock thật và xác nhận Chrome vẫn có Internet **chưa được thực thi trong phiên này**.
- Cần chạy checklist Administrator trong README. Cũng cần xác nhận policy Windows Firewall của máy mục tiêu có áp dụng program outbound rule lên loopback traffic hay không.

## 4. Quyền Administrator

Không cần Administrator để build, chạy server/simulator, đọc process/network snapshot hoặc xem firewall status. Chỉ `firewall block` và `firewall unblock` cần terminal Administrator. Nếu thiếu quyền, CLI dừng với thông báo rõ và không gọi UAC.

## 5. Giới hạn kỹ thuật

### TCP

- Snapshot polling có thể bỏ lỡ connection sống ngắn hơn refresh interval.
- TCP cung cấp local/remote endpoint và state, nhưng PID có thể biến mất trước lúc process metadata được đọc.
- IPv6 được parse riêng; scope ID được giữ khi dựng `IPAddress`.

### UDP

- `GetExtendedUdpTable` cung cấp bound local endpoints và owning PID, không phải flow table.
- Không có remote endpoint hoặc connection state. `*:*` biểu thị “API không cung cấp”, không phải remote address thật.

### PID/process mapping

- PID được Windows tái sử dụng. Prototype ghép snapshot theo PID tại thời điểm chụp nhưng lưu process identity bằng `(PID, ProcessStartTime)`.
- Vẫn có race giữa network snapshot và process snapshot; process đã thoát/không truy cập được sẽ không bị gán metadata suy đoán.
- System/protected process có thể không trả executable path hoặc start time khi chạy non-admin.

### Executable metadata

- SHA-256 hoạt động và có cache chống băm liên tục.
- Signature/publisher chưa được triển khai để tránh nhầm “có embedded certificate” với “Authenticode trust hợp lệ”. Interface và nullable fields đã sẵn sàng cho bước riêng sau khi Stage 0 được nghiệm thu.

### Firewall

- Chỉ một rule `EgressGuard-Prototype-Simulator-Outbound` được quản lý.
- Existing rule cùng tên nhưng không có ownership description sẽ bị từ chối, không bị ghi đè/xóa.
- Existing owned rule trỏ executable khác cũng bị từ chối; người dùng phải unblock rõ ràng trước.
- Không có global block, kill process, packet interception hoặc thay đổi rule bên ngoài.

## 6. Phần chưa thể kiểm tra trong môi trường hiện tại

- Tạo và gỡ firewall rule thật do process hiện tại không có Administrator token.
- Xác nhận Simulator bị block trong khi Chrome/Edge vẫn có Internet.
- Xác nhận behavior của outbound program rule đối với localhost trên đúng Windows 11 Home/Pro mục tiêu.
- Test trên Windows 11 Home và Pro riêng biệt; môi trường hiện tại chỉ cung cấp một Windows build.
- Authenticode signature và publisher.

## 7. Đánh giá chuyển Giai đoạn 1

**Chưa nên chuyển sang Giai đoạn 1.** Process/network visibility đã chứng minh khả thi: build sạch, test owner-PID TCP pass, TCP/UDP Simulator được nhận diện đúng. Tuy nhiên tiêu chí bắt buộc “chặn riêng Simulator, hoàn tác rule và không ảnh hưởng ứng dụng khác” chưa được xác minh runtime do thiếu Administrator token.

Chỉ đề nghị chấp thuận Giai đoạn 1 sau khi chạy đủ checklist firewall trong README trên Windows 11 mục tiêu và ghi nhận:

1. rule được tạo đúng một lần;
2. Simulator connection mới bị chặn;
3. Chrome/Edge vẫn có Internet;
4. unblock khôi phục Simulator;
5. không còn rule `EgressGuard-Prototype-*` mồ côi.
