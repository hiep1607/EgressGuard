# Threat model

## Tài sản bảo vệ

- Khả năng quan sát outbound theo đúng process.
- Integrity của policy/rule thuộc EgressGuard.
- Lịch sử process/network cục bộ.
- Khả năng khôi phục Internet khi enforcement lỗi.

## Đối thủ trong phạm vi

- User-mode malware hoặc script gửi dữ liệu ra ngoài.
- Portable/unsigned executable chạy từ Temp/AppData.
- Ứng dụng mới liên hệ destination mới hoặc explicit-blocked destination.
- Local user không được phép gửi IPC mutation.

## Ngoài phạm vi hiện tại

- Kernel malware/rootkit, administrator attacker và service tampering mạnh.
- VPN/DoH attribution đầy đủ, HTTPS content, packet payload.
- USB/Bluetooth/camera, file access và file-to-network correlation.
- Injection vào process hợp pháp, DNS tunneling tinh vi.

## Trust boundaries

1. Windows API → sensor: dữ liệu có race/PID reuse; identity thêm start time.
2. UI → Named Pipe: input untrusted, version/size/type validation và identity check.
3. Service → SQLite: parameterized SQL, transaction, no payload/file content.
4. Service → Firewall: fixed PowerShell scripts, data qua environment, ownership prefix/description.

## Failure policy

- Sensor/database/IPC lỗi không tự block toàn máy.
- Không có Lockdown.
- Không block System32 tự động.
- Không kill/quarantine/delete executable.
- Rule reset/uninstall chỉ xóa rule chứng minh ownership.

## Giới hạn diễn giải

Alert nói “process có hành vi kết nối bất thường”, không khẳng định file đã bị đánh cắp. `BytesSent/Received` luôn null khi IP Helper không cung cấp. Embedded certificate presence không đồng nghĩa trust chain hợp lệ.
