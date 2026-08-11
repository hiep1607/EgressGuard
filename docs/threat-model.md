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

## Khả năng Phase 4 trong phạm vi

- Thu thập observe-only metadata của Windows File I/O khi tính năng tùy chọn được bật.
- Tương quan thời gian file-to-network chỉ khi file event và flow có cùng exact process identity `(PID, ProcessStartTime)`.
- Giữ normalized raw file path trong RAM ngắn hạn, với retention và hard bound rõ ràng; overflow được công bố bằng drop counter.
- Chỉ lưu evidence đã bảo vệ: salted path identifier, redacted display identifier, extension, operation, timestamp, delta, confidence và reason.
- File evidence chỉ hỗ trợ điều tra; không thay đổi risk score, policy decision hoặc firewall enforcement.

## Ngoài phạm vi hiện tại

- Kernel malware/rootkit, administrator attacker và service tampering mạnh.
- Chứng minh nội dung một file đã được upload hoặc xác định byte nào đã đi qua mạng.
- VPN/DoH attribution đầy đủ, TLS plaintext, HTTPS content hoặc packet payload.
- Bảo đảm chặn mọi hình thức dữ liệu thoát ra ngoài.
- USB/Bluetooth/camera, clipboard, screen capture và dữ liệu chỉ tồn tại trong RAM.
- Injection vào process hợp pháp, DNS tunneling tinh vi.
- WFP/minifilter enforcement, kernel driver và các khả năng dự kiến cho Phase 5.

## Trust boundaries

1. Windows API → sensor: dữ liệu có race/PID reuse; identity thêm start time.
2. UI → Named Pipe: input untrusted, version/size/type validation và identity check.
3. Service → SQLite: parameterized SQL, transaction; chỉ correlation evidence đã salted/redacted, không có raw path, payload hoặc file content.
4. Service → Firewall: fixed PowerShell scripts, data qua environment, ownership prefix/description.

## Failure policy

- Sensor/database/IPC lỗi không tự block toàn máy.
- Không có Lockdown.
- Không block System32 tự động.
- Không kill/quarantine/delete executable.
- Rule reset/uninstall chỉ xóa rule chứng minh ownership.

## Giới hạn diễn giải

Alert nói “process có hành vi kết nối bất thường”; related file activity chỉ nói cùng process identity đã chạm file gần thời điểm flow. Không evidence nào khẳng định file đã bị đánh cắp hoặc upload. `BytesSent/Received` luôn null khi IP Helper không cung cấp. Embedded certificate presence không đồng nghĩa trust chain hợp lệ.
