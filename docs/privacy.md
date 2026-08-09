# Quyền riêng tư

EgressGuard local-first. Database mặc định nằm trong LocalAppData khi chạy interactive và ProgramData khi chạy Windows Service.

## Dữ liệu lưu

- Process name, PID + start time, parent PID.
- Executable path, SHA-256, embedded signing certificate subject nếu có, size/last-write time.
- TCP/UDP endpoint metadata, state và timestamps.
- Risk reasons, baseline counters, settings và EgressGuard-owned rules.

## Không thu thập

- Packet payload, HTTPS content, file content.
- Documents, browser profile, cookies, password database.
- Command line, credential hoặc secret.
- Cloud telemetry hoặc threat-intelligence lookup.

## Kiểm soát

- Retention flow mặc định 30 ngày.
- Settings có Clear History và Reset Baseline.
- Uninstall script reset owned firewall rules; database không tự xóa để tránh mất dữ liệu ngoài ý muốn. Người dùng có thể xóa thư mục dữ liệu sau khi xác nhận.

Publisher hiện lấy từ subject của embedded signing certificate. Đây là metadata, không phải xác minh certificate trust/revocation đầy đủ.
