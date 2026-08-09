# Kiến trúc EgressGuard

## Dependency direction

```text
UI ───────────────→ Protocol → Core
Service → Protocol/Persistence/Windows → Core
CLI → Protocol/Windows/Core
Persistence → Core
Windows → Core
```

UI không tham chiếu Windows hoặc Persistence và không sửa firewall trực tiếp. Core assembly chứa model và logic thuần. Các Stage 0 Windows source còn nằm vật lý trong thư mục Core để giảm rewrite, nhưng bị `Compile Remove` khỏi Core và được link/compile bởi Windows.

## Runtime flow

```text
IP Helper + Process snapshot
  → WindowsFlowSensor
  → FlowCoordinator
  → RiskEngine
  → PolicyEngine
  → bounded persistence queue
  → SQLite
  → Named Pipe snapshot
  → throttled WPF UI
```

Queue giới hạn 2.048 item, một producer/một consumer. `TryWrite` thất bại sẽ tăng `DroppedEvents`. Sensor exception được cô lập theo iteration. Database failure không kích hoạt block-all; service fail-open.

## Event identity

- Process: `(PID, ProcessStartTime)`.
- TCP flow: process identity + protocol/IP version + local/remote endpoints.
- UDP: process identity + protocol/IP version + local endpoint; Windows API không có remote peer.
- Executable cache: full path + file size + last-write time.

## Persistence

SQLite migration v1 tạo `executables`, `processes`, `network_flows`, `alerts`, `rules`, `baselines`, `settings`, `schema_versions`. SQL dùng parameter; related writes dùng transaction. WAL, foreign keys, busy timeout và index được cấu hình. Retention mặc định 30 ngày chạy khi service khởi động.

## IPC

Named Pipe `EgressGuard.Service.v1`, byte framing `length + JSON`, protocol version 1, maximum 1 MiB. Message type được allowlist trong switch; không có arbitrary type metadata. UI dùng timeout, cancellation và reconnect. Mutating commands xác minh Windows client identity là Administrator bằng pipe impersonation.

`SubscribeEvents` hiện được protocol nhận biết nhưng UI dùng snapshot polling/throttling để dễ reconnect. True push subscription là phần hardening còn lại.

## Firewall ownership

Rule name `EgressGuard-MVP-{guid}` và description `Owned by EgressGuard MVP;...`. Manager từ chối ownership mismatch, tạo idempotent, post-validates và rollback nếu validation thất bại. System32 executable không được automatic block. User block ưu tiên user allow khi conflict; quyết định này được test và tài liệu hóa.

## Risk/baseline

Risk score deterministic, clamp 0–100, reason có stable code/points/evidence. Threshold mặc định nằm trong `RiskThresholds`. Baseline version 1 theo executable SHA-256 + destination/protocol/port, không học blocked/critical flow và yêu cầu sample tối thiểu.
