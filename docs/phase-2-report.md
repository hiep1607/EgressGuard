# Báo cáo Giai đoạn 2

## Hoàn thành

- Worker Service Windows lifetime, graceful cancellation và timed test lifetime.
- Bounded queue 2.048, batching, dropped-event metric, sensor/database fail-open isolation.
- Versioned Named Pipe with max size, timeout, reconnect và admin identity check cho mutation.
- Owned firewall manager: ID/prefix/description, duplicate prevention, enable/disable, delete/reset, validation/rollback.
- Monitor/Learning/Protect và persisted protection mode.
- Install/uninstall/firewall acceptance scripts.

## Test

Service disconnect/reconnect pass; UI dừng nhưng service còn chạy; build sạch. Firewall code path/security guards build/test, nhưng mutation thật chưa chạy vì session non-admin.

## Chưa kiểm thử đầy đủ

- SCM install/recovery/uninstall.
- Firewall block/undo/reset/drift và Chrome unaffected.
- `SubscribeEvents` là acknowledged contract; UI hiện dùng throttled snapshots, chưa có push fan-out.
- Tray icon chưa triển khai.

## Điều kiện chuyển phase

Risk/baseline có thể phát triển trên service pipeline. Không coi enforcement hoàn tất trước Administrator acceptance.
