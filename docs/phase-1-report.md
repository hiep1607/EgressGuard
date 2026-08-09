# Báo cáo Giai đoạn 1

## Hoàn thành

- Event model, executable metadata cache, TCP/UDP IPv4/IPv6 sensor.
- SQLite migration/schema/index/transaction/parameter/retention.
- WPF Dashboard, Live Connections, Connection Detail, Alerts, Rules, Settings.
- Search process/IP/domain, protocol/IP/risk filters và DataGrid sorting.
- UI polling 2 giây, rules/alerts polling thưa hơn; không hash/signature trên UI thread.

## Module chính

`Core`, `Windows`, `Persistence`, `UI`, `Protocol`.

## Test

Build 0 warning/error; model/mapping/cache/persistence/IPv4/IPv6/TCP/UDP pass trong bộ 19 test.

## Chưa kiểm thử đầy đủ

- Visual QA tương tác dài hạn.
- UI hidden-process CPU đo 8.46%, chưa đạt mục tiêu dưới 3%.
- Domain luôn null nếu không có process-correlated DNS evidence.
- Authenticode chỉ kiểm tra embedded certificate/publisher subject, chưa verify trust/revocation.

## Điều kiện chuyển phase

Kiến trúc và data path đủ để phát triển Service; performance/visual hardening vẫn còn.
