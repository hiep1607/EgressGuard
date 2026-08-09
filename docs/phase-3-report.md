# Báo cáo Giai đoạn 3

## Hoàn thành

- Deterministic explainable Risk Engine, centralized thresholds, stable reason/evidence.
- Signals chỉ từ telemetry có thật; bytes/file access không được suy diễn.
- Versioned executable baseline, persisted destination/protocol/port/sample count.
- Baseline không học blocked/critical flow và trả `insufficient baseline`.
- Policy priority: user block → user allow → system safety → automatic risk → mode fallback.
- Alert persistence/UI và safe wording.
- Simulator hỗ trợ burst, many-connections và periodic beacon pattern.

## Test

Risk Low/Medium/High/Critical, 0–100 clamp, deterministic output, policy conflict, baseline sample/reset và persistence đều pass trong bộ 19 test.

## Chưa kiểm thử đầy đủ

- Automatic Protect firewall action vì non-admin.
- PID reuse thực cưỡng bức không deterministic trên Windows; identity equality và process churn đã test.
- Service restart baseline được code/load và database test, nhưng chưa có long-duration scenario suite.
- UI performance và push subscription cần hardening.

## Đánh giá Giai đoạn 4

Chưa đủ điều kiện chuyển ETW file correlation. Cần firewall/SCM Administrator acceptance, UI performance profiling, true event subscription và beta false-positive measurement trước.
