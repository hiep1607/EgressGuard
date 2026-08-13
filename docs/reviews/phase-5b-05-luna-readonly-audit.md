# Phase 5B-05 — Luna read-only UI/IPC audit

## Phạm vi và phương pháp

- Snapshot được khảo sát: `838bae471263a73187d5723998339b357754be6b`.
- Parent của snapshot: `76cb02bd6ab1579f1062d5ace68cb1e91477409a`.
- Repository: `hiep1607/EgressGuard`; remote `origin` là `https://github.com/hiep1607/EgressGuard.git`.
- Nhánh ghi báo cáo: `audit/phase-5b-05-luna-readonly`.
- Chỉ dùng `git show`, `git grep`, `git ls-tree` trên snapshot; không dùng checkout hiện tại để suy luận.
- Dòng dẫn chứng dùng dạng `path:line` của snapshot. Khi hành vi nằm ở symbol, tên symbol được ghi ngay cạnh dòng.

Kết luận nhanh: UI hiện tại là dashboard Phase 4/Firewall, không có simulated-decision surface. Simulator 5B-04 là console executable độc lập, không có Named Pipe/event bridge tới UI. Các Phase 5B message wrapper đã round-trip trong test nhưng `PipeServer` chưa dispatch chúng. Vì vậy 5B-05 chưa có input stream đủ để hiển thị challenge và chưa có đường mutation/revoke mô phỏng.

## 1. Bảng UI hiện tại

| Tab/control | ViewModel property/command | Hành vi hiện tại | Xung đột với simulated decision UI |
|---|---|---|---|
| Dashboard (`MainWindow.xaml:18-38`) | `ProtectionMode`, `ActiveCount`, `ProcessCount`, `AlertCount`, `FlowView`, `SelectedFlow`; `MainWindowViewModel.cs:63-84` | Hiển thị flow/risk và các counter của service. | Không có challenge, deadline, exact scope, Simulation label hay Critical Alert của gate. |
| Live Connections (`MainWindow.xaml:40-65`) | `SearchText`, `ProtocolFilter`, `IpFilter`, `RiskFilter`, `RefreshCommand`; `MainWindowViewModel.cs:129-132,141-170` | Lọc và refresh các `NetworkFlow` hiện hữu. | Flow quan sát được không phải simulated challenge; không có phân biệt new-flow/ExistingMultiplexed/`ReconnectRequired`. |
| Connection Detail (`MainWindow.xaml:67-104`) | `SelectedFlow`, `FileCorrelations`; `FlowRow` (`MainWindowViewModel.cs:433-454`) | Hiển thị PID/start time, executable path, SHA-256, signature, destination và correlation. Có cảnh báo correlation không chứng minh file contents đã truyền (`MainWindow.xaml:101-102`). | Hiển thị raw `ExecutablePath` (`MainWindow.xaml:71`, `FlowRow.ExecutablePath:448`) và `DisplayPath` (`MainWindow.xaml:87-90`), trái với decision UI phải chỉ có redacted label. Không có file-version scope, group collateral, expiry hay limitation. |
| Alerts (`MainWindow.xaml:106-115`) | `Alerts`, `SelectedAlert`, `AlertReasonText`; `AllowOnceCommand`, `AllowCommand`, `BlockCommand`, `UndoRuleCommand` (`MainWindowViewModel.cs:52-60,116-128`) | Có các nút Allow once/Always allow/Block/Undo rule trên alert hiện hữu. | Đây không phải prompt `NetworkGateChallenge`; không hiển thị decision deadline, fail-open Critical Alert của Phase 5B, `ReconnectRequired` hay exact remembered scope. |
| Rules (`MainWindow.xaml:117-125`) | `Rules`, `SelectedRule`; `AllowCommand`, `BlockCommand`, `UndoRuleCommand`, `ResetRulesCommand` | Quản lý rule firewall của EgressGuard. | Nút `Always allow`/`Block` ở đây là firewall mutation, không phải `Remember for 30 days`/Block current simulated flow. |
| Settings (`MainWindow.xaml:127-137`) | `ProtectionMode`, `RefreshIntervalMilliseconds`, `RetentionDays`, `ApplyModeCommand`, `ClearHistoryCommand`, `ResetBaselineCommand` | Thay đổi mode, retention, baseline và clear history. | Không có toggle/indicator Simulation; `ProtectionMode` hiện là mode service hiện hữu, không phải simulated-gate status. |
| Window/status (`MainWindow.xaml:1-5,13-15,139-140`; `MainWindow.xaml.cs:5-19`) | `ServiceStatus`, `LastOperation`; `StartAsync`/`DisposeAsync` | Cửa sổ 1180x640, mở `MainWindowViewModel`, refresh rồi subscribe event stream. | Không có AutomationId, challenge dialog, decision result, alert severity/reason code cho 5B-05. |

Các command hiện tại có ý nghĩa quan trọng:

- `AllowOnceCommand` chỉ đặt text: “uses the current default-allow connection and does not create a persistent rule” (`MainWindowViewModel.cs:54,413`); nó không gửi `UserDecision`.
- `AllowCommand` gọi `CreateRuleAsync(FirewallAction.Allow)` và `BlockCommand` gọi `CreateRuleAsync(FirewallAction.Block)` (`MainWindowViewModel.cs:53-55`). `CreateRuleAsync` tạo `FirewallRule` với path/hash/destination/protocol rồi gửi `MessageTypes.CreateRule` (`MainWindowViewModel.cs:348-358`).
- `RunSubscriptionLoopAsync` reconnect bằng `Task.Delay(1s)` (`MainWindowViewModel.cs:173-201`); đây là UI transport retry, không được tái sử dụng làm decision clock.

## 2. Named Pipe/Protocol và Service dispatch

### Client/stream hiện có

| Thành phần | Evidence | Hành vi |
|---|---|---|
| Request pipe client | `EgressGuardPipeClient.cs:5-58` | Tạo `NamedPipeClientStream` với `Impersonation`, handshake `EgressGuard.UI`, serialize một request/response dưới `SemaphoreSlim`; timeout do caller truyền vào. |
| Event client | `EgressGuardEventClient.cs:5-85` | Handshake `EgressGuard.UI.Events`, gửi `SubscribeEvents(lastSequence)`, chỉ chấp nhận envelope `FlowObserved`, `AlertRaised`, `ServiceStatusChanged` (`:43-74`). Không có Phase 5B challenge/status type. |
| Server pipe | `PipeServer.cs:60-84,92-137` | ACL explicit cho service/LocalSystem/Administrators FullControl và INTERACTIVE ReadWrite. Một client subscribe thì vào stream; request khác đi `DispatchAsync`. |
| Event hub | `EventHub.cs:8-111` | Sequence monotonic; subscriber channel bounded 512 (`:78-86`), overflow làm rỗng channel và ghi một `ResyncRequired` (`:47-71`). `_subscribers` là `ConcurrentDictionary` không có hard cap số subscriber (`:10`). |
| UI event buffer | `MainWindowViewModel.cs:15-20,214-233` | `SequencedEventBuffer(4096)`, drain tối đa 500; gap/overflow yêu cầu refresh. `SequencedEventBuffer` có capacity nhưng không phải challenge buffer. |
| UI selection buffer | `BoundedSelectionRefresh.cs:5-19,78-119` | Channel capacity 1, DropOldest, một worker dùng `Task.Delay`/wall clock để throttle. Đây là correlation refresh, không phải deterministic simulator scheduler. |

### Message type và dispatch

`MessageTypes` hiện chỉ có Handshake, GetStatus, GetActiveFlows, GetRules, GetAlerts, GetFileCorrelations, SubscribeEvents, CreateRule, DeleteRule, SetProtectionMode, ResetOwnedRules, ResetBaseline, ClearHistory, ServiceStatusChanged, FlowObserved, AlertRaised, Success, Error (`Messages.cs:21-40`). `PipeServer.DispatchAsync` xử lý đúng các type này (`PipeServer.cs:139-217`).

`OutboundGateMessageTypes` có 11 type Phase 5B và record wrapper (`OutboundGateMessages.cs:5-30`):

| Phase 5B type | Serialize/round-trip | Service dispatch hiện tại |
|---|---|---|
| `FileReadIntent` | Có wrapper; test round-trip `Program.cs:1774` | Chưa dispatch; không nằm trong `MessageTypes`/`PipeServer.DispatchAsync`. |
| `GateArmRequest` | Có; `Program.cs:1775` | Chưa dispatch. |
| `GateArmAck` | Có; `Program.cs:1776` | Chưa dispatch. |
| `FileReadDisposition` | Có; `Program.cs:1777` | Chưa dispatch. |
| `FileReadCompletionAck` | Có; `Program.cs:1778` | Chưa dispatch. |
| `NetworkGateChallenge` | Có; `Program.cs:1779` | Chưa dispatch và chưa có event envelope tương ứng. |
| `UserDecision` | Có; `Program.cs:1780` | Chưa dispatch; UI hiện không tạo request này. |
| `OneTimeTicket` | Có; `Program.cs:1781` | Chưa dispatch; service không phát ticket cho UI. |
| `EphemeralFlowGrant` | Có; `Program.cs:1782` | Chưa dispatch; service không phát grant cho UI. |
| `GateStatus` | Có; `Program.cs:1783` | Chưa dispatch; không có status stream Phase 5B. |
| `CriticalAlert` | Có; `Program.cs:1784` | Chưa dispatch; UI chỉ nhận `SecurityAlert` Phase 4 qua `AlertRaised`. |

`StreamEventsAsync` map `AlertRaised`/`ServiceStatusChanged`, còn mọi kind khác thành `FlowObserved` (`PipeServer.cs:241-260`); do đó ngay cả `ResyncRequired` cũng không có Phase 5B envelope riêng. Event client không có nhánh cho các message wrapper nêu trên.

### Mutation và quyền Administrator

`IsMutating` gồm `CreateRule`, `DeleteRule`, `SetProtectionMode`, `ResetOwnedRules`, `ResetBaseline`, `ClearHistory` (`PipeServer.cs:220-225`). Trước dispatch, các request này phải qua `IsAdministratorClient`, dùng `pipe.RunAsClient()` và `WindowsPrincipal.IsInRole(Administrator)` (`PipeServer.cs:141-144,227-235`). Query/status/subscribe không yêu cầu Administrator. Không có Phase 5B `UserDecision`/revoke/mutation endpoint để đánh giá quyền; đây là UNKNOWN cần contract mới.

## 3. Dữ liệu còn thiếu cho prompt 5B-05

| Dữ liệu/claim | Hiện trạng và evidence | Trạng thái |
|---|---|---|
| Nhãn file đã che | `NetworkGateChallenge` chỉ có `ChallengeId`, subject, destination, flow, coverage, time window, limitation (`OutboundGateModels.cs:609-646`), không có `FileVersionIdentity` hoặc display label. UI hiện còn hiển thị raw path. | THIẾU; cần một projection được redaction kiểm chứng. |
| Exact file-version scope | `FileReadIntent.File` và `RequestedPersistentScope.File` tồn tại (`OutboundGateModels.cs:322-354,661-681`), nhưng challenge/event/pipe UI không mang file. | THIẾU trong UI stream; Core có thể tái sử dụng. |
| Application/group scope | `GateSubject` chứa `ApplicationIdentity`, optional `ProcessGroupId`, bounded `GroupMembers` tối đa 32 (`OutboundGateModels.cs:210-240`). | Core SẴN CÓ; thiếu projection, redacted display và collateral warning ở UI. |
| Destination/protocol | `DestinationBinding` có IP family, port, TCP/UDP, direction, compartment/interface và domain evidence (`OutboundGateModels.cs:272-319`); challenge tham chiếu `Destination` (`:615`). | Core SẴN CÓ; chưa có challenge stream/UI. |
| Deadline | `NetworkGateChallenge.DecisionWindow` tối đa 15s (`OutboundGateModels.cs:620,632`) và design yêu cầu service-monotonic freshness (`docs/phase-5-design.md:41-45,125-129`). | Core SẴN CÓ; UI chưa nhận/render countdown/expired result. |
| Critical Alert | Core model có reason/scope/counters/`TrafficFailedOpen` (`OutboundGateModels.cs:924-954`), wrapper có ở `OutboundGateMessages.cs:16-17,29-30`. | Contract SẴN CÓ; Service dispatch/UI path THIẾU. |
| `ReconnectRequired` | Coverage flag tồn tại (`OutboundGateModels.cs:145-176`); simulator design-lock yêu cầu existing TCP/UDP/QUIC trả reconnect và không tạo challenge/hold (`docs/phase-5b-04-design-lock.md:383-396`). | Simulator SẴN CÓ; UI/event protocol THIẾU. |
| Revoke/mutation invalidation | Core có `ApplyPolicyEpoch` và restart invalidation (`OutboundGateStateMachine.cs:492-545`); service hiện chỉ có firewall `DeleteRule`/`ResetOwnedRules` (`PipeServer.cs:192-208`). | Core primitive SẴN CÓ; không có Phase 5B pipe mutation/revoke contract. |
| Decision identity/caller | `UserDecision` constructor nhận `AuthenticatedCaller` là string (`OutboundGateModels.cs:684-710`), không phải credential proof. | UNKNOWN về trust boundary UI→Service; phải có endpoint authorization/correlation trước khi dùng. |

## 4. Kiểm tra riêng theo yêu cầu

1. **`NetworkGateChallenge` và “Remember for 30 days”: không đủ.** Challenge không có file/version (`OutboundGateModels.cs:609-646`). Exact scope chỉ xuất hiện trong `RequestedPersistentScope` của `UserDecision` (`:661-681`), nên UI không thể preview/confirm exact file-version từ challenge hiện tại.
2. **UI tự tạo `AuthenticatedCaller`:** về mặt type, constructor `UserDecision(..., string authenticatedCaller)` là public (`OutboundGateModels.cs:684-710`), nên code UI mới có thể điền một chuỗi. Tuy nhiên UI hiện tại không gọi constructor này, và `PipeServer` không dispatch `UserDecision`. Chuỗi không tự chứng minh caller; việc cho phép UI tự khai caller sẽ là rủi ro P0 nếu không có server-side impersonation.
3. **UI mint ticket/grant:** Không có đường hiện tại. UI chỉ gọi các `MessageTypes` query/mutation (`MainWindowViewModel.cs:348-372`); wrappers ticket/grant chỉ round-trip trong test và không được server dispatch. Core ticket issuance nằm sau state-machine transition, không được UI gọi trực tiếp.
4. **`Always allow`:** hiện là firewall rule mutation, không phải remembered exact scope. Evidence: `AllowCommand`→`CreateRuleAsync(FirewallAction.Allow)` (`MainWindowViewModel.cs:53`), rule gửi `MessageTypes.CreateRule` với executable path/hash và destination (`:348-358`), service gọi `_firewallRuleCreateCoordinator.ApplyAsync` (`PipeServer.cs:184-191`).
5. **`Block`:** hiện tạo firewall rule lâu dài (owned rule lưu service/database) qua cùng `CreateRuleAsync(FirewallAction.Block)` (`MainWindowViewModel.cs:55,348-358`, `PipeServer.cs:184-191`). Điều này khác design Phase 5B: Block chỉ current intent/flow, không blanket/persistent firewall rule (`docs/phase-5-design.md:93-95`).
6. **UI Automation/AutomationId:** không thấy `AutomationProperties.AutomationId`, `AutomationPeer`, test STA hay UI Automation package trong `MainWindow.xaml`, `App.xaml`, `MainWindow.xaml.cs`, `EgressGuard.UI.csproj` hoặc test runner. `EgressGuard.Tests.csproj` chỉ là `OutputType=Exe` và project references (`:1-12`); test list không có WPF launch/Automation test (`Program.cs:165-175`). UNKNOWN: runtime WPF native peers tồn tại theo framework, nhưng chưa có harness/ID/acceptance evidence.
7. **Window/DPI:** `Width=1180`, `Height=640`, `MinWidth=900`, `MinHeight=560` (`MainWindow.xaml:1-5`). Có `ScrollViewer` cho Connection Detail (`:68-103`) và bounded/virtualized `ListBox` (`:81-84`), DataGrid virtualization ở `App.xaml:59-70`; không có explicit DPI/high-DPI setting hoặc small-window test. DPI behavior thực tế là UNKNOWN cần đo bằng UI Automation trên Windows.
8. **Bounded collection/event buffer có thể tái sử dụng:** `SequencedEventBuffer(4096)` trong VM (`MainWindowViewModel.cs:15-20`) và channel 512 trong EventHub (`EventHub.cs:78-86`) là bounded; `BoundedSelectionRefresh` channel 1/DropOldest (`BoundedSelectionRefresh.cs:5-12`) là bounded. `ObservableCollection` Flows/Rules/Alerts/FileCorrelations (`MainWindowViewModel.cs:63-68`) không có hard cap tại UI. EventHub subscriber dictionary không có subscriber-count cap (`EventHub.cs:10`). Các buffer này không chứa challenge authority và không thay thế simulator scheduler/manual clock.
9. **Test console khởi động WPF executable:** Không có đường hiện tại. `TestServicePipeReconnectAsync` chỉ khởi động `EgressGuard.Service.exe` (`Program.cs:3844-3864`); `TestConfiguredPipeNameAsync` chỉ dựng NamedPipe server fixture và client (`:3419-3479`); `TestUiCorrelationRefreshAsync` test helper thuần với `Task.Delay` (`:3506-3546`). Không có `Process.Start` cho `EgressGuard.UI.exe`, STA, window discovery hoặc UI Automation.

## 5. Gap matrix acceptance 5B-05

| Acceptance | Sẵn có | Thiếu | Có thể tái sử dụng | Rủi ro |
|---|---|---|---|---|
| Allow once qua UI Automation | Nút tên “Allow once” có mặt nhưng chỉ set status text (`MainWindow.xaml:113`; `MainWindowViewModel.cs:54`). | Challenge-bound `UserDecision`, server dispatch, result/ticket không tồn tại. | `UserDecision`/state machine/Core ticket contract; pipe framing. | P0: nút hiện tại tạo false sense nhưng không ra decision. |
| Preview exact file-version/application/destination/protocol | Core có `FileVersionIdentity`, `GateSubject`, `DestinationBinding`; UI có destination. | Challenge projection thiếu file/version/redacted label; không có scope card/AutomationId. | Core model validation (`OutboundGateModels.cs:179-319,661-726`). | P0: preview sai scope có thể làm người dùng approve authority khác. |
| Label `Remember for 30 days` | Enum `RememberFor30Days` tồn tại (`OutboundGateModels.cs:656-659`); design yêu cầu label (`docs/phase-5-design.md:93`). | Không có label/control/contract dispatch; `Always allow` đang là firewall rule. | Core `RequestedPersistentScope` validation. | P1: silent widening/persistence nhầm. |
| Revoke/mutation invalidation | Core `ApplyPolicyEpoch`, restart invalidation có sẵn. | UI/service mutation endpoint, policy epoch result và event chưa có. | Core transition + existing admin impersonation pattern. | P1: revoke không chứng minh được ticket/grant bị vô hiệu. |
| Block current flow | Nút Block có mặt. | Nút hiện tạo persistent firewall rule; không có current challenge/held-flow terminal result. | Core `UserDecisionKind.Block`, `ReceiveDecision`. | P1: claim semantics trái design, side effect lâu dài. |
| Decision timeout | Core `DecisionWindow` 15s và monotonic clock có. | UI countdown/timeout state/critical alert stream. | `ServiceMonotonicTimeRange`, simulator manual clock. | P1: UI có thể nhận decision stale hoặc không hiển thị fail-open. |
| Existing TCP/UDP/QUIC `ReconnectRequired` | Simulator design-lock có exact outcomes/reason codes; Core coverage flag có. | Không có stream/UI status/control hiển thị collateral/reconnect instruction. | Simulator JSON scenarios, protocol event framing. | P1: dễ nói sai rằng stream đã bị chặn. |
| Critical fail-open alert | Core `CriticalAlert` model và simulator reason/counter contract có. | `PipeServer` không dispatch Phase 5B `CriticalAlert`; UI chỉ `SecurityAlert`. | Existing Alerts tab/event buffer sau khi thêm projection. | P1: fail-open có thể không visible/không audit được. |
| Small-window/DPI | Có `MinWidth=900`, `MinHeight=560`, one ScrollViewer và DataGrid virtualization. | Không có automation resize/DPI test, prompt layout/overflow contract. | XAML styles/virtualization. | P2: decision/limitations có thể bị cắt ở 900x560 hoặc scale cao. |
| Không raw path | Alerts không hiển thị path; design privacy cấm raw path. | Connection Detail hiển thị `ExecutablePath` và `DisplayPath`; challenge projection chưa có redaction. | Existing `DisplayPath` chỉ làm negative test, không dùng làm prompt data. | P1: rò path qua UI/tooltip và test false-negative. |
| Không ticket secret/proof | UI hiện không nhận ticket/grant; simulator design-lock cấm serialize proof. | Chưa có protocol projection để chứng minh secret bị loại bỏ. | Reflection/source privacy checks của simulator (`docs/phase-5b-04-design-lock.md:527-545`). | P0 nếu ticket wrapper được đưa thẳng vào UI. |
| Không claim “upload blocked” | UI có cảnh báo correlation không chứng minh contents transmitted (`MainWindow.xaml:101-102`); design cũng cấm claim (`docs/phase-5-design.md:18,102`). | Chưa có wording cho simulated gate/fail-open/reconnect. | Existing warning text và design claim boundary. | P1: UI copy có thể biến simulation thành enforcement claim. |
| Simulation disabled/default | Core enum `OutboundGateMode.Disabled` (`OutboundGateModels.cs:830-834`); simulator no-arg disabled/zero-state (`docs/phase-5b-04-design-lock.md:210-221,343-348`). | UI không có Simulation indicator/toggle và không có status stream chứng minh zero authority. | Simulator redacted snapshot. | P1: UI có thể hiển thị control khi authority chưa tồn tại. |
| Three decisions + group collateral/expiry | Enum có AllowOnce/AlwaysAllow/Block; `GateSubject` group bounded. | Không có challenge card, group member disclosure, expiry/limitation view. | Core records/design step 5 (`docs/phase-5-design.md:41-43`). | P1: người dùng không thấy phạm vi ảnh hưởng browser group. |

## 6. File có khả năng phải thay đổi khi implementation (không sửa trong audit)

Danh sách dưới đây là inventory khả năng, không phải chấp thuận thay đổi:

1. `src/EgressGuard.UI/MainWindow.xaml` — prompt/scope/alert/Simulation layout và accessibility IDs.
2. `src/EgressGuard.UI/MainWindow.xaml.cs` — window lifecycle/automation-safe initialization nếu cần.
3. `src/EgressGuard.UI/MainWindowViewModel.cs` — challenge/status projection, decision commands, reconnect/fail-open state.
4. `src/EgressGuard.UI/App.xaml` — styles, focus/visual states, DPI/small-window resources nếu cần.
5. `src/EgressGuard.Protocol/OutboundGateMessages.cs` — chỉ nếu UI transport cần message projection đã được contract review.
6. `src/EgressGuard.Protocol/Messages.cs` — request/event envelope types cho challenge/status/decision/revoke nếu được phê duyệt.
7. `src/EgressGuard.Protocol/EgressGuardPipeClient.cs` và `EgressGuardEventClient.cs` — send/receive APIs cho contract mới.
8. `src/EgressGuard.Service/PipeServer.cs` và `src/EgressGuard.Service/EventHub.cs` — server-side dispatch, authorization, bounded event projection.
9. `tests/EgressGuard.Tests/Program.cs` — WPF/UI Automation harness, deterministic UI acceptance và privacy assertions.
10. `tests/EgressGuard.Tests/EgressGuard.Tests.csproj` — chỉ là khả năng có điều kiện nếu STA/Automation dependency thật sự cần; hiện design-lock 5B-04 nói không kỳ vọng đổi.
11. `docs/phase-5b-report.md` — expected evidence file trong `phase-5-plan.md:89-97`.

Không có căn cứ để sửa `src/EgressGuard.Core/OutboundGateModels.cs`, `OutboundGateStateMachine.cs` hay `OneTimeGateTicketService.cs` cho riêng UI audit; nếu cần đổi Core authority/API thì phải dừng và review design trước.

## 7. Top 10 rủi ro

| # | Mức | Rủi ro | Dẫn chứng |
|---:|---|---|---|
| 1 | P0 | Phase 5B wrapper không được Service dispatch; UI không có challenge/status/decision channel. | `OutboundGateMessages.cs:5-30`; `Messages.cs:21-40`; `PipeServer.cs:139-217`. |
| 2 | P0 | Nếu UI tự điền `AuthenticatedCaller` string thì caller có thể bị giả mạo; Core constructor không phải authentication. | `OutboundGateModels.cs:684-710`; server impersonation chỉ áp dụng `IsMutating` hiện hữu `PipeServer.cs:220-235`. |
| 3 | P0 | Challenge thiếu file-version nên không thể preview exact `Remember for 30 days`; quyết định có nguy cơ sai file scope. | `NetworkGateChallenge` `OutboundGateModels.cs:609-646`; scope `:661-726`. |
| 4 | P1 | Nút Always allow/Block hiện tạo rule firewall lâu dài, khác simulated decision và Block-current contract. | `MainWindowViewModel.cs:53-55,348-358`; `PipeServer.cs:184-191`; `docs/phase-5-design.md:93-95`. |
| 5 | P1 | Critical fail-open và `ReconnectRequired` không đi tới UI/event stream, có thể tạo claim “blocked” hoặc bỏ sót alert. | `OutboundGateMessages.cs:12-17`; `EgressGuardEventClient.cs:67-74`; design-lock `:383-396`. |
| 6 | P1 | Không có revoke/mutation invalidation endpoint cho Phase 5B; UI không chứng minh ticket/grant authority bị thu hồi. | Core transitions `OutboundGateStateMachine.cs:492-545`; `PipeServer.cs:192-225` chỉ firewall/service settings. |
| 7 | P1 | EventHub subscriber dictionary không có hard cap; channel từng subscriber bounded 512 nhưng tổng subscriber không bounded. | `EventHub.cs:10,15-26,78-86`. |
| 8 | P1 | UI raw path/tooltip hiện hữu có thể bị tái sử dụng vào prompt, trái privacy metadata-only. | `MainWindow.xaml:71,87-102`; `MainWindowViewModel.cs:448`; `docs/phase-5-design.md:154-163`. |
| 9 | P2 | Không có AutomationId/STA/UI Automation harness; acceptance không thể chứng minh click/preview/revoke/resize. | `MainWindow.xaml` toàn file không có `AutomationProperties`; `Program.cs:165-175`; csproj `:1-12`. |
| 10 | P2 | Layout/DPI và transport retry chưa có acceptance contract: min 900x560, ScrollViewer chỉ một vùng, selection refresh dùng wall clock/Task.Delay. | `MainWindow.xaml:1-5,67-103`; `BoundedSelectionRefresh.cs:78-103`; `MainWindowViewModel.cs:192-201`. |

## UNKNOWN cần xác minh trước khi implementation

- Chưa có server-side contract xác định challenge/status stream sẽ đưa `FileVersionIdentity` vào redacted UI projection như thế nào.
- Chưa có quyết định authorization cụ thể cho UI decision/revoke; `AuthenticatedCaller` hiện chỉ là validated string.
- DPI runtime behavior trên Windows và khả năng launch WPF từ test console chưa được đo; cần một harness STA/UI Automation riêng.
- Chưa có giới hạn tổng số simulated prompt/event trong UI; các collection Observable hiện không tự cap.
- Chưa có bằng chứng `CriticalAlert` của simulator được persisted/bridged tới Service; snapshot chỉ chứng minh console JSON/host counters.

## Kết luận audit

Snapshot đủ để lập bản đồ hiện trạng và chỉ ra các seam tái sử dụng, nhưng chưa có protocol/service path để 5B-05 hiển thị challenge một cách an toàn. Không nên coi các nút Firewall hiện hữu là simulated decisions. Mọi implementation phải giữ Simulation disabled mặc định, không nhận ticket proof/raw path, hiển thị exact scope/redaction/reconnect/fail-open, và bổ sung UI Automation evidence trước khi gọi acceptance đạt.

READ-ONLY: không sửa file, không tạo commit, không push, không mở PR.
