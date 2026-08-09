using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using EgressGuard.Core;
using EgressGuard.Protocol;

namespace EgressGuard.UI;

public sealed class MainWindowViewModel : INotifyPropertyChanged, IAsyncDisposable
{
    private readonly EgressGuardPipeClient _client = new();
    private readonly DispatcherTimer _timer;
    private string _serviceStatus = "Service disconnected";
    private string _lastOperation = "Starting…";
    private string _searchText = string.Empty;
    private string _protocolFilter = "All protocols";
    private string _ipFilter = "All IP versions";
    private string _riskFilter = "All risks";
    private FlowRow? _selectedFlow;
    private FirewallRule? _selectedRule;
    private SecurityAlert? _selectedAlert;
    private ProtectionMode _protectionMode = ProtectionMode.Learning;
    private int _refreshIntervalMilliseconds = 2000;
    private int _refreshCounter;
    private int _retentionDays = 30;
    private string _databasePath = "Unavailable until connected";

    public MainWindowViewModel()
    {
        FlowView = CollectionViewSource.GetDefaultView(Flows);
        FlowView.Filter = FilterFlow;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(_refreshIntervalMilliseconds) };
        _timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
        RefreshCommand = new AsyncCommand(RefreshAsync);
        AllowCommand = new AsyncCommand(() => CreateRuleAsync(FirewallAction.Allow));
        AllowOnceCommand = new AsyncCommand(() => SetOperationAsync("Allow once uses the current default-allow connection and does not create a persistent rule."));
        BlockCommand = new AsyncCommand(() => CreateRuleAsync(FirewallAction.Block));
        UndoRuleCommand = new AsyncCommand(UndoRuleAsync);
        ResetRulesCommand = new AsyncCommand(() => SendMutationAsync(MessageTypes.ResetOwnedRules, new { }));
        ApplyModeCommand = new AsyncCommand(() => SendMutationAsync(MessageTypes.SetProtectionMode, new SetProtectionModeMessage(ProtectionMode)));
        ClearHistoryCommand = new AsyncCommand(() => SendMutationAsync(MessageTypes.ClearHistory, new { }));
        ResetBaselineCommand = new AsyncCommand(() => SendMutationAsync(MessageTypes.ResetBaseline, new ResetBaselineMessage(SelectedFlow?.Flow.Executable?.Sha256)));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public ObservableCollection<FlowRow> Flows { get; } = [];
    public ObservableCollection<FirewallRule> Rules { get; } = [];
    public ObservableCollection<SecurityAlert> Alerts { get; } = [];
    public ICollectionView FlowView { get; }
    public IReadOnlyList<string> ProtocolFilters { get; } = ["All protocols", "TCP", "UDP"];
    public IReadOnlyList<string> IpFilters { get; } = ["All IP versions", "IPv4", "IPv6"];
    public IReadOnlyList<string> RiskFilters { get; } = ["All risks", "Low", "Medium", "High", "Critical"];
    public IReadOnlyList<ProtectionMode> ProtectionModes { get; } = Enum.GetValues<ProtectionMode>();
    public ICommand RefreshCommand { get; }
    public ICommand AllowCommand { get; }
    public ICommand AllowOnceCommand { get; }
    public ICommand BlockCommand { get; }
    public ICommand UndoRuleCommand { get; }
    public ICommand ResetRulesCommand { get; }
    public ICommand ApplyModeCommand { get; }
    public ICommand ClearHistoryCommand { get; }
    public ICommand ResetBaselineCommand { get; }
    public int ActiveCount => Flows.Count;
    public int ProcessCount => Flows.Select(item => item.Flow.ProcessIdentity).Distinct().Count();
    public int AlertCount => Flows.Count(item => item.Flow.Risk?.Level is RiskLevel.High or RiskLevel.Critical);

    public string ServiceStatus { get => _serviceStatus; private set => Set(ref _serviceStatus, value); }
    public string LastOperation { get => _lastOperation; private set => Set(ref _lastOperation, value); }
    public string DatabasePath { get => _databasePath; private set => Set(ref _databasePath, value); }
    public bool NotificationsEnabled { get; set; } = true;
    public int RetentionDays { get => _retentionDays; set => Set(ref _retentionDays, Math.Clamp(value, 1, 3650)); }
    public int RefreshIntervalMilliseconds { get => _refreshIntervalMilliseconds; set { if (Set(ref _refreshIntervalMilliseconds, Math.Clamp(value, 250, 60_000))) _timer.Interval = TimeSpan.FromMilliseconds(_refreshIntervalMilliseconds); } }
    public ProtectionMode ProtectionMode { get => _protectionMode; set => Set(ref _protectionMode, value); }
    public FlowRow? SelectedFlow { get => _selectedFlow; set => Set(ref _selectedFlow, value); }
    public FirewallRule? SelectedRule { get => _selectedRule; set => Set(ref _selectedRule, value); }
    public SecurityAlert? SelectedAlert
    {
        get => _selectedAlert;
        set
        {
            if (Set(ref _selectedAlert, value))
            {
                if (value is not null) SelectedFlow = Flows.FirstOrDefault(item => item.Flow.Id == value.FlowId);
                OnPropertyChanged(nameof(AlertReasonText));
            }
        }
    }
    public string AlertReasonText => SelectedAlert is null ? "Select an alert to inspect its evidence." : string.Join(" | ", SelectedAlert.Assessment.Reasons.Select(reason => $"{reason.Code} ({reason.Points:+#;-#;0}): {reason.Message}; evidence: {reason.Evidence}"));
    public string SearchText { get => _searchText; set { if (Set(ref _searchText, value)) FlowView.Refresh(); } }
    public string ProtocolFilter { get => _protocolFilter; set { if (Set(ref _protocolFilter, value)) FlowView.Refresh(); } }
    public string IpFilter { get => _ipFilter; set { if (Set(ref _ipFilter, value)) FlowView.Refresh(); } }
    public string RiskFilter { get => _riskFilter; set { if (Set(ref _riskFilter, value)) FlowView.Refresh(); } }

    public async Task StartAsync()
    {
        await EnsureConnectedAsync().ConfigureAwait(true);
        await RefreshAsync().ConfigureAwait(true);
        _timer.Start();
    }

    private async Task RefreshAsync()
    {
        try
        {
            await EnsureConnectedAsync().ConfigureAwait(true);
            var flowResponse = await _client.SendAsync(MessageEnvelope.Create(MessageTypes.GetActiveFlows, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
            var statusResponse = await _client.SendAsync(MessageEnvelope.Create(MessageTypes.GetStatus, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
            var active = flowResponse.ReadPayload<ActiveFlowsMessage>().Flows;
            var status = statusResponse.ReadPayload<ServiceStatusMessage>();
            Replace(Flows, active.Select(flow => new FlowRow(flow)));
            _refreshCounter++;
            if (_refreshCounter == 1 || _refreshCounter % 3 == 0)
            {
                var rulesResponse = await _client.SendAsync(MessageEnvelope.Create(MessageTypes.GetRules, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
                var alertsResponse = await _client.SendAsync(MessageEnvelope.Create(MessageTypes.GetAlerts, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
                Replace(Rules, rulesResponse.ReadPayload<RulesMessage>().Rules);
                Replace(Alerts, alertsResponse.ReadPayload<AlertsMessage>().Alerts);
            }
            ProtectionMode = status.Mode;
            DatabasePath = status.DatabasePath;
            ServiceStatus = $"Service online · {status.Mode} · dropped {status.DroppedEvents}";
            NotifyCounts();
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or OperationCanceledException or InvalidDataException)
        {
            ServiceStatus = "Service disconnected · reconnecting";
            LastOperation = exception.Message;
            await _client.DisconnectAsync().ConfigureAwait(true);
        }
    }

    private async Task EnsureConnectedAsync()
    {
        if (!_client.IsConnected)
        {
            await _client.ConnectAsync(TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
            LastOperation = "Connected to EgressGuard Service.";
        }
    }

    private async Task CreateRuleAsync(FirewallAction action)
    {
        if (SelectedFlow?.Flow.Executable is not { } executable)
        {
            LastOperation = "Select a flow with executable metadata first.";
            return;
        }

        var flow = SelectedFlow.Flow;
        var rule = new FirewallRule(Guid.NewGuid(), $"User {action}: {flow.ProcessName}", action, RuleSource.User, executable.Path, executable.Sha256, flow.Destination?.Address.ToString(), flow.Destination?.Port, flow.Protocol, true, DateTimeOffset.UtcNow, null);
        await SendMutationAsync(MessageTypes.CreateRule, new CreateRuleMessage(rule)).ConfigureAwait(true);
    }

    private Task UndoRuleAsync() => SelectedRule is null
        ? SetOperationAsync("Select a rule to undo.")
        : SendMutationAsync(MessageTypes.DeleteRule, new DeleteRuleMessage(SelectedRule.Id));

    private async Task SendMutationAsync<T>(string type, T payload)
    {
        try
        {
            await EnsureConnectedAsync().ConfigureAwait(true);
            var response = await _client.SendAsync(MessageEnvelope.Create(type, payload), TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(true);
            LastOperation = response.Type == MessageTypes.Error ? response.ReadPayload<ErrorMessage>().Message : response.ReadPayload<SuccessMessage>().Message;
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception exception)
        {
            LastOperation = exception.Message;
        }
    }

    private bool FilterFlow(object item)
    {
        if (item is not FlowRow row) return false;
        var searchMatches = string.IsNullOrWhiteSpace(SearchText)
            || row.Process.Contains(SearchText, StringComparison.OrdinalIgnoreCase)
            || row.Remote.Contains(SearchText, StringComparison.OrdinalIgnoreCase)
            || row.Domain.Contains(SearchText, StringComparison.OrdinalIgnoreCase);
        return searchMatches
            && (ProtocolFilter == "All protocols" || row.Protocol.StartsWith(ProtocolFilter, StringComparison.OrdinalIgnoreCase))
            && (IpFilter == "All IP versions" || row.Flow.IpVersion.ToString() == IpFilter)
            && (RiskFilter == "All risks" || row.Risk.Equals(RiskFilter, StringComparison.OrdinalIgnoreCase));
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear();
        foreach (var value in values) target.Add(value);
    }

    private void NotifyCounts()
    {
        OnPropertyChanged(nameof(ActiveCount));
        OnPropertyChanged(nameof(ProcessCount));
        OnPropertyChanged(nameof(AlertCount));
        FlowView.Refresh();
    }

    private Task SetOperationAsync(string message) { LastOperation = message; return Task.CompletedTask; }
    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null) { if (EqualityComparer<T>.Default.Equals(field, value)) return false; field = value; OnPropertyChanged(name); return true; }
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public async ValueTask DisposeAsync()
    {
        _timer.Stop();
        await _client.DisposeAsync().ConfigureAwait(false);
    }
}

public sealed class FlowRow
{
    public FlowRow(NetworkFlow flow) => Flow = flow;
    public NetworkFlow Flow { get; }
    public string Process => Flow.ProcessName;
    public string Publisher => Flow.Executable?.Publisher ?? "Unknown";
    public string Protocol => $"{Flow.Protocol}/{Flow.IpVersion}";
    public string Local => $"{Flow.LocalEndpoint.Address}:{Flow.LocalEndpoint.Port}";
    public string Remote => Flow.Destination is null ? "*:*" : $"{Flow.Destination.Address}:{Flow.Destination.Port}";
    public string Domain => Flow.Destination?.Domain ?? "—";
    public string FirstSeen => Flow.FirstSeen.LocalDateTime.ToString("G", System.Globalization.CultureInfo.CurrentCulture);
    public string LastSeen => Flow.LastSeen.LocalDateTime.ToString("G", System.Globalization.CultureInfo.CurrentCulture);
    public string Risk => Flow.Risk?.Level.ToString() ?? "Low";
    public string Status => Flow.IsBlocked ? "Blocked" : "Allowed";
    public string Identity => $"Identity: PID {Flow.ProcessIdentity?.ProcessId}, start {Flow.ProcessIdentity?.StartTime:O}";
    public string ExecutablePath => $"Executable: {Flow.Executable?.Path ?? "Unavailable"}";
    public string Hash => $"SHA-256: {Flow.Executable?.Sha256 ?? "Unavailable"}";
    public string Signature => $"Signature/publisher: {(Flow.Executable?.IsSigned is null ? "Not verified" : Flow.Executable.IsSigned.Value ? "Signed" : "Unsigned")} / {Publisher}";
    public string Parent => $"Parent PID: {Flow.ParentProcessId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "Unavailable"}";
    public string Destination => $"Destination: {Remote}; domain evidence: {Flow.Destination?.DomainEvidence ?? "Unavailable"}";
    public string Reasons => "Risk reasons: " + string.Join(" | ", Flow.Risk?.Reasons.Select(reason => $"{reason.Code} ({reason.Points:+#;-#;0}): {reason.Message}") ?? []);
}

internal sealed class AsyncCommand(Func<Task> execute) : ICommand
{
    private bool _running;
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => !_running;
    public async void Execute(object? parameter)
    {
        if (_running) return;
        _running = true;
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        try { await execute().ConfigureAwait(true); }
        finally { _running = false; CanExecuteChanged?.Invoke(this, EventArgs.Empty); }
    }
}
