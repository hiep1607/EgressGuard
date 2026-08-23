using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using EgressGuard.Core;
using EgressGuard.Protocol;

namespace EgressGuard.UI;

public sealed class MainWindowViewModel : INotifyPropertyChanged, IAsyncDisposable
{
    private readonly MainWindowRequestSession _requestSession;
    private readonly EgressGuardEventClient _eventClient;
    private readonly bool _ownsRequestSession;
    private readonly SequencedEventBuffer _eventBuffer = new(4096);
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly DispatcherTimer _batchTimer;
    private readonly BoundedSelectionRefresh<FileCorrelationsMessage> _correlationRefresh;
    private readonly Func<GetFileActivityHistoryMessage, CancellationToken, Task<FileActivityHistoryMessage>> _historyFetcher;
    private readonly Func<string?> _historyPathPicker;
    private readonly Func<string, IReadOnlyList<FileCorrelationHistoryItem>, CancellationToken, Task> _historyWriter;
    private Task? _subscriptionTask;
    private long _lastSequence;
    private int _resyncRequested;
    private int _batchBusy;
    private string _serviceStatus = "Service disconnected";
    private string _lastOperation = "Starting…";
    private string _searchText = string.Empty;
    private string _protocolFilter = "All protocols";
    private string _ipFilter = "All IP versions";
    private string _riskFilter = "All risks";
    private string _fileActivityFilter = FileActivityFilterAll;
    private string _historySearchText = string.Empty;
    private string _historyRange = FileHistoryRange24Hours;
    private string _historyOperationFilter = FileHistoryOperationAll;
    private string _historyConfidenceFilter = FileHistoryConfidenceAll;
    private FlowRow? _selectedFlow;
    private FirewallRule? _selectedRule;
    private SecurityAlert? _selectedAlert;
    private ProtectionMode _protectionMode = ProtectionMode.Learning;
    private int _refreshIntervalMilliseconds = 250;
    private int _retentionDays = 30;
    private string _databasePath = "Unavailable until connected";
    private string _fileSensorStatus = "File correlation status unavailable";
    private string _observedFileSensorStatus = "File correlation status unavailable";
    private FileSensorState? _fileSensorState;
    private bool _fileCorrelationEnabled;
    private bool _fileCorrelationPreferenceEnabled;
    private bool _fileCorrelationSavedEnabled;
    private bool _fileCorrelationRestartRequired;
    private bool _fileCorrelationLoading;
    private bool _fileCorrelationLoadFailed;
    private CancellationTokenSource? _historyRequestCancellation;
    private long _historyGeneration;
    private DateTimeOffset _historyEndUtc;
    private FileActivityHistoryCursorMessage? _historyCursor;
    private readonly HashSet<Guid> _historySeenIds = [];
    private readonly HashSet<string> _historyUsedCursors = new(StringComparer.Ordinal);
    private bool _historyHasMore;
    private bool _historyLoading;
    private bool _historyLoadFailed;
    private bool _historyStarted;
    private bool _historyExporting;
    private FileSensorState? _historySensorState;
    private string _historyExportStatus = string.Empty;
    private bool _disposed;

    public MainWindowViewModel()
        : this(new MainWindowRequestSession(), pipeName: null, ownsRequestSession: true)
    {
    }

    internal MainWindowViewModel(
        MainWindowRequestSession requestSession,
        string? pipeName,
        bool ownsRequestSession = false,
        Func<string, CancellationToken, Task<FileCorrelationsMessage>>? fileCorrelationFetcher = null,
        TimeSpan? fileCorrelationMinimumInterval = null,
        Func<GetFileActivityHistoryMessage, CancellationToken, Task<FileActivityHistoryMessage>>? historyFetcher = null,
        Func<string?>? historyPathPicker = null,
        Func<string, IReadOnlyList<FileCorrelationHistoryItem>, CancellationToken, Task>? historyWriter = null)
    {
        _requestSession = requestSession ?? throw new ArgumentNullException(nameof(requestSession));
        _eventClient = new EgressGuardEventClient(pipeName);
        _ownsRequestSession = ownsRequestSession;
        FlowView = CollectionViewSource.GetDefaultView(Flows);
        FlowView.Filter = FilterFlow;
        FileCorrelationView = CollectionViewSource.GetDefaultView(FileCorrelations);
        FileCorrelationView.Filter = FilterFileCorrelation;
        FileActivityHistoryView = CollectionViewSource.GetDefaultView(FileActivityHistory);
        _batchTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(_refreshIntervalMilliseconds) };
        _correlationRefresh = new BoundedSelectionRefresh<FileCorrelationsMessage>(
            fileCorrelationFetcher ?? FetchFileCorrelationsAsync,
            ApplyFileCorrelations,
            HandleFileCorrelationFailure,
            fileCorrelationMinimumInterval ?? TimeSpan.FromSeconds(1));
        _historyFetcher = historyFetcher ?? FetchFileActivityHistoryAsync;
        _historyPathPicker = historyPathPicker ?? PickFileActivityHistoryPath;
        _historyWriter = historyWriter ?? FileActivityHistoryCsvExporter.WriteAsync;
        _batchTimer.Tick += OnBatchTimerTick;
        RefreshCommand = new AsyncCommand(RefreshAsync);
        AllowCommand = new AsyncCommand(() => CreateRuleAsync(FirewallAction.Allow));
        AllowOnceCommand = new AsyncCommand(() => SetOperationAsync("Allow once uses the current default-allow connection and does not create a persistent rule."));
        BlockCommand = new AsyncCommand(() => CreateRuleAsync(FirewallAction.Block));
        UndoRuleCommand = new AsyncCommand(UndoRuleAsync);
        ResetRulesCommand = new AsyncCommand(() => ConfirmAndSendAsync("Reset every EgressGuard-owned firewall rule?", MessageTypes.ResetOwnedRules, new { }));
        ApplyModeCommand = new AsyncCommand(() => SendMutationAsync(MessageTypes.SetProtectionMode, new SetProtectionModeMessage(ProtectionMode)));
        SaveFileCorrelationPreferenceCommand = new AsyncCommand(SaveFileCorrelationPreferenceAsync);
        RefreshFileActivityHistoryCommand = new AsyncCommand(RefreshFileActivityHistoryAsync);
        LoadMoreFileActivityHistoryCommand = new AsyncCommand(LoadMoreFileActivityHistoryAsync);
        ExportFileActivityHistoryCommand = new AsyncCommand(ExportFileActivityHistoryAsync);
        ClearHistoryCommand = new AsyncCommand(() => ConfirmAndSendAsync("Delete local flow and alert history?", MessageTypes.ClearHistory, new { }));
        ResetBaselineCommand = new AsyncCommand(() => SendMutationAsync(MessageTypes.ResetBaseline, new ResetBaselineMessage(SelectedFlow?.Flow.Executable?.Sha256)));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    internal MainWindowRequestSession RequestSession => _requestSession;
    internal bool OwnsRequestSession => _ownsRequestSession;
    internal bool FileCorrelationLoading => _fileCorrelationLoading;
    internal bool FileCorrelationLoadFailed => _fileCorrelationLoadFailed;
    public ObservableCollection<FlowRow> Flows { get; } = [];
    public ObservableCollection<FirewallRule> Rules { get; } = [];
    public ObservableCollection<SecurityAlert> Alerts { get; } = [];
    public ObservableCollection<FileCorrelationRow> FileCorrelations { get; } = [];
    public ObservableCollection<FileActivityHistoryRow> FileActivityHistory { get; } = [];
    public ICollectionView FlowView { get; }
    public ICollectionView FileCorrelationView { get; }
    public ICollectionView FileActivityHistoryView { get; }
    public IReadOnlyList<string> ProtocolFilters { get; } = ["All protocols", "TCP", "UDP"];
    public IReadOnlyList<string> IpFilters { get; } = ["All IP versions", "IPv4", "IPv6"];
    public IReadOnlyList<string> RiskFilters { get; } = ["All risks", "Low", "Medium", "High", "Critical"];
    public IReadOnlyList<string> FileActivityFilters { get; } = [FileActivityFilterAll, FileActivityFilterReadOpen, FileActivityFilterModify];
    public IReadOnlyList<string> FileHistoryRanges { get; } = [FileHistoryRange24Hours, FileHistoryRange7Days, FileHistoryRange30Days];
    public IReadOnlyList<string> FileHistoryOperationFilters { get; } = [FileHistoryOperationAll, "Open / create", "Read", "Write", "Rename", "Delete"];
    public IReadOnlyList<string> FileHistoryConfidenceFilters { get; } = [FileHistoryConfidenceAll, "Low", "Medium", "High"];
    public IReadOnlyList<ProtectionMode> ProtectionModes { get; } = Enum.GetValues<ProtectionMode>();
    public ICommand RefreshCommand { get; }
    public ICommand AllowCommand { get; }
    public ICommand AllowOnceCommand { get; }
    public ICommand BlockCommand { get; }
    public ICommand UndoRuleCommand { get; }
    public ICommand ResetRulesCommand { get; }
    public ICommand ApplyModeCommand { get; }
    public ICommand SaveFileCorrelationPreferenceCommand { get; }
    public ICommand RefreshFileActivityHistoryCommand { get; }
    public ICommand LoadMoreFileActivityHistoryCommand { get; }
    public ICommand ExportFileActivityHistoryCommand { get; }
    public ICommand ClearHistoryCommand { get; }
    public ICommand ResetBaselineCommand { get; }
    public int ActiveCount => Flows.Count;
    public int ProcessCount => Flows.Select(item => item.Flow.ProcessIdentity).Distinct().Count();
    public int AlertCount => Alerts.Count;

    public string ServiceStatus { get => _serviceStatus; private set => Set(ref _serviceStatus, value); }
    public string LastOperation { get => _lastOperation; private set => Set(ref _lastOperation, value); }
    public string DatabasePath { get => _databasePath; private set => Set(ref _databasePath, value); }
    public string FileSensorStatus { get => _fileSensorStatus; private set => Set(ref _fileSensorStatus, value); }
    public string FileActivityHistoryStatus => _historyLoading
        ? "Loading file activity history…"
        : _historyExporting
            ? "Exporting file activity history…"
            : _historyLoadFailed
                ? "Service error while loading file activity history."
                : _historySensorState is { } state
                    ? FormatHistorySensor(state)
                    : "File activity sensor status unavailable.";
    public string FileActivityHistoryEmptyState
    {
        get
        {
            if (_historyLoading) return "Loading file activity history…";
            if (_historyLoadFailed) return "File activity history is unavailable because the Service returned an error.";
            if (FileActivityHistory.Count > 0) return string.Empty;
            return _historySensorState switch
            {
                FileSensorState.Disabled => "File activity sensor is turned off.",
                FileSensorState.AccessDenied => "File activity sensor permission was denied.",
                FileSensorState.ProviderUnavailable or FileSensorState.Failed => "File activity sensor is unavailable.",
                FileSensorState.Stopped => "File activity sensor has stopped.",
                _ => "No file activity related to an observed network connection was found."
            };
        }
    }
    public string FileActivityHistoryExportStatus { get => _historyExportStatus; private set => Set(ref _historyExportStatus, value); }
    public bool FileCorrelationEnabled { get => _fileCorrelationEnabled; private set => Set(ref _fileCorrelationEnabled, value); }
    public bool FileCorrelationPreferenceEnabled { get => _fileCorrelationPreferenceEnabled; set => Set(ref _fileCorrelationPreferenceEnabled, value); }
    public string FileCorrelationActiveStatus => _fileCorrelationEnabled ? "Applied now: enabled" : "Applied now: disabled";
    public string FileCorrelationSavedStatus => _fileCorrelationSavedEnabled ? "Saved choice: enabled" : "Saved choice: disabled";
    public string FileCorrelationRestartStatus => _fileCorrelationRestartRequired
        ? "Service restart required to apply the saved choice."
        : "No Service restart required; the saved choice is applied.";
    public string FileCorrelationEmptyState
    {
        get
        {
            if (_fileCorrelationLoading) return "Loading file activity for this connection…";
            if (_fileCorrelationLoadFailed) return "File activity is unavailable for this connection.";
            if (!FileCorrelationEnabled) return "File activity tracking is disabled.";
            if (!FileCorrelationView.IsEmpty) return string.Empty;
            if (FileCorrelations.Count > 0) return "No related file activity matches the selected filter.";
            return _fileSensorState switch
            {
                FileSensorState.AccessDenied => "File activity tracking permission was denied.",
                FileSensorState.ProviderUnavailable or FileSensorState.Failed => "File activity tracking is unavailable.",
                FileSensorState.Stopped => "File activity tracking has stopped.",
                _ => "No related file activity was observed for this connection."
            };
        }
    }
    public bool NotificationsEnabled { get; set; } = true;
    public int RetentionDays { get => _retentionDays; set => Set(ref _retentionDays, Math.Clamp(value, 1, 3650)); }
    public int RefreshIntervalMilliseconds { get => _refreshIntervalMilliseconds; set { if (Set(ref _refreshIntervalMilliseconds, Math.Clamp(value, 100, 1000))) _batchTimer.Interval = TimeSpan.FromMilliseconds(_refreshIntervalMilliseconds); } }
    public ProtectionMode ProtectionMode { get => _protectionMode; set => Set(ref _protectionMode, value); }
    public FlowRow? SelectedFlow
    {
        get => _selectedFlow;
        set
        {
            if (Set(ref _selectedFlow, value))
            {
                Replace(FileCorrelations, []);
                FileCorrelationView.Refresh();
                _fileCorrelationLoading = value is not null;
                _fileCorrelationLoadFailed = false;
                RefreshFileCorrelationPresentation();

                _correlationRefresh.Select(value?.Flow.Id);
            }
        }
    }
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
    public string FileActivityFilter
    {
        get => _fileActivityFilter;
        set
        {
            if (!Set(ref _fileActivityFilter, value)) return;
            FileCorrelationView.Refresh();
            OnPropertyChanged(nameof(FileCorrelationEmptyState));
        }
    }

    public string FileHistorySearchText { get => _historySearchText; set { var next = value.Length > 96 ? value[..96] : value; if (Set(ref _historySearchText, next)) QueueFileActivityHistoryRefresh(); } }
    public string FileHistoryRange { get => _historyRange; set { if (Set(ref _historyRange, value)) QueueFileActivityHistoryRefresh(); } }
    public string FileHistoryOperationFilter { get => _historyOperationFilter; set { if (Set(ref _historyOperationFilter, value)) QueueFileActivityHistoryRefresh(); } }
    public string FileHistoryConfidenceFilter { get => _historyConfidenceFilter; set { if (Set(ref _historyConfidenceFilter, value)) QueueFileActivityHistoryRefresh(); } }

    internal const string FileHistoryRange24Hours = "24 hours";
    internal const string FileHistoryRange7Days = "7 days";
    internal const string FileHistoryRange30Days = "30 days";
    internal const string FileHistoryOperationAll = "All activities";
    internal const string FileHistoryConfidenceAll = "All relevance";

    public async Task StartAsync()
    {
        await RefreshAsync().ConfigureAwait(true);
        _historyStarted = true;
        await RefreshFileActivityHistoryAsync().ConfigureAwait(true);
        _batchTimer.Start();
        _subscriptionTask = RunSubscriptionLoopAsync(_lifetimeCancellation.Token);
    }

    private void QueueFileActivityHistoryRefresh()
    {
        if (!_historyStarted || _disposed)
            return;

        _ = RefreshFileActivityHistoryAsync();
    }

    internal async Task RefreshFileActivityHistoryForTestAsync()
    {
        _historyStarted = true;
        await RefreshFileActivityHistoryAsync().ConfigureAwait(true);
    }

    private async Task RefreshFileActivityHistoryAsync()
    {
        CancelHistoryRequest();
        var requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCancellation.Token);
        _historyRequestCancellation = requestCancellation;
        var generation = Interlocked.Increment(ref _historyGeneration);
        _historyEndUtc = DateTimeOffset.UtcNow;
        _historyCursor = null;
        _historyHasMore = false;
        _historyLoading = true;
        _historyLoadFailed = false;
        _historySensorState = null;
        _historySeenIds.Clear();
        _historyUsedCursors.Clear();
        FileActivityHistoryExportStatus = string.Empty;
        Replace(FileActivityHistory, []);
        RefreshFileActivityHistoryPresentation();
        try
        {
            await LoadFileActivityHistoryPageAsync(generation, reset: true, cancellationToken: requestCancellation.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or InvalidDataException or UnauthorizedAccessException)
        {
            HandleFileActivityHistoryFailure(generation, exception);
        }
        finally
        {
            if (ReferenceEquals(Interlocked.CompareExchange(ref _historyRequestCancellation, null, requestCancellation), requestCancellation))
            {
                requestCancellation.Dispose();
            }
        }
    }

    private async Task LoadMoreFileActivityHistoryAsync()
    {
        if (!_historyStarted || _historyLoading || !_historyHasMore || _historyCursor is null)
            return;

        CancelHistoryRequest();
        var requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCancellation.Token);
        _historyRequestCancellation = requestCancellation;
        var generation = Interlocked.Read(ref _historyGeneration);
        _historyLoading = true;
        RefreshFileActivityHistoryPresentation();
        try
        {
            await LoadFileActivityHistoryPageAsync(generation, reset: false, cancellationToken: requestCancellation.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or InvalidDataException or UnauthorizedAccessException)
        {
            HandleFileActivityHistoryFailure(generation, exception);
        }
        finally
        {
            if (ReferenceEquals(Interlocked.CompareExchange(ref _historyRequestCancellation, null, requestCancellation), requestCancellation))
            {
                requestCancellation.Dispose();
            }
        }
    }

    private async Task LoadFileActivityHistoryPageAsync(long generation, bool reset, CancellationToken cancellationToken)
    {
        var request = BuildFileActivityHistoryRequest(_historyCursor, _historyEndUtc, limit: 100);
        var response = await _historyFetcher(request, cancellationToken).ConfigureAwait(true);
        if (generation != Interlocked.Read(ref _historyGeneration) || cancellationToken.IsCancellationRequested)
            return;

        var nextCursor = FileActivityHistoryPaginationValidator.Validate(request, response, _historySeenIds, _historyUsedCursors);
        foreach (var item in response.Items)
            FileActivityHistory.Add(new FileActivityHistoryRow(item));

        _historyCursor = nextCursor;
        _historyHasMore = response.HasMore;
        _historySensorState = response.SensorStatus.State;
        _historyLoading = false;
        _historyLoadFailed = false;
        RefreshFileActivityHistoryPresentation();
    }

    private void HandleFileActivityHistoryFailure(long generation, Exception exception)
    {
        if (generation != Interlocked.Read(ref _historyGeneration))
            return;
        _historyLoading = false;
        _historyLoadFailed = true;
        _historySensorState = null;
        LastOperation = "File activity history Service error.";
        RefreshFileActivityHistoryPresentation();
    }

    private GetFileActivityHistoryMessage BuildFileActivityHistoryRequest(
        FileActivityHistoryCursorMessage? cursor,
        DateTimeOffset endUtc,
        int limit)
    {
        return BuildFileActivityHistoryRequest(
            cursor,
            endUtc,
            limit,
            string.IsNullOrWhiteSpace(FileHistorySearchText) ? null : FileHistorySearchText,
            ParseFileHistoryOperation(FileHistoryOperationFilter),
            ParseFileHistoryConfidence(FileHistoryConfidenceFilter),
            HistoryRangeSpan(FileHistoryRange));
    }

    private static GetFileActivityHistoryMessage BuildFileActivityHistoryRequest(
        FileActivityHistoryCursorMessage? cursor,
        DateTimeOffset endUtc,
        int limit,
        string? search,
        FileActivityOperation? operation,
        CorrelationConfidence? confidence,
        TimeSpan span) => new(
            endUtc - span,
            endUtc,
            search,
            operation,
            confidence,
            limit,
            cursor);

    private static TimeSpan HistoryRangeSpan(string range) => range switch
    {
        FileHistoryRange7Days => TimeSpan.FromDays(7),
        FileHistoryRange30Days => TimeSpan.FromDays(30),
        _ => TimeSpan.FromHours(24)
    };

    private static FileActivityOperation? ParseFileHistoryOperation(string filter) => filter switch
    {
        "Open / create" => FileActivityOperation.OpenCreate,
        "Read" => FileActivityOperation.Read,
        "Write" => FileActivityOperation.Write,
        "Rename" => FileActivityOperation.Rename,
        "Delete" => FileActivityOperation.Delete,
        _ => null
    };

    private static CorrelationConfidence? ParseFileHistoryConfidence(string filter) => filter switch
    {
        "Low" => CorrelationConfidence.Low,
        "Medium" => CorrelationConfidence.Medium,
        "High" => CorrelationConfidence.High,
        _ => null
    };

    private void RefreshFileActivityHistoryPresentation()
    {
        OnPropertyChanged(nameof(FileActivityHistoryStatus));
        OnPropertyChanged(nameof(FileActivityHistoryEmptyState));
        OnPropertyChanged(nameof(FileActivityHistoryCanLoadMore));
    }

    private void CancelHistoryRequest()
    {
        var previous = Interlocked.Exchange(ref _historyRequestCancellation, null);
        if (previous is null)
            return;
        previous.Cancel();
    }

    public bool FileActivityHistoryCanLoadMore => _historyHasMore && _historyCursor is not null && !_historyLoading;

    private async Task RefreshAsync()
    {
        try
        {
            var flowResponse = await _requestSession.SendAsync(MessageEnvelope.Create(MessageTypes.GetActiveFlows, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
            var statusResponse = await _requestSession.SendAsync(MessageEnvelope.Create(MessageTypes.GetStatus, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
            var activeSnapshot = flowResponse.ReadPayload<ActiveFlowsMessage>();
            var active = activeSnapshot.Flows;
            var status = statusResponse.ReadPayload<ServiceStatusMessage>();
            Replace(Flows, active.Select(flow => new FlowRow(flow)));
            var rulesResponse = await _requestSession.SendAsync(MessageEnvelope.Create(MessageTypes.GetRules, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
            var alertsResponse = await _requestSession.SendAsync(MessageEnvelope.Create(MessageTypes.GetAlerts, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(true);
            Replace(Rules, rulesResponse.ReadPayload<RulesMessage>().Rules);
            Replace(Alerts, alertsResponse.ReadPayload<AlertsMessage>().Alerts);
            _eventBuffer.Reset();
            Interlocked.Exchange(ref _lastSequence, activeSnapshot.Sequence);
            Interlocked.Exchange(ref _resyncRequested, 0);
            ProtectionMode = status.Mode;
            DatabasePath = status.DatabasePath;
            UpdateFileSensor(status);
            var preferenceResponse = await _requestSession.SendAsync(
                MessageEnvelope.Create(MessageTypes.GetFileCorrelationPreference, new GetFileCorrelationPreferenceMessage()),
                TimeSpan.FromSeconds(3),
                CancellationToken.None).ConfigureAwait(true);
            if (preferenceResponse.Type == MessageTypes.GetFileCorrelationPreference)
            {
                UpdateFileCorrelationPreference(preferenceResponse.ReadPayload<FileCorrelationPreferenceResultMessage>());
            }
            else
            {
                // An older service has no preference endpoint. Keep the legacy
                // active status visible without inventing a saved choice.
                UpdateFileCorrelationPreference(new FileCorrelationPreferenceResultMessage(
                    status.FileCorrelationEnabled,
                    status.FileCorrelationEnabled,
                    false));
            }
            ServiceStatus = $"Service online · {status.Mode} · dropped {status.DroppedEvents}";
            NotifyCounts();
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or OperationCanceledException or InvalidDataException)
        {
            ServiceStatus = "Service disconnected · reconnecting";
            LastOperation = exception.Message;
        }
    }

    private async Task RunSubscriptionLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await _eventClient.SubscribeAsync(
                    Interlocked.Read(ref _lastSequence),
                    streamEvent =>
                    {
                        if (!_eventBuffer.Enqueue(streamEvent))
                        {
                            Interlocked.Exchange(ref _resyncRequested, 1);
                        }

                        return ValueTask.CompletedTask;
                    },
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or OperationCanceledException or ObjectDisposedException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                Interlocked.Exchange(ref _resyncRequested, 1);
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ApplyEventBatchAsync()
    {
        if (Interlocked.Exchange(ref _resyncRequested, 0) != 0)
        {
            await _eventClient.DisconnectAsync().ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
            return;
        }

        var batch = _eventBuffer.Drain(Interlocked.Read(ref _lastSequence), 500);
        if (batch.RequiresResync)
        {
            Interlocked.Exchange(ref _resyncRequested, 1);
            return;
        }

        if (batch.Events.Count == 0)
        {
            return;
        }

        foreach (var streamEvent in batch.Events)
        {
            ApplyEvent(streamEvent);
        }

        Interlocked.Exchange(ref _lastSequence, batch.LastSequence);
        NotifyCounts(refreshView: false);
    }

    private async void OnBatchTimerTick(object? sender, EventArgs eventArgs)
    {
        if (Interlocked.Exchange(ref _batchBusy, 1) != 0)
        {
            return;
        }

        try
        {
            await ApplyEventBatchAsync().ConfigureAwait(true);
        }
        catch (Exception exception)
        {
            ServiceStatus = "Service event stream failed · reconnecting";
            LastOperation = exception.Message;
            Interlocked.Exchange(ref _resyncRequested, 1);
        }
        finally
        {
            Interlocked.Exchange(ref _batchBusy, 0);
        }
    }

    private void ApplyEvent(StreamEventMessage streamEvent)
    {
        switch (streamEvent.Kind)
        {
            case StreamEventKind.FlowAdded when streamEvent.Flow is not null:
                if (Flows.All(row => row.Flow.Id != streamEvent.Flow.Id))
                {
                    Flows.Add(new FlowRow(streamEvent.Flow));
                }
                break;
            case StreamEventKind.FlowUpdated when streamEvent.Flow is not null:
                var updateIndex = IndexOfFlow(streamEvent.Flow.Id);
                if (updateIndex >= 0) Flows[updateIndex] = new FlowRow(streamEvent.Flow);
                else Flows.Add(new FlowRow(streamEvent.Flow));
                _correlationRefresh.NotifyFlowUpdated(streamEvent.Flow.Id);
                break;
            case StreamEventKind.FlowRemoved when streamEvent.FlowId is not null:
                var removeIndex = IndexOfFlow(streamEvent.FlowId);
                if (removeIndex >= 0) Flows.RemoveAt(removeIndex);
                break;
            case StreamEventKind.AlertRaised when streamEvent.Alert is not null:
                if (Alerts.All(alert => alert.Id != streamEvent.Alert.Id)) Alerts.Insert(0, streamEvent.Alert);
                break;
            case StreamEventKind.ServiceStatusChanged when streamEvent.Status is not null:
                ProtectionMode = streamEvent.Status.Mode;
                DatabasePath = streamEvent.Status.DatabasePath;
                ServiceStatus = $"Service online · {streamEvent.Status.Mode} · dropped {streamEvent.Status.DroppedEvents}";
                UpdateFileSensor(streamEvent.Status);
                break;
            case StreamEventKind.ResyncRequired:
                Interlocked.Exchange(ref _resyncRequested, 1);
                break;
        }
    }

    private int IndexOfFlow(string flowId)
    {
        for (var index = 0; index < Flows.Count; index++)
        {
            if (string.Equals(Flows[index].Flow.Id, flowId, StringComparison.Ordinal)) return index;
        }
        return -1;
    }

    private async Task<FileActivityHistoryMessage> FetchFileActivityHistoryAsync(
        GetFileActivityHistoryMessage request,
        CancellationToken cancellationToken)
    {
        var response = await _requestSession.SendAsync(
            MessageEnvelope.Create(MessageTypes.GetFileActivityHistory, request),
            TimeSpan.FromSeconds(5),
            cancellationToken).ConfigureAwait(true);
        if (response.Type == MessageTypes.Error)
        {
            var error = response.ReadPayload<ErrorMessage>();
            throw new InvalidDataException(error.Message);
        }

        return response.ReadPayload<FileActivityHistoryMessage>();
    }

    internal Task ExportFileActivityHistoryForTestAsync() => ExportFileActivityHistoryAsync();

    private static string? PickFileActivityHistoryPath()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export file activity history",
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".csv",
            AddExtension = true,
            FileName = "egressguard-file-activity-history.csv"
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private async Task ExportFileActivityHistoryAsync()
    {
        var path = _historyPathPicker();
        if (path is null)
            return;

        await ExportFileActivityHistoryToPathAsync(path).ConfigureAwait(true);
    }

    private async Task ExportFileActivityHistoryToPathAsync(string path)
    {
        var endUtc = DateTimeOffset.UtcNow;
        var cancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCancellation.Token);
        _historyExporting = true;
        FileActivityHistoryExportStatus = "Exporting…";
        OnPropertyChanged(nameof(FileActivityHistoryStatus));
        try
        {
            var rows = new List<FileCorrelationHistoryItem>(capacity: 200);
            var seenIds = new HashSet<Guid>();
            var usedCursors = new HashSet<string>(StringComparer.Ordinal);
            FileActivityHistoryCursorMessage? cursor = null;
            var truncated = false;
            var search = string.IsNullOrWhiteSpace(FileHistorySearchText) ? null : FileHistorySearchText;
            var operation = ParseFileHistoryOperation(FileHistoryOperationFilter);
            var confidence = ParseFileHistoryConfidence(FileHistoryConfidenceFilter);
            var range = HistoryRangeSpan(FileHistoryRange);
            while (rows.Count < FileActivityHistoryCsvExporter.MaximumRows)
            {
                var request = BuildFileActivityHistoryRequest(cursor, endUtc, 200, search, operation, confidence, range);
                var page = await _historyFetcher(request, cancellation.Token).ConfigureAwait(true);
                var nextCursor = FileActivityHistoryPaginationValidator.Validate(request, page, seenIds, usedCursors);
                var remaining = FileActivityHistoryCsvExporter.MaximumRows - rows.Count;
                if (page.Items.Count > remaining)
                    truncated = true;
                rows.AddRange(page.Items.Take(remaining));

                if (!page.HasMore)
                    break;
                if (rows.Count == FileActivityHistoryCsvExporter.MaximumRows)
                {
                    truncated = true;
                    break;
                }

                cursor = nextCursor ?? throw new InvalidDataException("A history response with more pages did not provide a cursor.");
            }

            await _historyWriter(path, rows, cancellation.Token).ConfigureAwait(true);
            FileActivityHistoryExportStatus = truncated
                ? $"Export complete; report limited to {FileActivityHistoryCsvExporter.MaximumRows.ToString(CultureInfo.InvariantCulture)} rows."
                : $"Export complete; {rows.Count.ToString(CultureInfo.InvariantCulture)} rows written.";
            LastOperation = FileActivityHistoryExportStatus;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested && _lifetimeCancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or TimeoutException)
        {
            FileActivityHistoryExportStatus = "Export failed; the report was not confirmed as written.";
            LastOperation = "File activity history export failed.";
        }
        finally
        {
            cancellation.Dispose();
            _historyExporting = false;
            OnPropertyChanged(nameof(FileActivityHistoryStatus));
        }
    }

    private async Task<FileCorrelationsMessage> FetchFileCorrelationsAsync(string flowId, CancellationToken cancellationToken)
    {
        var response = await _requestSession.SendAsync(
            MessageEnvelope.Create(MessageTypes.GetFileCorrelations, new GetFileCorrelationsMessage(flowId, 20)),
            TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(true);
        return response.ReadPayload<FileCorrelationsMessage>();
    }

    private async Task SaveFileCorrelationPreferenceAsync()
    {
        try
        {
            var response = await _requestSession.SendAsync(
                MessageEnvelope.Create(
                    MessageTypes.SetFileCorrelationPreference,
                    new SetFileCorrelationPreferenceMessage(FileCorrelationPreferenceEnabled)),
                TimeSpan.FromSeconds(10),
                CancellationToken.None).ConfigureAwait(true);
            if (response.Type == MessageTypes.Error)
            {
                LastOperation = response.ReadPayload<ErrorMessage>().Message;
                return;
            }

            var result = response.ReadPayload<FileCorrelationPreferenceResultMessage>();
            UpdateFileCorrelationPreference(result);
            LastOperation = result.RestartRequired
                ? "File activity tracking choice saved. Service restart required to apply it."
                : "File activity tracking choice saved and is applied.";
        }
        catch (Exception exception)
        {
            LastOperation = exception.Message;
        }
    }

    private void ApplyFileCorrelations(string flowId, FileCorrelationsMessage payload)
    {
        var selectedFlowId = SelectedFlow?.Flow.Id;
        var identifiersMatch = string.Equals(flowId, selectedFlowId, StringComparison.Ordinal)
            && string.Equals(selectedFlowId, payload.FlowId, StringComparison.Ordinal)
            && string.Equals(payload.FlowId, flowId, StringComparison.Ordinal);
        if (!identifiersMatch)
        {
            if (string.Equals(flowId, selectedFlowId, StringComparison.Ordinal))
            {
                HandleFileCorrelationFailure(
                    flowId,
                    new InvalidDataException("File correlation response did not match the selected connection."));
            }
            return;
        }

        Replace(FileCorrelations, payload.Correlations.Select(item => new FileCorrelationRow(item)));
        _fileSensorState = payload.SensorStatus.State;
        _observedFileSensorStatus = FormatFileSensor(payload.SensorStatus);
        _fileCorrelationLoading = false;
        _fileCorrelationLoadFailed = false;
        FileCorrelationView.Refresh();
        RefreshFileCorrelationPresentation();
    }

    private void HandleFileCorrelationFailure(string flowId, Exception exception)
    {
        if (exception is not (IOException or TimeoutException or InvalidDataException)) return;
        if (!string.Equals(SelectedFlow?.Flow.Id, flowId, StringComparison.Ordinal)) return;
        Replace(FileCorrelations, []);
        FileCorrelationView.Refresh();
        _fileCorrelationLoading = false;
        _fileCorrelationLoadFailed = true;
        LastOperation = exception.Message;
        RefreshFileCorrelationPresentation();
    }

    internal void UpdateFileSensor(ServiceStatusMessage status)
    {
        FileCorrelationEnabled = status.FileCorrelationEnabled;
        OnPropertyChanged(nameof(FileCorrelationActiveStatus));
        _fileSensorState = status.FileSensor?.State;
        _historySensorState = status.FileSensor?.State;
        _observedFileSensorStatus = status.FileSensor is null ? "File correlation status unavailable" : FormatFileSensor(status.FileSensor);
        RefreshFileCorrelationPresentation();
        RefreshFileActivityHistoryPresentation();
    }

    internal void UpdateFileCorrelationPreference(FileCorrelationPreferenceResultMessage result)
    {
        FileCorrelationEnabled = result.ActiveEnabled;
        FileCorrelationPreferenceEnabled = result.SavedEnabled;
        if (Set(ref _fileCorrelationSavedEnabled, result.SavedEnabled))
            OnPropertyChanged(nameof(FileCorrelationSavedStatus));
        if (Set(ref _fileCorrelationRestartRequired, result.RestartRequired))
            OnPropertyChanged(nameof(FileCorrelationRestartStatus));
        OnPropertyChanged(nameof(FileCorrelationActiveStatus));
    }

    private void RefreshFileCorrelationPresentation()
    {
        FileSensorStatus = _fileCorrelationLoading
            ? "File activity for this connection is loading…"
            : _fileCorrelationLoadFailed
                ? "File activity is unavailable for this connection."
                : _observedFileSensorStatus;
        OnPropertyChanged(nameof(FileCorrelationEmptyState));
    }

    internal static string FormatFileSensor(FileSensorStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        var state = status.State switch
        {
            FileSensorState.Disabled => "disabled",
            FileSensorState.Starting => "starting",
            FileSensorState.Running => "active",
            FileSensorState.AccessDenied => "permission denied",
            FileSensorState.ProviderUnavailable or FileSensorState.Failed => "unavailable",
            FileSensorState.OverflowDegraded => "active with dropped events",
            FileSensorState.Stopped => "stopped",
            _ => "unavailable"
        };
        return $"File activity tracker: {state} · dropped {Math.Max(0, status.DroppedEvents)}";
    }

    private static string FormatHistorySensor(FileSensorState state) => state switch
    {
        FileSensorState.Disabled => "File activity sensor: off",
        FileSensorState.AccessDenied => "File activity sensor: permission denied",
        FileSensorState.ProviderUnavailable or FileSensorState.Failed => "File activity sensor: unavailable",
        FileSensorState.Stopped => "File activity sensor: stopped",
        FileSensorState.OverflowDegraded => "File activity sensor: active with dropped events",
        FileSensorState.Starting => "File activity sensor: starting",
        FileSensorState.Running => "File activity sensor: active",
        _ => "File activity sensor: unavailable"
    };

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
            var response = await _requestSession.SendAsync(MessageEnvelope.Create(type, payload), TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(true);
            LastOperation = response.Type == MessageTypes.Error ? response.ReadPayload<ErrorMessage>().Message : response.ReadPayload<SuccessMessage>().Message;
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception exception)
        {
            LastOperation = exception.Message;
        }
    }

    private Task ConfirmAndSendAsync<T>(string question, string type, T payload) =>
        System.Windows.MessageBox.Show(question, "EgressGuard", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning)
            == System.Windows.MessageBoxResult.Yes
            ? SendMutationAsync(type, payload)
            : Task.CompletedTask;

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

    private bool FilterFileCorrelation(object item) =>
        item is FileCorrelationRow row && MatchesFileActivityFilter(row.Operation, FileActivityFilter);

    internal static bool MatchesFileActivityFilter(FileActivityOperation operation, string filter) => filter switch
    {
        FileActivityFilterAll => true,
        FileActivityFilterReadOpen => operation is FileActivityOperation.Read or FileActivityOperation.OpenCreate,
        FileActivityFilterModify => operation is FileActivityOperation.Write or FileActivityOperation.Rename or FileActivityOperation.Delete,
        _ => false
    };

    internal const string FileActivityFilterAll = "All file activity";
    internal const string FileActivityFilterReadOpen = "Read / open";
    internal const string FileActivityFilterModify = "Write / rename / delete";

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear();
        foreach (var value in values) target.Add(value);
    }

    private void NotifyCounts(bool refreshView = true)
    {
        OnPropertyChanged(nameof(ActiveCount));
        OnPropertyChanged(nameof(ProcessCount));
        OnPropertyChanged(nameof(AlertCount));
        if (refreshView) FlowView.Refresh();
    }

    private Task SetOperationAsync(string message) { LastOperation = message; return Task.CompletedTask; }
    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null) { if (EqualityComparer<T>.Default.Equals(field, value)) return false; field = value; OnPropertyChanged(name); return true; }
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;
        CancelHistoryRequest();
        _batchTimer.Stop();
        _lifetimeCancellation.Cancel();
        await _correlationRefresh.DisposeAsync().ConfigureAwait(false);
        await _eventClient.DisposeAsync().ConfigureAwait(false);
        if (_ownsRequestSession)
            await _requestSession.DisposeAsync().ConfigureAwait(false);
        if (_subscriptionTask is not null)
        {
            try { await _subscriptionTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
        _lifetimeCancellation.Dispose();
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
    public string Signature => $"Authenticode/publisher: {Flow.Executable?.SignatureStatus.ToString() ?? "Unknown"} / {Publisher}";
    public string Parent => $"Parent PID: {Flow.ParentProcessId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "Unavailable"}";
    public string Destination => $"Destination: {Remote}; domain evidence: {Flow.Destination?.DomainEvidence ?? "Unavailable"}";
    public string Reasons => "Risk reasons: " + string.Join(" | ", Flow.Risk?.Reasons.Select(reason => $"{reason.Code} ({reason.Points:+#;-#;0}): {reason.Message}") ?? []);
}

public sealed class FileCorrelationRow
{
    public FileCorrelationRow(FileCorrelation correlation)
    {
        ArgumentNullException.ThrowIfNull(correlation);
        var protectedCorrelation = FileCorrelationPrivacy.ProtectForBoundary(correlation);
        Operation = protectedCorrelation.Operation;
        OperationLabel = protectedCorrelation.Operation switch
        {
            FileActivityOperation.OpenCreate => "Open / create",
            FileActivityOperation.Read => "Read",
            FileActivityOperation.Write => "Write",
            FileActivityOperation.Rename => "Rename",
            FileActivityOperation.Delete => "Delete",
            _ => "Unknown"
        };
        RedactedFileLabel = protectedCorrelation.DisplayPath;
        ActivityTimestampUtc = protectedCorrelation.ActivityTimestampUtc;
        ActivityTime = protectedCorrelation.ActivityTimestampUtc.ToLocalTime().ToString("G", CultureInfo.CurrentCulture);
        var absoluteDelta = Math.Abs(protectedCorrelation.TimeDeltaSeconds);
        RelativeTiming = absoluteDelta < 0.0005
            ? "At connection time"
            : $"{absoluteDelta:0.###} s {(protectedCorrelation.TimeDeltaSeconds < 0 ? "before" : "after")} connection";
        Confidence = protectedCorrelation.Confidence.ToString();
        Reason = protectedCorrelation.Reason;
    }

    public FileActivityOperation Operation { get; }
    public string OperationLabel { get; }
    public string RedactedFileLabel { get; }
    public DateTimeOffset ActivityTimestampUtc { get; }
    public string ActivityTime { get; }
    public string RelativeTiming { get; }
    public string Confidence { get; }
    public string Reason { get; }
}

public sealed class FileActivityHistoryRow
{
    public FileActivityHistoryRow(FileCorrelationHistoryItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        Id = item.Id;
        ActivityTime = item.ActivityTimestampUtc.ToLocalTime().ToString("G", CultureInfo.CurrentCulture);
        ProcessName = item.ProcessName;
        Operation = item.Operation switch
        {
            FileActivityOperation.OpenCreate => "Open / create",
            FileActivityOperation.Read => "Read",
            FileActivityOperation.Write => "Write",
            FileActivityOperation.Rename => "Rename",
            FileActivityOperation.Delete => "Delete",
            _ => "Unknown"
        };
        DisplayPath = item.DisplayPath;
        Extension = item.Extension;
        Relevance = item.Confidence.ToString();
        TimeDistance = Math.Abs(item.TimeDeltaSeconds) < 0.0005
            ? "At connection time"
            : $"{Math.Abs(item.TimeDeltaSeconds):0.###} s {(item.TimeDeltaSeconds < 0 ? "before" : "after")} connection";
        Reason = item.Reason;
        ConnectionCode = item.FlowId;
    }

    public Guid Id { get; }
    public string ActivityTime { get; }
    public string ProcessName { get; }
    public string Operation { get; }
    public string DisplayPath { get; }
    public string Extension { get; }
    public string Relevance { get; }
    public string TimeDistance { get; }
    public string Reason { get; }
    public string ConnectionCode { get; }
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
