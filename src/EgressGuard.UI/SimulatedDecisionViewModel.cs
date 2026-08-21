using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Threading;
using EgressGuard.Protocol;

namespace EgressGuard.UI;

public sealed class SimulatedDecisionViewModel : INotifyPropertyChanged, IAsyncDisposable
{
    private const int EventBufferCapacity = 512;
    private const int MaximumBatchSize = 128;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(3);
    private readonly EgressGuardPipeClient _requestClient;
    private readonly EgressGuardSimulatedDecisionEventClient _eventClient;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly DispatcherTimer _timer;
    private readonly Dispatcher _dispatcher;
    private readonly object _eventSync = new();
    private readonly Queue<SimulatedDecisionEventMessage> _eventBuffer = [];
    private readonly SimulationCommand _allowOnceCommand;
    private readonly SimulationCommand _rememberCommand;
    private readonly SimulationCommand _blockCommand;
    private readonly SimulationCommand _revokeCommand;
    private readonly SimulationCommand _refreshCommand;
    private SimulatedDecisionAuthorizationProjection _authorization = new(false, false, false, false, false, "sim-ui-disabled");
    private SimulatedDecisionPromptProjection? _selectedPrompt;
    private SimulatedRememberedRuleProjection? _selectedRule;
    private string _simulationStatus = "Simulation decision service is disconnected.";
    private string _lastResult = "No Simulation decision has been submitted.";
    private long _lastSequence;
    private long _selectedPromptTick;
    private bool _simulationEnabled;
    private bool _streamContinuous;
    private bool _bufferOverflowed;
    private bool _disposed;
    private Task? _subscriptionTask;

    public SimulatedDecisionViewModel(string? pipeName = null)
    {
        _requestClient = new EgressGuardPipeClient(pipeName);
        _eventClient = new EgressGuardSimulatedDecisionEventClient(pipeName);
        _dispatcher = Dispatcher.CurrentDispatcher;
        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(250)
        };
        _timer.Tick += OnTimerTick;
        _allowOnceCommand = new SimulationCommand(() => SubmitAsync(SimulatedDecisionChoice.AllowOnce), () => CanSubmit(_authorization.CanAllowOnce));
        _rememberCommand = new SimulationCommand(() => SubmitAsync(SimulatedDecisionChoice.RememberFor30Days), () => CanSubmit(_authorization.CanRememberFor30Days));
        _blockCommand = new SimulationCommand(() => SubmitAsync(SimulatedDecisionChoice.BlockCurrent), () => CanSubmit(_authorization.CanBlockCurrent));
        _revokeCommand = new SimulationCommand(RevokeAsync, () => _streamContinuous && _authorization.CanRevoke && SelectedRule is not null);
        _refreshCommand = new SimulationCommand(RefreshAndReconnectAsync, () => !_disposed);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    internal event EventHandler? PromptTerminalized;

    public ObservableCollection<SimulatedDecisionPromptProjection> ActivePrompts { get; } = [];
    public ObservableCollection<SimulatedReconnectRequiredProjection> ReconnectNotices { get; } = [];
    public ObservableCollection<SimulatedRememberedRuleProjection> RememberedRules { get; } = [];
    public ObservableCollection<SimulatedGateStatusProjection> RecentStatuses { get; } = [];
    public ObservableCollection<SimulatedCriticalAlertProjection> CriticalAlerts { get; } = [];

    public ICommand AllowOnceCommand => _allowOnceCommand;
    public ICommand Remember30DaysCommand => _rememberCommand;
    public ICommand BlockCurrentFlowCommand => _blockCommand;
    public ICommand RevokeRememberedRuleCommand => _revokeCommand;
    public ICommand RefreshCommand => _refreshCommand;

    public string SimulationModeLabel { get; } = "Simulation";
    public string NonEnforcementCopy { get; } = "Simulation only. This surface does not claim real network enforcement.";

    public string SimulationStatus
    {
        get => _simulationStatus;
        private set => Set(ref _simulationStatus, value);
    }

    public string LastResult
    {
        get => _lastResult;
        private set => Set(ref _lastResult, value);
    }

    public SimulatedDecisionPromptProjection? SelectedPrompt
    {
        get => _selectedPrompt;
        set
        {
            if (!Set(ref _selectedPrompt, value))
                return;
            _selectedPromptTick = Environment.TickCount64;
            NotifyPromptDetails();
            RaiseCommandState();
        }
    }

    public SimulatedRememberedRuleProjection? SelectedRule
    {
        get => _selectedRule;
        set
        {
            if (Set(ref _selectedRule, value))
                RaiseCommandState();
        }
    }

    public string DecisionFileLabel => SelectedPrompt?.RedactedFileLabel ?? "Select an active Simulation prompt.";
    public string DecisionFileVersion => SelectedPrompt is null
        ? "Version metadata unavailable."
        : $"Metadata selector {SelectedPrompt.FileVersion.VersionToken}; size {SelectedPrompt.FileVersion.SizeBytes}; last write {SelectedPrompt.FileVersion.LastWriteTimeUtc:O}; change {SelectedPrompt.FileVersion.ChangeTimeUtc:O}; USN {SelectedPrompt.FileVersion.Usn?.ToString(CultureInfo.InvariantCulture) ?? "unavailable"}.";
    public string DecisionApplication => SelectedPrompt?.ApplicationIdentity ?? "Application unavailable.";
    public string DecisionSubjectScope => SelectedPrompt is null
        ? "Exact process scope unavailable."
        : $"{SelectedPrompt.Subject.Kind}: {string.Join(", ", SelectedPrompt.Subject.ExactMembers.Select(member => $"PID {member.ProcessId} at {member.StartTime:O}"))}";
    public string DecisionCollateralWarning => SelectedPrompt?.Subject.CollateralWarning ?? "This choice affects only the displayed exact process.";
    public string DecisionDestination => SelectedPrompt is null
        ? "Destination unavailable."
        : $"{SelectedPrompt.Destination.Protocol} {SelectedPrompt.Destination.Address}:{SelectedPrompt.Destination.RemotePort} ({SelectedPrompt.Destination.IpVersion})";
    public string DecisionDomainProvenance => SelectedPrompt?.Destination.DomainEvidence is null
        ? "No domain evidence was projected."
        : $"Domain {SelectedPrompt.Destination.DomainEvidence}; provenance {SelectedPrompt.Destination.DomainProvenance}; observed {SelectedPrompt.Destination.DomainObservedAtUtc:O}.";
    public string DecisionExistingFlowWarning { get; } = "Decision prompts represent only a new flow. Existing multiplexed traffic requires reconnect.";
    public string DecisionLimitation => SelectedPrompt?.LimitationReason ?? "No additional Simulation limitation was projected.";
    public string DecisionExpiry => SelectedPrompt is null
        ? "No active decision deadline."
        : RemainingMilliseconds() > 0
            ? $"About {RemainingMilliseconds()} ms remain. Service monotonic authority is final."
            : "The displayed deadline has elapsed. Choices stay disabled until authoritative resync.";
    public string DecisionScopePreview => SelectedPrompt is null
        ? "Select a prompt to preview the remembered scope."
        : $"Remember exact metadata selector {SelectedPrompt.FileVersion.VersionToken}, application {SelectedPrompt.ApplicationIdentity}, destination {SelectedPrompt.Destination.Address}:{SelectedPrompt.Destination.RemotePort}, protocol {SelectedPrompt.Destination.Protocol}. Remembered for up to 30 days in this simulation; service restart, mutation, revocation, or policy change clears it.";
    public string ReconnectRequiredNotice => ReconnectNotices.LastOrDefault() is { } notice
        ? $"Simulation reconnect required for {notice.RedactedFileLabel}: the existing flow was not held. Start a new connection to receive a decision prompt."
        : "No reconnect-required Simulation notice.";
    public string CriticalFailOpenBanner => CriticalAlerts.LastOrDefault(alert => alert.TrafficFailedOpen) is { } alert
        ? $"{alert.PresentationText} Reason {alert.ReasonCode}; dropped {alert.DroppedCount}; overflow {alert.OverflowCount}."
        : "No Critical Simulation fail-open alert.";

    public async Task StartAsync()
    {
        ThrowIfDisposed();
        _timer.Start();
        try
        {
            await RefreshSnapshotAsync().ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or TimeoutException or UnauthorizedAccessException)
        {
            SimulationStatus = "Simulation decision service is unavailable. Commands remain disabled.";
            LastResult = exception.Message;
        }
        StartSubscription();
    }

    private void StartSubscription()
    {
        if (_subscriptionTask is { IsCompleted: false })
            return;
        _subscriptionTask = RunSubscriptionAsync(_lifetime.Token);
    }

    private async Task RunSubscriptionAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var sequence = Interlocked.Read(ref _lastSequence);
                await _eventClient.SubscribeAsync(
                    sequence,
                    OnEventAsync,
                    () => _streamContinuous = true,
                    cancellationToken).ConfigureAwait(false);
                throw new EndOfStreamException("Simulation decision event stream ended.");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or TimeoutException or UnauthorizedAccessException or ObjectDisposedException)
            {
                _streamContinuous = false;
                await _dispatcher.InvokeAsync(() =>
                {
                    SimulationStatus = "Simulation event continuity lost. Commands are disabled while resyncing.";
                    RaiseCommandState();
                });
                try
                {
                    await _dispatcher.InvokeAsync(RefreshSnapshotAsync).Task.Unwrap().ConfigureAwait(false);
                }
                catch (Exception refreshException) when (refreshException is IOException or InvalidDataException or TimeoutException or UnauthorizedAccessException or ObjectDisposedException)
                {
                    await _dispatcher.InvokeAsync(() => LastResult = refreshException.Message);
                }
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private ValueTask OnEventAsync(SimulatedDecisionEventMessage streamEvent)
    {
        lock (_eventSync)
        {
            if (_eventBuffer.Count >= EventBufferCapacity)
            {
                _eventBuffer.Clear();
                _bufferOverflowed = true;
                _streamContinuous = false;
                return ValueTask.CompletedTask;
            }
            if (!_bufferOverflowed)
                _eventBuffer.Enqueue(streamEvent);
        }
        return ValueTask.CompletedTask;
    }

    private async void OnTimerTick(object? sender, EventArgs eventArgs)
    {
        try
        {
            if (DrainEvents())
                await RefreshAndReconnectAsync().ConfigureAwait(true);
            OnPropertyChanged(nameof(DecisionExpiry));
            RaiseCommandState();
        }
        catch (Exception exception)
        {
            _streamContinuous = false;
            LastResult = exception.Message;
            RaiseCommandState();
        }
    }

    private bool DrainEvents()
    {
        List<SimulatedDecisionEventMessage> batch = [];
        lock (_eventSync)
        {
            if (_bufferOverflowed)
            {
                _bufferOverflowed = false;
                _eventBuffer.Clear();
                return true;
            }
            while (batch.Count < MaximumBatchSize && _eventBuffer.TryDequeue(out var item))
                batch.Add(item);
        }

        var sequence = Interlocked.Read(ref _lastSequence);
        foreach (var streamEvent in batch)
        {
            if (streamEvent.RequiresResync || streamEvent.Sequence != sequence + 1)
                return true;
            ApplyEvent(streamEvent);
            sequence = streamEvent.Sequence;
        }
        Interlocked.Exchange(ref _lastSequence, sequence);
        return false;
    }

    private void ApplyEvent(SimulatedDecisionEventMessage streamEvent)
    {
        switch (streamEvent.Kind)
        {
            case SimulatedDecisionEventKind.PromptUpserted:
                Upsert(ActivePrompts, streamEvent.Prompt!, item => item.ChallengeId);
                break;
            case SimulatedDecisionEventKind.PromptRemoved:
                Remove(ActivePrompts, streamEvent.RemovedChallengeId!.Value, item => item.ChallengeId);
                PromptTerminalized?.Invoke(this, EventArgs.Empty);
                break;
            case SimulatedDecisionEventKind.ReconnectRequired:
                AppendBounded(ReconnectNotices, streamEvent.ReconnectNotice!, SimulatedDecisionProtocolLimits.MaximumReconnectNoticeCount);
                OnPropertyChanged(nameof(ReconnectRequiredNotice));
                break;
            case SimulatedDecisionEventKind.RememberedRuleUpserted:
                Upsert(RememberedRules, streamEvent.RememberedRule!, item => item.RuleId);
                break;
            case SimulatedDecisionEventKind.RememberedRuleRemoved:
                Remove(RememberedRules, streamEvent.RemovedRuleId!.Value, item => item.RuleId);
                break;
            case SimulatedDecisionEventKind.StatusChanged:
                AppendBounded(RecentStatuses, streamEvent.Status!, SimulatedDecisionProtocolLimits.MaximumStatusCount);
                break;
            case SimulatedDecisionEventKind.CriticalAlertRaised:
                AppendBounded(CriticalAlerts, streamEvent.CriticalAlert!, SimulatedDecisionProtocolLimits.MaximumCriticalAlertCount);
                OnPropertyChanged(nameof(CriticalFailOpenBanner));
                break;
            case SimulatedDecisionEventKind.ResyncRequired:
                _streamContinuous = false;
                break;
        }
        if (SelectedPrompt is not null)
            SelectedPrompt = ActivePrompts.FirstOrDefault(item => item.ChallengeId == SelectedPrompt.ChallengeId);
        if (SelectedRule is not null)
            SelectedRule = RememberedRules.FirstOrDefault(item => item.RuleId == SelectedRule.RuleId);
        RaiseCommandState();
    }

    private async Task RefreshAndReconnectAsync()
    {
        _streamContinuous = false;
        RaiseCommandState();
        try
        {
            await _eventClient.DisconnectAsync().ConfigureAwait(true);
            await RefreshSnapshotAsync().ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or TimeoutException or UnauthorizedAccessException or ObjectDisposedException)
        {
            SimulationStatus = "Simulation event continuity is unavailable. Commands remain disabled.";
            LastResult = exception.Message;
        }
        finally
        {
            RaiseCommandState();
        }
    }

    private async Task RefreshSnapshotAsync()
    {
        await EnsureRequestConnectedAsync().ConfigureAwait(true);
        var response = await _requestClient.SendAsync(
            MessageEnvelope.Create(
                OutboundGateMessageTypes.GetSimulatedDecisionSnapshot,
                new GetSimulatedDecisionSnapshotMessage(ProtocolConstants.Version)),
            RequestTimeout,
            _lifetime.Token).ConfigureAwait(true);
        ThrowIfError(response);
        if (response.Type != OutboundGateMessageTypes.SimulatedDecisionSnapshot)
            throw new InvalidDataException($"Unexpected Simulation snapshot response: {response.Type}");
        ApplySnapshot(response.ReadPayload<SimulatedDecisionSnapshotMessage>());
    }

    private void ApplySnapshot(SimulatedDecisionSnapshotMessage snapshot)
    {
        _simulationEnabled = snapshot.SimulationEnabled;
        _authorization = snapshot.Authorization;
        Replace(ActivePrompts, snapshot.ActivePrompts);
        Replace(ReconnectNotices, snapshot.ReconnectNotices);
        Replace(RememberedRules, snapshot.RememberedRules);
        Replace(RecentStatuses, snapshot.RecentStatuses);
        Replace(CriticalAlerts, snapshot.CriticalAlerts);
        Interlocked.Exchange(ref _lastSequence, snapshot.Sequence);
        lock (_eventSync)
        {
            _eventBuffer.Clear();
            _bufferOverflowed = false;
        }
        SelectedPrompt = ActivePrompts.FirstOrDefault();
        SelectedRule = RememberedRules.FirstOrDefault();
        SimulationStatus = snapshot.SimulationEnabled
            ? $"Simulation active. Sequence {snapshot.Sequence}; prompts {ActivePrompts.Count}; remembered rules {RememberedRules.Count}."
            : "Simulation is disabled by default. No decision authority is active.";
        OnPropertyChanged(nameof(ReconnectRequiredNotice));
        OnPropertyChanged(nameof(CriticalFailOpenBanner));
        RaiseCommandState();
    }

    private async Task SubmitAsync(SimulatedDecisionChoice choice)
    {
        if (SelectedPrompt is not { } prompt)
            return;
        try
        {
            await EnsureRequestConnectedAsync().ConfigureAwait(true);
            var response = await _requestClient.SendAsync(
                MessageEnvelope.Create(
                    OutboundGateMessageTypes.SubmitSimulatedDecision,
                    new SubmitSimulatedDecisionMessage(ProtocolConstants.Version, prompt.ChallengeId, choice)),
                RequestTimeout,
                _lifetime.Token).ConfigureAwait(true);
            ThrowIfError(response);
            var result = response.ReadPayload<SimulatedDecisionResultMessage>();
            LastResult = FormatDecisionResult(result);
            if (result.DecisionState != SimulatedDecisionItemState.AwaitingDecision)
                PromptTerminalized?.Invoke(this, EventArgs.Empty);
            await RefreshSnapshotAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or TimeoutException or UnauthorizedAccessException or ObjectDisposedException)
        {
            LastResult = exception.Message;
            _streamContinuous = false;
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        finally
        {
            RaiseCommandState();
        }
    }

    private async Task RevokeAsync()
    {
        if (SelectedRule is not { } rule)
            return;
        try
        {
            await EnsureRequestConnectedAsync().ConfigureAwait(true);
            var response = await _requestClient.SendAsync(
                MessageEnvelope.Create(
                    OutboundGateMessageTypes.RevokeSimulatedRememberedRule,
                    new RevokeSimulatedRememberedRuleMessage(ProtocolConstants.Version, rule.RuleId, rule.Revision)),
                RequestTimeout,
                _lifetime.Token).ConfigureAwait(true);
            ThrowIfError(response);
            var result = response.ReadPayload<SimulatedRuleMutationResultMessage>();
            LastResult = $"Simulation rule {result.RuleId:D}: {result.ReasonCode}.";
            await RefreshSnapshotAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or TimeoutException or UnauthorizedAccessException or ObjectDisposedException)
        {
            LastResult = exception.Message;
            _streamContinuous = false;
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        finally
        {
            RaiseCommandState();
        }
    }

    private bool CanSubmit(bool authorized) => _simulationEnabled
        && _streamContinuous
        && authorized
        && SelectedPrompt?.State == EgressGuard.Core.GateRuntimeState.AwaitingDecision
        && SelectedPrompt.Expiry.AcceptingDecisions
        && RemainingMilliseconds() > 0;

    private long RemainingMilliseconds()
    {
        if (SelectedPrompt is not { } prompt || !prompt.Expiry.AcceptingDecisions)
            return 0;
        var elapsed = Math.Max(0, Environment.TickCount64 - _selectedPromptTick);
        return Math.Max(0, prompt.Expiry.RemainingMilliseconds - elapsed);
    }

    private async Task EnsureRequestConnectedAsync()
    {
        if (!_requestClient.IsConnected)
            await _requestClient.ConnectAsync(RequestTimeout, _lifetime.Token).ConfigureAwait(true);
    }

    private static void ThrowIfError(MessageEnvelope response)
    {
        if (response.Type == MessageTypes.Error)
        {
            var error = response.ReadPayload<ErrorMessage>();
            throw new InvalidDataException($"{error.Code}: {error.Message}");
        }
    }

    private static string FormatDecisionResult(SimulatedDecisionResultMessage result)
    {
        var current = result.TrafficFailedOpen
            ? SimulatedDecisionProtocolLimits.FailOpenPresentationText
            : $"Current Simulation outcome: {result.DecisionState} ({result.DecisionReasonCode}).";
        return result.RememberedRule is null
            ? current
            : $"Rule remembered: {result.RememberedRule.RuleId:D} revision {result.RememberedRule.Revision}. {current}";
    }

    private void NotifyPromptDetails()
    {
        OnPropertyChanged(nameof(DecisionFileLabel));
        OnPropertyChanged(nameof(DecisionFileVersion));
        OnPropertyChanged(nameof(DecisionApplication));
        OnPropertyChanged(nameof(DecisionSubjectScope));
        OnPropertyChanged(nameof(DecisionCollateralWarning));
        OnPropertyChanged(nameof(DecisionDestination));
        OnPropertyChanged(nameof(DecisionDomainProvenance));
        OnPropertyChanged(nameof(DecisionExistingFlowWarning));
        OnPropertyChanged(nameof(DecisionLimitation));
        OnPropertyChanged(nameof(DecisionExpiry));
        OnPropertyChanged(nameof(DecisionScopePreview));
    }

    private void RaiseCommandState()
    {
        _allowOnceCommand.RaiseCanExecuteChanged();
        _rememberCommand.RaiseCanExecuteChanged();
        _blockCommand.RaiseCanExecuteChanged();
        _revokeCommand.RaiseCanExecuteChanged();
        _refreshCommand.RaiseCanExecuteChanged();
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear();
        foreach (var value in values)
            target.Add(value);
    }

    private static void Upsert<T, TKey>(ObservableCollection<T> target, T value, Func<T, TKey> key)
    {
        var index = target.Select((item, position) => (item, position)).FirstOrDefault(pair => EqualityComparer<TKey>.Default.Equals(key(pair.item), key(value))).position;
        if (target.Count > 0 && index >= 0 && index < target.Count && EqualityComparer<TKey>.Default.Equals(key(target[index]), key(value)))
            target[index] = value;
        else
            target.Add(value);
    }

    private static void Remove<T, TKey>(ObservableCollection<T> target, TKey value, Func<T, TKey> key)
    {
        for (var index = 0; index < target.Count; index++)
        {
            if (!EqualityComparer<TKey>.Default.Equals(key(target[index]), value))
                continue;
            target.RemoveAt(index);
            return;
        }
    }

    private static void AppendBounded<T>(ObservableCollection<T> target, T value, int capacity)
    {
        if (target.Count == capacity)
            target.RemoveAt(0);
        target.Add(value);
    }

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;
        _timer.Stop();
        _lifetime.Cancel();
        await _eventClient.DisposeAsync().ConfigureAwait(false);
        await _requestClient.DisposeAsync().ConfigureAwait(false);
        if (_subscriptionTask is not null)
        {
            try
            {
                await _subscriptionTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        lock (_eventSync)
            _eventBuffer.Clear();
        _lifetime.Dispose();
    }

    private sealed class SimulationCommand(Func<Task> execute, Func<bool> canExecute) : ICommand
    {
        private bool _running;
        public event EventHandler? CanExecuteChanged;
        public bool CanExecute(object? parameter) => !_running && canExecute();
        public async void Execute(object? parameter)
        {
            if (!CanExecute(parameter))
                return;
            _running = true;
            RaiseCanExecuteChanged();
            try
            {
                await execute().ConfigureAwait(true);
            }
            finally
            {
                _running = false;
                RaiseCanExecuteChanged();
            }
        }
        internal void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}
