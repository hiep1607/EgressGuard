using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;
using EgressGuard.Core;
using EgressGuard.Persistence;
using EgressGuard.Protocol;
using EgressGuard.Windows;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EgressGuard.Service;

public sealed partial class FlowCoordinator : BackgroundService
{
    private readonly INetworkFlowSensor _sensor;
    private readonly EgressGuardDatabase _database;
    private readonly RiskEngine _riskEngine;
    private readonly BaselineTracker _baseline;
    private readonly IFirewallRuleManager _firewall;
    private readonly ServiceState _state;
    private readonly EventHub _eventHub;
    private readonly ILogger<FlowCoordinator> _logger;
    private readonly Channel<NetworkFlow> _persistenceQueue;
    private readonly ConcurrentDictionary<string, byte> _seenExecutables = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _seenDestinations = new(StringComparer.OrdinalIgnoreCase);

    public FlowCoordinator(
        INetworkFlowSensor sensor,
        EgressGuardDatabase database,
        RiskEngine riskEngine,
        BaselineTracker baseline,
        IFirewallRuleManager firewall,
        ServiceState state,
        EventHub eventHub,
        ILogger<FlowCoordinator> logger)
    {
        _sensor = sensor;
        _database = database;
        _riskEngine = riskEngine;
        _baseline = baseline;
        _firewall = firewall;
        _state = state;
        _eventHub = eventHub;
        _logger = logger;
        _persistenceQueue = Channel.CreateBounded<NetworkFlow>(new BoundedChannelOptions(2048)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true
        });
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Let the host start PipeServer before the first potentially expensive
        // process/hash/signature inventory runs.
        await Task.Yield();
        try
        {
            await _database.InitializeAsync(stoppingToken).ConfigureAwait(false);
            foreach (var persisted in await _database.GetBaselinesAsync(stoppingToken).ConfigureAwait(false))
            {
                _baseline.Seed(persisted.ExecutableSha256, persisted.DestinationKey, persisted.ProtocolPort, persisted.SampleCount, persisted.LastObserved);
            }
            var savedMode = await _database.GetSettingAsync("protection_mode", stoppingToken).ConfigureAwait(false);
            if (Enum.TryParse<ProtectionMode>(savedMode, ignoreCase: true, out var mode))
            {
                _state.Mode = mode;
            }

            await _database.ApplyRetentionAsync(30, stoppingToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            LogDatabaseInitializationFailed(_logger, exception);
            return;
        }

        var persistenceTask = PersistAsync(stoppingToken);
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            do
            {
                await CaptureOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            _persistenceQueue.Writer.TryComplete();
            await persistenceTask.ConfigureAwait(false);
        }
    }

    private async Task CaptureOnceAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<NetworkFlow> captured;
        try
        {
            captured = _sensor.Capture();
        }
        catch (Exception exception)
        {
            LogSensorFailed(_logger, exception);
            return;
        }

        var rules = await SafeGetRulesAsync(cancellationToken).ConfigureAwait(false);
        var assessed = new List<NetworkFlow>(captured.Count);
        foreach (var flow in captured)
        {
            var enriched = Assess(flow, rules);
            assessed.Add(enriched);
            var policy = PolicyEngine.Evaluate(enriched, _state.Mode, rules, IsSystemProtected(enriched));
            var finalFlow = enriched with { IsBlocked = policy.Decision == PolicyDecision.Block };
            assessed[^1] = finalFlow;

            if (_state.Mode == ProtectionMode.Learning)
            {
                _baseline.Observe(finalFlow, finalFlow.IsBlocked, clearlyDangerous: finalFlow.Risk?.Score >= 80);
            }

            if (!_persistenceQueue.Writer.TryWrite(finalFlow))
            {
                _state.RecordDroppedEvent();
            }

            if (_state.Mode == ProtectionMode.Protect && policy.Decision == PolicyDecision.Block && policy.MatchedRule is null)
            {
                await TryApplyAutomaticRuleAsync(finalFlow, cancellationToken).ConfigureAwait(false);
            }
        }

        var changes = _state.ReplaceSnapshot(assessed);
        foreach (var change in changes)
        {
            _eventHub.PublishFlow(change.Kind, change.Flow, change.FlowId);
            if (change.Flow?.Risk?.Level is RiskLevel.High or RiskLevel.Critical)
            {
                _eventHub.PublishAlert(CreateAlert(change.Flow));
            }
        }

        _eventHub.PublishStatus(new ServiceStatusMessage(
            _state.Mode,
            true,
            _state.ActiveFlowCount,
            _state.DroppedEvents,
            _database.DatabasePath,
            DateTimeOffset.UtcNow));
    }

    private NetworkFlow Assess(NetworkFlow flow, IReadOnlyList<FirewallRule> rules)
    {
        var baseline = _baseline.Assess(flow);
        var executableKey = flow.Executable?.Sha256;
        var destinationKey = executableKey is null || flow.Destination is null
            ? null
            : $"{executableKey}|{flow.Destination.Address}|{flow.Destination.Port}|{flow.Protocol}";
        var firstExecutable = executableKey is not null && _seenExecutables.TryAdd(executableKey, 0);
        var firstDestination = destinationKey is not null && _seenDestinations.TryAdd(destinationKey, 0);
        var blockedDestination = rules.Any(rule =>
            rule.Enabled
            && rule.Action == FirewallAction.Block
            && PolicyEngine.RuleMatches(rule, flow));
        var signals = new RiskSignals(
            IsUnsigned: flow.Executable?.SignatureStatus == SignatureVerificationStatus.Unsigned,
            IsInTemp: flow.Executable?.IsInTemp == true,
            IsInUnusualAppData: flow.Executable?.IsInAppData == true,
            IsFirstSeenExecutable: firstExecutable,
            IsUnknownPublisher: flow.Executable is { Publisher: null },
            IsFirstDestination: firstDestination,
            IsDestinationBlocked: blockedDestination,
            IsSuspiciousParent: false,
            HasSufficientBaseline: baseline.HasSufficientSamples,
            DeviatesFromBaseline: baseline.HasSufficientSamples && !baseline.IsKnownDestination,
            ExecutableEvidence: flow.Executable?.Path ?? "Executable metadata unavailable.",
            DestinationEvidence: flow.Destination?.Address.ToString() ?? "UDP remote peer unavailable.",
            ParentEvidence: flow.ParentProcessId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "Parent unavailable.");
        return flow with { Risk = _riskEngine.Assess(signals) };
    }

    private async Task<IReadOnlyList<FirewallRule>> SafeGetRulesAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await _database.GetRulesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            LogRuleReadFailed(_logger, exception);
            return [];
        }
    }

    private async Task TryApplyAutomaticRuleAsync(NetworkFlow flow, CancellationToken cancellationToken)
    {
        if (flow.Executable is null || IsSystemProtected(flow))
        {
            return;
        }

        var rule = new FirewallRule(
            DeterministicRuleId(flow.Id),
            "Automatic critical-risk block",
            FirewallAction.Block,
            RuleSource.Automatic,
            flow.Executable.Path,
            flow.Executable.Sha256,
            flow.Destination?.Address.ToString(),
            flow.Destination?.Port,
            flow.Protocol,
            Enabled: true,
            DateTimeOffset.UtcNow,
            LastMatchedAt: null);
        try
        {
            await _firewall.CreateAsync(rule, cancellationToken).ConfigureAwait(false);
            await _database.SaveRuleAsync(rule, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            LogAutomaticRuleFailed(_logger, exception);
        }
    }

    private async Task PersistAsync(CancellationToken cancellationToken)
    {
        var batch = new List<NetworkFlow>(128);
        try
        {
            while (await _persistenceQueue.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                batch.Clear();
                while (batch.Count < 128 && _persistenceQueue.Reader.TryRead(out var flow))
                {
                    batch.Add(flow);
                }

                if (batch.Count > 0)
                {
                    try
                    {
                        await _database.SaveFlowsAsync(batch, cancellationToken).ConfigureAwait(false);
                        await _database.SaveAlertsAsync(batch, cancellationToken).ConfigureAwait(false);
                        if (_state.Mode == ProtectionMode.Learning)
                        {
                            await _database.SaveBaselineObservationsAsync(batch, cancellationToken).ConfigureAwait(false);
                        }
                    }
                    catch (Exception exception)
                    {
                        LogPersistenceFailed(_logger, exception);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private static bool IsSystemProtected(NetworkFlow flow) =>
        flow.Executable is not null && OwnedFirewallRuleManager.IsProtectedSystemExecutable(flow.Executable.Path);

    private static Guid DeterministicRuleId(string flowId)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(flowId));
        return new Guid(bytes.AsSpan(0, 16));
    }

    private static SecurityAlert CreateAlert(NetworkFlow flow) => new(
        DeterministicRuleId("alert|" + flow.Id),
        flow.Id,
        flow.FirstSeen,
        flow.ProcessName,
        flow.Destination is null ? "Remote endpoint unavailable" : $"{flow.Destination.Address}:{flow.Destination.Port}",
        flow.Risk!,
        null,
        false);

    [LoggerMessage(Level = LogLevel.Error, Message = "Database initialization failed. Protection remains fail-open; no automatic firewall changes will occur.")]
    private static partial void LogDatabaseInitializationFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Network sensor iteration failed; the service will retry.")]
    private static partial void LogSensorFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Rule database read failed; this iteration is fail-open.")]
    private static partial void LogRuleReadFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Automatic rule was not applied; monitoring continues fail-open.")]
    private static partial void LogAutomaticRuleFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Flow persistence batch failed; sensor remains active.")]
    private static partial void LogPersistenceFailed(ILogger logger, Exception exception);
}
