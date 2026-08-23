using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using EgressGuard.Core;
using EgressGuard.Persistence;
using EgressGuard.Protocol;
using EgressGuard.Windows;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EgressGuard.Service;

public sealed partial class PipeServer : BackgroundService
{
    private readonly ServiceState _state;
    private readonly EgressGuardDatabase _database;
    private readonly IFirewallRuleManager _firewall;
    private readonly EventHub _eventHub;
    private readonly ILogger<PipeServer> _logger;
    private readonly FirewallRuleCreateCoordinator _firewallRuleCreateCoordinator;
    private readonly SimulatedDecisionCoordinator _simulatedDecisionCoordinator;
    private readonly bool _ownsSimulatedDecisionCoordinator;
    private readonly SemaphoreSlim _pipeSlots = new(
        SimulatedDecisionProtocolLimits.PipeInstanceCapacity,
        SimulatedDecisionProtocolLimits.PipeInstanceCapacity);
    private int _activePipeCount;

    internal int ActivePipeCount => Volatile.Read(ref _activePipeCount);

    public PipeServer(ServiceState state, EgressGuardDatabase database, IFirewallRuleManager firewall, EventHub eventHub, ILogger<PipeServer> logger)
        : this(
            state,
            database,
            firewall,
            eventHub,
            logger,
            new SimulatedDecisionCoordinator(new DisabledSimulatedDecisionAuthority(), new SimulatedDecisionEventHub()),
            ownsSimulatedDecisionCoordinator: true)
    {
    }

    internal PipeServer(
        ServiceState state,
        EgressGuardDatabase database,
        IFirewallRuleManager firewall,
        EventHub eventHub,
        ILogger<PipeServer> logger,
        SimulatedDecisionCoordinator simulatedDecisionCoordinator)
        : this(state, database, firewall, eventHub, logger, simulatedDecisionCoordinator, ownsSimulatedDecisionCoordinator: false)
    {
    }

    private PipeServer(
        ServiceState state,
        EgressGuardDatabase database,
        IFirewallRuleManager firewall,
        EventHub eventHub,
        ILogger<PipeServer> logger,
        SimulatedDecisionCoordinator simulatedDecisionCoordinator,
        bool ownsSimulatedDecisionCoordinator)
    {
        _state = state;
        _database = database;
        _firewall = firewall;
        _eventHub = eventHub;
        _logger = logger;
        _simulatedDecisionCoordinator = simulatedDecisionCoordinator ?? throw new ArgumentNullException(nameof(simulatedDecisionCoordinator));
        _ownsSimulatedDecisionCoordinator = ownsSimulatedDecisionCoordinator;
        _firewallRuleCreateCoordinator = new FirewallRuleCreateCoordinator(
            _firewall,
            _database.SaveRuleAsync,
            logger,
            _database.GetRulesAsync);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var pipeName = ProtocolConstants.ResolvePipeName();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _pipeSlots.WaitAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreateServerPipe(pipeName);
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                _ = HandleClientAsync(pipe, stoppingToken);
                pipe = null;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                if (pipe is not null)
                    await pipe.DisposeAsync().ConfigureAwait(false);
                _pipeSlots.Release();
                break;
            }
            catch (Exception exception)
            {
                if (pipe is not null)
                    await pipe.DisposeAsync().ConfigureAwait(false);
                _pipeSlots.Release();
                LogAcceptFailed(_logger, exception);
            }
        }
    }

    private static NamedPipeServerStream CreateServerPipe(string pipeName)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var serviceIdentity = identity.User ?? throw new InvalidOperationException("The service Windows identity has no SID.");
        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            SimulatedDecisionProtocolLimits.PipeInstanceCapacity,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            0,
            0,
            CreatePipeSecurity(serviceIdentity));
    }

    internal static PipeSecurity CreatePipeSecurity(SecurityIdentifier serviceIdentity)
    {
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddAllowRule(security, serviceIdentity, PipeAccessRights.FullControl);
        AddAllowRule(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl);
        AddAllowRule(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl);
        AddAllowRule(security, new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite);
        return security;
    }

    private static void AddAllowRule(PipeSecurity security, SecurityIdentifier identity, PipeAccessRights rights)
    {
        security.AddAccessRule(new PipeAccessRule(identity, rights, AccessControlType.Allow));
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        Interlocked.Increment(ref _activePipeCount);
        try
        {
            await using (pipe)
            {
                while (pipe.IsConnected && !stoppingToken.IsCancellationRequested)
                {
                    MessageEnvelope? request = null;
                    try
                    {
                        request = await MessageFraming.ReadAsync(pipe, stoppingToken).ConfigureAwait(false);
                        if (request is null)
                        {
                            break;
                        }

                        if (request.Type == MessageTypes.SubscribeEvents)
                        {
                            await StreamEventsAsync(pipe, request, stoppingToken).ConfigureAwait(false);
                            return;
                        }
                        if (request.Type == OutboundGateMessageTypes.SubscribeSimulatedDecisionEvents)
                        {
                            try
                            {
                                await StreamSimulatedDecisionEventsAsync(pipe, request, stoppingToken).ConfigureAwait(false);
                            }
                            catch (SimulatedDecisionRequestException exception)
                            {
                                await WriteErrorAsync(pipe, request, exception.Code, exception.Message, stoppingToken).ConfigureAwait(false);
                            }
                            catch (Exception exception) when (exception is JsonException or ArgumentException or InvalidDataException)
                            {
                                await WriteErrorAsync(pipe, request, SimulatedDecisionReasonCodes.RequestInvalid, "The Simulation subscription request is invalid.", stoppingToken).ConfigureAwait(false);
                            }
                            return;
                        }

                        var response = await DispatchAsync(pipe, request, stoppingToken).ConfigureAwait(false);
                        await MessageFraming.WriteAsync(pipe, response, stoppingToken).ConfigureAwait(false);
                    }
                    catch (SimulatedDecisionRequestException exception)
                    {
                        LogRequestRejected(_logger, exception.Message);
                        if (!pipe.IsConnected)
                            break;
                        await WriteErrorAsync(pipe, request, exception.Code, exception.Message, stoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or JsonException)
                    {
                        var detail = string.IsNullOrWhiteSpace(exception.Message)
                            ? exception.GetType().FullName ?? exception.GetType().Name
                            : exception.Message;
                        LogRequestRejected(_logger, detail);
                        if (!pipe.IsConnected)
                        {
                            break;
                        }

                        var error = MessageEnvelope.Create(MessageTypes.Error, new ErrorMessage("REQUEST_REJECTED", detail), request?.CorrelationId);
                        await MessageFraming.WriteAsync(pipe, error, stoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception exception)
                    {
                        LogClientFailed(_logger, exception);
                        break;
                    }
                }
            }
        }
        finally
        {
            Interlocked.Decrement(ref _activePipeCount);
            _pipeSlots.Release();
        }
    }

    private async Task<MessageEnvelope> DispatchAsync(NamedPipeServerStream pipe, MessageEnvelope request, CancellationToken cancellationToken)
    {
        if (IsSimulatedDecisionRequest(request.Type))
            return DispatchSimulatedDecision(pipe, request);

        if (RequiresAdministrator(request.Type) && !IsAdministratorClient(pipe))
        {
            throw new UnauthorizedAccessException("The connected Windows identity is not authorized to modify protection state.");
        }

        switch (request.Type)
        {
            case MessageTypes.Handshake:
                var handshake = request.ReadPayload<HandshakeMessage>();
                if (handshake.MinimumVersion > ProtocolConstants.Version || handshake.MaximumVersion < ProtocolConstants.Version)
                {
                    throw new InvalidDataException("No compatible protocol version.");
                }

                return Success(request, "Handshake accepted.");
            case MessageTypes.GetStatus:
                return MessageEnvelope.Create(
                    MessageTypes.ServiceStatusChanged,
                    new ServiceStatusMessage(_state.Mode, true, _state.ActiveFlowCount, _state.DroppedEvents, _database.DatabasePath, DateTimeOffset.UtcNow, _state.FileSensorStatus, _state.FileCorrelationEnabled),
                    request.CorrelationId);
            case MessageTypes.GetFileCorrelationPreference:
                var savedPreference = await _database.GetFileCorrelationPreferenceAsync(cancellationToken).ConfigureAwait(false);
                return MessageEnvelope.Create(
                    MessageTypes.GetFileCorrelationPreference,
                    FileCorrelationPreferenceCoordinator.Read(savedPreference, _state.FileCorrelationEnabled),
                    request.CorrelationId);
            case MessageTypes.SetFileCorrelationPreference:
                var requestedPreference = request.ReadPayload<SetFileCorrelationPreferenceMessage>().Enabled;
                return MessageEnvelope.Create(
                    MessageTypes.SetFileCorrelationPreference,
                    await FileCorrelationPreferenceCoordinator.SaveAsync(
                        requestedPreference,
                        _state.FileCorrelationEnabled,
                        _database.SetFileCorrelationPreferenceAsync,
                        cancellationToken).ConfigureAwait(false),
                    request.CorrelationId);
            case MessageTypes.GetActiveFlows:
                return MessageEnvelope.Create(MessageTypes.GetActiveFlows, new ActiveFlowsMessage(_state.Snapshot(), _eventHub.CurrentSequence), request.CorrelationId);
            case MessageTypes.GetRules:
                return MessageEnvelope.Create(MessageTypes.GetRules, new RulesMessage(await _database.GetRulesAsync(cancellationToken).ConfigureAwait(false)), request.CorrelationId);
            case MessageTypes.GetAlerts:
                return MessageEnvelope.Create(MessageTypes.GetAlerts, new AlertsMessage(await _database.GetRecentAlertsAsync(200, cancellationToken).ConfigureAwait(false)), request.CorrelationId);
            case MessageTypes.GetFileCorrelations:
                var correlationRequest = request.ReadPayload<GetFileCorrelationsMessage>();
                if (correlationRequest.Limit is < 1 or > 100)
                {
                    throw new InvalidDataException("File correlation limit must be between 1 and 100.");
                }

                var correlations = _state.FileCorrelations(correlationRequest.FlowId);
                if (correlations.Count == 0)
                {
                    correlations = await _database.GetFileCorrelationsAsync(correlationRequest.FlowId, correlationRequest.Limit, cancellationToken).ConfigureAwait(false);
                }

                return MessageEnvelope.Create(
                    MessageTypes.GetFileCorrelations,
                    new FileCorrelationsMessage(
                        correlationRequest.FlowId,
                        correlations.Take(correlationRequest.Limit).Select(FileCorrelationPrivacy.ProtectForBoundary).ToArray(),
                        _state.FileSensorStatus),
                    request.CorrelationId);
            case MessageTypes.CreateRule:
                var rule = request.ReadPayload<CreateRuleMessage>().Rule;
                var result = await _firewallRuleCreateCoordinator.ApplyAsync(rule, cancellationToken, failOpen: false).ConfigureAwait(false);
                if (result.ExistingRuleId is Guid duplicateId)
                {
                    return Success(request, $"Equivalent rule already exists: {duplicateId:D}.");
                }
                return Success(request, "Rule created.");
            case MessageTypes.DeleteRule:
                var ruleId = request.ReadPayload<DeleteRuleMessage>().RuleId;
                await _firewall.DeleteAsync(ruleId, cancellationToken).ConfigureAwait(false);
                await _database.DeleteRuleAsync(ruleId, cancellationToken).ConfigureAwait(false);
                return Success(request, "Rule removed.");
            case MessageTypes.SetProtectionMode:
                _state.Mode = request.ReadPayload<SetProtectionModeMessage>().Mode;
                await _database.SetSettingAsync("protection_mode", _state.Mode.ToString(), cancellationToken).ConfigureAwait(false);
                return Success(request, "Protection mode updated.");
            case MessageTypes.ResetOwnedRules:
                await _firewall.ResetOwnedRulesAsync(cancellationToken).ConfigureAwait(false);
                foreach (var existing in await _database.GetRulesAsync(cancellationToken).ConfigureAwait(false))
                {
                    await _database.DeleteRuleAsync(existing.Id, cancellationToken).ConfigureAwait(false);
                }

                return Success(request, "Owned rules reset.");
            case MessageTypes.ResetBaseline:
                await _database.ResetBaselineAsync(request.ReadPayload<ResetBaselineMessage>().ExecutableSha256, cancellationToken).ConfigureAwait(false);
                return Success(request, "Baseline reset.");
            case MessageTypes.ClearHistory:
                await _database.ClearHistoryAsync(cancellationToken).ConfigureAwait(false);
                return Success(request, "History cleared.");
            default:
                throw new InvalidDataException($"Unknown message type: {request.Type}");
        }
    }

    private static bool RequiresAdministrator(string type) => type is MessageTypes.CreateRule
        or MessageTypes.DeleteRule
        or MessageTypes.SetProtectionMode
        or MessageTypes.ResetOwnedRules
        or MessageTypes.ResetBaseline
        or MessageTypes.ClearHistory;

    private static bool IsSimulatedDecisionRequest(string type) => type is
        OutboundGateMessageTypes.GetSimulatedDecisionSnapshot
        or OutboundGateMessageTypes.SubmitSimulatedDecision
        or OutboundGateMessageTypes.RevokeSimulatedRememberedRule;

    private MessageEnvelope DispatchSimulatedDecision(NamedPipeServerStream pipe, MessageEnvelope request)
    {
        var caller = CaptureSimulatedDecisionCaller(pipe);
        try
        {
            return request.Type switch
            {
                OutboundGateMessageTypes.GetSimulatedDecisionSnapshot => SnapshotResponse(request, caller),
                OutboundGateMessageTypes.SubmitSimulatedDecision => DecisionResponse(request, caller),
                OutboundGateMessageTypes.RevokeSimulatedRememberedRule => RuleMutationResponse(request, caller),
                _ => throw new InvalidOperationException("Unknown Simulation decision request.")
            };
        }
        catch (SimulatedDecisionRequestException)
        {
            throw;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or InvalidDataException)
        {
            throw new SimulatedDecisionRequestException(
                SimulatedDecisionReasonCodes.RequestInvalid,
                "The Simulation decision request failed version, identifier, enum, one-of, or bound validation.");
        }
    }

    private MessageEnvelope SnapshotResponse(MessageEnvelope request, SimulatedDecisionCaller caller)
    {
        _ = request.ReadPayload<GetSimulatedDecisionSnapshotMessage>();
        var snapshot = _simulatedDecisionCoordinator.GetSnapshot(caller, Volatile.Read(ref _activePipeCount));
        return MessageEnvelope.Create(OutboundGateMessageTypes.SimulatedDecisionSnapshot, snapshot, request.CorrelationId);
    }

    private MessageEnvelope DecisionResponse(MessageEnvelope request, SimulatedDecisionCaller caller)
    {
        var result = _simulatedDecisionCoordinator.SubmitDecision(caller, request.ReadPayload<SubmitSimulatedDecisionMessage>());
        return MessageEnvelope.Create(OutboundGateMessageTypes.SimulatedDecisionResult, result, request.CorrelationId);
    }

    private MessageEnvelope RuleMutationResponse(MessageEnvelope request, SimulatedDecisionCaller caller)
    {
        var result = _simulatedDecisionCoordinator.RevokeRule(caller, request.ReadPayload<RevokeSimulatedRememberedRuleMessage>());
        return MessageEnvelope.Create(OutboundGateMessageTypes.SimulatedRuleMutationResult, result, request.CorrelationId);
    }

    private static bool IsAdministratorClient(NamedPipeServerStream pipe)
    {
        var authorized = false;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent();
            authorized = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        });
        return authorized;
    }

    private static SimulatedDecisionCaller CaptureSimulatedDecisionCaller(NamedPipeServerStream pipe)
    {
        SimulatedDecisionCaller? caller = null;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent();
            var sid = identity.User?.Value;
            caller = new SimulatedDecisionCaller(
                sid is null ? string.Empty : $"sid:{sid}",
                new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator));
        });
        return caller ?? new SimulatedDecisionCaller(string.Empty, false);
    }

    private static MessageEnvelope Success(MessageEnvelope request, string message) =>
        MessageEnvelope.Create(MessageTypes.Success, new SuccessMessage(message), request.CorrelationId);

    private async Task StreamEventsAsync(
        NamedPipeServerStream pipe,
        MessageEnvelope request,
        CancellationToken cancellationToken)
    {
        var subscriptionRequest = request.ReadPayload<SubscribeEventsMessage>();
        await using var subscription = _eventHub.Subscribe(subscriptionRequest.LastSequence);
        await MessageFraming.WriteAsync(pipe, Success(request, "Event subscription active."), cancellationToken).ConfigureAwait(false);
        using var streamCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var disconnectMonitor = MonitorSubscriptionDisconnectAsync(pipe, streamCancellation);
        try
        {
            await foreach (var streamEvent in subscription.Reader.ReadAllAsync(streamCancellation.Token).ConfigureAwait(false))
            {
                var messageType = streamEvent.Kind switch
                {
                    StreamEventKind.AlertRaised => MessageTypes.AlertRaised,
                    StreamEventKind.ServiceStatusChanged => MessageTypes.ServiceStatusChanged,
                    _ => MessageTypes.FlowObserved
                };
                await MessageFraming.WriteAsync(
                    pipe,
                    MessageEnvelope.Create(messageType, streamEvent),
                    streamCancellation.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (streamCancellation.IsCancellationRequested)
        {
        }
        finally
        {
            await StopDisconnectMonitorAsync(streamCancellation, disconnectMonitor).ConfigureAwait(false);
        }
    }

    private async Task StreamSimulatedDecisionEventsAsync(
        NamedPipeServerStream pipe,
        MessageEnvelope request,
        CancellationToken cancellationToken)
    {
        var caller = CaptureSimulatedDecisionCaller(pipe);
        var subscriptionRequest = request.ReadPayload<SubscribeSimulatedDecisionEventsMessage>();
        await using var subscription = _simulatedDecisionCoordinator.Subscribe(caller, subscriptionRequest.LastSequence);
        await MessageFraming.WriteAsync(pipe, Success(request, "Simulation decision event subscription active."), cancellationToken).ConfigureAwait(false);
        using var streamCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var disconnectMonitor = MonitorSubscriptionDisconnectAsync(pipe, streamCancellation);
        try
        {
            await foreach (var streamEvent in subscription.Reader.ReadAllAsync(streamCancellation.Token).ConfigureAwait(false))
            {
                await MessageFraming.WriteAsync(
                    pipe,
                    MessageEnvelope.Create(OutboundGateMessageTypes.SimulatedDecisionEvent, streamEvent),
                    streamCancellation.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (streamCancellation.IsCancellationRequested)
        {
        }
        finally
        {
            await StopDisconnectMonitorAsync(streamCancellation, disconnectMonitor).ConfigureAwait(false);
        }
    }

    private static async Task MonitorSubscriptionDisconnectAsync(
        NamedPipeServerStream pipe,
        CancellationTokenSource streamCancellation)
    {
        try
        {
            _ = await MessageFraming.ReadAsync(pipe, streamCancellation.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or EndOfStreamException or OperationCanceledException or ObjectDisposedException)
        {
        }
        finally
        {
            if (!streamCancellation.IsCancellationRequested)
                await streamCancellation.CancelAsync().ConfigureAwait(false);
        }
    }

    private static async Task StopDisconnectMonitorAsync(
        CancellationTokenSource streamCancellation,
        Task disconnectMonitor)
    {
        if (!streamCancellation.IsCancellationRequested)
            await streamCancellation.CancelAsync().ConfigureAwait(false);
        try
        {
            await disconnectMonitor.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static Task WriteErrorAsync(
        NamedPipeServerStream pipe,
        MessageEnvelope? request,
        string code,
        string message,
        CancellationToken cancellationToken) => MessageFraming.WriteAsync(
            pipe,
            MessageEnvelope.Create(MessageTypes.Error, new ErrorMessage(code, message), request?.CorrelationId),
            cancellationToken);

    public override void Dispose()
    {
        if (_ownsSimulatedDecisionCoordinator)
            _simulatedDecisionCoordinator.Dispose();
        base.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Named pipe accept failed; retrying.")]
    private static partial void LogAcceptFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Named pipe request rejected: {Message}")]
    private static partial void LogRequestRejected(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Error, Message = "Named pipe client handler failed.")]
    private static partial void LogClientFailed(ILogger logger, Exception exception);
}
