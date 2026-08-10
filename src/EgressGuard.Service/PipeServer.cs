using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
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

    public PipeServer(ServiceState state, EgressGuardDatabase database, IFirewallRuleManager firewall, EventHub eventHub, ILogger<PipeServer> logger)
    {
        _state = state;
        _database = database;
        _firewall = firewall;
        _eventHub = eventHub;
        _logger = logger;
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
            var pipe = CreateServerPipe(pipeName);
            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                _ = HandleClientAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }
            catch (Exception exception)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
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
            8,
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
        await using (pipe)
        {
            while (pipe.IsConnected && !stoppingToken.IsCancellationRequested)
            {
                MessageEnvelope? request;
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

                    var response = await DispatchAsync(pipe, request, stoppingToken).ConfigureAwait(false);
                    await MessageFraming.WriteAsync(pipe, response, stoppingToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
                {
                    var detail = string.IsNullOrWhiteSpace(exception.Message)
                        ? exception.GetType().FullName ?? exception.GetType().Name
                        : exception.Message;
                    LogRequestRejected(_logger, detail);
                    if (!pipe.IsConnected)
                    {
                        break;
                    }

                    var error = MessageEnvelope.Create(MessageTypes.Error, new ErrorMessage("REQUEST_REJECTED", detail));
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

    private async Task<MessageEnvelope> DispatchAsync(NamedPipeServerStream pipe, MessageEnvelope request, CancellationToken cancellationToken)
    {
        if (IsMutating(request.Type) && !IsAdministratorClient(pipe))
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
                    new ServiceStatusMessage(_state.Mode, true, _state.ActiveFlowCount, _state.DroppedEvents, _database.DatabasePath, DateTimeOffset.UtcNow),
                    request.CorrelationId);
            case MessageTypes.GetActiveFlows:
                return MessageEnvelope.Create(MessageTypes.GetActiveFlows, new ActiveFlowsMessage(_state.Snapshot(), _eventHub.CurrentSequence), request.CorrelationId);
            case MessageTypes.GetRules:
                return MessageEnvelope.Create(MessageTypes.GetRules, new RulesMessage(await _database.GetRulesAsync(cancellationToken).ConfigureAwait(false)), request.CorrelationId);
            case MessageTypes.GetAlerts:
                return MessageEnvelope.Create(MessageTypes.GetAlerts, new AlertsMessage(await _database.GetRecentAlertsAsync(200, cancellationToken).ConfigureAwait(false)), request.CorrelationId);
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

    private static bool IsMutating(string type) => type is MessageTypes.CreateRule
        or MessageTypes.DeleteRule
        or MessageTypes.SetProtectionMode
        or MessageTypes.ResetOwnedRules
        or MessageTypes.ResetBaseline
        or MessageTypes.ClearHistory;

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
        await foreach (var streamEvent in subscription.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
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
                cancellationToken).ConfigureAwait(false);
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Named pipe accept failed; retrying.")]
    private static partial void LogAcceptFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Named pipe request rejected: {Message}")]
    private static partial void LogRequestRejected(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Error, Message = "Named pipe client handler failed.")]
    private static partial void LogClientFailed(ILogger logger, Exception exception);
}
