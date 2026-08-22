using System.IO.Pipes;

namespace EgressGuard.Protocol;

public sealed class EgressGuardSimulatedDecisionEventClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private NamedPipeClientStream? _pipe;

    public EgressGuardSimulatedDecisionEventClient(string? pipeName = null)
    {
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? ProtocolConstants.ResolvePipeName() : pipeName;
    }

    public async Task SubscribeAsync(
        long lastSequence,
        Func<SimulatedDecisionEventMessage, ValueTask> onEvent,
        Action? onSubscribed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(onEvent);
        ArgumentOutOfRangeException.ThrowIfNegative(lastSequence);
        await DisconnectAsync().ConfigureAwait(false);
        var pipe = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Impersonation);
        _pipe = pipe;
        await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
        pipe.ReadMode = PipeTransmissionMode.Byte;

        var handshake = MessageEnvelope.Create(
            MessageTypes.Handshake,
            new HandshakeMessage("EgressGuard.UI.Simulation", ProtocolConstants.Version, ProtocolConstants.Version));
        await MessageFraming.WriteAsync(pipe, handshake, cancellationToken).ConfigureAwait(false);
        var handshakeResponse = await MessageFraming.ReadAsync(pipe, cancellationToken).ConfigureAwait(false)
            ?? throw new EndOfStreamException("Service disconnected during Simulation event handshake.");
        ThrowIfError(handshakeResponse);

        var subscribe = MessageEnvelope.Create(
            OutboundGateMessageTypes.SubscribeSimulatedDecisionEvents,
            new SubscribeSimulatedDecisionEventsMessage(ProtocolConstants.Version, lastSequence));
        await MessageFraming.WriteAsync(pipe, subscribe, cancellationToken).ConfigureAwait(false);
        var accepted = await MessageFraming.ReadAsync(pipe, cancellationToken).ConfigureAwait(false)
            ?? throw new EndOfStreamException("Service disconnected before accepting the Simulation event subscription.");
        ThrowIfError(accepted);
        if (accepted.Type != MessageTypes.Success)
            throw new InvalidDataException($"Unexpected Simulation subscription response: {accepted.Type}");

        onSubscribed?.Invoke();
        while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
        {
            var envelope = await MessageFraming.ReadAsync(pipe, cancellationToken).ConfigureAwait(false);
            if (envelope is null)
                throw new EndOfStreamException("Simulation event subscription disconnected.");
            if (envelope.Type != OutboundGateMessageTypes.SimulatedDecisionEvent)
                throw new InvalidDataException($"Unexpected Simulation subscription message: {envelope.Type}");
            await onEvent(envelope.ReadPayload<SimulatedDecisionEventMessage>()).ConfigureAwait(false);
        }
    }

    private static void ThrowIfError(MessageEnvelope envelope)
    {
        if (envelope.Type == MessageTypes.Error)
        {
            var error = envelope.ReadPayload<ErrorMessage>();
            throw new InvalidDataException($"{error.Code}: {error.Message}");
        }
    }

    public Task DisconnectAsync()
    {
        _pipe?.Dispose();
        _pipe = null;
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync() => await DisconnectAsync().ConfigureAwait(false);
}
