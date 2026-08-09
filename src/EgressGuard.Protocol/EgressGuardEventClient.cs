using System.IO.Pipes;

namespace EgressGuard.Protocol;

public sealed class EgressGuardEventClient : IAsyncDisposable
{
    private NamedPipeClientStream? _pipe;

    public async Task SubscribeAsync(
        long lastSequence,
        Func<StreamEventMessage, ValueTask> onEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(onEvent);
        await DisconnectAsync().ConfigureAwait(false);
        _pipe = new NamedPipeClientStream(
            ".",
            ProtocolConstants.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification);
        await _pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
        _pipe.ReadMode = PipeTransmissionMode.Byte;

        var handshake = MessageEnvelope.Create(MessageTypes.Handshake, new HandshakeMessage("EgressGuard.UI.Events", 1, 1));
        await MessageFraming.WriteAsync(_pipe, handshake, cancellationToken).ConfigureAwait(false);
        _ = await MessageFraming.ReadAsync(_pipe, cancellationToken).ConfigureAwait(false)
            ?? throw new EndOfStreamException("Service disconnected during event handshake.");

        var subscribe = MessageEnvelope.Create(MessageTypes.SubscribeEvents, new SubscribeEventsMessage(lastSequence));
        await MessageFraming.WriteAsync(_pipe, subscribe, cancellationToken).ConfigureAwait(false);
        var accepted = await MessageFraming.ReadAsync(_pipe, cancellationToken).ConfigureAwait(false)
            ?? throw new EndOfStreamException("Service disconnected before accepting event subscription.");
        if (accepted.Type == MessageTypes.Error)
        {
            throw new InvalidDataException(accepted.ReadPayload<ErrorMessage>().Message);
        }

        while (!cancellationToken.IsCancellationRequested && _pipe.IsConnected)
        {
            var envelope = await MessageFraming.ReadAsync(_pipe, cancellationToken).ConfigureAwait(false);
            if (envelope is null)
            {
                throw new EndOfStreamException("Service event subscription disconnected.");
            }

            if (envelope.Type != MessageTypes.FlowObserved
                && envelope.Type != MessageTypes.AlertRaised
                && envelope.Type != MessageTypes.ServiceStatusChanged)
            {
                throw new InvalidDataException($"Unexpected subscription message: {envelope.Type}");
            }

            await onEvent(envelope.ReadPayload<StreamEventMessage>()).ConfigureAwait(false);
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
