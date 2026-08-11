using System.IO.Pipes;

namespace EgressGuard.Protocol;

public sealed class EgressGuardPipeClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private NamedPipeClientStream? _pipe;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public EgressGuardPipeClient(string? pipeName = null)
    {
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? ProtocolConstants.ResolvePipeName() : pipeName;
    }

    public bool IsConnected => _pipe?.IsConnected == true;

    public async Task ConnectAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        await DisconnectAsync().ConfigureAwait(false);
        _pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Impersonation);
        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCancellation.CancelAfter(timeout);
        await _pipe.ConnectAsync(timeoutCancellation.Token).ConfigureAwait(false);
        _pipe.ReadMode = PipeTransmissionMode.Byte;
        _ = await SendAsync(MessageEnvelope.Create(MessageTypes.Handshake, new HandshakeMessage("EgressGuard.UI", 1, 1)), timeout, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MessageEnvelope> SendAsync(MessageEnvelope request, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var pipe = _pipe is { IsConnected: true } ? _pipe : throw new IOException("Named pipe is not connected.");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCancellation.CancelAfter(timeout);
            await MessageFraming.WriteAsync(pipe, request, timeoutCancellation.Token).ConfigureAwait(false);
            return await MessageFraming.ReadAsync(pipe, timeoutCancellation.Token).ConfigureAwait(false)
                ?? throw new EndOfStreamException("Service disconnected before responding.");
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task DisconnectAsync()
    {
        _pipe?.Dispose();
        _pipe = null;
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync().ConfigureAwait(false);
        _gate.Dispose();
    }
}
