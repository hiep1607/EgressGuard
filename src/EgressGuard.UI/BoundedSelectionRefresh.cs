using System.Threading.Channels;

namespace EgressGuard.UI;

internal sealed class BoundedSelectionRefresh<T> : IAsyncDisposable
{
    private readonly Channel<RefreshRequest> _requests = Channel.CreateBounded<RefreshRequest>(new BoundedChannelOptions(1)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
        SingleWriter = false
    });
    private readonly Func<string, CancellationToken, Task<T>> _fetch;
    private readonly Action<string, T> _apply;
    private readonly Action<string, Exception> _failed;
    private readonly TimeSpan _minimumInterval;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _sync = new();
    private readonly Task _worker;
    private CancellationTokenSource? _activeRequest;
    private string? _selectedFlowId;
    private long _selectionVersion;
    private DateTimeOffset _lastStarted = DateTimeOffset.MinValue;

    public BoundedSelectionRefresh(
        Func<string, CancellationToken, Task<T>> fetch,
        Action<string, T> apply,
        Action<string, Exception> failed,
        TimeSpan? minimumInterval = null)
    {
        _fetch = fetch;
        _apply = apply;
        _failed = failed;
        _minimumInterval = minimumInterval ?? TimeSpan.FromSeconds(1);
        _worker = RunAsync();
    }

    public void Select(string? flowId)
    {
        long version;
        lock (_sync)
        {
            if (string.Equals(_selectedFlowId, flowId, StringComparison.Ordinal)) return;
            _selectedFlowId = flowId;
            version = ++_selectionVersion;
            _activeRequest?.Cancel();
            _lastStarted = DateTimeOffset.MinValue;
        }

        if (flowId is not null) _requests.Writer.TryWrite(new RefreshRequest(flowId, version));
    }

    public void NotifyFlowUpdated(string flowId)
    {
        lock (_sync)
        {
            if (!string.Equals(_selectedFlowId, flowId, StringComparison.Ordinal)) return;
            _requests.Writer.TryWrite(new RefreshRequest(flowId, _selectionVersion));
        }
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel();
        lock (_sync) _activeRequest?.Cancel();
        _requests.Writer.TryComplete();
        try
        {
            await _worker.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        _activeRequest?.Dispose();
        _lifetime.Dispose();
    }

    private async Task RunAsync()
    {
        await foreach (var request in _requests.Reader.ReadAllAsync(_lifetime.Token))
        {
            CancellationTokenSource requestCancellation;
            TimeSpan delay;
            lock (_sync)
            {
                if (!IsCurrent(request)) continue;
                _activeRequest?.Dispose();
                _activeRequest = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                requestCancellation = _activeRequest;
                delay = _lastStarted == DateTimeOffset.MinValue
                    ? TimeSpan.Zero
                    : _minimumInterval - (DateTimeOffset.UtcNow - _lastStarted);
            }

            try
            {
                if (delay > TimeSpan.Zero) await Task.Delay(delay, requestCancellation.Token);
                lock (_sync)
                {
                    if (!IsCurrent(request)) continue;
                    _lastStarted = DateTimeOffset.UtcNow;
                }

                var result = await _fetch(request.FlowId, requestCancellation.Token);
                lock (_sync)
                {
                    if (!IsCurrent(request) || requestCancellation.IsCancellationRequested) continue;
                }

                _apply(request.FlowId, result);
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException)
            {
            }
            catch (Exception exception)
            {
                lock (_sync)
                {
                    if (!IsCurrent(request) || requestCancellation.IsCancellationRequested) continue;
                }

                _failed(request.FlowId, exception);
            }
        }
    }

    private bool IsCurrent(RefreshRequest request) =>
        request.SelectionVersion == _selectionVersion
        && string.Equals(request.FlowId, _selectedFlowId, StringComparison.Ordinal);

    private sealed record RefreshRequest(string FlowId, long SelectionVersion);
}
