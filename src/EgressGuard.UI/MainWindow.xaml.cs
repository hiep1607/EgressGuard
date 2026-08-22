using System.Windows;
using EgressGuard.Protocol;

namespace EgressGuard.UI;

public partial class MainWindow : Window, IAsyncDisposable
{
    private readonly MainWindowRequestSession _requestSession;
    private readonly MainWindowViewModel _viewModel;
    private readonly SimulatedDecisionViewModel _simulatedDecisionViewModel;
    private readonly TrayIconController _trayIcon;
    private bool _disposed;

    public MainWindow()
        : this(pipeName: null)
    {
    }

    internal MainWindow(string? pipeName)
    {
        InitializeComponent();
        _requestSession = new MainWindowRequestSession(pipeName);
        _viewModel = new MainWindowViewModel(_requestSession, pipeName);
        _simulatedDecisionViewModel = new SimulatedDecisionViewModel(_requestSession, pipeName);
        _trayIcon = new TrayIconController(this, _viewModel);
        DataContext = _viewModel;
        SimulationDecisionPanel.DataContext = _simulatedDecisionViewModel;
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    internal MainWindowViewModel ViewModel => _viewModel;
    internal SimulatedDecisionViewModel SimulatedDecisionViewModel => _simulatedDecisionViewModel;
    internal MainWindowRequestSession SharedRequestSession => _requestSession;
    internal SimulatedDecisionPanel DecisionPanel => SimulationDecisionPanel;

    private async void OnLoaded(object sender, RoutedEventArgs eventArgs)
    {
        await _viewModel.StartAsync().ConfigureAwait(true);
        await _simulatedDecisionViewModel.StartAsync().ConfigureAwait(true);
    }

    private async void OnClosed(object? sender, EventArgs eventArgs)
    {
        await DisposeAsync().ConfigureAwait(true);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;
        _trayIcon.Dispose();
        await _simulatedDecisionViewModel.DisposeAsync().ConfigureAwait(true);
        await _viewModel.DisposeAsync().ConfigureAwait(true);
        await _requestSession.DisposeAsync().ConfigureAwait(true);
        GC.SuppressFinalize(this);
    }
}

internal sealed class MainWindowRequestSession : IAsyncDisposable
{
    private readonly EgressGuardPipeClient _client;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private int _pendingOperationCount;
    private int _connected;
    private long _connectionGeneration;
    private bool _disposed;

    internal MainWindowRequestSession(string? pipeName = null)
    {
        _client = new EgressGuardPipeClient(pipeName);
    }

    internal bool IsConnected => Volatile.Read(ref _connected) != 0;
    internal int PendingOperationCount => Volatile.Read(ref _pendingOperationCount);
    internal long ConnectionGeneration => Interlocked.Read(ref _connectionGeneration);

    internal async Task<MessageEnvelope> SendAsync(
        MessageEnvelope request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        Interlocked.Increment(ref _pendingOperationCount);
        try
        {
            await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                try
                {
                    if (!_client.IsConnected)
                    {
                        await _client.ConnectAsync(timeout, cancellationToken).ConfigureAwait(false);
                        Volatile.Write(ref _connected, 1);
                        Interlocked.Increment(ref _connectionGeneration);
                    }
                    return await _client.SendAsync(request, timeout, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    Volatile.Write(ref _connected, 0);
                    await _client.DisconnectAsync().ConfigureAwait(false);
                    throw;
                }
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }
        finally
        {
            Interlocked.Decrement(ref _pendingOperationCount);
        }
    }

    internal async Task DisconnectAsync()
    {
        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_disposed)
            {
                Volatile.Write(ref _connected, 0);
                await _client.DisconnectAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
                return;
            _disposed = true;
            Volatile.Write(ref _connected, 0);
            await _client.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }
}
