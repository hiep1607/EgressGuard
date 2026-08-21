using System.Windows;
using EgressGuard.Protocol;

namespace EgressGuard.UI;

public partial class MainWindow : Window, IAsyncDisposable
{
    private readonly EgressGuardPipeClient _requestClient;
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
        _requestClient = new EgressGuardPipeClient(pipeName);
        _viewModel = new MainWindowViewModel(_requestClient, pipeName);
        _simulatedDecisionViewModel = new SimulatedDecisionViewModel(_requestClient, pipeName);
        _trayIcon = new TrayIconController(this, _viewModel);
        DataContext = _viewModel;
        SimulationDecisionPanel.DataContext = _simulatedDecisionViewModel;
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    internal MainWindowViewModel ViewModel => _viewModel;
    internal SimulatedDecisionViewModel SimulatedDecisionViewModel => _simulatedDecisionViewModel;
    internal EgressGuardPipeClient SharedRequestClient => _requestClient;
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
        await _requestClient.DisposeAsync().ConfigureAwait(true);
        GC.SuppressFinalize(this);
    }
}
