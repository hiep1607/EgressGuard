using System.Windows;

namespace EgressGuard.UI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var viewModel = new MainWindowViewModel();
        var trayIcon = new TrayIconController(this, viewModel);
        DataContext = viewModel;
        Loaded += async (_, _) => await viewModel.StartAsync().ConfigureAwait(true);
        Closed += async (_, _) =>
        {
            trayIcon.Dispose();
            await viewModel.DisposeAsync().ConfigureAwait(true);
        };
    }
}
