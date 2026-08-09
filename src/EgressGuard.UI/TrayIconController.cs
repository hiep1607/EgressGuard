using System.Drawing;
using System.Windows;
using Forms = System.Windows.Forms;

namespace EgressGuard.UI;

internal sealed class TrayIconController : IDisposable
{
    private readonly Window _window;
    private readonly MainWindowViewModel _viewModel;
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _modeItem;
    private readonly Forms.ToolStripMenuItem _serviceItem;

    internal TrayIconController(Window window, MainWindowViewModel viewModel)
    {
        _window = window;
        _viewModel = viewModel;
        _modeItem = new Forms.ToolStripMenuItem { Enabled = false };
        _serviceItem = new Forms.ToolStripMenuItem { Enabled = false };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open Dashboard", null, (_, _) => ShowWindow());
        menu.Items.Add(_modeItem);
        menu.Items.Add(_serviceItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit UI", null, (_, _) => _window.Dispatcher.Invoke(_window.Close));
        menu.Opening += (_, _) =>
        {
            _modeItem.Text = $"Mode: {_viewModel.ProtectionMode}";
            _serviceItem.Text = _viewModel.ServiceStatus;
        };

        _icon = new Forms.NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "EgressGuard",
            ContextMenuStrip = menu,
            Visible = true
        };
        _icon.DoubleClick += (_, _) => ShowWindow();
    }

    private void ShowWindow() => _window.Dispatcher.Invoke(() =>
    {
        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
    });

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
