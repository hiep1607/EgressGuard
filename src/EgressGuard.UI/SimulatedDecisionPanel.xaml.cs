using System.Windows;
using System.Windows.Threading;

namespace EgressGuard.UI;

public partial class SimulatedDecisionPanel : System.Windows.Controls.UserControl
{
    public SimulatedDecisionPanel()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Unloaded += (_, _) => Detach(DataContext as SimulatedDecisionViewModel);
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs eventArgs)
    {
        Detach(eventArgs.OldValue as SimulatedDecisionViewModel);
        Attach(eventArgs.NewValue as SimulatedDecisionViewModel);
    }

    private void Attach(SimulatedDecisionViewModel? viewModel)
    {
        if (viewModel is not null)
            viewModel.PromptTerminalized += OnPromptTerminalized;
    }

    private void Detach(SimulatedDecisionViewModel? viewModel)
    {
        if (viewModel is not null)
            viewModel.PromptTerminalized -= OnPromptTerminalized;
    }

    private void OnPromptTerminalized(object? sender, EventArgs eventArgs)
    {
        Dispatcher.BeginInvoke(DispatcherPriority.Input, () =>
        {
            if (PromptList.Items.Count > 0)
            {
                PromptList.SelectedIndex = Math.Clamp(PromptList.SelectedIndex, 0, PromptList.Items.Count - 1);
                PromptList.Focus();
            }
            else
            {
                SimulationHeading.Focus();
            }
        });
    }
}
