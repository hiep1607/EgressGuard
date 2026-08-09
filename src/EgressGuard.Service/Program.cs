using EgressGuard.Core;
using EgressGuard.Persistence;
using EgressGuard.Service;
using EgressGuard.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "EgressGuard Service");

var dataRoot = Environment.GetEnvironmentVariable("EGRESSGUARD_DATA_DIR");
if (string.IsNullOrWhiteSpace(dataRoot))
{
    dataRoot = Path.Combine(
        Environment.GetFolderPath(Environment.UserInteractive ? Environment.SpecialFolder.LocalApplicationData : Environment.SpecialFolder.CommonApplicationData),
        "EgressGuard");
}

builder.Services.AddSingleton(new EgressGuardDatabase(Path.Combine(dataRoot, "egressguard.db")));
builder.Services.AddSingleton<INetworkFlowSensor, WindowsFlowSensor>();
builder.Services.AddSingleton<IFirewallRuleManager, OwnedFirewallRuleManager>();
builder.Services.AddSingleton<RiskEngine>();
builder.Services.AddSingleton<BaselineTracker>();
builder.Services.AddSingleton<ServiceState>();
builder.Services.AddHostedService<FlowCoordinator>();
builder.Services.AddHostedService<PipeServer>();
if (int.TryParse(Environment.GetEnvironmentVariable("EGRESSGUARD_TEST_DURATION_SECONDS"), out var testDurationSeconds)
    && testDurationSeconds > 0)
{
    builder.Services.AddSingleton(new TimedShutdownOptions(TimeSpan.FromSeconds(testDurationSeconds)));
    builder.Services.AddHostedService<TimedShutdownService>();
}

await builder.Build().RunAsync().ConfigureAwait(false);
