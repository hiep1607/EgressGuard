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
builder.Services.AddSingleton<IFileActivitySensor>(_ => new EtwFileActivitySensor([dataRoot]));
builder.Services.AddSingleton(_ => new FileCorrelationEngine(excludedRoots: [dataRoot]));
builder.Services.AddSingleton<IFirewallRuleManager, OwnedFirewallRuleManager>();
builder.Services.AddSingleton<RiskEngine>();
builder.Services.AddSingleton<BaselineTracker>();
builder.Services.AddSingleton<ServiceState>();
builder.Services.AddSingleton<EventHub>();
builder.Services.AddSingleton<SimulatedDecisionEventHub>();
builder.Services.AddSingleton<ISimulatedDecisionAuthority, DisabledSimulatedDecisionAuthority>();
builder.Services.AddSingleton(serviceProvider => new SimulatedDecisionCoordinator(
    serviceProvider.GetRequiredService<ISimulatedDecisionAuthority>(),
    serviceProvider.GetRequiredService<SimulatedDecisionEventHub>()));
builder.Services.AddHostedService<FlowCoordinator>();
builder.Services.AddHostedService(serviceProvider => new PipeServer(
    serviceProvider.GetRequiredService<ServiceState>(),
    serviceProvider.GetRequiredService<EgressGuardDatabase>(),
    serviceProvider.GetRequiredService<IFirewallRuleManager>(),
    serviceProvider.GetRequiredService<EventHub>(),
    serviceProvider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<PipeServer>>(),
    serviceProvider.GetRequiredService<SimulatedDecisionCoordinator>()));
if (int.TryParse(Environment.GetEnvironmentVariable("EGRESSGUARD_TEST_DURATION_SECONDS"), out var testDurationSeconds)
    && testDurationSeconds > 0)
{
    builder.Services.AddSingleton(new TimedShutdownOptions(TimeSpan.FromSeconds(testDurationSeconds)));
    builder.Services.AddHostedService<TimedShutdownService>();
}

await builder.Build().RunAsync().ConfigureAwait(false);
