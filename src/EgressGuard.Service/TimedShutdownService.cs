using Microsoft.Extensions.Hosting;

namespace EgressGuard.Service;

public sealed record TimedShutdownOptions(TimeSpan Duration);

public sealed class TimedShutdownService : BackgroundService
{
    private readonly TimedShutdownOptions _options;
    private readonly IHostApplicationLifetime _lifetime;

    public TimedShutdownService(TimedShutdownOptions options, IHostApplicationLifetime lifetime)
    {
        _options = options;
        _lifetime = lifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(_options.Duration, stoppingToken).ConfigureAwait(false);
            _lifetime.StopApplication();
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }
}
