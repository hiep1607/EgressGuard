namespace EgressGuard.Launcher;

/// <summary>
/// Checks whether a named pipe owned by the launched Service is accepting
/// client connections.
/// </summary>
public interface IPipeReadinessProbe
{
    Task<bool> WaitUntilReadyAsync(string pipeName, TimeSpan timeout);
}

/// <summary>Real probe that repeatedly attempts a short client connection.</summary>
public sealed class NamedPipeReadinessProbe : IPipeReadinessProbe
{
    /// <inheritdoc />
    public async Task<bool> WaitUntilReadyAsync(string pipeName, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            await using var client = new System.IO.Pipes.NamedPipeClientStream(
                ".",
                pipeName,
                System.IO.Pipes.PipeDirection.InOut,
                System.IO.Pipes.PipeOptions.Asynchronous);
            try
            {
                await client.ConnectAsync(400).ConfigureAwait(false);
                if (client.IsConnected)
                {
                    return true;
                }
            }
            catch (TimeoutException)
            {
            }
            catch (System.IO.IOException)
            {
            }

            await Task.Delay(200).ConfigureAwait(false);
        }

        return false;
    }
}
