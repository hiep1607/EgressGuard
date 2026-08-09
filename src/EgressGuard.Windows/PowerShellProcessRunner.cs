using System.Diagnostics;

namespace EgressGuard.Windows;

internal sealed record PowerShellProcessResult(string StandardOutput, string StandardError, int ExitCode);

internal interface IPowerShellProcessRunner
{
    Task<PowerShellProcessResult> RunAsync(
        string script,
        IReadOnlyDictionary<string, string> environment,
        CancellationToken cancellationToken);
}

internal sealed class PowerShellProcessException : InvalidOperationException
{
    internal PowerShellProcessException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

internal sealed class PowerShellProcessRunner : IPowerShellProcessRunner
{
    private static readonly TimeSpan DefaultOperationTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultCleanupTimeout = TimeSpan.FromSeconds(5);

    private readonly TimeSpan _operationTimeout;
    private readonly TimeSpan _cleanupTimeout;
    private readonly Func<ProcessStartInfo, Process?> _startProcess;

    internal PowerShellProcessRunner(
        TimeSpan? operationTimeout = null,
        TimeSpan? cleanupTimeout = null,
        Func<ProcessStartInfo, Process?>? startProcess = null)
    {
        _operationTimeout = operationTimeout ?? DefaultOperationTimeout;
        _cleanupTimeout = cleanupTimeout ?? DefaultCleanupTimeout;
        _startProcess = startProcess ?? Process.Start;
        if (_operationTimeout <= TimeSpan.Zero || _cleanupTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(operationTimeout), "PowerShell operation and cleanup timeouts must be positive.");
        }
    }

    public async Task<PowerShellProcessResult> RunAsync(
        string script,
        IReadOnlyDictionary<string, string> environment,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(script);
        ArgumentNullException.ThrowIfNull(environment);
        cancellationToken.ThrowIfCancellationRequested();

        var startInfo = CreateStartInfo(script, environment);
        cancellationToken.ThrowIfCancellationRequested();
        using var process = _startProcess(startInfo) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var outputTask = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var errorTask = process.StandardError.ReadToEndAsync(CancellationToken.None);
        var exitTask = process.WaitForExitAsync(CancellationToken.None);
        using var timeout = new CancellationTokenSource(_operationTimeout);
        using var execution = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);

        try
        {
            await Task.WhenAll(exitTask, outputTask, errorTask).WaitAsync(execution.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            var cleanupException = await CleanupAsync(process, exitTask, outputTask, errorTask).ConfigureAwait(false);
            var innerException = Combine(exception, cleanupException);
            if (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(
                    "PowerShell operation was cancelled after its process started; the owned process tree was cleaned up.",
                    innerException,
                    cancellationToken);
            }

            throw new TimeoutException(
                $"PowerShell operation exceeded the {_operationTimeout.TotalSeconds:0.###}-second timeout; the owned process tree was cleaned up.",
                innerException);
        }
        catch (Exception exception)
        {
            var cleanupException = await CleanupAsync(process, exitTask, outputTask, errorTask).ConfigureAwait(false);
            throw new PowerShellProcessException(
                "PowerShell output or process completion failed; the owned process tree was cleaned up.",
                Combine(exception, cleanupException));
        }

        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            throw new PowerShellProcessException($"PowerShell exited with code {process.ExitCode}: {error.Trim()}");
        }

        return new PowerShellProcessResult(output, error, process.ExitCode);
    }

    private static ProcessStartInfo CreateStartInfo(string script, IReadOnlyDictionary<string, string> environment)
    {
        var startInfo = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script })
        {
            startInfo.ArgumentList.Add(argument);
        }

        foreach (var variable in environment)
        {
            startInfo.Environment[variable.Key] = variable.Value;
        }

        return startInfo;
    }

    private async Task<Exception?> CleanupAsync(
        Process process,
        Task exitTask,
        Task<string> outputTask,
        Task<string> errorTask)
    {
        var failures = new List<Exception>();
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        using var cleanup = new CancellationTokenSource(_cleanupTimeout);
        try
        {
            await exitTask.WaitAsync(cleanup.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        try
        {
            await Task.WhenAll(outputTask, errorTask).WaitAsync(cleanup.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        return failures.Count switch
        {
            0 => null,
            1 => failures[0],
            _ => new AggregateException("PowerShell cleanup encountered multiple failures.", failures)
        };
    }

    private static Exception Combine(Exception primary, Exception? cleanup) =>
        cleanup is null ? primary : new AggregateException("PowerShell execution and cleanup both failed.", primary, cleanup);
}
