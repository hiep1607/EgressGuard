namespace EgressGuard.Launcher;

/// <summary>Outcome of one launch attempt.</summary>
internal sealed record LaunchResult(
    int ExitCode,
    int? ServiceProcessId,
    int? UiProcessId,
    IReadOnlyList<string> CleanupFailures);

/// <summary>
/// Orchestrates the preview session: single-instance guard, service start,
/// pipe readiness wait, UI start, and full teardown of exactly the processes
/// this launcher started.
/// </summary>
internal static class LauncherEngine
{
    public static async Task<LaunchResult> RunAsync(
        LaunchOptions options,
        Func<string, bool> fileExists,
        ProcessStarter startProcess,
        IPipeReadinessProbe probe,
        TextWriter log)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileExists);
        ArgumentNullException.ThrowIfNull(startProcess);
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(log);

        if (!fileExists(options.ServiceExecutablePath))
        {
            await log.WriteLineAsync($"[error] Service executable is missing: {options.ServiceExecutablePath}").ConfigureAwait(false);
            return new LaunchResult(ExitCodes.MissingComponent, null, null, []);
        }

        if (!fileExists(options.UiExecutablePath))
        {
            await log.WriteLineAsync($"[error] UI executable is missing: {options.UiExecutablePath}").ConfigureAwait(false);
            return new LaunchResult(ExitCodes.MissingComponent, null, null, []);
        }

        try
        {
            Directory.CreateDirectory(options.DataDirectory);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or System.IO.PathTooLongException
                or NotSupportedException)
        {
            await log.WriteLineAsync("[error] Cannot create the data folder '" + options.DataDirectory + "': " + exception.Message).ConfigureAwait(false);
            return new LaunchResult(ExitCodes.InvalidDataFolder, null, null, ["cannot create the data folder"]);
        }

        using var dataLock = new DataFolderLock();
        dataLock.Acquire(options.DataDirectory);
        if (!dataLock.Acquired)
        {
            await log.WriteLineAsync("[error] " + dataLock.Error).ConfigureAwait(false);
            return new LaunchResult(ExitCodes.AlreadyRunning, null, null, []);
        }

        var serviceEnvironment = new Dictionary<string, string>
        {
            ["EGRESSGUARD_DATA_DIR"] = options.DataDirectory,
            ["EGRESSGUARD_PIPE_NAME"] = options.PipeName,
        };
        var uiEnvironment = new Dictionary<string, string>
        {
            ["EGRESSGUARD_PIPE_NAME"] = options.PipeName,
        };

        IPreviewProcess? service = null;
        IPreviewProcess? ui = null;
        var cleanupFailures = new List<string>();
        try
        {
            var serviceDir = Path.GetDirectoryName(options.ServiceExecutablePath)!;
            service = startProcess(new ProcessSpec(
                options.ServiceExecutablePath,
                serviceDir,
                serviceEnvironment));
            await log.WriteLineAsync($"[info ] Service started (PID {service.Id}).").ConfigureAwait(false);

            var ready = await probe
                .WaitUntilReadyAsync(options.PipeName, TimeSpan.FromSeconds(options.ServiceReadyTimeoutSeconds))
                .ConfigureAwait(false);
            if (!ready)
            {
                await log.WriteLineAsync("[error] The Service pipe did not become ready in time.").ConfigureAwait(false);
                TryStopProcess(service, "Service", cleanupFailures, log);
                return new LaunchResult(ExitCodes.ServiceNotReady, service.Id, null, cleanupFailures);
            }

            await log.WriteLineAsync("[ok  ] Service pipe is ready.").ConfigureAwait(false);

            var uiDir = Path.GetDirectoryName(options.UiExecutablePath)!;
            ui = startProcess(new ProcessSpec(options.UiExecutablePath, uiDir, uiEnvironment));
            await log.WriteLineAsync($"[info ] UI started (PID {ui.Id}).").ConfigureAwait(false);

            if (options.SmokeExitAfterSeconds > 0)
            {
                await log.WriteLineAsync($"[smoke] Closing the UI after {options.SmokeExitAfterSeconds}s for smoke verification.").ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(options.SmokeExitAfterSeconds)).ConfigureAwait(false);
            }
            else
            {
                ui.WaitForExit(Timeout.Infinite);
                await log.WriteLineAsync("[info ] UI window closed by the user.").ConfigureAwait(false);
            }

            TryStopProcess(ui, "UI", cleanupFailures, log);
            TryStopProcess(service, "Service", cleanupFailures, log);

            if (cleanupFailures.Count == 0)
            {
                await log.WriteLineAsync("[done ] Preview session stopped cleanly; both processes confirmed exit.").ConfigureAwait(false);
                return new LaunchResult(ExitCodes.Ok, service.Id, ui.Id, cleanupFailures);
            }

            await log.WriteLineAsync("[fail ] Preview session ended but some processes could not be confirmed stopped:").ConfigureAwait(false);
            foreach (var failure in cleanupFailures)
            {
                await log.WriteLineAsync("[fail ]   " + failure).ConfigureAwait(false);
            }

            return new LaunchResult(ExitCodes.StopFailed, service.Id, ui.Id, cleanupFailures);
        }
        catch (Exception exception)
        {
            await log.WriteLineAsync($"[error] Launch failed: {exception.Message}").ConfigureAwait(false);
            if (ui is not null)
            {
                TryStopProcess(ui, "UI", cleanupFailures, log);
            }

            if (service is not null)
            {
                TryStopProcess(service, "Service", cleanupFailures, log);
            }

            await log.WriteLineAsync($"[done ] Cleanup attempted for every launcher-started process ({cleanupFailures.Count} stop operation(s) did not confirm).").ConfigureAwait(false);
            return new LaunchResult(ExitCodes.StartFailed, service?.Id, ui?.Id, cleanupFailures);
        }
        finally
        {
            ui?.Dispose();
            service?.Dispose();
        }
    }

    /// <summary>
    /// Stops exactly one launcher-owned process tree. Returns false when the
    /// kill or the exit confirmation fails; the failure is also logged and
    /// recorded so the launcher never reports a fake success.
    /// </summary>
    private static bool TryStopProcess(IPreviewProcess process, string name, List<string> cleanupFailures, TextWriter log)
    {
        try
        {
            process.KillEntireTree();
            if (!process.WaitForExit(10_000))
            {
                var message = name + " (PID " + process.Id + ") did not confirm exit within 10s.";
                log.WriteLine("[warn ] " + message);
                cleanupFailures.Add(message);
                return false;
            }

            log.WriteLine($"[stop ] {name} (PID {process.Id}) stopped.");
            return true;
        }
        catch (Exception exception)
        {
            var message = name + " (PID " + process.Id + ") stop failed: " + exception.Message;
            log.WriteLine("[error] " + message);
            cleanupFailures.Add(message);
            return false;
        }
    }
}
