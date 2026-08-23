namespace EgressGuard.Launcher;

/// <summary>Outcome of one launch attempt.</summary>
internal sealed record LaunchResult(int ExitCode, int? ServiceProcessId, int? UiProcessId);

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
            return new LaunchResult(ExitCodes.MissingComponent, null, null);
        }

        if (!fileExists(options.UiExecutablePath))
        {
            await log.WriteLineAsync($"[error] UI executable is missing: {options.UiExecutablePath}").ConfigureAwait(false);
            return new LaunchResult(ExitCodes.MissingComponent, null, null);
        }

        using var guard = new SingleInstanceGuard(options.MutexName);
        if (!guard.Acquired)
        {
            await log.WriteLineAsync("[error] Another preview session is already using this data folder. Close it first.").ConfigureAwait(false);
            return new LaunchResult(ExitCodes.AlreadyRunning, null, null);
        }

        Directory.CreateDirectory(options.DataDirectory);

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
                StopProcess(service, "Service", log);
                return new LaunchResult(ExitCodes.ServiceNotReady, service.Id, null);
            }

            await log.WriteLineAsync("[ok  ] Service pipe is ready.").ConfigureAwait(false);

            var uiDir = Path.GetDirectoryName(options.UiExecutablePath)!;
            ui = startProcess(new ProcessSpec(options.UiExecutablePath, uiDir, uiEnvironment));
            await log.WriteLineAsync($"[info ] UI started (PID {ui.Id}).").ConfigureAwait(false);

            if (options.SmokeExitAfterSeconds > 0)
            {
                await log.WriteLineAsync($"[smoke] Closing the UI after {options.SmokeExitAfterSeconds}s for smoke verification.").ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(options.SmokeExitAfterSeconds)).ConfigureAwait(false);
                StopProcess(ui, "UI", log);
            }
            else
            {
                ui.WaitForExit(Timeout.Infinite);
                await log.WriteLineAsync("[info ] UI window closed by the user.").ConfigureAwait(false);
            }

            StopProcess(service, "Service", log);
            await log.WriteLineAsync("[done ] Preview session stopped cleanly.").ConfigureAwait(false);
            return new LaunchResult(ExitCodes.Ok, service.Id, ui.Id);
        }
        catch (Exception exception)
        {
            await log.WriteLineAsync($"[error] Launch failed: {exception.Message}").ConfigureAwait(false);
            if (ui is not null)
            {
                StopProcess(ui, "UI", log);
            }

            if (service is not null)
            {
                StopProcess(service, "Service", log);
            }

            await log.WriteLineAsync("[done ] All launcher-started processes were cleaned up.").ConfigureAwait(false);
            return new LaunchResult(ExitCodes.StartFailed, service?.Id, ui?.Id);
        }
        finally
        {
            ui?.Dispose();
            service?.Dispose();
        }
    }

    /// <summary>Stops exactly one launcher-owned process tree; never throws.</summary>
    private static void StopProcess(IPreviewProcess process, string name, TextWriter log)
    {
        try
        {
            process.KillEntireTree();
            if (!process.WaitForExit(10_000))
            {
                log.WriteLine($"[warn ] {name} (PID {process.Id}) did not confirm exit within 10s.");
            }
            else
            {
                log.WriteLine($"[stop ] {name} (PID {process.Id}) stopped.");
            }
        }
        catch (Exception exception)
        {
            log.WriteLine($"[warn ] Stopping {name} (PID {process.Id}) reported: {exception.Message}");
        }
    }
}
