using System.Diagnostics;

namespace EgressGuard.Launcher;

/// <summary>Everything the launcher needs to start one packaged executable.</summary>
internal sealed record ProcessSpec(
    string ExecutablePath,
    string WorkingDirectory,
    IReadOnlyDictionary<string, string> EnvironmentVariables);

/// <summary>A handle for a process started by this launcher itself.</summary>
internal interface IPreviewProcess : IDisposable
{
    int Id { get; }

    bool WaitForExit(int milliseconds);

    void KillEntireTree();
}

/// <summary>Starts packaged executables and returns handles to them.</summary>
internal delegate IPreviewProcess ProcessStarter(ProcessSpec spec);

/// <summary>Real process implementation backed by System.Diagnostics.Process.</summary>
internal sealed class SystemProcessHandle : IPreviewProcess
{
    private readonly Process _process;

    public SystemProcessHandle(Process process)
    {
        _process = process;
    }

    public int Id => _process.Id;

    public bool WaitForExit(int milliseconds) => _process.WaitForExit(milliseconds);

    /// <summary>
    /// Kills only the tree rooted at this exact process instance. The launcher
    /// never searches or kills by name or by unrelated PID.
    /// </summary>
    public void KillEntireTree()
    {
        if (_process.HasExited)
        {
            return;
        }

        _process.Kill(entireProcessTree: true);
        _process.WaitForExit(10_000);
    }

    public void Dispose() => _process.Dispose();
}

/// <summary>Starts real processes from specs.</summary>
internal sealed class SystemProcessStarter
{
    public static IPreviewProcess Start(ProcessSpec spec)
    {
        var info = new ProcessStartInfo(spec.ExecutablePath)
        {
            WorkingDirectory = spec.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = false,
        };
        foreach (var pair in spec.EnvironmentVariables)
        {
            info.EnvironmentVariables[pair.Key] = pair.Value;
        }

        return new SystemProcessHandle(Process.Start(info)!);
    }
}
