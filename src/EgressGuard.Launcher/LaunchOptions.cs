using System.Security.Cryptography;
using System.Text;

namespace EgressGuard.Launcher;

/// <summary>
/// Fully resolved launch settings for one preview session.
/// </summary>
internal sealed record LaunchOptions(
    string RootDirectory,
    string DataDirectory,
    string ServiceExecutablePath,
    string UiExecutablePath,
    string PipeName,
    int ServiceReadyTimeoutSeconds,
    int SmokeExitAfterSeconds);

/// <summary>
/// Exit codes reported by the launcher executable.
/// </summary>
internal static class ExitCodes
{
    public const int Ok = 0;
    public const int AlreadyRunning = 1;
    public const int MissingComponent = 2;
    public const int ServiceNotReady = 3;
    public const int StartFailed = 4;
    public const int StopFailed = 5;
}

/// <summary>
/// Builds launch options from explicit overrides or sensible defaults.
/// </summary>
internal static class LaunchOptionsFactory
{
    public const string DefaultDataDirectoryName = "EgressGuard-Preview";
    public const string ServiceRelativePath = @"service\EgressGuard.Service.exe";
    public const string UiRelativePath = @"ui\EgressGuard.UI.exe";

    /// <summary>
    /// Creates the launch options. Every path may contain spaces; nothing is
    /// passed through a shell so no quoting is required anywhere.
    /// </summary>
    public static LaunchOptions Create(
        string? rootDirectory = null,
        string? dataDirectory = null,
        string? pipeName = null,
        int serviceReadyTimeoutSeconds = 30,
        int smokeExitAfterSeconds = 0)
    {
        var root = rootDirectory ?? AppContext.BaseDirectory;
        var dataDir = dataDirectory
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                DefaultDataDirectoryName);
        var servicePath = Path.Combine(root, "service", "EgressGuard.Service.exe");
        var uiPath = Path.Combine(root, "ui", "EgressGuard.UI.exe");
        var pipe = pipeName ?? $"EgressGuard.Service.preview-{Guid.NewGuid():N}";
        return new LaunchOptions(
            root,
            dataDir,
            servicePath,
            uiPath,
            pipe,
            serviceReadyTimeoutSeconds,
            Math.Max(0, smokeExitAfterSeconds));
    }
}
