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

/// <summary>Exit codes reported by the launcher executable.</summary>
internal static class ExitCodes
{
    public const int Ok = 0;
    public const int AlreadyRunning = 1;
    public const int MissingComponent = 2;
    public const int ServiceNotReady = 3;
    public const int StartFailed = 4;
    public const int StopFailed = 5;
    public const int InvalidDataFolder = 6;
}

/// <summary>
/// Thrown when user-supplied launch paths cannot be turned into usable
/// absolute locations. The launcher reports the message and exits with
/// <see cref="ExitCodes.InvalidDataFolder"/> instead of letting an unhandled
/// exception escape.
/// </summary>
public sealed class LaunchOptionsException : Exception
{
    public LaunchOptionsException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Builds launch options from explicit overrides or sensible defaults. Root
/// and data-folder inputs are normalized to absolute paths before any other
/// path is derived, so relative user input still produces one exact data
/// folder shared by the launcher and the Service.
/// </summary>
internal static class LaunchOptionsFactory
{
    public const string DefaultDataDirectoryName = "EgressGuard-Preview";
    public const string ServiceRelativePath = @"service\EgressGuard.Service.exe";
    public const string UiRelativePath = @"ui\EgressGuard.UI.exe";

    /// <summary>
    /// Creates the launch options. Every path may contain spaces and may be
    /// relative to the current directory; nothing is passed through a shell so
    /// no quoting is required anywhere.
    /// </summary>
    /// <exception cref="LaunchOptionsException">
    /// A path is malformed or exceeds the system length limit.
    /// </exception>
    public static LaunchOptions Create(
        string? rootDirectory = null,
        string? dataDirectory = null,
        string? pipeName = null,
        int serviceReadyTimeoutSeconds = 30,
        int smokeExitAfterSeconds = 0)
    {
        var root = NormalizePath(rootDirectory ?? AppContext.BaseDirectory, "package root directory");
        var dataDir = NormalizePath(
            dataDirectory
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                DefaultDataDirectoryName),
            "data folder");
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

    private static string NormalizePath(string rawPath, string description)
    {
        try
        {
            return Path.GetFullPath(rawPath);
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or System.IO.PathTooLongException
                or NotSupportedException)
        {
            throw new LaunchOptionsException(
                $"The {description} '{rawPath}' is not a valid path: {exception.Message}");
        }
    }
}
