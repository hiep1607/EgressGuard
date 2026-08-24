using System.Text;

namespace EgressGuard.Launcher;

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        LaunchOptions options;
        try
        {
            options = LaunchOptionsFactory.Create(
                rootDirectory: GetOption(args, "--root"),
                dataDirectory: GetOption(args, "--data-dir"),
                pipeName: GetOption(args, "--pipe-name"),
                smokeExitAfterSeconds: GetIntOption(args, "--smoke-exit-after")
                    ?? ParseIntEnvironment("EGRESSGUARD_LAUNCHER_SMOKE_EXIT_AFTER_SECONDS") ?? 0);
        }
        catch (LaunchOptionsException exception)
        {
            Console.Error.WriteLine("[error] " + exception.Message);
            Console.Error.WriteLine("[error ] Fix the path and run the launcher again.");
            return ExitCodes.InvalidDataFolder;
        }

        using var logWriter = new StreamWriter(Console.OpenStandardOutput(), Encoding.UTF8) { AutoFlush = true };
        var result = LauncherEngine.RunAsync(
            options,
            fileExists: static path => File.Exists(path),
            startProcess: static spec => SystemProcessStarter.Start(spec),
            probe: new NamedPipeReadinessProbe(),
            log: logWriter).ConfigureAwait(false).GetAwaiter().GetResult();
        return result.ExitCode;
    }

    private static string? GetOption(string[] args, string name)
    {
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return null;
    }

    private static int? GetIntOption(string[] args, string name)
    {
        var raw = GetOption(args, name);
        return int.TryParse(raw, out var parsed) ? parsed : null;
    }

    private static int? ParseIntEnvironment(string variable)
    {
        var raw = Environment.GetEnvironmentVariable(variable);
        return int.TryParse(raw, out var parsed) ? parsed : null;
    }
}
