using System.Diagnostics;
using System.Security.Principal;

namespace EgressGuard.Core;

public sealed record FirewallOperationResult(bool Changed, string Message);

public sealed class WindowsFirewallManager
{
    public const string RuleName = "EgressGuard-Prototype-Simulator-Outbound";
    private const string RuleDescription = "Owned by EgressGuard Stage 0 prototype";

    private const string StatusScript = """
        $ErrorActionPreference = 'Stop'
        $rule = Get-NetFirewallRule -DisplayName $env:EGRESSGUARD_RULE_NAME -ErrorAction SilentlyContinue
        if ($null -eq $rule) { Write-Output 'ABSENT'; exit 0 }
        $owned = @($rule | Where-Object { $_.Description -eq $env:EGRESSGUARD_RULE_DESCRIPTION })
        if ($owned.Count -ne @($rule).Count) { Write-Error 'A non-EgressGuard rule uses the reserved prototype name.'; exit 4 }
        $programs = $owned | Get-NetFirewallApplicationFilter | Select-Object -ExpandProperty Program
        Write-Output ('PRESENT|' + ($programs -join ','))
        """;

    private const string BlockScript = """
        $ErrorActionPreference = 'Stop'
        $name = $env:EGRESSGUARD_RULE_NAME
        $description = $env:EGRESSGUARD_RULE_DESCRIPTION
        $program = $env:EGRESSGUARD_SIMULATOR_PATH
        $existing = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) {
            $foreign = @($existing | Where-Object { $_.Description -ne $description })
            if ($foreign.Count -gt 0) { Write-Error 'A non-EgressGuard rule uses the reserved prototype name.'; exit 4 }
            $programs = @($existing | Get-NetFirewallApplicationFilter | Select-Object -ExpandProperty Program)
            if ($existing.Count -eq 1 -and $programs.Count -eq 1 -and $programs[0] -ieq $program) {
                Write-Output 'UNCHANGED'; exit 0
            }
            Write-Error 'The existing EgressGuard rule targets a different executable. Remove it explicitly first.'; exit 5
        }
        New-NetFirewallRule -DisplayName $name -Description $description -Direction Outbound -Action Block -Program $program -Profile Any -Enabled True | Out-Null
        Write-Output 'CREATED'
        """;

    private const string UnblockScript = """
        $ErrorActionPreference = 'Stop'
        $name = $env:EGRESSGUARD_RULE_NAME
        $description = $env:EGRESSGUARD_RULE_DESCRIPTION
        $existing = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        if ($existing.Count -eq 0) { Write-Output 'UNCHANGED'; exit 0 }
        $foreign = @($existing | Where-Object { $_.Description -ne $description })
        if ($foreign.Count -gt 0) { Write-Error 'Refusing to remove a rule not owned by EgressGuard.'; exit 4 }
        $existing | Remove-NetFirewallRule
        Write-Output 'REMOVED'
        """;

    public static FirewallOperationResult GetStatus()
    {
        var result = RunPowerShell(StatusScript, simulatorPath: null);
        EnsureSuccess(result);
        var output = result.StandardOutput.Trim();
        return output.StartsWith("PRESENT|", StringComparison.Ordinal)
            ? new FirewallOperationResult(false, $"Rule is active for {output[8..]}")
            : new FirewallOperationResult(false, "Rule is not present.");
    }

    public static FirewallOperationResult BlockSimulator(string simulatorPath)
    {
        EnsureAdministrator();
        var validatedPath = ValidateSimulatorPath(simulatorPath);
        var result = RunPowerShell(BlockScript, validatedPath);
        EnsureSuccess(result);
        var changed = result.StandardOutput.Contains("CREATED", StringComparison.Ordinal);
        return new FirewallOperationResult(
            changed,
            changed ? "Simulator outbound block rule created." : "The matching block rule already exists.");
    }

    public static FirewallOperationResult UnblockSimulator()
    {
        EnsureAdministrator();
        var result = RunPowerShell(UnblockScript, simulatorPath: null);
        EnsureSuccess(result);
        var changed = result.StandardOutput.Contains("REMOVED", StringComparison.Ordinal);
        return new FirewallOperationResult(
            changed,
            changed ? "Simulator outbound block rule removed." : "No prototype rule was present.");
    }

    public static string ValidateSimulatorPath(string simulatorPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(simulatorPath);
        var fullPath = Path.GetFullPath(simulatorPath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Simulator executable was not found.", fullPath);
        }

        if (!string.Equals(Path.GetFileName(fullPath), "EgressGuard.Simulator.exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Only EgressGuard.Simulator.exe can be blocked by the prototype.", nameof(simulatorPath));
        }

        return fullPath;
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void EnsureAdministrator()
    {
        if (!IsAdministrator())
        {
            throw new UnauthorizedAccessException(
                "Administrator rights are required to change Windows Firewall. " +
                "Open a terminal with Run as administrator; EgressGuard will not elevate itself.");
        }
    }

    private static ProcessResult RunPowerShell(string script, string? simulatorPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);
        startInfo.Environment["EGRESSGUARD_RULE_NAME"] = RuleName;
        startInfo.Environment["EGRESSGUARD_RULE_DESCRIPTION"] = RuleDescription;
        if (simulatorPath is not null)
        {
            startInfo.Environment["EGRESSGUARD_SIMULATOR_PATH"] = simulatorPath;
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start Windows PowerShell.");
        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new ProcessResult(process.ExitCode, standardOutput, standardError);
    }

    private static void EnsureSuccess(ProcessResult result)
    {
        if (result.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(result.StandardError)
                ? "Windows PowerShell returned no error detail."
                : result.StandardError.Trim();
            throw new InvalidOperationException($"Firewall operation failed (exit {result.ExitCode}): {detail}");
        }
    }

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);
}
