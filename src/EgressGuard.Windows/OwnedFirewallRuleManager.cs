using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using EgressGuard.Core;

namespace EgressGuard.Windows;

public interface IFirewallRuleManager
{
    Task CreateAsync(FirewallRule rule, CancellationToken cancellationToken);
    Task DeleteAsync(Guid ruleId, CancellationToken cancellationToken);
    Task SetEnabledAsync(Guid ruleId, bool enabled, CancellationToken cancellationToken);
    Task ResetOwnedRulesAsync(CancellationToken cancellationToken);
    Task<bool> ExistsAsync(Guid ruleId, CancellationToken cancellationToken);
}

public sealed class OwnedFirewallRuleManager : IFirewallRuleManager
{
    public const string RulePrefix = "EgressGuard-MVP-";
    private const string DescriptionPrefix = "Owned by EgressGuard MVP;";

    public async Task CreateAsync(FirewallRule rule, CancellationToken cancellationToken)
    {
        ValidateRule(rule);
        ValidateExecutableHash(rule);
        EnsureAdministrator();
        var script = """
            $ErrorActionPreference='Stop'
            $name=$env:EG_RULE_NAME; $description=$env:EG_RULE_DESCRIPTION
            $existing=@(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
            if($existing.Count -gt 0) {
              if(@($existing | Where-Object {$_.Description -ne $description}).Count -gt 0) { throw 'Rule ownership mismatch.' }
              if($existing.Count -ne 1) { throw 'Duplicate firewall rules exist for this EgressGuard rule ID.' }
              $application=$existing | Get-NetFirewallApplicationFilter
              if(-not [string]::Equals($application.Program,$env:EG_PROGRAM,[StringComparison]::OrdinalIgnoreCase) -or $existing.Direction -ne 'Outbound' -or $existing.Action -ne $env:EG_ACTION) { throw 'Existing rule semantics do not match the requested rule.' }
              Write-Output 'UNCHANGED'; exit 0
            }
            $parameters=@{DisplayName=$name;Description=$description;Direction='Outbound';Action=$env:EG_ACTION;Program=$env:EG_PROGRAM;Profile='Any';Enabled='True'}
            if($env:EG_REMOTE_ADDRESS) {$parameters.RemoteAddress=$env:EG_REMOTE_ADDRESS}
            if($env:EG_REMOTE_PORT) {$parameters.RemotePort=$env:EG_REMOTE_PORT}
            if($env:EG_PROTOCOL) {$parameters.Protocol=$env:EG_PROTOCOL}
            New-NetFirewallRule @parameters | Out-Null
            $created=Get-NetFirewallRule -DisplayName $name -ErrorAction Stop
            $createdApplication=$created | Get-NetFirewallApplicationFilter
            if(@($created).Count -ne 1 -or $created.Description -ne $description -or -not [string]::Equals($createdApplication.Program,$env:EG_PROGRAM,[StringComparison]::OrdinalIgnoreCase) -or $created.Direction -ne 'Outbound' -or $created.Action -ne $env:EG_ACTION) { Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue; throw 'Post-create validation failed; rolled back.' }
            Write-Output 'CREATED'
            """;
        var environment = CreateEnvironment(rule);
        await RunPowerShellAsync(script, environment, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid ruleId, CancellationToken cancellationToken)
    {
        EnsureAdministrator();
        var script = """
            $ErrorActionPreference='Stop'; $rules=@(Get-NetFirewallRule -DisplayName $env:EG_RULE_NAME -ErrorAction SilentlyContinue)
            if($rules.Count -eq 0) { Write-Output 'UNCHANGED'; exit 0 }
            if(@($rules | Where-Object {$_.Description -notlike 'Owned by EgressGuard MVP;*'}).Count -gt 0) { throw 'Refusing to remove a rule not owned by EgressGuard.' }
            $rules | Remove-NetFirewallRule
            """;
        await RunPowerShellAsync(script, RuleIdEnvironment(ruleId), cancellationToken).ConfigureAwait(false);
    }

    public async Task SetEnabledAsync(Guid ruleId, bool enabled, CancellationToken cancellationToken)
    {
        EnsureAdministrator();
        var environment = RuleIdEnvironment(ruleId);
        environment["EG_ENABLED"] = enabled ? "True" : "False";
        var script = """
            $ErrorActionPreference='Stop'; $rules=@(Get-NetFirewallRule -DisplayName $env:EG_RULE_NAME -ErrorAction Stop)
            if(@($rules | Where-Object {$_.Description -notlike 'Owned by EgressGuard MVP;*'}).Count -gt 0) { throw 'Rule ownership mismatch.' }
            $rules | Set-NetFirewallRule -Enabled $env:EG_ENABLED
            """;
        await RunPowerShellAsync(script, environment, cancellationToken).ConfigureAwait(false);
    }

    public async Task ResetOwnedRulesAsync(CancellationToken cancellationToken)
    {
        EnsureAdministrator();
        var script = """
            $ErrorActionPreference='Stop'
            Get-NetFirewallRule -ErrorAction SilentlyContinue |
              Where-Object {$_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'} |
              Remove-NetFirewallRule
            """;
        await RunPowerShellAsync(script, new Dictionary<string, string>(), cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> ExistsAsync(Guid ruleId, CancellationToken cancellationToken)
    {
        var script = """
            $rule=Get-NetFirewallRule -DisplayName $env:EG_RULE_NAME -ErrorAction SilentlyContinue
            if($null -ne $rule -and @($rule | Where-Object {$_.Description -like 'Owned by EgressGuard MVP;*'}).Count -eq @($rule).Count) {Write-Output 'TRUE'} else {Write-Output 'FALSE'}
            """;
        var output = await RunPowerShellAsync(script, RuleIdEnvironment(ruleId), cancellationToken).ConfigureAwait(false);
        return output.Contains("TRUE", StringComparison.Ordinal);
    }

    private static void ValidateRule(FirewallRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (rule.Id == Guid.Empty || string.IsNullOrWhiteSpace(rule.ExecutablePath) || !Path.IsPathFullyQualified(rule.ExecutablePath))
        {
            throw new ArgumentException("Firewall rule requires an ID and absolute executable path.", nameof(rule));
        }

        if (IsProtectedSystemExecutable(rule.ExecutablePath) && rule.Action == FirewallAction.Block)
        {
            throw new InvalidOperationException("Automatic blocking of protected Windows executables is not allowed.");
        }
    }

    public static void ValidateExecutableHash(FirewallRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (!File.Exists(rule.ExecutablePath))
        {
            throw new FileNotFoundException("Firewall rule executable does not exist.", rule.ExecutablePath);
        }

        if (string.IsNullOrWhiteSpace(rule.ExecutableSha256) || rule.ExecutableSha256.Length != 64)
        {
            throw new ArgumentException("Firewall rule requires a SHA-256 executable identity.", nameof(rule));
        }

        using var stream = new FileStream(rule.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actualHash = Convert.ToHexString(SHA256.HashData(stream));
        if (!actualHash.Equals(rule.ExecutableSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Executable changed after the rule was proposed; refresh its identity before enforcing.");
        }
    }

    public static bool IsProtectedSystemExecutable(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return path.StartsWith(Path.Combine(windows, "System32") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, string> CreateEnvironment(FirewallRule rule)
    {
        var environment = RuleIdEnvironment(rule.Id);
        environment["EG_RULE_DESCRIPTION"] = DescriptionPrefix + JsonSerializer.Serialize(new { id = rule.Id, hash = rule.ExecutableSha256, action = rule.Action, path = Path.GetFullPath(rule.ExecutablePath) });
        environment["EG_ACTION"] = rule.Action.ToString();
        environment["EG_PROGRAM"] = Path.GetFullPath(rule.ExecutablePath);
        environment["EG_REMOTE_ADDRESS"] = rule.RemoteAddress ?? string.Empty;
        environment["EG_REMOTE_PORT"] = rule.RemotePort?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        environment["EG_PROTOCOL"] = rule.Protocol?.ToString() ?? string.Empty;
        return environment;
    }

    private static Dictionary<string, string> RuleIdEnvironment(Guid id) =>
        new() { ["EG_RULE_NAME"] = RulePrefix + id.ToString("D") };

    private static void EnsureAdministrator()
    {
        if (!WindowsFirewallManager.IsAdministrator())
        {
            throw new UnauthorizedAccessException("Administrator rights are required; EgressGuard does not elevate itself.");
        }
    }

    private static async Task<string> RunPowerShellAsync(
        string script,
        IReadOnlyDictionary<string, string> environment,
        CancellationToken cancellationToken)
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

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Firewall operation failed: {error.Trim()}");
        }

        return output;
    }
}
