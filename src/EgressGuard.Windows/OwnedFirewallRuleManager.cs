using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using EgressGuard.Core;

namespace EgressGuard.Windows;

public enum FirewallMutationStatus
{
    Created,
    Unchanged,
    Failed
}

public interface IFirewallRuleManager
{
    Task<FirewallMutationStatus> CreateAsync(FirewallRule rule, CancellationToken cancellationToken);
    Task DeleteAsync(Guid ruleId, CancellationToken cancellationToken);
    Task SetEnabledAsync(Guid ruleId, bool enabled, CancellationToken cancellationToken);
    Task ResetOwnedRulesAsync(CancellationToken cancellationToken);
    Task<bool> ExistsAsync(Guid ruleId, CancellationToken cancellationToken);
}

public sealed class OwnedFirewallRuleManager : IFirewallRuleManager
{
    public const string RulePrefix = "EgressGuard-MVP-";
    private const string DescriptionPrefix = "Owned by EgressGuard MVP;";
    private static readonly SemaphoreSlim MutationGate = new(1, 1);
    private readonly IPowerShellProcessRunner _runner;
    private readonly Func<bool> _isAdministrator;

    public OwnedFirewallRuleManager()
        : this(new PowerShellProcessRunner(), WindowsFirewallManager.IsAdministrator)
    {
    }

    internal OwnedFirewallRuleManager(IPowerShellProcessRunner runner, Func<bool>? isAdministrator = null)
    {
        _runner = runner;
        _isAdministrator = isAdministrator ?? WindowsFirewallManager.IsAdministrator;
    }

    public async Task<FirewallMutationStatus> CreateAsync(FirewallRule rule, CancellationToken cancellationToken)
    {
        ValidateRule(rule);
        ValidateExecutableHash(rule);
        EnsureAdministrator();
        cancellationToken.ThrowIfCancellationRequested();
        await MutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var environment = CreateEnvironment(rule);
            var state = await QueryExactRuleAsync(environment, cancellationToken).ConfigureAwait(false);
            if (state == ExactRuleState.Match)
            {
                return FirewallMutationStatus.Unchanged;
            }

            if (state == ExactRuleState.Mismatch)
            {
                throw new InvalidOperationException("A firewall rule with this ID exists but its ownership or semantics do not match.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var output = await RunPowerShellAsync(CreateScript, environment, cancellationToken).ConfigureAwait(false);
                if (HasOutputToken(output, "CREATED"))
                {
                    return FirewallMutationStatus.Created;
                }

                if (HasOutputToken(output, "UNCHANGED"))
                {
                    return FirewallMutationStatus.Unchanged;
                }

                throw new InvalidOperationException("PowerShell returned an unrecognized firewall mutation result.");
            }
            catch (Exception originalException)
            {
                await ReconcileFailedCreateAsync(environment, originalException).ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            MutationGate.Release();
        }
    }

    public async Task DeleteAsync(Guid ruleId, CancellationToken cancellationToken)
    {
        EnsureAdministrator();
        cancellationToken.ThrowIfCancellationRequested();
        await MutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            const string script = """
                $ErrorActionPreference='Stop'
                $rules=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.DisplayName -eq $env:EG_RULE_NAME})
                if($rules.Count -eq 0) { Write-Output 'UNCHANGED'; exit 0 }
                if(@($rules | Where-Object {$_.Description -notlike 'Owned by EgressGuard MVP;*'}).Count -gt 0) { throw 'Refusing to remove a rule not owned by EgressGuard.' }
                $rules | Remove-NetFirewallRule -ErrorAction Stop
                """;
            await RunPowerShellAsync(script, RuleIdEnvironment(ruleId), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            MutationGate.Release();
        }
    }

    public async Task SetEnabledAsync(Guid ruleId, bool enabled, CancellationToken cancellationToken)
    {
        EnsureAdministrator();
        var environment = RuleIdEnvironment(ruleId);
        environment["EG_ENABLED"] = enabled ? "True" : "False";
        const string script = """
            $ErrorActionPreference='Stop'; $rules=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.DisplayName -eq $env:EG_RULE_NAME})
            if($rules.Count -eq 0) { throw 'Rule does not exist.' }
            if(@($rules | Where-Object {$_.Description -notlike 'Owned by EgressGuard MVP;*'}).Count -gt 0) { throw 'Rule ownership mismatch.' }
            foreach($rule in $rules) {
              $identity=$rule.Description.Substring('Owned by EgressGuard MVP;'.Length) | ConvertFrom-Json -ErrorAction Stop
              if($null -eq $identity.enabled) { throw 'Rule ownership description does not contain enabled state.' }
              $identity.enabled=[bool]::Parse($env:EG_ENABLED)
              $description='Owned by EgressGuard MVP;' + ($identity | ConvertTo-Json -Compress -Depth 4)
              $rule | Set-NetFirewallRule -Enabled $env:EG_ENABLED -Description $description -ErrorAction Stop
            }
            """;
        await RunSerializedMutationAsync(script, environment, cancellationToken).ConfigureAwait(false);
    }

    public async Task ResetOwnedRulesAsync(CancellationToken cancellationToken)
    {
        EnsureAdministrator();
        const string script = """
            $ErrorActionPreference='Stop'
            Get-NetFirewallRule -ErrorAction Stop |
              Where-Object {$_.DisplayName -like 'EgressGuard-MVP-*' -and $_.Description -like 'Owned by EgressGuard MVP;*'} |
              Remove-NetFirewallRule -ErrorAction Stop
            """;
        await RunSerializedMutationAsync(script, new Dictionary<string, string>(), cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> ExistsAsync(Guid ruleId, CancellationToken cancellationToken)
    {
        const string script = """
            $ErrorActionPreference='Stop'
            $rule=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.DisplayName -eq $env:EG_RULE_NAME})
            if($rule.Count -gt 0 -and @($rule | Where-Object {$_.Description -like 'Owned by EgressGuard MVP;*'}).Count -eq $rule.Count) {Write-Output 'TRUE'} else {Write-Output 'FALSE'}
            """;
        var output = await RunPowerShellAsync(script, RuleIdEnvironment(ruleId), cancellationToken).ConfigureAwait(false);
        return HasOutputToken(output, "TRUE");
    }

    private async Task RunSerializedMutationAsync(
        string script,
        IReadOnlyDictionary<string, string> environment,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await MutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await RunPowerShellAsync(script, environment, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            MutationGate.Release();
        }
    }

    private async Task ReconcileFailedCreateAsync(
        IReadOnlyDictionary<string, string> environment,
        Exception originalException)
    {
        Exception? reconciliationException = null;
        try
        {
            var state = await QueryExactRuleAsync(environment, CancellationToken.None).ConfigureAwait(false);
            if (state == ExactRuleState.Match)
            {
                await RunPowerShellAsync(DeleteExactRuleScript, environment, CancellationToken.None).ConfigureAwait(false);
                if (await QueryExactRuleAsync(environment, CancellationToken.None).ConfigureAwait(false) != ExactRuleState.Absent)
                {
                    reconciliationException = new InvalidOperationException("Exact firewall rule remained after reconciliation delete.");
                }
            }
            else if (state == ExactRuleState.Mismatch)
            {
                reconciliationException = new InvalidOperationException(
                    "Reconciliation found a same-name rule with mismatched ownership or semantics; it was not removed.");
            }
        }
        catch (Exception exception)
        {
            reconciliationException = exception;
        }

        if (originalException is OperationCanceledException cancellation)
        {
            throw new OperationCanceledException(
                cancellation.Message,
                reconciliationException is null
                    ? cancellation.InnerException
                    : new AggregateException(originalException, reconciliationException),
                cancellation.CancellationToken);
        }

        if (originalException is TimeoutException timeout)
        {
            throw new TimeoutException(
                timeout.Message,
                reconciliationException is null
                    ? timeout.InnerException
                    : new AggregateException(originalException, reconciliationException));
        }

        throw new InvalidOperationException(
            "Firewall rule creation failed and was reconciled to a deterministic state.",
            reconciliationException is null
                ? originalException
                : new AggregateException(originalException, reconciliationException));
    }

    private async Task<ExactRuleState> QueryExactRuleAsync(
        IReadOnlyDictionary<string, string> environment,
        CancellationToken cancellationToken)
    {
        var output = await RunPowerShellAsync(QueryExactRuleScript, environment, cancellationToken).ConfigureAwait(false);
        if (HasOutputToken(output, "MATCH")) return ExactRuleState.Match;
        if (HasOutputToken(output, "ABSENT")) return ExactRuleState.Absent;
        return ExactRuleState.Mismatch;
    }

    private static bool HasOutputToken(string output, string token) =>
        output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(line => string.Equals(line, token, StringComparison.Ordinal));

    private async Task<string> RunPowerShellAsync(
        string script,
        IReadOnlyDictionary<string, string> environment,
        CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync(script, environment, cancellationToken).ConfigureAwait(false);
        return result.StandardOutput;
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
        var identity = ExactFirewallRuleIdentity.FromRule(rule);
        var environment = RuleIdEnvironment(rule.Id);
        environment["EG_RULE_DESCRIPTION"] = identity.Description;
        environment["EG_ACTION"] = identity.Action;
        environment["EG_PROGRAM"] = identity.Program;
        environment["EG_REMOTE_ADDRESS"] = identity.RemoteAddress;
        environment["EG_REMOTE_PORT"] = identity.RemotePort;
        environment["EG_PROTOCOL"] = identity.Protocol;
        environment["EG_ENABLED"] = identity.Enabled;
        environment["EG_PROFILE"] = identity.Profile;
        return environment;
    }

    private static Dictionary<string, string> RuleIdEnvironment(Guid id) =>
        new() { ["EG_RULE_NAME"] = RulePrefix + id.ToString("D") };

    private void EnsureAdministrator()
    {
        if (!_isAdministrator())
        {
            throw new UnauthorizedAccessException("Administrator rights are required; EgressGuard does not elevate itself.");
        }
    }

    private const string ExactRuleSemanticsScript = """
        function ConvertTo-EgressGuardAnyList {
          param($Value)
          $items=@($Value) | ForEach-Object { @("$_" -split ',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ }
          if($items.Count -eq 0 -or ($items.Count -eq 1 -and ($items[0] -eq 'Any' -or $items[0] -eq '*'))) { return 'Any' }
          return (($items | Sort-Object -Unique) -join ',')
        }
        function ConvertTo-EgressGuardProtocol {
          param($Value)
          $text="$Value".Trim()
          if(-not $text -or $text -eq 'Any' -or $text -eq '*' -or $text -eq '256') { return 'ANY' }
          if($text -eq 'Tcp' -or $text -eq '6') { return 'TCP' }
          if($text -eq 'Udp' -or $text -eq '17') { return 'UDP' }
          return $text.ToUpperInvariant()
        }
        function Test-EgressGuardExactRule {
          param($Rules)
          $items=@($Rules)
          if($items.Count -ne 1) { return $false }
          $rule=$items[0]
          if(-not [string]::Equals("$($rule.Description)",$env:EG_RULE_DESCRIPTION,[StringComparison]::OrdinalIgnoreCase)) { return $false }
          if(-not [string]::Equals("$($rule.Direction)",'Outbound',[StringComparison]::OrdinalIgnoreCase)) { return $false }
          if(-not [string]::Equals("$($rule.Action)",$env:EG_ACTION,[StringComparison]::OrdinalIgnoreCase)) { return $false }
          if(-not [string]::Equals("$($rule.Enabled)",$env:EG_ENABLED,[StringComparison]::OrdinalIgnoreCase)) { return $false }
          if(-not [string]::Equals("$($rule.Profile)",$env:EG_PROFILE,[StringComparison]::OrdinalIgnoreCase)) { return $false }
          $application=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
          $address=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
          $port=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
          if($application.Count -ne 1 -or $address.Count -ne 1 -or $port.Count -ne 1) { return $false }
          if(-not [string]::Equals("$($application[0].Program)",$env:EG_PROGRAM,[StringComparison]::OrdinalIgnoreCase)) { return $false }
          if(-not [string]::Equals((ConvertTo-EgressGuardAnyList $address[0].RemoteAddress),(ConvertTo-EgressGuardAnyList $env:EG_REMOTE_ADDRESS),[StringComparison]::OrdinalIgnoreCase)) { return $false }
          if(-not [string]::Equals((ConvertTo-EgressGuardAnyList $port[0].RemotePort),(ConvertTo-EgressGuardAnyList $env:EG_REMOTE_PORT),[StringComparison]::OrdinalIgnoreCase)) { return $false }
          if(-not [string]::Equals((ConvertTo-EgressGuardProtocol $port[0].Protocol),(ConvertTo-EgressGuardProtocol $env:EG_PROTOCOL),[StringComparison]::OrdinalIgnoreCase)) { return $false }
          return $true
        }
        """;

    private static readonly string CreateScript = ExactRuleSemanticsScript + """
        # EGRESSGUARD_CREATE_MUTATION
        $ErrorActionPreference='Stop'
        $name=$env:EG_RULE_NAME; $description=$env:EG_RULE_DESCRIPTION
        $existing=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.DisplayName -eq $name})
        if($existing.Count -gt 0) {
          if(-not (Test-EgressGuardExactRule $existing)) { throw 'Existing rule ownership or semantics do not match the requested rule.' }
          Write-Output 'UNCHANGED'; exit 0
        }
        $parameters=@{DisplayName=$name;Description=$description;Direction='Outbound';Action=$env:EG_ACTION;Program=$env:EG_PROGRAM;Profile=$env:EG_PROFILE;Enabled=$env:EG_ENABLED}
        if($env:EG_REMOTE_ADDRESS -ne 'Any') {$parameters.RemoteAddress=$env:EG_REMOTE_ADDRESS}
        if($env:EG_REMOTE_PORT -ne 'Any') {$parameters.RemotePort=$env:EG_REMOTE_PORT}
        if($env:EG_PROTOCOL -ne 'ANY') {$parameters.Protocol=$env:EG_PROTOCOL}
        New-NetFirewallRule @parameters | Out-Null
        # EGRESSGUARD_AFTER_CREATE
        $created=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.DisplayName -eq $name})
        if(-not (Test-EgressGuardExactRule $created)) { $created | Where-Object {[string]::Equals("$($_.Description)",$description,[StringComparison]::OrdinalIgnoreCase)} | Remove-NetFirewallRule -ErrorAction SilentlyContinue; throw 'Post-create validation failed; rolled back.' }
        Write-Output 'CREATED'
        """;

    private static readonly string QueryExactRuleScript = ExactRuleSemanticsScript + """
        # EGRESSGUARD_EXACT_RULE_QUERY
        $ErrorActionPreference='Stop'
        $rules=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.DisplayName -eq $env:EG_RULE_NAME})
        if($rules.Count -eq 0) { Write-Output 'ABSENT'; exit 0 }
        if(-not (Test-EgressGuardExactRule $rules)) { Write-Output 'MISMATCH'; exit 0 }
        Write-Output 'MATCH'
        """;

    private static readonly string DeleteExactRuleScript = ExactRuleSemanticsScript + """
        # EGRESSGUARD_EXACT_RULE_DELETE
        $ErrorActionPreference='Stop'
        $rules=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.DisplayName -eq $env:EG_RULE_NAME})
        if($rules.Count -eq 0) { Write-Output 'UNCHANGED'; exit 0 }
        if(-not (Test-EgressGuardExactRule $rules)) { throw 'Refusing to reconcile a rule with mismatched ownership or semantics.' }
        $rules[0] | Remove-NetFirewallRule -ErrorAction Stop
        Write-Output 'DELETED'
        """;

    private enum ExactRuleState
    {
        Absent,
        Match,
        Mismatch
    }

    internal sealed record ExactFirewallRuleIdentity(
        Guid Id,
        string ExecutableSha256,
        string Program,
        string Action,
        string RemoteAddress,
        string RemotePort,
        string Protocol,
        string Enabled,
        string Profile)
    {
        public string Description => DescriptionPrefix + JsonSerializer.Serialize(new
        {
            id = Id,
            hash = ExecutableSha256,
            path = Program,
            action = Action,
            remoteAddress = RemoteAddress,
            remotePort = RemotePort,
            protocol = Protocol,
            enabled = bool.Parse(Enabled)
        });

        public static ExactFirewallRuleIdentity FromRule(FirewallRule rule) => new(
            rule.Id,
            rule.ExecutableSha256!,
            Path.GetFullPath(rule.ExecutablePath),
            rule.Action.ToString(),
            NormalizeAny(rule.RemoteAddress),
            rule.RemotePort?.ToString(CultureInfo.InvariantCulture) ?? "Any",
            rule.Protocol?.ToString().ToUpperInvariant() ?? "ANY",
            rule.Enabled ? "True" : "False",
            "Any");

        private static string NormalizeAny(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Equals("Any", StringComparison.OrdinalIgnoreCase) || value == "*")
            {
                return "Any";
            }

            return string.Join(",", value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Order(StringComparer.OrdinalIgnoreCase));
        }
    }
}
