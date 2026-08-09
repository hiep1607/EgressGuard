namespace EgressGuard.Core;

public sealed record PolicyResult(PolicyDecision Decision, string Reason, FirewallRule? MatchedRule);

public sealed class PolicyEngine
{
    public static PolicyResult Evaluate(
        NetworkFlow flow,
        ProtectionMode mode,
        IEnumerable<FirewallRule> rules,
        bool isSystemProtected)
    {
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(rules);
        var enabled = rules.Where(rule => rule.Enabled && RuleMatches(rule, flow)).ToArray();

        var userBlock = enabled.FirstOrDefault(rule => rule.Source == RuleSource.User && rule.Action == FirewallAction.Block);
        if (userBlock is not null)
        {
            return new PolicyResult(PolicyDecision.Block, "Explicit user block rule has highest priority.", userBlock);
        }

        var userAllow = enabled.FirstOrDefault(rule => rule.Source == RuleSource.User && rule.Action == FirewallAction.Allow);
        if (userAllow is not null)
        {
            return new PolicyResult(PolicyDecision.Allow, "Explicit user allow rule matched.", userAllow);
        }

        if (isSystemProtected)
        {
            return new PolicyResult(PolicyDecision.Allow, "System safety policy prevents automatic blocking.", null);
        }

        if (mode == ProtectionMode.Protect && flow.Risk?.Decision == PolicyDecision.Block)
        {
            return new PolicyResult(PolicyDecision.Block, "Protect mode automatic risk policy matched.", null);
        }

        return new PolicyResult(
            PolicyDecision.Allow,
            mode == ProtectionMode.Learning ? "Learning mode fallback allows and records the flow." : "Monitor mode fallback allows the flow.",
            null);
    }

    public static bool RuleMatches(FirewallRule rule, NetworkFlow flow)
    {
        if (!string.Equals(rule.ExecutablePath, flow.Executable?.Path, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (rule.ExecutableSha256 is not null
            && !string.Equals(rule.ExecutableSha256, flow.Executable?.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (rule.Protocol is not null && rule.Protocol != flow.Protocol)
        {
            return false;
        }

        if (rule.RemotePort is not null && rule.RemotePort != flow.Destination?.Port)
        {
            return false;
        }

        return rule.RemoteAddress is null
            || string.Equals(rule.RemoteAddress, flow.Destination?.Address.ToString(), StringComparison.OrdinalIgnoreCase)
            || string.Equals(rule.RemoteAddress, flow.Destination?.Domain, StringComparison.OrdinalIgnoreCase);
    }
}
