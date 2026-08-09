using EgressGuard.Core;
using EgressGuard.Windows;
using Microsoft.Extensions.Logging;

namespace EgressGuard.Service;

internal sealed partial class AutomaticFirewallRuleApplier
{
    private readonly IFirewallRuleManager _firewall;
    private readonly Func<FirewallRule, CancellationToken, Task> _saveRule;
    private readonly ILogger _logger;

    internal AutomaticFirewallRuleApplier(
        IFirewallRuleManager firewall,
        Func<FirewallRule, CancellationToken, Task> saveRule,
        ILogger logger)
    {
        _firewall = firewall;
        _saveRule = saveRule;
        _logger = logger;
    }

    internal async Task ApplyAsync(FirewallRule rule, CancellationToken cancellationToken)
    {
        var created = false;
        try
        {
            created = await _firewall.CreateAsync(rule, cancellationToken).ConfigureAwait(false);
            await _saveRule(rule, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception originalException)
        {
            Exception? rollbackException = null;
            if (created)
            {
                try
                {
                    await _firewall.DeleteAsync(rule.Id, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    rollbackException = exception;
                }
            }

            var cancellationRequested = originalException is OperationCanceledException && cancellationToken.IsCancellationRequested;
            if (!cancellationRequested || rollbackException is not null)
            {
                LogPersistenceFailed(_logger, originalException);
            }

            if (rollbackException is not null)
            {
                LogRollbackFailed(_logger, rule.Id, originalException.GetType().Name, rollbackException);
            }

            if (cancellationRequested)
            {
                throw;
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Automatic firewall rule persistence failed; monitoring remains fail-open.")]
    private static partial void LogPersistenceFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Rollback failed for EgressGuard-owned automatic firewall rule {RuleId}; the original failure was {OriginalExceptionType}.")]
    private static partial void LogRollbackFailed(ILogger logger, Guid ruleId, string originalExceptionType, Exception exception);
}
