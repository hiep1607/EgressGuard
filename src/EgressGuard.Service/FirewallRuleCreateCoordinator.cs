using System.Runtime.ExceptionServices;
using EgressGuard.Core;
using EgressGuard.Windows;
using Microsoft.Extensions.Logging;

namespace EgressGuard.Service;

internal sealed record FirewallRuleApplyResult(FirewallMutationStatus Status, Guid? ExistingRuleId = null);

internal sealed partial class FirewallRuleCreateCoordinator
{
    private static readonly SemaphoreSlim CreationGate = new(1, 1);

    private readonly IFirewallRuleManager _firewall;
    private readonly Func<FirewallRule, CancellationToken, Task> _saveRule;
    private readonly Func<CancellationToken, Task<IReadOnlyList<FirewallRule>>> _getRules;
    private readonly ILogger _logger;

    internal FirewallRuleCreateCoordinator(
        IFirewallRuleManager firewall,
        Func<FirewallRule, CancellationToken, Task> saveRule,
        ILogger logger,
        Func<CancellationToken, Task<IReadOnlyList<FirewallRule>>>? getRules = null)
    {
        _firewall = firewall;
        _saveRule = saveRule;
        _logger = logger;
        _getRules = getRules ?? (_ => Task.FromResult<IReadOnlyList<FirewallRule>>([]));
    }

    internal async Task<FirewallRuleApplyResult> ApplyAsync(
        FirewallRule rule,
        CancellationToken cancellationToken,
        bool failOpen = true)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await CreationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var duplicate = (await _getRules(cancellationToken).ConfigureAwait(false)).FirstOrDefault(existing =>
                existing.Enabled
                && existing.Action == rule.Action
                && string.Equals(existing.ExecutablePath, rule.ExecutablePath, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.ExecutableSha256, rule.ExecutableSha256, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.RemoteAddress, rule.RemoteAddress, StringComparison.OrdinalIgnoreCase)
                && existing.RemotePort == rule.RemotePort
                && existing.Protocol == rule.Protocol);
            if (duplicate is not null)
            {
                return new FirewallRuleApplyResult(FirewallMutationStatus.Unchanged, duplicate.Id);
            }

            var status = FirewallMutationStatus.Unchanged;
            try
            {
                status = await _firewall.CreateAsync(rule, cancellationToken).ConfigureAwait(false);
                if (status == FirewallMutationStatus.Failed)
                {
                    throw new InvalidOperationException("Firewall manager reported a failed create operation.");
                }
                await _saveRule(rule, cancellationToken).ConfigureAwait(false);
                return new FirewallRuleApplyResult(status);
            }
            catch (Exception originalException)
            {
                Exception? rollbackException = null;
                if (status == FirewallMutationStatus.Created)
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

                var cancellation = originalException as OperationCanceledException;
                if (cancellation is null || rollbackException is not null)
                {
                    LogPersistenceFailed(_logger, originalException);
                }

                if (rollbackException is not null)
                {
                    LogRollbackFailed(_logger, rule.Id, originalException.GetType().Name, rollbackException);
                }

                if (cancellation is not null)
                {
                    throw new OperationCanceledException(
                        cancellation.Message,
                        rollbackException is null
                            ? cancellation.InnerException
                            : new AggregateException(originalException, rollbackException),
                        cancellation.CancellationToken);
                }

                if (!failOpen)
                {
                    if (rollbackException is not null)
                    {
                        throw new InvalidOperationException(
                            "Firewall rule persistence and rollback both failed.",
                            new AggregateException(originalException, rollbackException));
                    }

                    ExceptionDispatchInfo.Capture(originalException).Throw();
                }

                return new FirewallRuleApplyResult(FirewallMutationStatus.Failed);
            }
        }
        finally
        {
            CreationGate.Release();
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Firewall rule persistence failed; monitoring remains fail-open.")]
    private static partial void LogPersistenceFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Rollback failed for EgressGuard-owned firewall rule {RuleId}; the original failure was {OriginalExceptionType}.")]
    private static partial void LogRollbackFailed(ILogger logger, Guid ruleId, string originalExceptionType, Exception exception);
}
