using EgressGuard.Protocol;

namespace EgressGuard.Service;

internal static class FileCorrelationPreferenceCoordinator
{
    internal static FileCorrelationPreferenceResultMessage Read(bool? savedEnabled, bool activeEnabled)
    {
        var saved = savedEnabled ?? activeEnabled;
        return new FileCorrelationPreferenceResultMessage(saved, activeEnabled, saved != activeEnabled);
    }

    internal static async Task<FileCorrelationPreferenceResultMessage> SaveAsync(
        bool savedEnabled,
        bool activeEnabled,
        Func<bool, CancellationToken, Task> save,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(save);
        await save(savedEnabled, cancellationToken).ConfigureAwait(false);
        return new FileCorrelationPreferenceResultMessage(savedEnabled, activeEnabled, savedEnabled != activeEnabled);
    }
}
