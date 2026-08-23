using System.Threading;

namespace EgressGuard.Launcher;

/// <summary>
/// Prevents two preview sessions from ever sharing one data folder. The guard
/// uses a Local-session mutex named after the data folder, so it is visible
/// only to the current user's session and cannot collide with other users or
/// unrelated applications.
/// </summary>
public sealed class SingleInstanceGuard : IDisposable
{
    private readonly Mutex _mutex;

    public SingleInstanceGuard(string name)
    {
        _mutex = new Mutex(initiallyOwned: true, @"Local\" + name, out var createdNew);
        Acquired = createdNew;
    }

    public bool Acquired { get; }

    public void Dispose()
    {
        if (Acquired)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // The owning thread already released; nothing to do.
            }
        }

        _mutex.Dispose();
    }
}
