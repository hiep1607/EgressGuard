namespace EgressGuard.Launcher;

/// <summary>
/// Exclusive file lock placed inside the data folder itself. Holding the open
/// file stream keeps the lock for the whole launcher lifetime and, unlike a
/// thread-affine Mutex, survives thread switches across await points. Because
/// the lock is a file inside the folder, equivalent spellings of that folder
/// (different casing, '.' segments or trailing separators) map to the same
/// ownership.
/// </summary>
public sealed class DataFolderLock : IDisposable
{
    private FileStream? _stream;

    public bool Acquired { get; private set; }

    public string? Error { get; private set; }

    /// <summary>Normalized lock-file path for a data folder.</summary>
    public static string GetLockPath(string dataDirectory) =>
        Path.Combine(Path.GetFullPath(dataDirectory), "session.lock");

    /// <summary>Attempts to take the exclusive data-folder lock.</summary>
    public void Acquire(string dataDirectory)
    {
        var lockPath = GetLockPath(dataDirectory);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);
            _stream = new FileStream(
                lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None);
            Acquired = true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Acquired = false;
            Error = "The data folder is already in use by another preview session, or it cannot be locked: "
                + exception.Message;
        }
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _stream = null;
        Acquired = false;
    }
}
