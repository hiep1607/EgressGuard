using System.Globalization;
using System.IO;
using System.Text;
using EgressGuard.Core;
using EgressGuard.Protocol;

namespace EgressGuard.UI;

internal static class FileActivityHistoryCsvExporter
{
    public const int MaximumRows = 5_000;
    private static readonly UTF8Encoding Utf8WithBom = new(encoderShouldEmitUTF8Identifier: true);

    public static async Task WriteAsync(
        string path,
        IReadOnlyList<FileCorrelationHistoryItem> items,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(items);
        if (items.Count > MaximumRows)
            throw new ArgumentOutOfRangeException(nameof(items));
        await using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 16 * 1024, useAsync: true);
        await using var writer = new StreamWriter(stream, Utf8WithBom, 16 * 1024, leaveOpen: false);
        await writer.WriteLineAsync("Time,Process,Activity,File,Extension,Relevance,Time distance,Reason,Connection code".AsMemory(), cancellationToken).ConfigureAwait(false);
        foreach (var item in items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var fields = new[]
            {
                item.ActivityTimestampUtc.ToLocalTime().ToString("G", CultureInfo.CurrentCulture),
                item.ProcessName,
                OperationLabel(item.Operation),
                item.DisplayPath,
                item.Extension,
                item.Confidence.ToString(),
                FormatTimeDistance(item.TimeDeltaSeconds),
                item.Reason,
                item.FlowId
            };
            await writer.WriteLineAsync(string.Join(',', fields.Select(Escape)).AsMemory(), cancellationToken).ConfigureAwait(false);
        }

        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static string Escape(string? value)
    {
        var safe = NeutralizeFormula(value ?? string.Empty);
        return safe.IndexOfAny([',', '"', '\r', '\n']) >= 0
            ? $"\"{safe.Replace("\"", "\"\"", StringComparison.Ordinal)}\""
            : safe;
    }

    internal static string NeutralizeFormula(string value) => value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n'
        ? "'" + value
        : value;

    private static string OperationLabel(FileActivityOperation operation) => operation switch
    {
        FileActivityOperation.OpenCreate => "Open / create",
        FileActivityOperation.Read => "Read",
        FileActivityOperation.Write => "Write",
        FileActivityOperation.Rename => "Rename",
        FileActivityOperation.Delete => "Delete",
        _ => "Unknown"
    };

    private static string FormatTimeDistance(double seconds)
    {
        var absolute = Math.Abs(seconds);
        return absolute < 0.0005
            ? "At connection time"
            : $"{absolute:0.###} s {(seconds < 0 ? "before" : "after")} connection";
    }
}

internal static class FileActivityHistoryPaginationValidator
{
    public static FileActivityHistoryCursorMessage? Validate(
        GetFileActivityHistoryMessage request,
        FileActivityHistoryMessage response,
        ISet<Guid> seenIds,
        ISet<string> usedCursors)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(seenIds);
        ArgumentNullException.ThrowIfNull(usedCursors);
        ArgumentNullException.ThrowIfNull(response.Items);
        ArgumentNullException.ThrowIfNull(response.SensorStatus);
        if (request.Limit is < 1 or > 200)
            throw new InvalidDataException("The history request limit is invalid.");
        if (response.StartUtc != request.StartUtc || response.EndUtc != request.EndUtc)
            throw new InvalidDataException("The history response range does not match the request.");
        if (response.Items.Count > request.Limit)
            throw new InvalidDataException("The history response exceeded the requested limit.");
        if (response.HasMore && response.Items.Count == 0)
            throw new InvalidDataException("A history response with more pages must contain records.");
        if (!response.HasMore && response.NextCursor is not null)
            throw new InvalidDataException("A final history response must not contain a cursor.");
        if (response.HasMore && response.NextCursor is null)
            throw new InvalidDataException("A history response with more pages must contain a cursor.");

        var pageIds = new HashSet<Guid>();
        for (var index = 0; index < response.Items.Count; index++)
        {
            var item = response.Items[index];
            if (item.Id == Guid.Empty || !pageIds.Add(item.Id) || seenIds.Contains(item.Id))
                throw new InvalidDataException("The history response contains an invalid or repeated ID.");
            if (item.ActivityTimestampUtc < request.StartUtc || item.ActivityTimestampUtc > request.EndUtc)
                throw new InvalidDataException("A history record is outside the requested range.");
            if (request.Operation is { } operation && item.Operation != operation)
                throw new InvalidDataException("A history record does not match the requested operation filter.");
            if (request.Confidence is { } confidence && item.Confidence != confidence)
                throw new InvalidDataException("A history record does not match the requested relevance filter.");
            if (index > 0 && CompareDescending(response.Items[index - 1], item) > 0)
                throw new InvalidDataException("The history response is not stably ordered.");
            if (request.Cursor is { } previousCursor && CompareDescending(previousCursor, item) >= 0)
                throw new InvalidDataException("The history response did not advance past its cursor.");
        }

        if (response.NextCursor is { } nextCursor)
        {
            var last = response.Items[^1];
            if (nextCursor.Id != last.Id || nextCursor.ActivityTimestampUtc != last.ActivityTimestampUtc)
                throw new InvalidDataException("The history cursor does not point to the last record.");
            if (request.Cursor is { } previousCursor && CompareDescending(previousCursor, nextCursor) >= 0)
                throw new InvalidDataException("The history cursor did not advance.");
            if (!usedCursors.Add(CursorKey(nextCursor)))
                throw new InvalidDataException("The history cursor repeated.");
        }

        foreach (var id in pageIds)
            seenIds.Add(id);
        return response.NextCursor;
    }

    internal static string CursorKey(FileActivityHistoryCursorMessage cursor) =>
        $"{cursor.ActivityTimestampUtc.UtcTicks}:{cursor.Id:D}";

    private static int CompareDescending(FileCorrelationHistoryItem left, FileCorrelationHistoryItem right)
    {
        var timestamp = right.ActivityTimestampUtc.CompareTo(left.ActivityTimestampUtc);
        return timestamp != 0 ? timestamp : right.Id.CompareTo(left.Id);
    }

    private static int CompareDescending(FileActivityHistoryCursorMessage left, FileCorrelationHistoryItem right)
    {
        var timestamp = right.ActivityTimestampUtc.CompareTo(left.ActivityTimestampUtc);
        return timestamp != 0 ? timestamp : right.Id.CompareTo(left.Id);
    }

    private static int CompareDescending(FileActivityHistoryCursorMessage left, FileActivityHistoryCursorMessage right)
    {
        var timestamp = right.ActivityTimestampUtc.CompareTo(left.ActivityTimestampUtc);
        return timestamp != 0 ? timestamp : right.Id.CompareTo(left.Id);
    }
}
