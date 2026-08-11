using System.Text.Json;
using System.Text.Json.Serialization;
using System.Net;
using EgressGuard.Core;

namespace EgressGuard.Protocol;

public static class ProtocolConstants
{
    public const int Version = 1;
    public const int MaximumMessageBytes = 1024 * 1024;
    public const string PipeName = "EgressGuard.Service.v1";

    public static string ResolvePipeName()
    {
        var configured = Environment.GetEnvironmentVariable("EGRESSGUARD_PIPE_NAME");
        return string.IsNullOrWhiteSpace(configured) ? PipeName : configured;
    }
}

public static class MessageTypes
{
    public const string Handshake = "Handshake";
    public const string GetStatus = "GetStatus";
    public const string GetActiveFlows = "GetActiveFlows";
    public const string GetRules = "GetRules";
    public const string GetAlerts = "GetAlerts";
    public const string GetFileCorrelations = "GetFileCorrelations";
    public const string SubscribeEvents = "SubscribeEvents";
    public const string CreateRule = "CreateRule";
    public const string DeleteRule = "DeleteRule";
    public const string SetProtectionMode = "SetProtectionMode";
    public const string ResetOwnedRules = "ResetOwnedRules";
    public const string ResetBaseline = "ResetBaseline";
    public const string ClearHistory = "ClearHistory";
    public const string ServiceStatusChanged = "ServiceStatusChanged";
    public const string FlowObserved = "FlowObserved";
    public const string AlertRaised = "AlertRaised";
    public const string Success = "Success";
    public const string Error = "Error";
}

public sealed record MessageEnvelope(
    int Version,
    string Type,
    Guid CorrelationId,
    JsonElement Payload)
{
    public static MessageEnvelope Create<T>(string type, T payload, Guid? correlationId = null) =>
        new(ProtocolConstants.Version, type, correlationId ?? Guid.NewGuid(), JsonSerializer.SerializeToElement(payload, JsonDefaults.Options));

    public T ReadPayload<T>() => Payload.Deserialize<T>(JsonDefaults.Options)
        ?? throw new InvalidDataException($"Message {Type} has an empty or invalid payload.");
}

public sealed record HandshakeMessage(string ClientName, int MinimumVersion, int MaximumVersion);
public sealed record ServiceStatusMessage(
    ProtectionMode Mode,
    bool IsRunning,
    int ActiveFlowCount,
    long DroppedEvents,
    string DatabasePath,
    DateTimeOffset Timestamp,
    FileSensorStatus? FileSensor = null,
    bool FileCorrelationEnabled = false);
public sealed record ActiveFlowsMessage(IReadOnlyList<NetworkFlow> Flows, long Sequence = 0);
public sealed record RulesMessage(IReadOnlyList<FirewallRule> Rules);
public sealed record AlertsMessage(IReadOnlyList<SecurityAlert> Alerts);
public sealed record GetFileCorrelationsMessage(string FlowId, int Limit = 20);
public sealed record FileCorrelationsMessage(string FlowId, IReadOnlyList<FileCorrelation> Correlations, FileSensorStatus SensorStatus);
public sealed record FlowObservedMessage(NetworkFlow Flow);
public sealed record AlertRaisedMessage(SecurityAlert Alert);
public sealed record CreateRuleMessage(FirewallRule Rule);
public sealed record DeleteRuleMessage(Guid RuleId);
public sealed record SetProtectionModeMessage(ProtectionMode Mode);
public sealed record ResetBaselineMessage(string? ExecutableSha256);
public sealed record SuccessMessage(string Message);
public sealed record ErrorMessage(string Code, string Message);
public sealed record SubscribeEventsMessage(long LastSequence);

public enum StreamEventKind
{
    FlowAdded,
    FlowUpdated,
    FlowRemoved,
    AlertRaised,
    ServiceStatusChanged,
    ResyncRequired
}

public sealed record StreamEventMessage(
    long Sequence,
    StreamEventKind Kind,
    NetworkFlow? Flow,
    string? FlowId,
    SecurityAlert? Alert,
    ServiceStatusMessage? Status,
    bool RequiresResync);

public static class JsonDefaults
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = false };
        options.Converters.Add(new IpAddressJsonConverter());
        return options;
    }

    private sealed class IpAddressJsonConverter : JsonConverter<IPAddress>
    {
        public override IPAddress Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            IPAddress.Parse(reader.GetString() ?? throw new JsonException("IP address was null."));

        public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }
}
