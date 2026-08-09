using System.Globalization;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using EgressGuard.Core;
using Microsoft.Data.Sqlite;

namespace EgressGuard.Persistence;

public sealed record PersistedBaseline(string ExecutableSha256, string DestinationKey, string ProtocolPort, int SampleCount, DateTimeOffset LastObserved);

public sealed class EgressGuardDatabase
{
    public const int CurrentSchemaVersion = 2;
    private readonly string _connectionString;

    public EgressGuardDatabase(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? throw new ArgumentException("Database path has no directory."));
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 5
        }.ToString();
        DatabasePath = fullPath;
    }

    public string DatabasePath { get; }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, null, "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;", cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, null, "CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);", cancellationToken).ConfigureAwait(false);

        var versionCommand = connection.CreateCommand();
        versionCommand.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_versions;";
        var version = Convert.ToInt32(await versionCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
        if (version < 1)
        {
            await ApplyVersion1Async(connection, cancellationToken).ConfigureAwait(false);
            version = 1;
        }

        if (version < 2)
        {
            await ApplyVersion2Async(connection, cancellationToken).ConfigureAwait(false);
            version = 2;
        }

        if (version > CurrentSchemaVersion)
        {
            throw new InvalidDataException($"Database schema {version} is newer than supported version {CurrentSchemaVersion}.");
        }
    }

    public async Task SaveFlowsAsync(IEnumerable<NetworkFlow> flows, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(flows);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        foreach (var flow in flows)
        {
            var executableId = await UpsertExecutableAsync(connection, transaction, flow.Executable, cancellationToken).ConfigureAwait(false);
            await UpsertProcessAsync(connection, transaction, flow, executableId, cancellationToken).ConfigureAwait(false);
            await UpsertFlowAsync(connection, transaction, flow, executableId, cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<NetworkFlow>> GetRecentFlowsAsync(int limit, CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.id,f.pid,f.process_start_ticks,f.process_name,e.path,e.sha256,e.signature_status,e.publisher,e.file_size,e.last_write_time,e.is_temp,e.is_appdata,
                   f.parent_pid,f.protocol,f.ip_version,f.local_address,f.local_port,f.remote_address,f.remote_port,f.domain,f.domain_evidence,
                   f.first_seen,f.last_seen,f.state,f.bytes_sent,f.bytes_received,f.is_blocked,f.risk_score,f.risk_level,f.risk_decision,f.risk_reasons
            FROM network_flows f LEFT JOIN executables e ON e.id=f.executable_id
            ORDER BY f.last_seen DESC LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);
        var result = new List<NetworkFlow>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(ReadFlow(reader));
        }

        return result;
    }

    public async Task SaveRuleAsync(FirewallRule rule, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO rules(id,name,action,source,executable_path,executable_sha256,remote_address,remote_port,protocol,enabled,created_at,last_matched_at)
            VALUES($id,$name,$action,$source,$path,$hash,$address,$port,$protocol,$enabled,$created,$matched)
            ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,last_matched_at=excluded.last_matched_at;
            """;
        Add(command, "$id", rule.Id.ToString("D"));
        Add(command, "$name", rule.Name);
        Add(command, "$action", rule.Action.ToString());
        Add(command, "$source", rule.Source.ToString());
        Add(command, "$path", rule.ExecutablePath);
        Add(command, "$hash", rule.ExecutableSha256);
        Add(command, "$address", rule.RemoteAddress);
        Add(command, "$port", rule.RemotePort);
        Add(command, "$protocol", rule.Protocol?.ToString());
        Add(command, "$enabled", rule.Enabled ? 1 : 0);
        Add(command, "$created", rule.CreatedAt.ToString("O", CultureInfo.InvariantCulture));
        Add(command, "$matched", rule.LastMatchedAt?.ToString("O", CultureInfo.InvariantCulture));
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<FirewallRule>> GetRulesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,action,source,executable_path,executable_sha256,remote_address,remote_port,protocol,enabled,created_at,last_matched_at FROM rules ORDER BY created_at DESC;";
        var rules = new List<FirewallRule>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rules.Add(new FirewallRule(
                Guid.Parse(reader.GetString(0)),
                reader.GetString(1),
                Enum.Parse<FirewallAction>(reader.GetString(2)),
                Enum.Parse<RuleSource>(reader.GetString(3)),
                reader.GetString(4),
                NullableString(reader, 5),
                NullableString(reader, 6),
                reader.IsDBNull(7) ? null : reader.GetInt32(7),
                reader.IsDBNull(8) ? null : Enum.Parse<TransportProtocol>(reader.GetString(8)),
                reader.GetInt32(9) != 0,
                DateTimeOffset.Parse(reader.GetString(10), CultureInfo.InvariantCulture),
                reader.IsDBNull(11) ? null : DateTimeOffset.Parse(reader.GetString(11), CultureInfo.InvariantCulture)));
        }

        return rules;
    }

    public async Task SaveAlertsAsync(IEnumerable<NetworkFlow> flows, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        foreach (var flow in flows.Where(item => item.Risk?.Level is RiskLevel.High or RiskLevel.Critical))
        {
            var alert = CreateAlert(flow);
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO alerts(id,flow_id,created_at,process_name,destination,risk_score,risk_level,decision,reasons,related_rule_id,acknowledged)
                VALUES($id,$flow,$created,$process,$destination,$score,$level,$decision,$reasons,$rule,$acknowledged)
                ON CONFLICT(id) DO UPDATE SET risk_score=excluded.risk_score,risk_level=excluded.risk_level,decision=excluded.decision,reasons=excluded.reasons;
                """;
            Add(command, "$id", alert.Id.ToString("D"));
            Add(command, "$flow", alert.FlowId);
            Add(command, "$created", alert.CreatedAt.ToString("O", CultureInfo.InvariantCulture));
            Add(command, "$process", alert.ProcessName);
            Add(command, "$destination", alert.Destination);
            Add(command, "$score", alert.Assessment.Score);
            Add(command, "$level", alert.Assessment.Level.ToString());
            Add(command, "$decision", alert.Assessment.Decision.ToString());
            Add(command, "$reasons", JsonSerializer.Serialize(alert.Assessment.Reasons));
            Add(command, "$rule", alert.RelatedRuleId?.ToString("D"));
            Add(command, "$acknowledged", alert.IsAcknowledged ? 1 : 0);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<SecurityAlert>> GetRecentAlertsAsync(int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT id,flow_id,created_at,process_name,destination,risk_score,risk_level,decision,reasons,related_rule_id,acknowledged FROM alerts ORDER BY created_at DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", limit);
        var alerts = new List<SecurityAlert>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            alerts.Add(new SecurityAlert(
                Guid.Parse(reader.GetString(0)), reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture), reader.GetString(3), reader.GetString(4),
                new RiskAssessment(reader.GetInt32(5), Enum.Parse<RiskLevel>(reader.GetString(6)), Enum.Parse<PolicyDecision>(reader.GetString(7)), JsonSerializer.Deserialize<RiskReason[]>(reader.GetString(8)) ?? []),
                reader.IsDBNull(9) ? null : Guid.Parse(reader.GetString(9)), reader.GetInt32(10) != 0));
        }

        return alerts;
    }

    public async Task DeleteRuleAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM rules WHERE id=$id;";
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ApplyRetentionAsync(int retentionDays, CancellationToken cancellationToken = default)
    {
        if (retentionDays is < 1 or > 3650)
        {
            throw new ArgumentOutOfRangeException(nameof(retentionDays));
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM network_flows WHERE last_seen < $cutoff;";
        command.Parameters.AddWithValue("$cutoff", DateTimeOffset.UtcNow.AddDays(-retentionDays).ToString("O", CultureInfo.InvariantCulture));
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ClearHistoryAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "DELETE FROM alerts; DELETE FROM network_flows; DELETE FROM processes;", cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> GetSettingAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM settings WHERE key=$key;";
        command.Parameters.AddWithValue("$key", key);
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
    }

    public async Task SetSettingAsync(string key, string value, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(value);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO settings(key,value,updated_at) VALUES($key,$value,$updated) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at;";
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$value", value);
        command.Parameters.AddWithValue("$updated", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ResetBaselineAsync(string? executableSha256, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = executableSha256 is null ? "DELETE FROM baselines;" : "DELETE FROM baselines WHERE executable_sha256=$hash;";
        if (executableSha256 is not null)
        {
            command.Parameters.AddWithValue("$hash", executableSha256);
        }

        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SaveBaselineObservationsAsync(IEnumerable<NetworkFlow> flows, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        foreach (var flow in flows.Where(item => !item.IsBlocked && item.Risk?.Score < 80 && item.Executable is not null && item.Destination is not null))
        {
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO baselines(executable_sha256,version,destination,protocol,port,sample_count,first_seen,last_seen)
                VALUES($hash,$version,$destination,$protocol,$port,1,$first,$last)
                ON CONFLICT(executable_sha256,version,destination,protocol,port)
                DO UPDATE SET sample_count=baselines.sample_count+1,last_seen=excluded.last_seen;
                """;
            Add(command, "$hash", flow.Executable!.Sha256);
            Add(command, "$version", BaselineTracker.CurrentVersion);
            Add(command, "$destination", $"{flow.Destination!.Address}:{flow.Destination.Port}/{flow.Protocol}");
            Add(command, "$protocol", flow.Protocol.ToString());
            Add(command, "$port", flow.Destination.Port);
            Add(command, "$first", flow.FirstSeen.ToString("O", CultureInfo.InvariantCulture));
            Add(command, "$last", flow.LastSeen.ToString("O", CultureInfo.InvariantCulture));
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PersistedBaseline>> GetBaselinesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT executable_sha256,destination,protocol,port,sample_count,last_seen FROM baselines WHERE version=$version;";
        command.Parameters.AddWithValue("$version", BaselineTracker.CurrentVersion);
        var rows = new List<PersistedBaseline>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new PersistedBaseline(
                reader.GetString(0),
                reader.GetString(1),
                $"{reader.GetString(2)}:{reader.GetInt32(3)}",
                reader.GetInt32(4),
                DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture)));
        }

        return rows;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    private static async Task ApplyVersion1Async(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        const string sql = """
            CREATE TABLE executables(id INTEGER PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE, is_signed INTEGER, publisher TEXT, file_size INTEGER NOT NULL, last_write_time TEXT NOT NULL, is_temp INTEGER NOT NULL, is_appdata INTEGER NOT NULL, first_seen TEXT NOT NULL);
            CREATE TABLE processes(id INTEGER PRIMARY KEY, pid INTEGER NOT NULL, process_start_ticks INTEGER NOT NULL, process_name TEXT NOT NULL, executable_id INTEGER, parent_pid INTEGER, last_seen TEXT NOT NULL, UNIQUE(pid,process_start_ticks), FOREIGN KEY(executable_id) REFERENCES executables(id));
            CREATE TABLE network_flows(id TEXT PRIMARY KEY, pid INTEGER, process_start_ticks INTEGER, process_name TEXT NOT NULL, executable_id INTEGER, parent_pid INTEGER, protocol TEXT NOT NULL, ip_version TEXT NOT NULL, local_address TEXT NOT NULL, local_port INTEGER NOT NULL, remote_address TEXT, remote_port INTEGER, domain TEXT, domain_evidence TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, state TEXT, bytes_sent INTEGER, bytes_received INTEGER, is_blocked INTEGER NOT NULL, risk_score INTEGER, risk_level TEXT, risk_decision TEXT, risk_reasons TEXT, FOREIGN KEY(executable_id) REFERENCES executables(id));
            CREATE TABLE alerts(id TEXT PRIMARY KEY, flow_id TEXT NOT NULL, created_at TEXT NOT NULL, process_name TEXT NOT NULL, destination TEXT NOT NULL, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL, decision TEXT NOT NULL, reasons TEXT NOT NULL, related_rule_id TEXT, acknowledged INTEGER NOT NULL);
            CREATE TABLE rules(id TEXT PRIMARY KEY, name TEXT NOT NULL, action TEXT NOT NULL, source TEXT NOT NULL, executable_path TEXT NOT NULL, executable_sha256 TEXT, remote_address TEXT, remote_port INTEGER, protocol TEXT, enabled INTEGER NOT NULL, created_at TEXT NOT NULL, last_matched_at TEXT);
            CREATE TABLE baselines(executable_sha256 TEXT NOT NULL, version INTEGER NOT NULL, destination TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL, sample_count INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(executable_sha256,version,destination,protocol,port));
            CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE INDEX ix_flows_last_seen ON network_flows(last_seen);
            CREATE INDEX ix_flows_executable ON network_flows(executable_id);
            CREATE INDEX ix_flows_process_identity ON network_flows(pid,process_start_ticks);
            CREATE INDEX ix_flows_remote ON network_flows(remote_address,remote_port);
            CREATE INDEX ix_alerts_created_at ON alerts(created_at);
            INSERT INTO schema_versions(version,applied_at) VALUES(1,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
            """;
        await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ApplyVersion2Async(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(
            connection,
            transaction,
            "ALTER TABLE executables ADD COLUMN signature_status TEXT NOT NULL DEFAULT 'Unknown'; INSERT INTO schema_versions(version,applied_at) VALUES(2,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<long?> UpsertExecutableAsync(SqliteConnection connection, SqliteTransaction transaction, ExecutableInfo? executable, CancellationToken cancellationToken)
    {
        if (executable is null)
        {
            return null;
        }

        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO executables(path,sha256,is_signed,signature_status,publisher,file_size,last_write_time,is_temp,is_appdata,first_seen)
            VALUES($path,$hash,$signed,$signatureStatus,$publisher,$size,$write,$temp,$appdata,$seen)
            ON CONFLICT(sha256) DO UPDATE SET path=excluded.path,is_signed=excluded.is_signed,signature_status=excluded.signature_status,publisher=excluded.publisher,file_size=excluded.file_size,last_write_time=excluded.last_write_time,is_temp=excluded.is_temp,is_appdata=excluded.is_appdata
            RETURNING id;
            """;
        Add(command, "$path", executable.Path);
        Add(command, "$hash", executable.Sha256);
        Add(command, "$signed", executable.SignatureStatus == SignatureVerificationStatus.Unsigned ? 0 : 1);
        Add(command, "$signatureStatus", executable.SignatureStatus.ToString());
        Add(command, "$publisher", executable.Publisher);
        Add(command, "$size", executable.FileSize);
        Add(command, "$write", executable.LastWriteTime.ToString("O", CultureInfo.InvariantCulture));
        Add(command, "$temp", executable.IsInTemp ? 1 : 0);
        Add(command, "$appdata", executable.IsInAppData ? 1 : 0);
        Add(command, "$seen", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    private static async Task UpsertProcessAsync(SqliteConnection connection, SqliteTransaction transaction, NetworkFlow flow, long? executableId, CancellationToken cancellationToken)
    {
        if (flow.ProcessIdentity is null)
        {
            return;
        }

        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO processes(pid,process_start_ticks,process_name,executable_id,parent_pid,last_seen)
            VALUES($pid,$start,$name,$executable,$parent,$seen)
            ON CONFLICT(pid,process_start_ticks) DO UPDATE SET last_seen=excluded.last_seen,process_name=excluded.process_name,executable_id=excluded.executable_id,parent_pid=excluded.parent_pid;
            """;
        Add(command, "$pid", flow.ProcessIdentity.Value.ProcessId);
        Add(command, "$start", flow.ProcessIdentity.Value.StartTime.UtcTicks);
        Add(command, "$name", flow.ProcessName);
        Add(command, "$executable", executableId);
        Add(command, "$parent", flow.ParentProcessId);
        Add(command, "$seen", flow.LastSeen.ToString("O", CultureInfo.InvariantCulture));
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task UpsertFlowAsync(SqliteConnection connection, SqliteTransaction transaction, NetworkFlow flow, long? executableId, CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO network_flows(id,pid,process_start_ticks,process_name,executable_id,parent_pid,protocol,ip_version,local_address,local_port,remote_address,remote_port,domain,domain_evidence,first_seen,last_seen,state,bytes_sent,bytes_received,is_blocked,risk_score,risk_level,risk_decision,risk_reasons)
            VALUES($id,$pid,$start,$name,$executable,$parent,$protocol,$ip,$localAddress,$localPort,$remoteAddress,$remotePort,$domain,$evidence,$first,$last,$state,$sent,$received,$blocked,$score,$level,$decision,$reasons)
            ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,state=excluded.state,is_blocked=excluded.is_blocked,risk_score=excluded.risk_score,risk_level=excluded.risk_level,risk_decision=excluded.risk_decision,risk_reasons=excluded.risk_reasons
            WHERE excluded.last_seen<>network_flows.last_seen OR excluded.state IS NOT network_flows.state OR excluded.is_blocked<>network_flows.is_blocked OR excluded.risk_score IS NOT network_flows.risk_score;
            """;
        Add(command, "$id", flow.Id);
        Add(command, "$pid", flow.ProcessIdentity?.ProcessId);
        Add(command, "$start", flow.ProcessIdentity?.StartTime.UtcTicks);
        Add(command, "$name", flow.ProcessName);
        Add(command, "$executable", executableId);
        Add(command, "$parent", flow.ParentProcessId);
        Add(command, "$protocol", flow.Protocol.ToString());
        Add(command, "$ip", flow.IpVersion.ToString());
        Add(command, "$localAddress", flow.LocalEndpoint.Address.ToString());
        Add(command, "$localPort", flow.LocalEndpoint.Port);
        Add(command, "$remoteAddress", flow.Destination?.Address.ToString());
        Add(command, "$remotePort", flow.Destination?.Port);
        Add(command, "$domain", flow.Destination?.Domain);
        Add(command, "$evidence", flow.Destination?.DomainEvidence ?? "UDP owner table has no remote peer.");
        Add(command, "$first", flow.FirstSeen.ToString("O", CultureInfo.InvariantCulture));
        Add(command, "$last", flow.LastSeen.ToString("O", CultureInfo.InvariantCulture));
        Add(command, "$state", flow.State);
        Add(command, "$sent", flow.BytesSent);
        Add(command, "$received", flow.BytesReceived);
        Add(command, "$blocked", flow.IsBlocked ? 1 : 0);
        Add(command, "$score", flow.Risk?.Score);
        Add(command, "$level", flow.Risk?.Level.ToString());
        Add(command, "$decision", flow.Risk?.Decision.ToString());
        Add(command, "$reasons", flow.Risk is null ? null : JsonSerializer.Serialize(flow.Risk.Reasons));
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static NetworkFlow ReadFlow(SqliteDataReader reader)
    {
        ProcessIdentity? identity = reader.IsDBNull(1) || reader.IsDBNull(2)
            ? null
            : new ProcessIdentity(reader.GetInt32(1), new DateTimeOffset(reader.GetInt64(2), TimeSpan.Zero));
        var executable = reader.IsDBNull(4)
            ? null
            : new ExecutableInfo(reader.GetString(4), reader.GetString(5), Enum.Parse<SignatureVerificationStatus>(reader.GetString(6)), NullableString(reader, 7), reader.GetInt64(8), DateTimeOffset.Parse(reader.GetString(9), CultureInfo.InvariantCulture), reader.GetInt32(10) != 0, reader.GetInt32(11) != 0);
        var destination = reader.IsDBNull(17)
            ? null
            : new DestinationInfo(System.Net.IPAddress.Parse(reader.GetString(17)), reader.GetInt32(18), NullableString(reader, 19), reader.GetString(20));
        var risk = reader.IsDBNull(27)
            ? null
            : new RiskAssessment(reader.GetInt32(27), Enum.Parse<RiskLevel>(reader.GetString(28)), Enum.Parse<PolicyDecision>(reader.GetString(29)), JsonSerializer.Deserialize<RiskReason[]>(reader.GetString(30)) ?? []);
        return new NetworkFlow(reader.GetString(0), identity, reader.GetString(3), executable, reader.IsDBNull(12) ? null : reader.GetInt32(12), Enum.Parse<TransportProtocol>(reader.GetString(13)), Enum.Parse<IpVersion>(reader.GetString(14)), new NetworkEndpoint(System.Net.IPAddress.Parse(reader.GetString(15)), reader.GetInt32(16)), destination, DateTimeOffset.Parse(reader.GetString(21), CultureInfo.InvariantCulture), DateTimeOffset.Parse(reader.GetString(22), CultureInfo.InvariantCulture), NullableString(reader, 23), reader.IsDBNull(24) ? null : reader.GetInt64(24), reader.IsDBNull(25) ? null : reader.GetInt64(25), reader.GetInt32(26) != 0, risk);
    }

    private static SecurityAlert CreateAlert(NetworkFlow flow)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(flow.Id));
        return new SecurityAlert(
            new Guid(bytes.AsSpan(0, 16)),
            flow.Id,
            flow.FirstSeen,
            flow.ProcessName,
            flow.Destination is null ? "Remote endpoint unavailable" : $"{flow.Destination.Address}:{flow.Destination.Port}",
            flow.Risk!,
            null,
            false);
    }

    private static async Task ExecuteAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void Add(SqliteCommand command, string name, object? value) => command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    private static string? NullableString(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
