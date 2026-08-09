namespace EgressGuard.Core;

public sealed record RiskThresholds(int Medium = 30, int High = 60, int Critical = 80)
{
    public void Validate()
    {
        if (Medium is < 1 or > 100 || High <= Medium || Critical <= High || Critical > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(Medium), "Risk thresholds must be ordered within 1..100.");
        }
    }
}

public sealed record RiskSignals(
    bool IsUnsigned,
    bool IsInTemp,
    bool IsInUnusualAppData,
    bool IsFirstSeenExecutable,
    bool IsUnknownPublisher,
    bool IsFirstDestination,
    bool IsDestinationBlocked,
    bool IsSuspiciousParent,
    bool HasSufficientBaseline,
    bool DeviatesFromBaseline,
    string ExecutableEvidence,
    string DestinationEvidence,
    string ParentEvidence);

public sealed class RiskEngine
{
    private readonly RiskThresholds _thresholds;

    public RiskEngine(RiskThresholds? thresholds = null)
    {
        _thresholds = thresholds ?? new RiskThresholds();
        _thresholds.Validate();
    }

    public RiskAssessment Assess(RiskSignals signals)
    {
        ArgumentNullException.ThrowIfNull(signals);
        var reasons = new List<RiskReason>();
        Add(reasons, signals.IsUnsigned, "EXECUTABLE_UNSIGNED", "Executable has no verified digital signature.", 20, signals.ExecutableEvidence);
        Add(reasons, signals.IsInTemp, "EXECUTABLE_IN_TEMP", "Executable is running from a temporary directory.", 30, signals.ExecutableEvidence);
        Add(reasons, signals.IsInUnusualAppData, "EXECUTABLE_IN_APPDATA", "Executable is running from an unusual AppData location.", 15, signals.ExecutableEvidence);
        Add(reasons, signals.IsFirstSeenExecutable, "EXECUTABLE_FIRST_SEEN", "Executable is first seen on this device.", 10, signals.ExecutableEvidence);
        Add(reasons, signals.IsUnknownPublisher, "PUBLISHER_FIRST_SEEN", "Publisher has not been observed before.", 10, signals.ExecutableEvidence);
        Add(reasons, signals.IsFirstDestination, "DESTINATION_FIRST_SEEN", "Destination is first seen for this executable.", 10, signals.DestinationEvidence);
        Add(reasons, signals.IsDestinationBlocked, "DESTINATION_BLOCK_RULE", "Destination matches an explicit block rule.", 80, signals.DestinationEvidence);
        Add(reasons, signals.IsSuspiciousParent, "PARENT_SUSPICIOUS", "Parent process is unusual for this executable.", 20, signals.ParentEvidence);
        Add(reasons, signals.HasSufficientBaseline && signals.DeviatesFromBaseline, "BASELINE_DEVIATION", "Connection differs from the established baseline.", 20, signals.DestinationEvidence);

        if (!signals.HasSufficientBaseline)
        {
            reasons.Add(new RiskReason("BASELINE_INSUFFICIENT", "Insufficient baseline; no strong anomaly conclusion was made.", 0, signals.DestinationEvidence));
        }

        var score = Math.Clamp(reasons.Sum(reason => reason.Points), 0, 100);
        var level = score >= _thresholds.Critical
            ? RiskLevel.Critical
            : score >= _thresholds.High
                ? RiskLevel.High
                : score >= _thresholds.Medium
                    ? RiskLevel.Medium
                    : RiskLevel.Low;
        var decision = level switch
        {
            RiskLevel.Critical => PolicyDecision.Block,
            RiskLevel.High => PolicyDecision.Ask,
            _ => PolicyDecision.Allow
        };
        return new RiskAssessment(score, level, decision, reasons);
    }

    private static void Add(
        List<RiskReason> reasons,
        bool condition,
        string code,
        string message,
        int points,
        string evidence)
    {
        if (condition)
        {
            reasons.Add(new RiskReason(code, message, points, evidence));
        }
    }
}
