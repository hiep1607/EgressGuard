using EgressGuard.Core;

namespace EgressGuard.Protocol;

public static class OutboundGateMessageTypes
{
    public const string FileReadIntent = "Phase5B.FileReadIntent";
    public const string GateArmRequest = "Phase5B.GateArmRequest";
    public const string GateArmAck = "Phase5B.GateArmAck";
    public const string FileReadDisposition = "Phase5B.FileReadDisposition";
    public const string FileReadCompletionAck = "Phase5B.FileReadCompletionAck";
    public const string NetworkGateChallenge = "Phase5B.NetworkGateChallenge";
    public const string UserDecision = "Phase5B.UserDecision";
    public const string OneTimeTicket = "Phase5B.OneTimeTicket";
    public const string EphemeralFlowGrant = "Phase5B.EphemeralFlowGrant";
    public const string GateStatus = "Phase5B.GateStatus";
}

public sealed record FileReadIntentMessage(FileReadIntent Intent);
public sealed record GateArmRequestMessage(GateArmRequest Request);
public sealed record GateArmAckMessage(GateArmAck Ack);
public sealed record FileReadDispositionMessage(FileReadDisposition Disposition);
public sealed record FileReadCompletionAckMessage(FileReadCompletionAck Completion);
public sealed record NetworkGateChallengeMessage(NetworkGateChallenge Challenge);
public sealed record UserDecisionMessage(UserDecision Decision);
public sealed record OneTimeTicketMessage(OneTimeTicket Ticket);
public sealed record EphemeralFlowGrantMessage(EphemeralFlowGrant Grant);
public sealed record GateStatusMessage(GateStatus Status);
