using System;
using System.Collections.Generic;

namespace Mockaco.Attack
{
    /// <summary>
    /// Attack lifecycle states.
    /// </summary>
    public enum AttackState
    {
        Queued = 0,
        Researching = 1,
        Running = 2,
        Success = 3,
        Failed = 4
    }

    /// <summary>
    /// Severity levels reported by the LLM.
    /// </summary>
    public enum FindingSeverity
    {
        Critical = 0,
        High = 1,
        Medium = 2,
        Low = 3
    }

    /// <summary>
    /// Represents a single outbound attack record.
    /// </summary>
    public sealed record Attack(
        long AttackId,
        long HostId,
        string AttackName,
        AttackType Type,
        AttackState Status,
        string Result,
        DateTime CreatedAt,
        DateTime UpdatedAt);

    /// <summary>
    /// A vulnerability or issue identified by LLM research.
    /// </summary>
    public sealed record AttackFinding(
        long FindingId,
        long AttackId,
        string FindingType,
        string Severity,
        string Title,
        string Description,
        string Evidence,
        bool Exploitable);

    /// <summary>
    /// Result of an attack execution.
    /// </summary>
    public sealed record AttackResult(
        long ResultId,
        long AttackId,
        bool Success,
        string Response,
        string ErrorMessage);

    /// <summary>
    /// Row model for querying hosts that have recon findings (nmap ports or shodan data).
    /// </summary>
    public sealed record HostWithFindings(
        long HostId,
        string IpAddress,
        int PortCount,
        int ShodanRecordCount,
        string PortDetails,
        string ShodanData);

    /// <summary>
    /// Payload sent to the LLM for research.
    /// </summary>
    public sealed record LlmResearchRequest(
        string IpAddress,
        IReadOnlyList<string> Ports,
        IReadOnlyList<string> ShodanServices,
        string Prompt);

    /// <summary>
    /// Structured LLM response containing findings and recommended attacks.
    /// </summary>
    public sealed record LlmResearchResponse(
        IReadOnlyList<LlmFinding> Findings,
        IReadOnlyList<LlmRecommendedAttack> RecommendedAttacks);

    /// <summary>
    /// A single finding returned by the LLM.
    /// </summary>
    public sealed record LlmFinding(
        string FindingType,
        string Severity,
        string Title,
        string Description,
        string Evidence,
        bool Exploitable);

    /// <summary>
    /// An attack the LLM recommends launching.
    /// </summary>
    public sealed record LlmRecommendedAttack(
        string AttackName,
        AttackType Type,
        string Method,
        string Target,
        string Parameters);
}
