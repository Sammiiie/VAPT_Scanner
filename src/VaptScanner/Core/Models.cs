using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace VaptScanner.Core;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public static class SeverityExtensions
{
    public static bool TryParse(string? value, out Severity severity)
    {
        severity = Severity.High;
        if (string.IsNullOrWhiteSpace(value)) return false;
        if (value.Equals("none", StringComparison.OrdinalIgnoreCase) || value.Equals("never", StringComparison.OrdinalIgnoreCase))
        {
            severity = (Severity)99;
            return true;
        }
        return Enum.TryParse(value, ignoreCase: true, out severity);
    }

    public static string SarifLevel(this Severity s) => s switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        _ => "note"
    };

    public static string SecuritySeverityScore(this Severity s) => s switch
    {
        Severity.Critical => "9.5",
        Severity.High => "8.0",
        Severity.Medium => "5.5",
        Severity.Low => "3.0",
        _ => "0.0"
    };
}

/// <summary>Metadata describing a rule. Shared by every analyzer.</summary>
public sealed record RuleInfo(
    string Id,
    string Title,
    Severity Severity,
    string Category,
    string Description,
    string Remediation,
    string? Cwe = null,
    string? Owasp = null);

public sealed class Finding
{
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; set; }
    public required string Category { get; init; }
    public required string Description { get; init; }
    public required string Remediation { get; init; }
    public string? Cwe { get; init; }
    public string? Owasp { get; init; }

    /// <summary>Path relative to the scan root (forward slashes), or a URL for DAST findings.</summary>
    public required string Location { get; init; }
    public int Line { get; init; }
    public int Column { get; init; }
    public string Snippet { get; init; } = "";
    public string Source { get; init; } = "sast"; // sast | secrets | config | dependencies | dast

    /// <summary>
    /// Stable identifier that survives line moves: rule + file + normalised snippet.
    /// Used by the baseline file.
    /// </summary>
    public string Fingerprint
    {
        get
        {
            var normalised = string.Concat(Snippet.Where(c => !char.IsWhiteSpace(c)));
            var raw = $"{RuleId}|{Location}|{normalised}";
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
            return Convert.ToHexString(hash)[..24].ToLowerInvariant();
        }
    }

    public static Finding From(RuleInfo rule, string location, int line, int column, string snippet, string source,
        Severity? severityOverride = null, string? extraDetail = null) => new()
    {
        RuleId = rule.Id,
        Title = rule.Title,
        Severity = severityOverride ?? rule.Severity,
        Category = rule.Category,
        Description = extraDetail is null ? rule.Description : $"{rule.Description} {extraDetail}",
        Remediation = rule.Remediation,
        Cwe = rule.Cwe,
        Owasp = rule.Owasp,
        Location = location,
        Line = line,
        Column = column,
        Snippet = snippet,
        Source = source
    };
}

public sealed class ScanResult
{
    public string Tool { get; init; } = "VaptScanner";
    public string Version { get; init; } = typeof(ScanResult).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    public required string Target { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset FinishedAt { get; set; }
    public int FilesScanned { get; set; }
    public int SuppressedCount { get; set; }
    public int BaselinedCount { get; set; }
    public List<Finding> Findings { get; } = new();
    public List<string> Notes { get; } = new();

    public Dictionary<Severity, int> CountsBySeverity() =>
        Enum.GetValues<Severity>().ToDictionary(s => s, s => Findings.Count(f => f.Severity == s));
}
