using System.Text.Json;
using System.Text.RegularExpressions;

namespace VaptScanner.Core;

/// <summary>
/// Inline suppressions: a comment containing "vapt-ignore" on the flagged line or the line above.
///   // vapt-ignore                      -> suppress every rule on that line
///   // vapt-ignore VAPT-SQL-001: reason -> suppress only the listed rule(s)
/// </summary>
public static class InlineSuppressions
{
    private static readonly Regex Marker = new(@"vapt-ignore(?<ids>(\s*[:,]?\s*VAPT-[A-Z]+-\d{3})*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool IsSuppressed(SourceText src, int line, string ruleId) =>
        Check(src.LineText(line), ruleId) || (line > 1 && Check(src.LineText(line - 1), ruleId));

    private static bool Check(string text, string ruleId)
    {
        var m = Marker.Match(text);
        if (!m.Success) return false;
        var ids = Regex.Matches(m.Groups["ids"].Value, @"VAPT-[A-Z]+-\d{3}", RegexOptions.IgnoreCase)
            .Select(x => x.Value.ToUpperInvariant()).ToList();
        return ids.Count == 0 || ids.Contains(ruleId.ToUpperInvariant());
    }
}

/// <summary>
/// A baseline records the fingerprints of accepted, pre-existing findings so the pipeline only
/// fails on new issues. Generate with: vapt baseline &lt;path&gt;
/// </summary>
public sealed class Baseline
{
    public const string DefaultFileName = ".vapt-baseline.json";

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<BaselineEntry> Entries { get; set; } = new();

    public sealed class BaselineEntry
    {
        public string Fingerprint { get; set; } = "";
        public string RuleId { get; set; } = "";
        public string Location { get; set; } = "";
        public string? Justification { get; set; }
    }

    public HashSet<string> Fingerprints() => Entries.Select(e => e.Fingerprint).ToHashSet();

    public static Baseline? TryLoad(string path)
    {
        if (!File.Exists(path)) return null;
        return JsonSerializer.Deserialize<Baseline>(File.ReadAllText(path), JsonOpts.Read);
    }

    public static Baseline FromFindings(IEnumerable<Finding> findings) => new()
    {
        Entries = findings.Select(f => new BaselineEntry
        {
            Fingerprint = f.Fingerprint,
            RuleId = f.RuleId,
            Location = f.Location,
            Justification = "Accepted at baseline creation - review and replace with a real justification"
        }).DistinctBy(e => e.Fingerprint).ToList()
    };

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOpts.Write));
}
