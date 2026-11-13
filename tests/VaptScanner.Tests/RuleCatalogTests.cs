using System.Text.RegularExpressions;

namespace VaptScanner.Tests;

/// <summary>Guards the rule catalogue: unique IDs, complete metadata, and docs in sync with code.</summary>
public class RuleCatalogTests
{
    private static readonly List<RuleInfo> Rules = Scanner.AllRules().ToList();

    [Fact]
    public void Catalogue_IsNotEmpty() => Assert.True(Rules.Count >= 100, $"Only {Rules.Count} rules registered");

    [Fact]
    public void RuleIds_AreUniqueAndWellFormed()
    {
        Assert.Equal(Rules.Count, Rules.Select(r => r.Id).Distinct().Count());
        foreach (var r in Rules)
            Assert.Matches(@"^VAPT-[A-Z]+-\d{3}$", r.Id);
    }

    [Fact]
    public void EveryRule_HasTitleDescriptionAndRemediation()
    {
        foreach (var r in Rules)
        {
            Assert.False(string.IsNullOrWhiteSpace(r.Title), $"{r.Id} has no title");
            Assert.False(string.IsNullOrWhiteSpace(r.Description), $"{r.Id} has no description");
            Assert.False(string.IsNullOrWhiteSpace(r.Remediation), $"{r.Id} has no remediation");
        }
    }

    [Fact]
    public void EveryRule_MapsToCweAndOwasp()
    {
        var unmapped = Rules
            .Where(r => r.Severity > Severity.Info)
            .Where(r => r.Cwe is null || !Regex.IsMatch(r.Cwe, @"^CWE-\d+$") ||
                        r.Owasp is null || !Regex.IsMatch(r.Owasp, @"^A\d{2}:2021 "))
            .Select(r => $"{r.Id} (CWE: {r.Cwe ?? "none"}, OWASP: {r.Owasp ?? "none"})")
            .ToList();
        Assert.True(unmapped.Count == 0, "Rules missing a CWE/OWASP mapping:\n  " + string.Join("\n  ", unmapped));
    }

    [Fact]
    public void RulesMarkdown_ListsEveryRule()
    {
        var doc = File.ReadAllText(Path.Combine(TestPaths.RepoRoot, "RULES.md"));
        var missing = Rules.Where(r => !doc.Contains($"| {r.Id} |")).Select(r => r.Id).ToList();
        Assert.True(missing.Count == 0,
            "RULES.md is out of date (regenerate with `vapt rules --format md`). Missing: " + string.Join(", ", missing));
    }
}
