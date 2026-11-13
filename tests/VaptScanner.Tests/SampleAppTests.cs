namespace VaptScanner.Tests;

/// <summary>
/// End-to-end tests: scan the bundled sample apps and compare against what we know is in them.
/// VulnerableApp contains one or more deliberate instances of each issue below; SafeApp contains the
/// secure equivalents and must produce no findings at all.
/// </summary>
public class SampleAppTests
{
    /// <summary>
    /// Every rule that must fire on samples/VulnerableApp. When you add a rule, add a positive case to
    /// VulnerableApp, a negative case to SafeApp, and its ID here.
    /// </summary>
    private static readonly string[] ExpectedVulnerableAppRules =
    {
        "VAPT-AUTH-001", "VAPT-AUTH-003",
        "VAPT-CFG-001", "VAPT-CFG-002", "VAPT-CFG-003", "VAPT-CFG-004", "VAPT-CFG-006",
        "VAPT-CFG-010", "VAPT-CFG-011", "VAPT-CFG-012", "VAPT-CFG-014",
        "VAPT-CFG-020", "VAPT-CFG-021", "VAPT-CFG-022", "VAPT-CFG-024", "VAPT-CFG-030", "VAPT-CFG-031",
        "VAPT-CMD-001",
        "VAPT-CRYPTO-001", "VAPT-CRYPTO-003", "VAPT-CRYPTO-004", "VAPT-CRYPTO-005", "VAPT-CRYPTO-006",
        "VAPT-DEP-001",
        "VAPT-DESER-001", "VAPT-DESER-002",
        "VAPT-JS-001", "VAPT-JS-002",
        "VAPT-PATH-001", "VAPT-PATH-002",
        "VAPT-SECRET-007", "VAPT-SECRET-015", "VAPT-SECRET-017",
        "VAPT-SQL-001", "VAPT-SQL-002", "VAPT-SQL-004",
        "VAPT-SSRF-001",
        "VAPT-TLS-001",
        "VAPT-WEB-002", "VAPT-WEB-003", "VAPT-WEB-006", "VAPT-WEB-007", "VAPT-WEB-008", "VAPT-WEB-009",
        "VAPT-WEB-010", "VAPT-WEB-011", "VAPT-WEB-013", "VAPT-WEB-020", "VAPT-WEB-021", "VAPT-WEB-022",
        "VAPT-XSS-001", "VAPT-XSS-004",
    };

    private static readonly Lazy<ScanResult> Vulnerable = new(() => Scan.Folder(TestPaths.VulnerableApp));
    private static readonly Lazy<ScanResult> Safe = new(() => Scan.Folder(TestPaths.SafeApp));

    [Fact]
    public void VulnerableApp_ReportsExactlyTheExpectedRules()
    {
        var actual = Vulnerable.Value.Findings.Select(f => f.RuleId).ToHashSet();
        var expected = ExpectedVulnerableAppRules.ToHashSet();

        var missing = expected.Except(actual).OrderBy(x => x).ToList();
        var unexpected = actual.Except(expected).OrderBy(x => x).ToList();

        Assert.True(missing.Count == 0 && unexpected.Count == 0,
            $"Rule set changed.\n  No longer detected (regression?): {string.Join(", ", missing)}\n" +
            $"  Newly reported (false positive or new rule?): {string.Join(", ", unexpected)}");
    }

    [Theory]
    [InlineData("Controllers/AccountController.cs", 26, "VAPT-SQL-001")]
    [InlineData("Controllers/AccountController.cs", 47, "VAPT-CMD-001")]
    [InlineData("Controllers/AccountController.cs", 81, "VAPT-DESER-001")]
    [InlineData("Controllers/AccountController.cs", 15, "VAPT-SECRET-007")]
    [InlineData("Views/Home/Index.cshtml", 3, "VAPT-XSS-001")]
    [InlineData("Program.cs", 21, "VAPT-TLS-001")]
    [InlineData("web.config", 5, "VAPT-CFG-001")]
    public void VulnerableApp_FlagsKnownIssueAtTheRightLine(string location, int line, string ruleId)
    {
        Assert.Contains(Vulnerable.Value.Findings, f => f.Location == location && f.Line == line && f.RuleId == ruleId);
    }

    [Fact]
    public void VulnerableApp_FailsTheReleaseGate()
    {
        var findings = Vulnerable.Value.Findings;
        Assert.Contains(findings, f => f.Severity >= Severity.High);
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
        foreach (var source in new[] { "sast", "secrets", "config", "dependencies" })
            Assert.Contains(findings, f => f.Source == source);
    }

    [Fact]
    public void VulnerableApp_SecretsAreMaskedInSnippets()
    {
        foreach (var f in Vulnerable.Value.Findings.Where(f => f.Source == "secrets"))
        {
            Assert.DoesNotContain("Pr0d!Passw0rd2024", f.Snippet);
            Assert.DoesNotContain("51HxQzLKj3n8Vq2mPq9RtYbWc4Xa7Ze", f.Snippet);
        }
    }

    [Fact]
    public void SafeApp_HasNoFindings()
    {
        var findings = Safe.Value.Findings;
        Assert.True(findings.Count == 0,
            "False positives on SafeApp:\n" + string.Join("\n", findings.Select(f => $"  {f.RuleId} {f.Location}:{f.Line} {f.Snippet.Trim()}")));
    }

    [Fact]
    public void SafeApp_IgnoresCommentedOutVulnerableCode()
    {
        // SafeApp's controller ends with a commented-out SqlCommand concat and BinaryFormatter.
        var text = File.ReadAllText(Path.Combine(TestPaths.SafeApp, "Controllers", "AccountController.cs"));
        Assert.Contains("BinaryFormatter", text);
        Assert.DoesNotContain(Safe.Value.Findings, f => f.RuleId is "VAPT-SQL-001" or "VAPT-DESER-001");
    }

    [Fact]
    public void Findings_PointAtRealLines()
    {
        foreach (var f in Vulnerable.Value.Findings)
        {
            var file = Path.Combine(TestPaths.VulnerableApp, f.Location);
            Assert.True(File.Exists(file), $"{f.RuleId}: location '{f.Location}' is not a file");
            var lineCount = File.ReadAllLines(file).Length;
            Assert.InRange(f.Line, 1, lineCount);
            Assert.False(string.IsNullOrWhiteSpace(f.Snippet), $"{f.RuleId} at {f.Location}:{f.Line} has no snippet");
        }
    }

    [Fact]
    public void Findings_CarryRuleMetadata()
    {
        foreach (var f in Vulnerable.Value.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Title));
            Assert.False(string.IsNullOrWhiteSpace(f.Remediation));
            Assert.Matches(@"^[0-9a-f]{24}$", f.Fingerprint);
        }
    }
}
