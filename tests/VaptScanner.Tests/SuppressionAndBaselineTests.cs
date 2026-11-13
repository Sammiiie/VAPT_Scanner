namespace VaptScanner.Tests;

public class SuppressionAndBaselineTests
{
    private const string VulnerableLine = """var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + username + "'", conn);""";

    private static string ProjectWith(string body)
    {
        var dir = TestPaths.NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Repo.cs"), $$"""
            public class Repo
            {
                public void Find(string username)
                {
                    {{body}}
                }
            }
            """);
        return dir;
    }

    private static ScanResult ScanNoDeps(string dir, Action<ScanOptions>? configure = null) =>
        Scan.Folder(dir, o => { o.SkipDependencyAudit = true; configure?.Invoke(o); });

    [Fact]
    public void Unsuppressed_SqlConcat_IsReported()
    {
        var result = ScanNoDeps(ProjectWith(VulnerableLine));
        Assert.Contains(result.Findings, f => f.RuleId == "VAPT-SQL-001");
        Assert.Equal(0, result.SuppressedCount);
    }

    [Theory]
    [InlineData("// vapt-ignore VAPT-SQL-001: table name comes from an enum")]
    [InlineData("// vapt-ignore")]
    public void InlineIgnore_OnLineAbove_SuppressesTheFinding(string comment)
    {
        var result = ScanNoDeps(ProjectWith(comment + "\n        " + VulnerableLine));
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "VAPT-SQL-001");
        Assert.True(result.SuppressedCount >= 1);
    }

    [Fact]
    public void InlineIgnore_ForADifferentRule_DoesNotSuppress()
    {
        var result = ScanNoDeps(ProjectWith("// vapt-ignore VAPT-CMD-001: unrelated\n        " + VulnerableLine));
        Assert.Contains(result.Findings, f => f.RuleId == "VAPT-SQL-001");
    }

    [Fact]
    public void Baseline_HidesKnownFindings_AndReportsOnlyNewOnes()
    {
        var dir = ProjectWith(VulnerableLine);
        var baselinePath = Path.Combine(TestPaths.NewTempDir(), Baseline.DefaultFileName);

        var first = ScanNoDeps(dir);
        Assert.NotEmpty(first.Findings);
        Baseline.FromFindings(first.Findings).Save(baselinePath);

        var second = ScanNoDeps(dir, o => o.BaselinePath = baselinePath);
        Assert.Empty(second.Findings);
        Assert.Equal(first.Findings.Count, second.BaselinedCount);

        // A new issue introduced after the baseline must still be reported.
        File.AppendAllText(Path.Combine(dir, "Ping.cs"), """
            public class Ping { public void Run(string host) => System.Diagnostics.Process.Start("cmd.exe", "/c ping " + host); }
            """);
        var third = ScanNoDeps(dir, o => o.BaselinePath = baselinePath);
        Assert.Contains(third.Findings, f => f.RuleId == "VAPT-CMD-001");
        Assert.DoesNotContain(third.Findings, f => f.RuleId == "VAPT-SQL-001");
    }

    [Fact]
    public void Fingerprint_SurvivesLineMoves()
    {
        var a = ScanNoDeps(ProjectWith(VulnerableLine)).Findings.Single(f => f.RuleId == "VAPT-SQL-001");
        var b = ScanNoDeps(ProjectWith("\n\n\n        " + VulnerableLine)).Findings.Single(f => f.RuleId == "VAPT-SQL-001");
        Assert.NotEqual(a.Line, b.Line);
        Assert.Equal(a.Fingerprint, b.Fingerprint);
    }

    [Fact]
    public void DisabledRules_AreRemoved()
    {
        var result = ScanNoDeps(ProjectWith(VulnerableLine), o => o.DisabledRules.Add("VAPT-SQL-001"));
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "VAPT-SQL-001");
    }

    [Fact]
    public void SeverityOverrides_AreApplied()
    {
        // Uses a rule that is the only match on its line: overrides run before de-duplication, so lowering a
        // rule that shares a line with a sibling rule in the same category lets the sibling win instead.
        const string md5 = "using var md5 = System.Security.Cryptography.MD5.Create();";
        Assert.NotEqual(Severity.Low, ScanNoDeps(ProjectWith(md5)).Findings.Single(f => f.RuleId == "VAPT-CRYPTO-001").Severity);

        var result = ScanNoDeps(ProjectWith(md5), o => o.SeverityOverrides["VAPT-CRYPTO-001"] = Severity.Low);
        Assert.Equal(Severity.Low, result.Findings.Single(f => f.RuleId == "VAPT-CRYPTO-001").Severity);
    }

    [Fact]
    public void MinSeverity_FiltersLowerFindings()
    {
        var all = Scan.Folder(TestPaths.VulnerableApp);
        var highPlus = Scan.Folder(TestPaths.VulnerableApp, o => o.MinSeverity = Severity.High);
        Assert.True(highPlus.Findings.Count < all.Findings.Count);
        Assert.All(highPlus.Findings, f => Assert.True(f.Severity >= Severity.High));
    }

    [Fact]
    public void Exclude_SkipsMatchingPaths()
    {
        var result = Scan.Folder(TestPaths.VulnerableApp, o => o.Exclude.Add("**/Controllers/**"));
        Assert.DoesNotContain(result.Findings, f => f.Location.StartsWith("Controllers/"));
        Assert.Contains(result.Findings, f => f.Location == "Program.cs");
    }
}
