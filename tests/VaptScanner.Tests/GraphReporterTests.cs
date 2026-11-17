using VaptScanner.Reporting;

namespace VaptScanner.Tests;

public class GraphReporterTests
{
    private static Finding F(Severity severity, string title = "Issue", string location = "src/A.cs", string source = "sast", string category = "Injection") => new()
    {
        RuleId = "VAPT-TEST-001",
        Title = title,
        Severity = severity,
        Category = category,
        Description = "d",
        Remediation = "r",
        Location = location,
        Source = source,
    };

    private static ScanResult Result(params Finding[] findings)
    {
        var r = new ScanResult { Target = "C:/app", StartedAt = DateTimeOffset.UnixEpoch, FilesScanned = 3 };
        r.Findings.AddRange(findings);
        return r;
    }

    [Fact]
    public void Render_ShowsTotalsPerSeverity_AndCharts()
    {
        var html = GraphReporter.Render(Result(F(Severity.Critical), F(Severity.High), F(Severity.High), F(Severity.Low, source: "secrets")), SeverityExtensions.Never);

        Assert.StartsWith("<!doctype html>", html);
        Assert.Contains("<b>4</b><span>Findings</span>", html);
        Assert.Contains("<div class=\"tile High\"><b>2</b><span>High</span></div>", html);
        Assert.Contains("<svg", html);
        Assert.Contains("Findings by source", html);
        Assert.Contains(">secrets<", html);
        Assert.Contains("4 vulnerabilities found. Report only", html);
    }

    [Fact]
    public void Render_EscapesFindingText()
    {
        var html = GraphReporter.Render(Result(F(Severity.High, title: "<script>alert(1)</script>", location: "a\"><img src=x>.cs")), SeverityExtensions.Never);

        Assert.DoesNotContain("<script>alert(1)</script>", html);
        Assert.DoesNotContain("<img src=x>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void Render_WithGate_ShowsGateResult()
    {
        var failed = GraphReporter.Render(Result(F(Severity.High)), Severity.High);
        Assert.Contains("Release gate failed: 1 finding(s) at or above High", failed);

        var passed = GraphReporter.Render(Result(F(Severity.Low)), Severity.High);
        Assert.Contains("Release gate passed", passed);
    }

    [Fact]
    public void Render_NoFindings_ShowsEmptyState()
    {
        var html = GraphReporter.Render(Result(), SeverityExtensions.Never);
        Assert.Contains("No vulnerabilities found", html);
        Assert.DoesNotContain("Findings by source", html);
    }
}
