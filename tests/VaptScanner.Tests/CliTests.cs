using System.Text.Json;

namespace VaptScanner.Tests;

[CollectionDefinition("Console", DisableParallelization = true)]
public class ConsoleCollection { }

/// <summary>The CLI contract CI pipelines rely on: exit codes and report files.</summary>
[Collection("Console")]
public class CliTests
{
    private static int Run(params string[] args)
    {
        var originalOut = Console.Out;
        var originalErr = Console.Error;
        try
        {
            Console.SetOut(TextWriter.Null);
            Console.SetError(TextWriter.Null);
            return global::VaptScanner.Program.Main(args).GetAwaiter().GetResult();
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalErr);
        }
    }

    [Fact]
    public void Scan_VulnerableApp_WithFailBuild_ExitsWith1_AndWritesJsonAndSarif()
    {
        var outDir = TestPaths.NewTempDir();
        var code = Run("scan", TestPaths.VulnerableApp, "--offline", "--fail-build", "--format", "json,sarif", "--out", outDir);

        Assert.Equal(1, code);

        var json = Path.Combine(outDir, "vapt-report.json");
        Assert.True(File.Exists(json));
        using (var doc = JsonDocument.Parse(File.ReadAllText(json)))
            Assert.True(doc.RootElement.GetProperty("findings").GetArrayLength() > 0);

        var sarif = Path.Combine(outDir, "vapt-report.sarif");
        Assert.True(File.Exists(sarif));
        using (var doc = JsonDocument.Parse(File.ReadAllText(sarif)))
        {
            Assert.Equal("2.1.0", doc.RootElement.GetProperty("version").GetString());
            var results = doc.RootElement.GetProperty("runs")[0].GetProperty("results");
            Assert.True(results.GetArrayLength() > 0);
        }
    }

    [Fact]
    public void Scan_SafeApp_ExitsWith0()
    {
        Assert.Equal(0, Run("scan", TestPaths.SafeApp, "--offline", "--format", "json", "--out", TestPaths.NewTempDir()));
    }

    [Fact]
    public void Scan_VulnerableApp_Default_IsReportOnly_ExitsWith0()
    {
        var outDir = TestPaths.NewTempDir();
        Assert.Equal(0, Run("scan", TestPaths.VulnerableApp, "--offline", "--format", "json", "--out", outDir));
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(outDir, "vapt-report.json")));
        Assert.True(doc.RootElement.GetProperty("findings").GetArrayLength() > 0);
    }

    [Theory]
    [InlineData("Critical")]
    [InlineData("high")]
    [InlineData("Low")]
    public void Scan_FailBuildWithSeverity_ExitsWith1(string severity) =>
        Assert.Equal(1, Run("scan", TestPaths.VulnerableApp, "--offline", "--fail-build", severity, "--format", "json", "--out", TestPaths.NewTempDir()));

    [Fact]
    public void Scan_FailBuildBeforePath_TreatsPathAsPositional()
    {
        // "--fail-build <path>": the path is not a severity, so it must not be swallowed as the option's value.
        Assert.Equal(1, Run("scan", "--fail-build", TestPaths.VulnerableApp, "--offline", "--format", "json", "--out", TestPaths.NewTempDir()));
        Assert.Equal(0, Run("scan", "--fail-build", TestPaths.SafeApp, "--offline", "--format", "json", "--out", TestPaths.NewTempDir()));
    }

    [Fact]
    public void Scan_FailBuildEqualsSyntax_Works() =>
        Assert.Equal(1, Run("scan", TestPaths.VulnerableApp, "--offline", "--fail-build=Medium", "--format", "json", "--out", TestPaths.NewTempDir()));

    [Fact]
    public void Scan_FailOnAlias_StillWorks() =>
        Assert.Equal(1, Run("scan", TestPaths.VulnerableApp, "--offline", "--fail-on", "High", "--format", "json", "--out", TestPaths.NewTempDir()));

    [Fact]
    public void Scan_ConfigFailOnHigh_ExitsWith1()
    {
        var project = TestPaths.NewTempDir();
        foreach (var file in Directory.EnumerateFiles(TestPaths.VulnerableApp, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(TestPaths.VulnerableApp, file);
            if (rel.Split(Path.DirectorySeparatorChar).Any(p => p is "bin" or "obj")) continue;
            var dest = Path.Combine(project, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(file, dest);
        }
        File.WriteAllText(Path.Combine(project, ".vaptconfig.json"), """{ "failOn": "High" }""");

        Assert.Equal(1, Run("scan", project, "--offline", "--format", "json", "--out", TestPaths.NewTempDir()));
        // An explicit --fail-on on the command line still overrides the config file.
        Assert.Equal(0, Run("scan", project, "--offline", "--fail-on", "None", "--format", "json", "--out", TestPaths.NewTempDir()));
    }

    [Fact]
    public void Scan_Graph_WritesSelfContainedHtml5AtGivenPath()
    {
        var graph = Path.Combine(TestPaths.NewTempDir(), "nested", "deeper", "security-graph.html");
        Assert.Equal(0, Run("scan", TestPaths.VulnerableApp, "--offline", "--format", "console", "--graph", graph));

        Assert.True(File.Exists(graph));
        var html = File.ReadAllText(graph);
        Assert.StartsWith("<!doctype html>", html.TrimStart(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<svg", html);
        Assert.DoesNotMatch(@"<(script|link)[^>]+(src|href)\s*=\s*[""']https?://", html);
    }

    [Fact]
    public void Scan_GraphToExistingFolder_WritesDefaultFileName()
    {
        var dir = TestPaths.NewTempDir();
        Assert.Equal(0, Run("scan", TestPaths.SafeApp, "--offline", "--format", "console", "--graph", dir));
        Assert.True(File.Exists(Path.Combine(dir, "vapt-graph.html")));
    }

    [Fact]
    public void Scan_FailOnNone_NeverFails()
    {
        Assert.Equal(0, Run("scan", TestPaths.VulnerableApp, "--offline", "--fail-on", "None", "--format", "json", "--out", TestPaths.NewTempDir()));
    }

    [Fact]
    public void UnknownCommand_ExitsWith2() => Assert.Equal(2, Run("frobnicate"));

    [Fact]
    public void MissingPath_ExitsWith2() =>
        Assert.Equal(2, Run("scan", Path.Combine(TestPaths.NewTempDir(), "does-not-exist")));

    [Fact]
    public void Dast_WithoutAuthorizedFlag_Refuses() => Assert.Equal(2, Run("dast", "https://example.com"));
}
