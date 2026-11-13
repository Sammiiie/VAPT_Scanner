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
    public void Scan_VulnerableApp_ExitsWith1_AndWritesJsonAndSarif()
    {
        var outDir = TestPaths.NewTempDir();
        var code = Run("scan", TestPaths.VulnerableApp, "--offline", "--format", "json,sarif", "--out", outDir);

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
