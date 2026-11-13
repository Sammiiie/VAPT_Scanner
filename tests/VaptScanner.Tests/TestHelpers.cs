using VaptScanner.Analyzers;

namespace VaptScanner.Tests;

internal static class TestPaths
{
    private static readonly Lazy<string> Root = new(() =>
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "VaptScanner.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Could not find the repository root (VaptScanner.sln).");
    });

    public static string RepoRoot => Root.Value;
    public static string VulnerableApp => Path.Combine(RepoRoot, "samples", "VulnerableApp");
    public static string SafeApp => Path.Combine(RepoRoot, "samples", "SafeApp");

    /// <summary>A fresh, empty directory under the system temp folder.</summary>
    public static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "vapt-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}

internal static class Scan
{
    /// <summary>
    /// Deterministic scan: offline NuGet advisory list (no network), every severity,
    /// and a baseline path that does not exist so a stray baseline file can never hide findings.
    /// </summary>
    public static ScanResult Folder(string path, Action<ScanOptions>? configure = null)
    {
        var options = new ScanOptions
        {
            Path = path,
            MinSeverity = Severity.Info,
            OfflineDependencyAudit = true,
            BaselinePath = Path.Combine(Path.GetTempPath(), "vapt-no-baseline-" + Guid.NewGuid().ToString("N")),
        };
        configure?.Invoke(options);
        return new Scanner(options).Run();
    }

    private static readonly IFileAnalyzer[] Analyzers = { new CodeAnalyzer(), new SecretsAnalyzer(), new ConfigAnalyzer() };

    /// <summary>Runs every file analyzer over an in-memory file and returns the findings.</summary>
    public static List<Finding> Text(string fileName, string content)
    {
        var src = new SourceText(Path.Combine("C:\\fake", fileName), fileName, content.Replace("\r\n", "\n"));
        return Analyzers.SelectMany(a => a.Analyze(src)).ToList();
    }

    public static HashSet<string> RuleIds(string fileName, string content) =>
        Text(fileName, content).Select(f => f.RuleId).ToHashSet();
}
