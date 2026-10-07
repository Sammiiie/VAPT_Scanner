using System.Collections.Concurrent;
using System.Text;
using VaptScanner.Analyzers;

namespace VaptScanner.Core;

/// <summary>Coordinates a static scan: walk files, run analyzers in parallel, then filter and de-duplicate.</summary>
public sealed class Scanner
{
    private readonly ScanOptions _options;
    private readonly IFileAnalyzer[] _analyzers = { new CodeAnalyzer(), new SecretsAnalyzer(), new ConfigAnalyzer() };

    public Scanner(ScanOptions options) => _options = options;

    public static IEnumerable<RuleInfo> AllRules() =>
        new IFileAnalyzer[] { new CodeAnalyzer(), new SecretsAnalyzer(), new ConfigAnalyzer() }
            .SelectMany(a => a.Rules)
            .Concat(DependencyAnalyzer.Rules)
            .Concat(Dast.WebScanner.Rules)
            .DistinctBy(r => r.Id)
            .OrderBy(r => r.Id);

    public ScanResult Run(Action<string>? progress = null)
    {
        var result = new ScanResult { Target = Path.GetFullPath(_options.Path), StartedAt = DateTimeOffset.Now };
        var walker = new FileWalker(_options.Path, _options.Exclude);
        var files = walker.Enumerate().ToList();
        progress?.Invoke($"Scanning {files.Count} files…");

        var bag = new ConcurrentBag<Finding>();
        var suppressed = 0;
        var sources = new ConcurrentDictionary<string, SourceText>();

        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, file =>
        {
            string text;
            try { text = ReadText(file); }
            catch { return; }

            var src = new SourceText(file, walker.Relative(file), text);
            sources[src.RelativePath] = src;
            foreach (var analyzer in _analyzers)
            {
                IEnumerable<Finding> found;
                try { found = analyzer.Analyze(src).ToList(); }
                catch (Exception ex)
                {
                    lock (result.Notes) result.Notes.Add($"{analyzer.Source} analyzer failed on {src.RelativePath}: {ex.Message}");
                    continue;
                }
                foreach (var f in found)
                {
                    if (f.Line > 0 && InlineSuppressions.IsSuppressed(src, f.Line, f.RuleId)) { Interlocked.Increment(ref suppressed); continue; }
                    bag.Add(f);
                }
            }
        });
        result.FilesScanned = files.Count;

        if (!_options.SkipDependencyAudit)
        {
            progress?.Invoke(_options.OfflineDependencyAudit ? "Checking NuGet packages (offline list)…" : "Auditing NuGet packages (dotnet restore + list --vulnerable)…");
            foreach (var f in new DependencyAnalyzer().Analyze(_options.Path, _options.OfflineDependencyAudit, n => result.Notes.Add(n)))
                bag.Add(f);
        }

        var findings = bag
            .Where(f => !_options.DisabledRules.Contains(f.RuleId))
            .Select(f =>
            {
                if (_options.SeverityOverrides.TryGetValue(f.RuleId, out var s)) f.Severity = s;
                return f;
            })
            .Where(f => f.Severity >= _options.MinSeverity || f.RuleId == DependencyAnalyzer.AuditUnavailable.Id)
            // One finding per location+category: keeps the most severe when several rules describe the same issue.
            .GroupBy(f => (f.Location, f.Line, f.Category))
            .Select(g => g.OrderByDescending(f => f.Severity).ThenBy(f => f.RuleId).First())
            .OrderByDescending(f => f.Severity).ThenBy(f => f.Location).ThenBy(f => f.Line)
            .ToList();

        var baselinePath = _options.BaselinePath ?? DefaultBaselinePath();
        var baseline = baselinePath is null ? null : Baseline.TryLoad(baselinePath);
        if (baseline is not null)
        {
            var known = baseline.Fingerprints();
            int before = findings.Count;
            findings = findings.Where(f => !known.Contains(f.Fingerprint)).ToList();
            result.BaselinedCount = before - findings.Count;
            result.Notes.Add($"Baseline applied from {Path.GetFileName(baselinePath)}: {result.BaselinedCount} known finding(s) hidden.");
        }

        result.Findings.AddRange(findings);
        result.SuppressedCount = suppressed;
        result.FinishedAt = DateTimeOffset.Now;
        return result;
    }

    private string? DefaultBaselinePath()
    {
        var dir = File.Exists(_options.Path) ? Path.GetDirectoryName(Path.GetFullPath(_options.Path))! : _options.Path;
        var p = Path.Combine(dir, Baseline.DefaultFileName);
        return File.Exists(p) ? p : null;
    }

    private static string ReadText(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext is ".pfx" or ".p12") return "\0"; // binary - only the file's presence matters
        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd().Replace("\r\n", "\n");
    }
}
