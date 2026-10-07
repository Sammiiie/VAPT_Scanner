using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using VaptScanner.Core;

namespace VaptScanner.Analyzers;

/// <summary>
/// Software composition analysis for NuGet packages.
/// Primary source: `dotnet list package --vulnerable --include-transitive` (GitHub Advisory Database via nuget.org).
/// Fallback: a small built-in advisory snapshot used when the SDK/network isn't available.
/// </summary>
public sealed class DependencyAnalyzer
{
    public static readonly RuleInfo VulnerablePackage = new("VAPT-DEP-001", "Vulnerable NuGet package", Severity.High,
        "Vulnerable Dependency",
        "A referenced package version has a published security advisory.",
        "Upgrade to a patched version (see the advisory). For transitive packages, add a direct PackageReference to the patched version or upgrade the parent package.",
        "CWE-1395", "A06:2021 Vulnerable and Outdated Components");

    public static readonly RuleInfo AuditUnavailable = new("VAPT-DEP-000", "Online dependency audit could not run", Severity.Info,
        "Vulnerable Dependency",
        "The NuGet vulnerability audit needs the .NET SDK and access to nuget.org. Only the built-in offline advisory list was checked.",
        "Run the scan where `dotnet restore` works (e.g. in CI), or run `dotnet list package --vulnerable --include-transitive` manually.",
        null, "A06:2021 Vulnerable and Outdated Components");

    public static IEnumerable<RuleInfo> Rules => new[] { VulnerablePackage, AuditUnavailable };

    private sealed record PackageRef(string Id, string Version, string File, int Line);

    private sealed record Advisory(string Package, string[] Ranges, Severity Severity, string Id, string Summary);

    // Ranges are "[min,max)" with min inclusive and max exclusive. Offline snapshot; the online audit is authoritative.
    private static readonly Advisory[] OfflineAdvisories =
    {
        new("Newtonsoft.Json", new[] { "[0,13.0.1)" }, Severity.High, "GHSA-5crp-9r3c-p9vr", "Deeply nested JSON can cause stack overflow / DoS."),
        new("System.Text.Encodings.Web", new[] { "[4.0.0,4.5.1)", "[4.6.0,4.7.2)", "[5.0.0,5.0.1)" }, Severity.Critical, "CVE-2021-26701", "Remote code execution."),
        new("System.Net.Http", new[] { "[4.0.0,4.3.4)" }, Severity.High, "CVE-2018-8292", "Information disclosure (credentials sent on redirect)."),
        new("Microsoft.Data.SqlClient", new[] { "[0,2.1.7)", "[3.0.0,3.1.5)", "[4.0.0,4.0.5)", "[5.0.0,5.1.3)" }, Severity.High, "CVE-2024-0056", "Security feature bypass allowing TLS man-in-the-middle."),
        new("System.Data.SqlClient", new[] { "[0,4.8.6)" }, Severity.High, "CVE-2024-0056", "Security feature bypass allowing TLS man-in-the-middle."),
        new("log4net", new[] { "[0,2.0.10)" }, Severity.Critical, "CVE-2018-1285", "XML external entity (XXE) injection."),
        new("SharpZipLib", new[] { "[0,1.3.3)" }, Severity.High, "CVE-2021-32840", "Zip Slip directory traversal."),
        new("System.Drawing.Common", new[] { "[0,4.7.2)", "[5.0.0,5.0.3)" }, Severity.Critical, "CVE-2021-24112", "Remote code execution."),
        new("System.IdentityModel.Tokens.Jwt", new[] { "[5.0.0,5.7.0)", "[6.0.0,6.34.0)", "[7.0.0,7.1.2)" }, Severity.Medium, "CVE-2024-21319", "Denial of service via crafted JWE."),
        new("Microsoft.IdentityModel.JsonWebTokens", new[] { "[5.0.0,5.7.0)", "[6.0.0,6.34.0)", "[7.0.0,7.1.2)" }, Severity.Medium, "CVE-2024-21319", "Denial of service via crafted JWE."),
        new("Npgsql", new[] { "[0,4.0.14)", "[4.1.0,4.1.13)", "[5.0.0,5.0.18)", "[6.0.0,6.0.11)", "[7.0.0,7.0.7)", "[8.0.0,8.0.3)" }, Severity.High, "CVE-2024-32655", "SQL injection via protocol message size overflow."),
        new("DotNetZip", new[] { "[0,9999)" }, Severity.High, "CVE-2024-48510", "Directory traversal; package is unmaintained - migrate to System.IO.Compression."),
        new("YamlDotNet", new[] { "[0,5.0.0)" }, Severity.Critical, "CVE-2018-1000210", "Arbitrary type instantiation during deserialization."),
        new("RestSharp", new[] { "[0,106.11.7)" }, Severity.High, "CVE-2021-27293", "Regular expression denial of service (ReDoS)."),
    };

    public List<Finding> Analyze(string root, bool offlineOnly, Action<string> note)
    {
        var findings = new List<Finding>();
        var baseDir = File.Exists(root) ? Path.GetDirectoryName(Path.GetFullPath(root))! : Path.GetFullPath(root);
        var refs = CollectPackageReferences(baseDir);

        bool onlineOk = false;
        if (!offlineOnly)
        {
            onlineOk = RunDotnetAudit(baseDir, refs, findings, note);
        }

        if (!onlineOk)
        {
            if (!offlineOnly && refs.Count > 0)
                findings.Add(Finding.From(AuditUnavailable, ".", 0, 0, "", "dependencies"));
            findings.AddRange(OfflineCheck(refs));
        }
        return findings;
    }

    private static List<PackageRef> CollectPackageReferences(string baseDir)
    {
        var refs = new List<PackageRef>();
        var walker = new FileWalker(baseDir, Array.Empty<string>());
        foreach (var file in walker.Enumerate())
        {
            var name = Path.GetFileName(file);
            bool isProject = file.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase);
            bool isProps = name.Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase) || name.Equals("Directory.Build.props", StringComparison.OrdinalIgnoreCase);
            bool isPackagesConfig = name.Equals("packages.config", StringComparison.OrdinalIgnoreCase);
            if (!isProject && !isProps && !isPackagesConfig) continue;

            var text = File.ReadAllText(file);
            var src = new SourceText(file, walker.Relative(file), text);
            var patterns = new[]
            {
                @"<Package(?:Reference|Version)\s+(?:Include|Update)\s*=\s*""(?<id>[^""]+)""[^>]*?\bVersion\s*=\s*""(?<v>[^""]+)""",
                @"<Package(?:Reference|Version)\s+(?:Include|Update)\s*=\s*""(?<id>[^""]+)""[^>]*?>\s*<Version>(?<v>[^<]+)</Version>",
                @"<package\s+id\s*=\s*""(?<id>[^""]+)""[^>]*?\bversion\s*=\s*""(?<v>[^""]+)""",
            };
            foreach (var p in patterns)
                foreach (Match m in Regex.Matches(src.NoComments, p, RegexOptions.IgnoreCase))
                    refs.Add(new PackageRef(m.Groups["id"].Value, m.Groups["v"].Value, src.RelativePath, src.Position(m.Index).line));
        }
        return refs;
    }

    private static bool RunDotnetAudit(string baseDir, List<PackageRef> refs, List<Finding> findings, Action<string> note)
    {
        // Prefer solution files; fall back to individual projects.
        var targets = Directory.EnumerateFiles(baseDir, "*.sln", SearchOption.TopDirectoryOnly)
            .Concat(Directory.EnumerateFiles(baseDir, "*.slnx", SearchOption.TopDirectoryOnly)).ToList();
        if (targets.Count == 0)
            targets = new FileWalker(baseDir, Array.Empty<string>()).Enumerate()
                .Where(f => f.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)).ToList();
        if (targets.Count == 0) return true; // nothing to audit

        int ran = 0;
        var seen = new HashSet<string>();
        foreach (var target in targets)
        {
            var restore = Run("dotnet", $"restore \"{target}\" --verbosity quiet", baseDir, TimeSpan.FromMinutes(5));
            if (restore.exit != 0)
            {
                note($"Dependency audit: restore failed for {Path.GetFileName(target)} ({FirstLine(restore.output)})");
                continue;
            }
            var list = Run("dotnet", $"list \"{target}\" package --vulnerable --include-transitive --format json", baseDir, TimeSpan.FromMinutes(5));
            if (list.exit != 0 || !list.output.TrimStart().StartsWith("{"))
            {
                note($"Dependency audit: 'dotnet list package' failed for {Path.GetFileName(target)} ({FirstLine(list.output)})");
                continue;
            }
            ran++;
            ParseAuditJson(list.output, baseDir, refs, findings, seen);
        }
        if (ran > 0) note($"Dependency audit: checked {ran} solution/project file(s) against the NuGet advisory database.");
        return ran > 0;
    }

    private static void ParseAuditJson(string json, string baseDir, List<PackageRef> refs, List<Finding> findings, HashSet<string> seen)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("projects", out var projects)) return;
        foreach (var project in projects.EnumerateArray())
        {
            var projectPath = project.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
            var relProject = projectPath.Length > 0 ? Path.GetRelativePath(baseDir, projectPath).Replace('\\', '/') : ".";
            if (!project.TryGetProperty("frameworks", out var frameworks)) continue;
            foreach (var fw in frameworks.EnumerateArray())
            {
                foreach (var (prop, transitive) in new[] { ("topLevelPackages", false), ("transitivePackages", true) })
                {
                    if (!fw.TryGetProperty(prop, out var packages)) continue;
                    foreach (var pkg in packages.EnumerateArray())
                    {
                        var id = pkg.GetProperty("id").GetString() ?? "?";
                        var version = pkg.TryGetProperty("resolvedVersion", out var rv) ? rv.GetString() ?? "?" : "?";
                        if (!pkg.TryGetProperty("vulnerabilities", out var vulns)) continue;
                        foreach (var v in vulns.EnumerateArray())
                        {
                            var sevText = v.TryGetProperty("severity", out var s) ? s.GetString() ?? "High" : "High";
                            var url = v.TryGetProperty("advisoryurl", out var u) ? u.GetString() ?? "" : "";
                            var sev = sevText.ToLowerInvariant() switch
                            {
                                "critical" => Severity.Critical, "high" => Severity.High,
                                "moderate" or "medium" => Severity.Medium, "low" => Severity.Low, _ => Severity.High
                            };
                            var key = $"{relProject}|{id}|{version}|{url}";
                            if (!seen.Add(key)) continue;

                            var directRef = refs.FirstOrDefault(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase) && r.File == relProject);
                            var detail = $"{id} {version} ({(transitive ? "transitive" : "direct")}) - {sevText} advisory: {url}";
                            findings.Add(Finding.From(VulnerablePackage, relProject, directRef?.Line ?? 0, 0,
                                $"{id} {version}", "dependencies", sev, detail));
                        }
                    }
                }
            }
        }
    }

    private static IEnumerable<Finding> OfflineCheck(List<PackageRef> refs)
    {
        foreach (var r in refs)
        {
            var version = ParseVersion(r.Version);
            if (version is null) continue;
            foreach (var adv in OfflineAdvisories.Where(a => a.Package.Equals(r.Id, StringComparison.OrdinalIgnoreCase)))
            {
                if (!adv.Ranges.Any(range => InRange(version, range))) continue;
                yield return Finding.From(VulnerablePackage, r.File, r.Line, 1, $"{r.Id} {r.Version}", "dependencies", adv.Severity,
                    $"{r.Id} {r.Version} - {adv.Id}: {adv.Summary} (offline advisory snapshot)");
            }
        }
    }

    private static Version? ParseVersion(string v)
    {
        var m = Regex.Match(v, @"\d+(?:\.\d+){0,3}");
        if (!m.Success) return null;
        var parts = m.Value.Split('.').ToList();
        while (parts.Count < 3) parts.Add("0");
        return Version.TryParse(string.Join('.', parts), out var ver) ? ver : null;
    }

    private static bool InRange(Version v, string range)
    {
        var m = Regex.Match(range, @"^\[(?<min>[^,]*),(?<max>[^)]*)\)$");
        if (!m.Success) return false;
        var min = ParseVersion(m.Groups["min"].Value) ?? new Version(0, 0, 0);
        var max = ParseVersion(m.Groups["max"].Value) ?? new Version(int.MaxValue, 0, 0);
        return v >= min && v < max;
    }

    private static string FirstLine(string s) =>
        s.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0 && (l.Contains("error", StringComparison.OrdinalIgnoreCase) || l.Contains("fail", StringComparison.OrdinalIgnoreCase)))
        ?? s.Split('\n').FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "no output";

    private static (int exit, string output) Run(string file, string args, string cwd, TimeSpan timeout)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                WorkingDirectory = cwd,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
            psi.Environment["DOTNET_NOLOGO"] = "1";
            using var proc = Process.Start(psi)!;
            var stdout = proc.StandardOutput.ReadToEndAsync();
            var stderr = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit((int)timeout.TotalMilliseconds))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return (-1, "timed out");
            }
            return (proc.ExitCode, stdout.Result + stderr.Result);
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }
}
