using System.Text;
using System.Text.Json;
using VaptScanner.Core;
using VaptScanner.Dast;
using VaptScanner.Reporting;

namespace VaptScanner;

public static class Program
{
    private const int ExitOk = 0, ExitGateFailed = 1, ExitError = 2;

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        try
        {
            if (args.Length == 0 || args[0] is "-h" or "--help" or "help") { PrintHelp(); return ExitOk; }
            if (args[0] is "--version" or "version") { Console.WriteLine(typeof(Program).Assembly.GetName().Version?.ToString(3)); return ExitOk; }

            var cmd = args[0].ToLowerInvariant();
            var a = new Args(args.Skip(1).ToArray());
            return cmd switch
            {
                "scan" => RunScan(a),
                "dast" => await RunDast(a),
                "baseline" => RunBaseline(a),
                "rules" => ListRules(a),
                "init" => Init(a),
                _ => Fail($"Unknown command '{args[0]}'. Run 'vapt --help'.")
            };
        }
        catch (ArgumentException ex) { return Fail(ex.Message); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unexpected error: {ex}");
            return ExitError;
        }
    }

    // ─────────────────────────────── scan ───────────────────────────────

    private static int RunScan(Args a)
    {
        var path = a.Positional.FirstOrDefault() ?? ".";
        if (!Directory.Exists(path) && !File.Exists(path)) return Fail($"Path not found: {path}");

        var notes = new List<string>();
        var cfg = VaptConfig.Load(Path.GetFullPath(path), notes.Add);
        var opt = new ScanOptions { Path = Path.GetFullPath(path) };
        opt.Exclude.AddRange(cfg.Exclude);
        opt.Exclude.AddRange(a.All("--exclude"));
        foreach (var r in cfg.DisabledRules.Concat(a.All("--disable"))) opt.DisabledRules.Add(r);
        foreach (var (k, v) in cfg.SeverityOverrides) opt.SeverityOverrides[k] = v;
        opt.FailOn = ParseSeverity(a.Value("--fail-on") ?? cfg.FailOn, Severity.High);
        opt.MinSeverity = ParseSeverity(a.Value("--min-severity") ?? cfg.MinSeverity, Severity.Low);
        opt.SkipDependencyAudit = a.Flag("--no-deps") || cfg.SkipDependencyAudit;
        opt.OfflineDependencyAudit = a.Flag("--offline");
        opt.BaselinePath = a.Value("--baseline");

        var formats = Formats(a);
        Banner($"Static scan · {opt.Path}");
        var result = new Scanner(opt).Run(p => Status(p));
        result.Notes.InsertRange(0, notes);

        return Output(result, formats, a.Value("--out") ?? "vapt-reports", "vapt-report", opt.FailOn, a.Flag("--verbose") || a.Flag("-v"));
    }

    // ─────────────────────────────── dast ───────────────────────────────

    private static async Task<int> RunDast(Args a)
    {
        var url = a.Positional.FirstOrDefault() ?? a.Value("--url");
        if (url is null || !Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https"))
            return Fail("Usage: vapt dast <https://staging.example.com> --authorized");

        if (!a.Flag("--authorized"))
        {
            Console.Error.WriteLine("""
The DAST module sends live requests to the target. Only scan systems you own or have
written permission to test (ideally staging/UAT, not production).

Re-run with --authorized to confirm you are authorised to test this target.
""");
            return ExitError;
        }

        var opt = new DastOptions { Target = uri };
        foreach (var h in a.All("--header"))
        {
            var idx = h.IndexOf(':');
            if (idx <= 0) return Fail($"Invalid --header '{h}'. Use \"Name: value\".");
            opt.Headers[h[..idx].Trim()] = h[(idx + 1)..].Trim();
        }
        if (int.TryParse(a.Value("--max-requests"), out var max)) opt.MaxRequests = max;
        if (int.TryParse(a.Value("--delay"), out var delay)) opt.DelayMs = Math.Max(0, delay);
        if (int.TryParse(a.Value("--timeout"), out var timeout)) opt.Timeout = TimeSpan.FromSeconds(timeout);
        opt.ExtraPaths.AddRange(a.All("--path"));

        var failOn = ParseSeverity(a.Value("--fail-on"), Severity.High);
        var minSev = ParseSeverity(a.Value("--min-severity"), Severity.Low);
        Banner($"Dynamic baseline scan · {uri}");

        using var scanner = new WebScanner(opt);
        var result = await scanner.RunAsync(p => Status(p));
        result.Findings.RemoveAll(f => f.Severity < minSev);
        return Output(result, Formats(a), a.Value("--out") ?? "vapt-reports", "vapt-dast-report", failOn, a.Flag("--verbose") || a.Flag("-v"));
    }

    // ─────────────────────────────── baseline / rules / init ───────────────────────────────

    private static int RunBaseline(Args a)
    {
        var path = Path.GetFullPath(a.Positional.FirstOrDefault() ?? ".");
        var cfg = VaptConfig.Load(path, _ => { });
        var opt = new ScanOptions { Path = path, MinSeverity = Severity.Info, BaselinePath = Path.Combine(Path.GetTempPath(), "vapt-no-baseline-" + Guid.NewGuid()) };
        opt.Exclude.AddRange(cfg.Exclude);
        opt.Exclude.AddRange(a.All("--exclude"));
        opt.SkipDependencyAudit = a.Flag("--no-deps") || cfg.SkipDependencyAudit;
        opt.OfflineDependencyAudit = a.Flag("--offline");

        Banner($"Creating baseline · {path}");
        var result = new Scanner(opt).Run(p => Status(p));
        var dir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;
        var outFile = a.Value("--out") ?? Path.Combine(dir, Baseline.DefaultFileName);
        Baseline.FromFindings(result.Findings.Where(f => f.Line > 0 || f.Source == "dependencies")).Save(outFile);
        Console.WriteLine($"Wrote {result.Findings.Count} finding fingerprint(s) to {outFile}");
        Console.WriteLine("Commit it, then future scans only report NEW findings. Review the file and add justifications.");
        return ExitOk;
    }

    private static int ListRules(Args a)
    {
        var rules = Scanner.AllRules().ToList();
        if (a.Value("--format") == "md")
        {
            Console.WriteLine("| Rule | Severity | Title | CWE | OWASP |\n|---|---|---|---|---|");
            foreach (var r in rules) Console.WriteLine($"| {r.Id} | {r.Severity} | {r.Title} | {r.Cwe} | {r.Owasp} |");
        }
        else
        {
            foreach (var r in rules) Console.WriteLine($"{r.Id,-17} {r.Severity,-9} {r.Title}");
            Console.WriteLine($"\n{rules.Count} rules.");
        }
        return ExitOk;
    }

    private static int Init(Args a)
    {
        var dir = Path.GetFullPath(a.Positional.FirstOrDefault() ?? ".");
        var file = Path.Combine(dir, ".vaptconfig.json");
        if (File.Exists(file) && !a.Flag("--force")) return Fail($"{file} already exists (use --force to overwrite).");
        File.WriteAllText(file, """
{
  // Globs to skip (relative to this folder). bin/obj/node_modules/.git are always skipped.
  "exclude": [
    "**/Migrations/**",
    "**/wwwroot/lib/**",
    "**/*.Designer.cs"
  ],
  // Rule IDs to turn off entirely (see: vapt rules)
  "disabledRules": [],
  // Change the severity of specific rules for this codebase
  "severityOverrides": {
    // "VAPT-WEB-022": "Low"
  },
  // Pipeline fails when a finding is at or above this severity: Critical | High | Medium | Low | None
  "failOn": "High",
  // Findings below this severity are not reported
  "minSeverity": "Low",
  "skipDependencyAudit": false
}
""");
        Console.WriteLine($"Created {file}");
        return ExitOk;
    }

    // ─────────────────────────────── output ───────────────────────────────

    private static int Output(ScanResult result, HashSet<string> formats, string outDir, string baseName, Severity failOn, bool verbose)
    {
        if (formats.Contains("console")) ConsoleReporter.Write(result, failOn, verbose);

        var written = new List<string>();
        if (formats.Overlaps(new[] { "html", "json", "sarif" })) Directory.CreateDirectory(outDir);
        if (formats.Contains("html")) written.Add(WriteFile(outDir, $"{baseName}.html", HtmlReporter.Render(result, failOn)));
        if (formats.Contains("json")) written.Add(WriteFile(outDir, $"{baseName}.json", JsonReporter.Render(result)));
        if (formats.Contains("sarif")) written.Add(WriteFile(outDir, $"{baseName}.sarif", SarifReporter.Render(result)));
        foreach (var w in written) Console.WriteLine($"  report: {w}");

        return result.Findings.Any(f => f.Severity >= failOn) ? ExitGateFailed : ExitOk;
    }

    private static string WriteFile(string dir, string name, string content)
    {
        var path = Path.GetFullPath(Path.Combine(dir, name));
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    private static HashSet<string> Formats(Args a)
    {
        var raw = a.All("--format").SelectMany(f => f.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList();
        if (raw.Count == 0) raw.AddRange(new[] { "console", "html" });
        if (raw.Contains("all")) raw.AddRange(new[] { "console", "html", "json", "sarif" });
        var set = raw.Select(f => f.ToLowerInvariant()).ToHashSet();
        var unknown = set.Except(new[] { "console", "html", "json", "sarif", "all" }).ToList();
        if (unknown.Count > 0) throw new ArgumentException($"Unknown format(s): {string.Join(", ", unknown)}. Use console, html, json, sarif or all.");
        return set;
    }

    private static Severity ParseSeverity(string? value, Severity fallback)
    {
        if (value is null) return fallback;
        if (SeverityExtensions.TryParse(value, out var s)) return s;
        throw new ArgumentException($"Unknown severity '{value}'. Use Critical, High, Medium, Low, Info or None.");
    }

    private static void Banner(string text)
    {
        Console.WriteLine();
        Console.WriteLine($"VaptScanner · {text}");
    }

    private static void Status(string text)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  … {text}");
        Console.ForegroundColor = prev;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return ExitError;
    }

    private static void PrintHelp() => Console.WriteLine("""
VaptScanner - catch security issues in .NET apps before they reach production.

USAGE
  vapt scan [path]            Static scan: code (SAST), secrets, config, NuGet vulnerabilities
  vapt dast <url> --authorized
                              Safe baseline scan of a running deployment you own (staging/UAT)
  vapt baseline [path]        Record current findings so CI only fails on NEW ones
  vapt init [path]            Create a .vaptconfig.json with sensible defaults
  vapt rules [--format md]    List all rules

COMMON OPTIONS
  --format <list>             console, html, json, sarif or all   (default: console,html)
  --out <dir>                 Report folder                        (default: ./vapt-reports)
  --fail-on <severity>        Exit code 1 if any finding >= this   (default: High; 'None' to never fail)
  --min-severity <severity>   Hide findings below this             (default: Low)
  -v, --verbose               Show explanation and fix for every finding in the console

SCAN OPTIONS
  --exclude <glob>            Skip paths, e.g. --exclude "**/Migrations/**" (repeatable)
  --disable <RULE-ID>         Turn a rule off (repeatable)
  --baseline <file>           Baseline file (default: .vapt-baseline.json in the scan root, if present)
  --no-deps                   Skip the NuGet vulnerability audit
  --offline                   Use the built-in advisory list instead of 'dotnet list package --vulnerable'

DAST OPTIONS
  --authorized                Required. Confirms you own / are permitted to test the target
  --header "Name: value"      Extra header, e.g. an auth token for a test account (repeatable)
  --path </x>                 Extra path that must NOT be public (repeatable)
  --max-requests <n>          Request budget (default 120)    --delay <ms>  Delay between requests (default 100)

SUPPRESSING A FINDING
  Add a comment on the line or the line above:   // vapt-ignore VAPT-SQL-005: table name is from an enum

EXIT CODES
  0 = passed   1 = findings at/above --fail-on   2 = usage or runtime error
""");
}

/// <summary>Minimal argument parser: positional values, --flag, --key value, --key=value (repeatable).</summary>
internal sealed class Args
{
    private static readonly HashSet<string> Flags = new(StringComparer.OrdinalIgnoreCase)
    { "--no-deps", "--offline", "--verbose", "-v", "--authorized", "--force" };

    private readonly List<(string key, string? value)> _named = new();
    public List<string> Positional { get; } = new();

    public Args(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("-"))
            {
                var eq = arg.IndexOf('=');
                if (eq > 0) { _named.Add((arg[..eq], arg[(eq + 1)..])); continue; }
                if (Flags.Contains(arg)) { _named.Add((arg, null)); continue; }
                if (i + 1 >= args.Length) throw new ArgumentException($"Missing value for {arg}");
                _named.Add((arg, args[++i]));
            }
            else Positional.Add(arg);
        }
    }

    public bool Flag(string name) => _named.Any(n => n.key.Equals(name, StringComparison.OrdinalIgnoreCase));
    public string? Value(string name) => _named.LastOrDefault(n => n.key.Equals(name, StringComparison.OrdinalIgnoreCase)).value;
    public IEnumerable<string> All(string name) => _named.Where(n => n.key.Equals(name, StringComparison.OrdinalIgnoreCase) && n.value is not null).Select(n => n.value!);
}
