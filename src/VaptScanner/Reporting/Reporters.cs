using System.Text.Json;
using System.Text.Json.Nodes;
using VaptScanner.Core;

namespace VaptScanner.Reporting;

public static class ConsoleReporter
{
    public static void Write(ScanResult result, Severity failOn, bool verbose)
    {
        var counts = result.CountsBySeverity();
        Console.WriteLine();
        foreach (var group in result.Findings.GroupBy(f => f.Severity).OrderByDescending(g => g.Key))
        {
            WriteColored($"━━ {group.Key.ToString().ToUpperInvariant()} ({group.Count()}) ", Color(group.Key));
            Console.WriteLine(new string('━', Math.Max(0, 60 - group.Key.ToString().Length)));
            foreach (var f in group)
            {
                WriteColored($"  [{f.RuleId}] ", Color(f.Severity));
                Console.WriteLine(f.Title);
                var loc = f.Line > 0 ? $"{f.Location}:{f.Line}" : f.Location;
                WriteColored($"    {loc}\n", ConsoleColor.DarkGray);
                if (!string.IsNullOrWhiteSpace(f.Snippet)) Console.WriteLine($"    › {f.Snippet}");
                if (verbose)
                {
                    Console.WriteLine($"    Why: {f.Description}");
                    Console.WriteLine($"    Fix: {f.Remediation}");
                    if (f.Cwe is not null) WriteColored($"    {f.Cwe} · {f.Owasp}\n", ConsoleColor.DarkGray);
                }
            }
            Console.WriteLine();
        }

        foreach (var note in result.Notes) WriteColored($"  note: {note}\n", ConsoleColor.DarkGray);

        Console.WriteLine();
        Console.WriteLine("Summary");
        Console.Write("  ");
        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
        {
            WriteColored($"{sev}: {counts[sev]}", counts[sev] > 0 ? Color(sev) : ConsoleColor.DarkGray);
            Console.Write("   ");
        }
        Console.WriteLine();
        var duration = result.FinishedAt - result.StartedAt;
        if (result.FilesScanned > 0)
            Console.WriteLine($"  {result.FilesScanned} files scanned in {duration.TotalSeconds:0.0}s · {result.SuppressedCount} suppressed inline · {result.BaselinedCount} in baseline");
        else
            Console.WriteLine($"  Completed in {duration.TotalSeconds:0.0}s");

        int blocking = result.Findings.Count(f => f.Severity >= failOn);
        Console.WriteLine();
        if (blocking > 0)
            WriteColored($"✗ GATE FAILED: {blocking} finding(s) at or above {failOn}. Fix them or document accepted risk before releasing.\n", ConsoleColor.Red);
        else if ((int)failOn <= (int)Severity.Critical)
            WriteColored($"✓ GATE PASSED: nothing at or above {failOn}.\n", ConsoleColor.Green);
    }

    private static ConsoleColor Color(Severity s) => s switch
    {
        Severity.Critical => ConsoleColor.Magenta,
        Severity.High => ConsoleColor.Red,
        Severity.Medium => ConsoleColor.Yellow,
        Severity.Low => ConsoleColor.Cyan,
        _ => ConsoleColor.Gray
    };

    private static void WriteColored(string text, ConsoleColor color)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = previous;
    }
}

public static class JsonReporter
{
    public static string Render(ScanResult result) => JsonSerializer.Serialize(new
    {
        result.Tool,
        result.Version,
        result.Target,
        result.StartedAt,
        result.FinishedAt,
        result.FilesScanned,
        result.SuppressedCount,
        result.BaselinedCount,
        Summary = result.CountsBySeverity().ToDictionary(k => k.Key.ToString(), v => v.Value),
        Findings = result.Findings.Select(f => new
        {
            f.RuleId, f.Title, f.Severity, f.Category, f.Location, f.Line, f.Column, f.Snippet,
            f.Description, f.Remediation, f.Cwe, f.Owasp, f.Source, f.Fingerprint
        }),
        result.Notes
    }, JsonOpts.Write);
}

/// <summary>SARIF 2.1.0 - understood by GitHub code scanning, Azure DevOps (SARIF SAST Scans Tab) and VS SARIF Viewer.</summary>
public static class SarifReporter
{
    public static string Render(ScanResult result)
    {
        var rules = result.Findings.GroupBy(f => f.RuleId).Select(g => g.First()).ToList();
        var ruleIndex = rules.Select((r, i) => (r.RuleId, i)).ToDictionary(x => x.RuleId, x => x.i);

        var sarif = new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray
            {
                new JsonObject
                {
                    ["tool"] = new JsonObject
                    {
                        ["driver"] = new JsonObject
                        {
                            ["name"] = "VaptScanner",
                            ["version"] = result.Version,
                            ["informationUri"] = "https://owasp.org/Top10/",
                            ["rules"] = new JsonArray(rules.Select(r => (JsonNode)new JsonObject
                            {
                                ["id"] = r.RuleId,
                                ["name"] = ToPascal(r.Title),
                                ["shortDescription"] = new JsonObject { ["text"] = r.Title },
                                ["fullDescription"] = new JsonObject { ["text"] = r.Description },
                                ["help"] = new JsonObject { ["text"] = r.Remediation, ["markdown"] = $"**Fix:** {r.Remediation}" },
                                ["defaultConfiguration"] = new JsonObject { ["level"] = r.Severity.SarifLevel() },
                                ["properties"] = new JsonObject
                                {
                                    ["security-severity"] = r.Severity.SecuritySeverityScore(),
                                    ["tags"] = new JsonArray(new[] { "security", r.Category, r.Cwe, r.Owasp }
                                        .Where(t => t is not null).Select(t => (JsonNode)JsonValue.Create(t)!).ToArray())
                                }
                            }).ToArray())
                        }
                    },
                    ["results"] = new JsonArray(result.Findings.Select(f => (JsonNode)new JsonObject
                    {
                        ["ruleId"] = f.RuleId,
                        ["ruleIndex"] = ruleIndex[f.RuleId],
                        ["level"] = f.Severity.SarifLevel(),
                        ["message"] = new JsonObject { ["text"] = $"{f.Title}. {f.Description}" },
                        ["locations"] = new JsonArray(Location(f)),
                        ["partialFingerprints"] = new JsonObject { ["vaptFingerprint/v1"] = f.Fingerprint },
                        ["properties"] = new JsonObject { ["severity"] = f.Severity.ToString(), ["source"] = f.Source }
                    }).ToArray())
                }
            }
        };
        return sarif.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    private static JsonNode Location(Finding f)
    {
        var region = new JsonObject { ["startLine"] = Math.Max(1, f.Line) };
        if (f.Column > 0) region["startColumn"] = f.Column;
        if (!string.IsNullOrEmpty(f.Snippet)) region["snippet"] = new JsonObject { ["text"] = f.Snippet };
        bool isUrl = f.Location.StartsWith("http", StringComparison.OrdinalIgnoreCase);
        return new JsonObject
        {
            ["physicalLocation"] = new JsonObject
            {
                ["artifactLocation"] = new JsonObject { ["uri"] = isUrl ? f.Location : f.Location == "." ? "." : f.Location.Replace(" ", "%20") },
                ["region"] = region
            }
        };
    }

    private static string ToPascal(string s) =>
        string.Concat(s.Split(' ', '/', '-', '(', ')', '.', ',').Where(w => w.Length > 0).Select(w => char.ToUpperInvariant(w[0]) + w[1..]));
}
