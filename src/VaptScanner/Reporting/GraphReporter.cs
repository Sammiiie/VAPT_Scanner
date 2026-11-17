using System.Globalization;
using System.Text;
using VaptScanner.Core;
using static VaptScanner.Reporting.HtmlReporter;

namespace VaptScanner.Reporting;

/// <summary>
/// Self-contained HTML5 dashboard of a scan: severity mix, findings by source, top categories, hotspot files and rules.
/// Charts are inline SVG and plain HTML/CSS generated here, so the file needs no scripts, fonts or CDN and opens offline
/// or as a CI artifact.
/// </summary>
public static class GraphReporter
{
    private static readonly Severity[] Severities = { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info };
    private static readonly string[] Sources = { "sast", "secrets", "config", "dependencies", "dast" };
    private const int TopN = 10;

    public static string Render(ScanResult r, Severity failOn)
    {
        var counts = r.CountsBySeverity();
        var sb = new StringBuilder();

        sb.Append($$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VAPT Graph Report</title>
<style>
{{ReportTheme.Tokens}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}.sub{color:var(--muted);font-size:13px;word-break:break-all}
h2{font-size:15px;margin:0 0 12px;font-weight:600}
.gate{margin:20px 0;padding:14px 18px;border-radius:10px;font-weight:600;border:1px solid}
.gate.fail{color:var(--high);border-color:var(--high);background:color-mix(in srgb,var(--high) 8%,transparent)}
.gate.pass{color:var(--ok);border-color:var(--ok);background:color-mix(in srgb,var(--ok) 8%,transparent)}
.gate.info{color:var(--med);border-color:var(--med);background:color-mix(in srgb,var(--med) 8%,transparent)}
.tiles{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:10px;margin:18px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;min-width:0;overflow-wrap:anywhere}
.tile b{display:block;font-size:26px;line-height:1.1;color:var(--c,var(--ink))}.tile span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.Critical{--c:var(--crit)}.High{--c:var(--high)}.Medium{--c:var(--med)}.Low{--c:var(--low)}.Info{--c:var(--info)}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.gate{overflow-wrap:anywhere}
.bars{display:grid;gap:8px;font-size:13px}
.row{display:grid;grid-template-columns:minmax(0,38%) minmax(0,1fr) 2.5em;align-items:center;gap:10px}
.lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right}
.bar{height:14px;border-radius:3px;background:color-mix(in srgb,var(--line) 45%,transparent);overflow:hidden}
.fill{display:flex;height:100%;gap:1px}.fill i{background:var(--c);min-width:2px}
.val{color:var(--muted);font-variant-numeric:tabular-nums}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;min-width:0}
section.wide{grid-column:1/-1}
svg{display:block;width:100%;height:auto;overflow:visible}
svg text{fill:var(--ink);font:12px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
svg text.muted{fill:var(--muted)}svg text.big{font-size:28px;font-weight:700}
.track{fill:var(--line)}
.s-Critical{stroke:var(--crit)}.s-High{stroke:var(--high)}.s-Medium{stroke:var(--med)}.s-Low{stroke:var(--low)}.s-Info{stroke:var(--info)}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:10px;font-size:12px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px;background:var(--c)}
.empty{padding:28px;text-align:center;color:var(--muted)}
footer{margin-top:24px;color:var(--muted);font-size:12px}
@media (max-width:760px){.grid{grid-template-columns:minmax(0,1fr)}.tiles{grid-template-columns:repeat(3,minmax(0,1fr))}.row{grid-template-columns:minmax(0,42%) minmax(0,1fr) 2em} }
</style>
</head>
<body><div class="wrap">
<h1>Security scan · graph report</h1>
<div class="sub">{{E(r.Target)}} · {{r.StartedAt:yyyy-MM-dd HH:mm}} · VaptScanner {{E(r.Version)}}</div>
""");

        sb.Append(GateBanner(r, failOn));

        sb.Append("<div class=\"tiles\">");
        sb.Append($"<div class=\"tile\"><b>{r.Findings.Count}</b><span>Findings</span></div>");
        sb.Append($"<div class=\"tile\"><b>{r.FilesScanned}</b><span>Files scanned</span></div>");
        foreach (var s in Severities)
            sb.Append($"<div class=\"tile {s}\"><b>{counts[s]}</b><span>{s}</span></div>");
        sb.Append("</div>");

        if (r.Findings.Count == 0)
        {
            sb.Append("<section><div class=\"empty\">No vulnerabilities found, so there is nothing to chart.</div></section>");
        }
        else
        {
            sb.Append("<div class=\"grid\">");

            sb.Append("<section><h2>Severity mix</h2>").Append(Donut(counts, r.Findings.Count)).Append(Legend()).Append("</section>");

            var bySource = Sources
                .Select(src => (label: src, parts: Severities.Select(s => (s, r.Findings.Count(f => f.Source == src && f.Severity == s))).ToList()))
                .Where(x => x.parts.Sum(p => p.Item2) > 0)
                .ToList();
            sb.Append("<section><h2>Findings by source</h2>").Append(StackedBars(bySource, "Findings by source, split by severity")).Append(Legend()).Append("</section>");

            sb.Append("<section><h2>Top categories</h2>")
              .Append(StackedBars(Top(r.Findings, f => f.Category), "Most frequent finding categories")).Append("</section>");

            sb.Append("<section><h2>Top rules</h2>")
              .Append(StackedBars(Top(r.Findings, f => $"{f.RuleId} · {f.Title}"), "Most frequently triggered rules")).Append("</section>");

            sb.Append("<section class=\"wide\"><h2>Hotspot files and URLs</h2>")
              .Append(StackedBars(Top(r.Findings, f => f.Location), "Files or URLs with the most findings")).Append(Legend()).Append("</section>");

            sb.Append("</div>");
        }

        sb.Append($"<footer>{r.SuppressedCount} suppressed inline · {r.BaselinedCount} hidden by baseline · generated {DateTimeOffset.Now:yyyy-MM-dd HH:mm}</footer>");
        sb.Append("</div></body></html>\n");
        return sb.ToString();
    }

    /// <summary>Top N groups by count, each split into severity segments, largest first.</summary>
    private static List<(string label, List<(Severity, int)> parts)> Top(IEnumerable<Finding> findings, Func<Finding, string> key) =>
        findings.GroupBy(key)
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal)
            .Take(TopN)
            .Select(g => (g.Key, Severities.Select(s => (s, g.Count(f => f.Severity == s))).ToList()))
            .ToList();

    /// <summary>Ring chart: one arc per severity, total in the middle.</summary>
    private static string Donut(Dictionary<Severity, int> counts, int total)
    {
        const double r = 70, c = 2 * Math.PI * r;
        var sb = new StringBuilder();
        var summary = string.Join(", ", Severities.Where(s => counts[s] > 0).Select(s => $"{s} {counts[s]}"));
        sb.Append($"<svg viewBox=\"0 0 200 200\" role=\"img\" aria-label=\"Severity mix: {E(summary)}\" style=\"max-width:240px;margin:0 auto\"><title>Severity mix: {E(summary)}</title>");
        sb.Append($"<circle cx=\"100\" cy=\"100\" r=\"{N(r)}\" fill=\"none\" stroke-width=\"26\" class=\"track\" style=\"stroke:var(--line)\"/>");
        double offset = 0;
        foreach (var s in Severities)
        {
            if (counts[s] == 0) continue;
            var len = c * counts[s] / total;
            // Leave a hairline gap between arcs when there is more than one, so adjacent colours stay distinct.
            var gap = counts[s] == total ? 0 : Math.Min(2, len / 2);
            sb.Append($"<circle cx=\"100\" cy=\"100\" r=\"{N(r)}\" fill=\"none\" stroke-width=\"26\" class=\"s-{s}\" " +
                      $"stroke-dasharray=\"{N(len - gap)} {N(c - len + gap)}\" stroke-dashoffset=\"{N(-offset)}\" transform=\"rotate(-90 100 100)\">" +
                      $"<title>{s}: {counts[s]}</title></circle>");
            offset += len;
        }
        sb.Append($"<text x=\"100\" y=\"104\" text-anchor=\"middle\" class=\"big\">{total}</text>");
        sb.Append("<text x=\"100\" y=\"124\" text-anchor=\"middle\" class=\"muted\">findings</text></svg>");
        return sb.ToString();
    }

    /// <summary>
    /// Horizontal bars, one row per label, each bar split into severity segments, value at the end.
    /// Drawn with HTML/CSS rather than SVG so text keeps its real size at any card width and long labels ellipsize.
    /// </summary>
    private static string StackedBars(List<(string label, List<(Severity, int)> parts)> rows, string description)
    {
        if (rows.Count == 0) return "<div class=\"empty\">No data.</div>";
        int max = rows.Max(x => x.parts.Sum(p => p.Item2));

        var sb = new StringBuilder();
        sb.Append($"<div class=\"bars\" role=\"list\" aria-label=\"{E(description)}\">");
        foreach (var (label, parts) in rows)
        {
            int total = parts.Sum(p => p.Item2);
            var detail = string.Join(", ", parts.Where(p => p.Item2 > 0).Select(p => $"{p.Item1} {p.Item2}"));
            sb.Append($"<div class=\"row\" role=\"listitem\" title=\"{E(label)}: {total} ({E(detail)})\">");
            sb.Append($"<span class=\"lbl\">{E(label)}</span><span class=\"bar\"><span class=\"fill\" style=\"width:{N(100.0 * total / max)}%\">");
            foreach (var (sev, n) in parts)
                if (n > 0) sb.Append($"<i class=\"{sev}\" style=\"flex:{n}\"></i>");
            sb.Append($"</span></span><span class=\"val\">{total}</span></div>");
        }
        sb.Append("</div>");
        return sb.ToString();
    }

    private static string Legend() =>
        "<div class=\"legend\">" + string.Concat(Severities.Select(s => $"<span class=\"{s}\"><i></i>{s}</span>")) + "</div>";

    private static string N(double v) => v.ToString("0.##", CultureInfo.InvariantCulture);
}
