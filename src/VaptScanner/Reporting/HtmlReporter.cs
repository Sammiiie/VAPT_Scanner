using System.Net;
using System.Text;
using VaptScanner.Core;

namespace VaptScanner.Reporting;

/// <summary>Single self-contained HTML file (no external assets) suitable for attaching to a release or CI run.</summary>
public static class HtmlReporter
{
    public static string Render(ScanResult r, Severity failOn)
    {
        var counts = r.CountsBySeverity();
        int blocking = r.Findings.Count(f => f.Severity >= failOn);
        bool gateApplies = (int)failOn <= (int)Severity.Critical;
        var sb = new StringBuilder();

        sb.Append($$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VAPT Report</title>
<style>
:root{--bg:#f6f5f2;--card:#fff;--ink:#1d1d1b;--muted:#6b6a66;--line:#e4e2dc;--crit:#8b1e5b;--high:#c0392b;--med:#b7791f;--low:#2b6cb0;--info:#6b6a66;--ok:#2f7d4f;--code:#f1efe9}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1e1e1c;--ink:#ecebe6;--muted:#9a9890;--line:#2f2e2b;--crit:#e06aa6;--high:#ef6b5b;--med:#e0a645;--low:#6aa7e8;--info:#9a9890;--ok:#5cbf86;--code:#262624} }
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}.sub{color:var(--muted);font-size:13px;word-break:break-all}
.gate{margin:20px 0;padding:14px 18px;border-radius:10px;font-weight:600;border:1px solid}
.gate.fail{color:var(--high);border-color:var(--high);background:color-mix(in srgb,var(--high) 8%,transparent)}
.gate.pass{color:var(--ok);border-color:var(--ok);background:color-mix(in srgb,var(--ok) 8%,transparent)}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:18px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer;user-select:none}
.tile b{display:block;font-size:26px;line-height:1.1}.tile span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.tile.off{opacity:.4}
.Critical{--c:var(--crit)}.High{--c:var(--high)}.Medium{--c:var(--med)}.Low{--c:var(--low)}.Info{--c:var(--info)}
.tile b{color:var(--c)}
.tools{display:flex;gap:10px;margin:8px 0 16px;flex-wrap:wrap}
input[type=search]{flex:1;min-width:200px;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit}
select{padding:9px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit}
details{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:8px;margin:8px 0}
summary{padding:12px 14px;cursor:pointer;list-style:none;display:grid;grid-template-columns:82px 1fr;gap:4px 12px}
summary::-webkit-details-marker{display:none}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--c);padding-top:3px}
.title{font-weight:600}.loc{grid-column:2;color:var(--muted);font-size:13px;font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.body{padding:0 14px 14px 108px}
pre{background:var(--code);padding:10px 12px;border-radius:6px;overflow-x:auto;font:13px/1.45 ui-monospace,Consolas,monospace;margin:6px 0 10px;white-space:pre-wrap;word-break:break-word}
.k{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-top:8px}
.tags{font-size:12px;color:var(--muted);margin-top:8px}
.notes{margin-top:28px;color:var(--muted);font-size:13px}
.empty{padding:40px;text-align:center;color:var(--muted)}
@media (max-width:640px){.tiles{grid-template-columns:repeat(3,1fr)}.body{padding:0 14px 14px}summary{grid-template-columns:1fr}.loc{grid-column:1} }
</style>
</head>
<body><div class="wrap">
<h1>Security scan report</h1>
<div class="sub">{{E(r.Target)}} · {{r.StartedAt:yyyy-MM-dd HH:mm}} · {{r.FilesScanned}} files · VaptScanner {{E(r.Version)}}</div>
""");

        if (gateApplies)
            sb.Append(blocking > 0
                ? $"<div class=\"gate fail\">Release gate failed: {blocking} finding(s) at or above {failOn}.</div>"
                : $"<div class=\"gate pass\">Release gate passed: nothing at or above {failOn}.</div>");

        sb.Append("<div class=\"tiles\">");
        foreach (var s in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
            sb.Append($"<div class=\"tile {s}\" data-sev=\"{s}\"><b>{counts[s]}</b><span>{s}</span></div>");
        sb.Append("</div>");

        var categories = r.Findings.Select(f => f.Category).Distinct().OrderBy(c => c);
        sb.Append("<div class=\"tools\"><input type=\"search\" id=\"q\" placeholder=\"Filter by text, file, rule id…\">");
        sb.Append("<select id=\"cat\"><option value=\"\">All categories</option>");
        foreach (var c in categories) sb.Append($"<option>{E(c)}</option>");
        sb.Append("</select></div><div id=\"list\">");

        if (r.Findings.Count == 0) sb.Append("<div class=\"empty\">No findings. Nice.</div>");
        foreach (var f in r.Findings)
        {
            var loc = f.Line > 0 ? $"{f.Location}:{f.Line}" : f.Location;
            sb.Append($"""
<details class="{f.Severity}" data-sev="{f.Severity}" data-cat="{E(f.Category)}">
<summary><span class="sev">{f.Severity}</span><span class="title">{E(f.Title)}</span><span class="loc">{E(loc)} · {f.RuleId}</span></summary>
<div class="body">
{(string.IsNullOrWhiteSpace(f.Snippet) ? "" : $"<pre>{E(f.Snippet)}</pre>")}
<div class="k">Why it matters</div><div>{E(f.Description)}</div>
<div class="k">How to fix</div><div>{E(f.Remediation)}</div>
<div class="tags">{E(string.Join(" · ", new[] { f.Category, f.Cwe, f.Owasp }.Where(x => x is not null)))} · fingerprint {f.Fingerprint}</div>
</div></details>
""");
        }
        sb.Append("</div>");

        if (r.Notes.Count > 0 || r.SuppressedCount > 0 || r.BaselinedCount > 0)
        {
            sb.Append("<div class=\"notes\"><b>Notes</b><ul>");
            if (r.SuppressedCount > 0) sb.Append($"<li>{r.SuppressedCount} finding(s) suppressed with inline vapt-ignore comments.</li>");
            if (r.BaselinedCount > 0) sb.Append($"<li>{r.BaselinedCount} finding(s) hidden by the baseline file.</li>");
            foreach (var n in r.Notes) sb.Append($"<li>{E(n)}</li>");
            sb.Append("</ul></div>");
        }

        sb.Append("""
<script>
(function(){
  var off = {}, q = document.getElementById('q'), cat = document.getElementById('cat');
  function apply(){
    var t = q.value.toLowerCase(), c = cat.value;
    document.querySelectorAll('#list details').forEach(function(d){
      var show = !off[d.dataset.sev] && (!c || d.dataset.cat === c) && (!t || d.textContent.toLowerCase().indexOf(t) >= 0);
      d.style.display = show ? '' : 'none';
    });
  }
  document.querySelectorAll('.tile').forEach(function(tile){
    tile.addEventListener('click', function(){ var s = tile.dataset.sev; off[s] = !off[s]; tile.classList.toggle('off', off[s]); apply(); });
  });
  q.addEventListener('input', apply); cat.addEventListener('change', apply);
})();
</script>
</div></body></html>
""");
        return sb.ToString();
    }

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
}
