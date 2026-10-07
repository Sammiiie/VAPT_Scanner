using System.Text.RegularExpressions;
using VaptScanner.Core;

namespace VaptScanner.Analyzers;

public interface IFileAnalyzer
{
    string Source { get; }
    IEnumerable<RuleInfo> Rules { get; }
    IEnumerable<Finding> Analyze(SourceText src);
}

/// <summary>Runs the C#/Razor/JS pattern rules plus a few whole-file checks.</summary>
public sealed class CodeAnalyzer : IFileAnalyzer
{
    public string Source => "sast";

    private static readonly RuleInfo MissingHttps = new("VAPT-WEB-020", "HTTPS redirection not configured", Severity.Low,
        "Security Misconfiguration",
        "The app's startup pipeline doesn't call UseHttpsRedirection(), so plain-HTTP requests are served as-is (unless a proxy/gateway enforces HTTPS).",
        "Add app.UseHttpsRedirection(), or confirm HTTPS is enforced at the load balancer / reverse proxy.", "CWE-319", "A05:2021 Security Misconfiguration");

    private static readonly RuleInfo MissingHsts = new("VAPT-WEB-021", "HSTS not enabled", Severity.Low,
        "Security Headers",
        "Without Strict-Transport-Security, browsers may be downgraded to HTTP on first visit (SSL stripping).",
        "Add if (!app.Environment.IsDevelopment()) app.UseHsts(); or set the header at the proxy.", "CWE-523", "A05:2021 Security Misconfiguration");

    private static readonly RuleInfo NoRateLimit = new("VAPT-WEB-022", "No rate limiting configured", Severity.Info,
        "Resource Exhaustion",
        "No rate limiter was found in the startup pipeline; login and API endpoints are open to brute force and abuse.",
        "Use builder.Services.AddRateLimiter(...) + app.UseRateLimiter() (built into .NET 7+), or enforce limits at the gateway.", "CWE-770", "A04:2021 Insecure Design");

    public IEnumerable<RuleInfo> Rules => CodeRules.All.Select(r => r.Info).Append(MissingHttps).Append(MissingHsts).Append(NoRateLimit);

    public IEnumerable<Finding> Analyze(SourceText src)
    {
        foreach (var rule in CodeRules.All)
        {
            if (!rule.AppliesTo(src)) continue;
            foreach (var f in rule.Run(src, Source)) yield return f;
        }

        if (src.Extension == ".cs") foreach (var f in StartupChecks(src)) yield return f;
    }

    private IEnumerable<Finding> StartupChecks(SourceText src)
    {
        var text = src.NoComments;
        var anchor = Regex.Match(text, @"\b(?:builder|\w+)\.Build\s*\(\s*\)\s*;");
        bool isWebStartup = Regex.IsMatch(text, @"WebApplication\.CreateBuilder|\bConfigure\s*\(\s*IApplicationBuilder\b") &&
                            Regex.IsMatch(text, @"\.Map(?:Controllers|RazorPages|Get|Post|Blazor\w*|Fallback\w*|Hub)\b|\.UseEndpoints\s*\(|\.UseMvc\w*\s*\(");
        if (!isWebStartup) yield break;

        int line = anchor.Success ? src.Position(anchor.Index).line : 1;
        var snippet = src.Snippet(line);
        if (!Regex.IsMatch(text, @"\.UseHttpsRedirection\s*\(|AddHttpsRedirection"))
            yield return Finding.From(MissingHttps, src.RelativePath, line, 1, snippet, Source);
        if (!Regex.IsMatch(text, @"\.UseHsts\s*\(|Strict-Transport-Security"))
            yield return Finding.From(MissingHsts, src.RelativePath, line, 1, snippet, Source);
        if (!Regex.IsMatch(text, @"\.UseRateLimiter\s*\(|AddRateLimiter|IpRateLimit|AspNetCoreRateLimit"))
            yield return Finding.From(NoRateLimit, src.RelativePath, line, 1, snippet, Source);
    }
}
