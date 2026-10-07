using System.Text.RegularExpressions;
using VaptScanner.Core;

namespace VaptScanner.Analyzers;

/// <summary>
/// Reviews deployment/configuration files: web.config, appsettings*.json, Dockerfile,
/// docker-compose and project files (target framework support status, disabled security analyzers).
/// </summary>
public sealed class ConfigAnalyzer : IFileAnalyzer
{
    public string Source => "config";

    private const string A05 = "A05:2021 Security Misconfiguration";
    private const string A06 = "A06:2021 Vulnerable and Outdated Components";

    private static RuleInfo I(string id, string title, Severity s, string desc, string fix, string cwe, string owasp = A05) =>
        new(id, title, s, "Security Misconfiguration", desc, fix, cwe, owasp);

    // web.config / app.config
    private static readonly (RuleInfo info, Regex rx)[] XmlConfigRules =
    {
        (I("VAPT-CFG-001", "Custom errors turned off", Severity.Medium,
            "customErrors mode=\"Off\" shows detailed ASP.NET error pages, including stack traces, to remote users.",
            "Use mode=\"RemoteOnly\" or \"On\" with a generic error page.", "CWE-209"),
         Rx(@"<customErrors[^>]*\bmode\s*=\s*""Off""")),
        (I("VAPT-CFG-002", "Debug compilation enabled", Severity.Medium,
            "debug=\"true\" disables optimisations, extends request timeouts and can expose debugging information.",
            "Set debug=\"false\" for release, ideally via a web.Release.config transform.", "CWE-489"),
         Rx(@"<compilation[^>]*\bdebug\s*=\s*""true""")),
        (I("VAPT-CFG-003", "Cookies not restricted to HTTPS / HttpOnly", Severity.Medium,
            "Session and auth cookies may be sent over HTTP or read by JavaScript.",
            "Set <httpCookies httpOnlyCookies=\"true\" requireSSL=\"true\" /> and requireSSL=\"true\" on <forms>.", "CWE-614"),
         Rx(@"<(?:httpCookies|forms)[^>]*\b(?:requireSSL|httpOnlyCookies)\s*=\s*""false""")),
        (I("VAPT-CFG-004", "ASP.NET tracing enabled", Severity.Medium,
            "trace.axd exposes request details, headers and session data.",
            "Set <trace enabled=\"false\" />.", "CWE-489"),
         Rx(@"<trace[^>]*\benabled\s*=\s*""true""")),
        (I("VAPT-CFG-005", "Request validation or ViewState MAC disabled", Severity.High,
            "Disabling ViewState MAC enables ViewState tampering and RCE; disabling request validation weakens XSS defences.",
            "Remove enableViewStateMac=\"false\", validateRequest=\"false\" and requestValidationMode=\"2.0\".", "CWE-642"),
         Rx(@"\benableViewStateMac\s*=\s*""false""|\bvalidateRequest\s*=\s*""false""|\brequestValidationMode\s*=\s*""2\.0""")),
        (I("VAPT-CFG-006", "Directory browsing enabled", Severity.Medium,
            "Directory listings reveal file names, backups and configuration files.",
            "Set <directoryBrowse enabled=\"false\" />.", "CWE-548"),
         Rx(@"<directoryBrowse[^>]*\benabled\s*=\s*""true""")),
        (I("VAPT-CFG-007", "Server version header not removed", Severity.Low,
            "The X-AspNet-Version header advertises the framework version to attackers.",
            "Set <httpRuntime enableVersionHeader=\"false\" /> and remove X-Powered-By in <customHeaders>.", "CWE-200"),
         Rx(@"<httpRuntime(?![^>]*enableVersionHeader\s*=\s*""false"")[^>]*>")),
    };

    // appsettings*.json (non-Development)
    private static readonly (RuleInfo info, Regex rx)[] JsonRules =
    {
        (I("VAPT-CFG-010", "Detailed errors enabled in non-development settings", Severity.Medium,
            "DetailedErrors / IncludeExceptionDetails sends exception details to clients.",
            "Only enable it in appsettings.Development.json.", "CWE-209"),
         Rx(@"""(?:DetailedErrors|IncludeExceptionDetails|EnableDetailedErrors)""\s*:\s*true")),
        (I("VAPT-CFG-011", "AllowedHosts accepts any host", Severity.Low,
            "AllowedHosts \"*\" disables host filtering, which helps host-header attacks (e.g. poisoned password-reset links).",
            "List your real host names, e.g. \"AllowedHosts\": \"app.example.com;api.example.com\".", "CWE-644"),
         Rx(@"""AllowedHosts""\s*:\s*""\*""")),
        (I("VAPT-CFG-012", "Verbose logging in production settings", Severity.Low,
            "Debug/Trace logging in production can capture tokens, PII and request bodies, and adds noise.",
            "Use Information or Warning in appsettings.json / Production.", "CWE-532", "A09:2021 Security Logging and Monitoring Failures"),
         Rx(@"""(?:Default|Microsoft[\w.]*|System[\w.]*)""\s*:\s*""(?:Debug|Trace)""")),
        (I("VAPT-CFG-013", "Token validation disabled in configuration", Severity.High,
            "A setting disables HTTPS metadata or token validation.",
            "Remove the override outside Development.", "CWE-347", "A07:2021 Identification and Authentication Failures"),
         Rx(@"""(?:RequireHttpsMetadata|ValidateIssuerSigningKey|ValidateLifetime|ValidateIssuer|ValidateAudience|RequireSignedTokens)""\s*:\s*false")),
        (I("VAPT-CFG-014", "Cleartext HTTP endpoint in configuration", Severity.Low,
            "A configured URL uses http:// for a non-local host.",
            "Use https:// endpoints.", "CWE-319", "A02:2021 Cryptographic Failures"),
         Rx(@"""[\w.]*(?:Url|Uri|Endpoint|Authority|Issuer|Host|Address|BaseAddress)""\s*:\s*""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\+|\*)")),
        (I("VAPT-CFG-015", "Sensitive data logging enabled in configuration", Severity.Medium,
            "EF Core sensitive data logging writes parameter values to logs.",
            "Disable it outside Development.", "CWE-532", "A09:2021 Security Logging and Monitoring Failures"),
         Rx(@"""EnableSensitiveDataLogging""\s*:\s*true")),
    };

    private static readonly RuleInfo DockerRoot = I("VAPT-CFG-020", "Container runs as root", Severity.Medium,
        "The final image has no USER instruction (or switches to root), so a compromise of the app gives root in the container.",
        "Add USER app (built into mcr.microsoft.com/dotnet images since .NET 8) or USER $APP_UID before ENTRYPOINT.", "CWE-250");
    private static readonly RuleInfo DockerTag = I("VAPT-CFG-021", "Unpinned base image", Severity.Low,
        "Using :latest or no tag makes builds non-reproducible and can silently pull a vulnerable image.",
        "Pin a specific tag (e.g. mcr.microsoft.com/dotnet/aspnet:8.0.10) or a digest.", "CWE-1357", A06);
    private static readonly RuleInfo DockerDevEnv = I("VAPT-CFG-022", "Development environment baked into deployment", Severity.Medium,
        "ASPNETCORE_ENVIRONMENT=Development enables developer exception pages and dev-only settings.",
        "Set Production (the default when unset) in deployment manifests.", "CWE-489");
    private static readonly RuleInfo DockerAddUrl = I("VAPT-CFG-023", "Remote file added without verification", Severity.Low,
        "ADD with a URL downloads content without checksum verification.",
        "Download with curl + checksum verification, or use ADD --checksum=sha256:... (BuildKit).", "CWE-494", "A08:2021 Software and Data Integrity Failures");
    private static readonly RuleInfo DockerSecret = I("VAPT-CFG-024", "Secret passed via ENV/ARG", Severity.High,
        "Values set with ENV or ARG are stored in image layers and visible with docker history.",
        "Use BuildKit secrets (RUN --mount=type=secret) for build time and runtime secret injection (orchestrator secrets / vault).", "CWE-798");
    private static readonly RuleInfo ComposePrivileged = I("VAPT-CFG-025", "Privileged container", Severity.High,
        "privileged: true gives the container full access to the host.",
        "Remove privileged and grant only the specific capabilities needed (cap_add).", "CWE-250");

    private static readonly RuleInfo FrameworkEol = I("VAPT-CFG-030", "Target framework out of support", Severity.High,
        "This target framework no longer receives security patches.",
        "Upgrade to a supported release (.NET 10 LTS is current) and keep the runtime patched.", "CWE-1104", A06);
    private static readonly RuleInfo AnalyzersOff = I("VAPT-CFG-031", "Built-in security analyzers suppressed", Severity.Low,
        "The project disables .NET analyzers or suppresses security warnings (CA2100, CA3xxx, CA5xxx), hiding issues the compiler would flag.",
        "Remove the suppression and set <AnalysisMode>Recommended</AnalysisMode> or enable the security rule set.", "CWE-1164");

    /// <summary>End-of-support dates per Microsoft's .NET support policy.</summary>
    private static readonly Dictionary<string, DateTime> FrameworkEndOfSupport = new(StringComparer.OrdinalIgnoreCase)
    {
        ["netcoreapp1.0"] = new(2019, 6, 27), ["netcoreapp1.1"] = new(2019, 6, 27),
        ["netcoreapp2.0"] = new(2018, 10, 1), ["netcoreapp2.1"] = new(2021, 8, 21), ["netcoreapp2.2"] = new(2019, 12, 23),
        ["netcoreapp3.0"] = new(2020, 3, 3), ["netcoreapp3.1"] = new(2022, 12, 13),
        ["net5.0"] = new(2022, 5, 10), ["net6.0"] = new(2024, 11, 12), ["net7.0"] = new(2024, 5, 14),
        ["net8.0"] = new(2026, 11, 10), ["net9.0"] = new(2026, 11, 10), ["net10.0"] = new(2028, 11, 14),
        ["net40"] = new(2016, 1, 12), ["net403"] = new(2016, 1, 12), ["net45"] = new(2016, 1, 12),
        ["net451"] = new(2016, 1, 12), ["net452"] = new(2022, 4, 26), ["net46"] = new(2022, 4, 26), ["net461"] = new(2022, 4, 26),
    };

    public IEnumerable<RuleInfo> Rules =>
        XmlConfigRules.Select(r => r.info).Concat(JsonRules.Select(r => r.info))
            .Concat(new[] { DockerRoot, DockerTag, DockerDevEnv, DockerAddUrl, DockerSecret, ComposePrivileged, FrameworkEol, AnalyzersOff });

    private static Regex Rx(string p) => new(p, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline, TimeSpan.FromSeconds(2));

    public IEnumerable<Finding> Analyze(SourceText src)
    {
        var name = src.FileName;
        var lower = name.ToLowerInvariant();

        if (lower.EndsWith(".config") && (lower.StartsWith("web") || lower.StartsWith("app")))
        {
            bool isDebugTransform = lower.Contains(".debug.") || lower.Contains(".development.");
            foreach (var (info, rx) in XmlConfigRules)
            {
                if (isDebugTransform && info.Id is "VAPT-CFG-002" or "VAPT-CFG-001") continue;
                foreach (var f in MatchAll(src, src.NoComments, info, rx)) yield return f;
            }
        }
        else if (lower.StartsWith("appsettings") && lower.EndsWith(".json") && !Regex.IsMatch(lower, @"\.(development|dev|local|test|testing)\.json$"))
        {
            foreach (var (info, rx) in JsonRules)
                foreach (var f in MatchAll(src, src.Raw, info, rx)) yield return f;
        }
        else if (lower.StartsWith("dockerfile") || lower.EndsWith(".dockerfile"))
        {
            foreach (var f in Dockerfile(src)) yield return f;
        }
        else if (lower.StartsWith("docker-compose") || lower.StartsWith("compose.") || src.Extension is ".yml" or ".yaml")
        {
            foreach (var f in MatchAll(src, src.Raw, ComposePrivileged, Rx(@"^\s*privileged\s*:\s*true"))) yield return f;
            if (!lower.Contains("override") && !lower.Contains("dev"))
                foreach (var f in MatchAll(src, src.Raw, DockerDevEnv, Rx(@"ASPNETCORE_ENVIRONMENT\s*[:=]\s*[""']?Development"))) yield return f;
        }
        else if (src.Extension is ".csproj" or ".props")
        {
            foreach (var f in ProjectFile(src)) yield return f;
        }
    }

    private static IEnumerable<Finding> MatchAll(SourceText src, string text, RuleInfo info, Regex rx)
    {
        foreach (Match m in rx.Matches(text))
        {
            var (line, col) = src.Position(m.Index);
            yield return Finding.From(info, src.RelativePath, line, col, src.Snippet(line), "config");
        }
    }

    private static IEnumerable<Finding> Dockerfile(SourceText src)
    {
        var lines = src.Lines.Select(l => l.TrimEnd('\r')).ToArray();
        var stageAliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int lastFrom = -1, lastUser = -1;
        string? lastUserValue = null;

        for (int i = 0; i < lines.Length; i++)
        {
            var l = lines[i].Trim();
            if (l.StartsWith('#')) continue;
            var from = Regex.Match(l, @"^FROM\s+(?:--platform=\S+\s+)?(?<img>\S+)(?:\s+AS\s+(?<alias>\S+))?", RegexOptions.IgnoreCase);
            if (from.Success)
            {
                lastFrom = i; lastUser = -1; lastUserValue = null;
                var img = from.Groups["img"].Value;
                if (from.Groups["alias"].Success) stageAliases.Add(from.Groups["alias"].Value);
                bool isStageRef = stageAliases.Contains(img) && !from.Groups["alias"].Value.Equals(img, StringComparison.OrdinalIgnoreCase);
                if (!isStageRef && !img.Equals("scratch", StringComparison.OrdinalIgnoreCase) && !img.Contains('@') && !img.Contains('$'))
                {
                    var lastSegment = img.Split('/').Last();
                    if (!lastSegment.Contains(':') || lastSegment.EndsWith(":latest", StringComparison.OrdinalIgnoreCase))
                        yield return Finding.From(DockerTag, src.RelativePath, i + 1, 1, l, "config");
                }
                continue;
            }
            var user = Regex.Match(l, @"^USER\s+(?<u>\S+)", RegexOptions.IgnoreCase);
            if (user.Success) { lastUser = i; lastUserValue = user.Groups["u"].Value; }

            if (Regex.IsMatch(l, @"ASPNETCORE_ENVIRONMENT[= ]+[""']?Development", RegexOptions.IgnoreCase))
                yield return Finding.From(DockerDevEnv, src.RelativePath, i + 1, 1, l, "config");
            if (Regex.IsMatch(l, @"^ADD\s+(?:--\S+\s+)*https?://", RegexOptions.IgnoreCase) && !l.Contains("--checksum"))
                yield return Finding.From(DockerAddUrl, src.RelativePath, i + 1, 1, l, "config");
            if (Regex.IsMatch(l, @"^(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CONNECTIONSTRING|CONNECTION_STRING)\w*\s*[= ]\s*\S+", RegexOptions.IgnoreCase))
                yield return Finding.From(DockerSecret, src.RelativePath, i + 1, 1, Regex.Replace(l, @"(=\s*|\s)(\S{2})\S+$", "$1$2****"), "config");
        }

        if (lastFrom >= 0 && (lastUser < 0 || lastUserValue is "root" or "0" or "0:0"))
        {
            int line = lastUser >= 0 ? lastUser + 1 : lastFrom + 1;
            yield return Finding.From(DockerRoot, src.RelativePath, line, 1, lines[line - 1].Trim(), "config");
        }
    }

    private static IEnumerable<Finding> ProjectFile(SourceText src)
    {
        var text = src.NoComments;
        foreach (Match m in Regex.Matches(text, @"<TargetFrameworks?>(?<tfms>[^<]+)</TargetFrameworks?>", RegexOptions.IgnoreCase))
        {
            var (line, col) = src.Position(m.Index);
            foreach (var raw in m.Groups["tfms"].Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var tfm = raw.Split('-')[0];
                if (!FrameworkEndOfSupport.TryGetValue(tfm, out var eol)) continue;
                var daysLeft = (eol - DateTime.UtcNow.Date).TotalDays;
                if (daysLeft < 0)
                    yield return Finding.From(FrameworkEol, src.RelativePath, line, col, src.Snippet(line), "config",
                        extraDetail: $"{tfm} reached end of support on {eol:yyyy-MM-dd}.");
                else if (daysLeft <= 180)
                    yield return Finding.From(FrameworkEol, src.RelativePath, line, col, src.Snippet(line), "config",
                        daysLeft <= 60 ? Severity.Medium : Severity.Low,
                        $"{tfm} reaches end of support on {eol:yyyy-MM-dd} ({daysLeft:0} days). Plan the upgrade now.");
            }
        }

        var off = Regex.Match(text, @"<EnableNETAnalyzers>\s*false\s*</EnableNETAnalyzers>|<NoWarn>[^<]*\b(?:CA2100|CA3\d{3}|CA5\d{3})\b[^<]*</NoWarn>|<AnalysisMode>\s*None\s*</AnalysisMode>", RegexOptions.IgnoreCase);
        if (off.Success)
        {
            var (line, col) = src.Position(off.Index);
            yield return Finding.From(AnalyzersOff, src.RelativePath, line, col, src.Snippet(line), "config");
        }
    }
}
