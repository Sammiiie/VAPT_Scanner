using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using VaptScanner.Core;

namespace VaptScanner.Dast;

public sealed class DastOptions
{
    public required Uri Target { get; init; }
    public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int MaxRequests { get; set; } = 120;
    public int DelayMs { get; set; } = 100;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(15);
    public List<string> ExtraPaths { get; } = new();
}

/// <summary>
/// A safe, non-destructive baseline scan of a running deployment (staging/UAT) that you own or are
/// authorised to test. Only GET/HEAD/OPTIONS/TRACE requests are sent, with a request budget and a delay.
/// It does not brute-force, fuzz, or attempt exploitation.
/// </summary>
public sealed class WebScanner : IDisposable
{
    private const string A05 = "A05:2021 Security Misconfiguration";
    private static RuleInfo I(string id, string title, Severity s, string cat, string desc, string fix, string cwe, string owasp = A05) =>
        new(id, title, s, cat, desc, fix, cwe, owasp);

    private static readonly RuleInfo Cleartext = I("VAPT-DAST-001", "Site served over plain HTTP", Severity.High, "Insecure Transport",
        "The application responds over unencrypted HTTP without redirecting to HTTPS.", "Redirect all HTTP traffic to HTTPS (UseHttpsRedirection or at the proxy) and enable HSTS.", "CWE-319", "A02:2021 Cryptographic Failures");
    private static readonly RuleInfo NoHsts = I("VAPT-DAST-002", "Missing or weak HSTS header", Severity.Medium, "Security Headers",
        "Strict-Transport-Security is missing or has max-age below 180 days.", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", "CWE-523");
    private static readonly RuleInfo NoCsp = I("VAPT-DAST-003", "Missing or weak Content-Security-Policy", Severity.Medium, "Security Headers",
        "No CSP (or one allowing 'unsafe-inline'/'unsafe-eval'), so any injected script runs freely.", "Add a restrictive Content-Security-Policy (default-src 'self'; use nonces/hashes instead of 'unsafe-inline').", "CWE-1021");
    private static readonly RuleInfo NoFrameOptions = I("VAPT-DAST-004", "Clickjacking protection missing", Severity.Medium, "Security Headers",
        "Neither X-Frame-Options nor CSP frame-ancestors is set, so pages can be framed by other sites.", "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.", "CWE-1021");
    private static readonly RuleInfo NoSniff = I("VAPT-DAST-005", "X-Content-Type-Options missing", Severity.Low, "Security Headers",
        "Browsers may MIME-sniff responses into executable types.", "Send X-Content-Type-Options: nosniff.", "CWE-693");
    private static readonly RuleInfo NoReferrer = I("VAPT-DAST-006", "Referrer-Policy missing", Severity.Low, "Security Headers",
        "Full URLs (which may contain tokens) can leak to third-party sites via the Referer header.", "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).", "CWE-200");
    private static readonly RuleInfo VersionHeaders = I("VAPT-DAST-007", "Technology/version disclosure in headers", Severity.Low, "Information Disclosure",
        "Server, X-Powered-By, X-AspNet-Version or X-AspNetMvc-Version reveal the stack and versions.", "Remove them: Kestrel AddServerHeader = false; remove X-Powered-By in IIS / web.config.", "CWE-200");
    private static readonly RuleInfo CookieFlags = I("VAPT-DAST-008", "Cookie missing security attributes", Severity.Medium, "Session Management",
        "A cookie is set without Secure, HttpOnly or SameSite.", "Set Secure, HttpOnly and SameSite=Lax/Strict on session and auth cookies.", "CWE-614");
    private static readonly RuleInfo CorsReflect = I("VAPT-DAST-009", "CORS policy trusts arbitrary origins", Severity.High, "Security Misconfiguration",
        "The server reflects an attacker-controlled Origin (or 'null') in Access-Control-Allow-Origin.", "Allowlist exact origins; never reflect the Origin header blindly, especially with credentials.", "CWE-942");
    private static readonly RuleInfo TraceEnabled = I("VAPT-DAST-010", "HTTP TRACE enabled", Severity.Low, "Security Misconfiguration",
        "TRACE echoes requests, which can expose headers in cross-site tracing scenarios.", "Disable TRACE at the server or proxy.", "CWE-693");
    private static readonly RuleInfo SensitiveFile = I("VAPT-DAST-011", "Sensitive file or endpoint publicly reachable", Severity.High, "Information Disclosure",
        "A file or diagnostic endpoint that should never be public returned its content.", "Remove it from the deployment / web root, or protect it with authentication and network restrictions.", "CWE-538");
    private static readonly RuleInfo ErrorLeak = I("VAPT-DAST-012", "Detailed error / stack trace returned", Severity.Medium, "Information Disclosure",
        "Malformed input produced an error page containing stack traces or framework internals.", "Use UseExceptionHandler with a generic error page in non-development environments.", "CWE-209");
    private static readonly RuleInfo Reflected = I("VAPT-DAST-013", "Input reflected without HTML encoding", Severity.Medium, "Cross-Site Scripting",
        "A query parameter value was echoed in the HTML response with its markup intact - a strong indicator of reflected XSS.", "HTML-encode output (Razor does this by default - look for Html.Raw / HtmlString / manual string building).", "CWE-79", "A03:2021 Injection");
    private static readonly RuleInfo TlsProblem = I("VAPT-DAST-014", "TLS certificate problem", Severity.High, "Insecure Transport",
        "The certificate is invalid, expired, expiring soon or doesn't match the host name.", "Install a valid certificate from a trusted CA and automate renewal.", "CWE-295", "A02:2021 Cryptographic Failures");
    private static readonly RuleInfo LegacyTls = I("VAPT-DAST-015", "Legacy TLS protocol accepted", Severity.Medium, "Insecure Transport",
        "The server negotiates TLS 1.0 or 1.1.", "Disable TLS 1.0/1.1 on the server/load balancer; allow TLS 1.2+ only.", "CWE-326", "A02:2021 Cryptographic Failures");
    private static readonly RuleInfo DirListing = I("VAPT-DAST-016", "Directory listing enabled", Severity.Medium, "Information Disclosure",
        "A directory returns an index of its files.", "Disable directory browsing (don't call UseDirectoryBrowser; <directoryBrowse enabled=\"false\"/> in IIS).", "CWE-548");
    private static readonly RuleInfo ApiDocs = I("VAPT-DAST-017", "API documentation exposed", Severity.Low, "Information Disclosure",
        "Swagger/OpenAPI UI or documents are publicly reachable, mapping the whole attack surface for attackers.", "Only map Swagger in Development, or put it behind authentication.", "CWE-200");

    public static IEnumerable<RuleInfo> Rules => new[]
    {
        Cleartext, NoHsts, NoCsp, NoFrameOptions, NoSniff, NoReferrer, VersionHeaders, CookieFlags, CorsReflect,
        TraceEnabled, SensitiveFile, ErrorLeak, Reflected, TlsProblem, LegacyTls, DirListing, ApiDocs
    };

    private sealed record Probe(string Path, string Signature, RuleInfo Rule, Severity Severity, string What);

    private static readonly Probe[] Probes =
    {
        new("/.git/config", @"\[core\]", SensitiveFile, Severity.Critical, "Git repository metadata - the full source can usually be reconstructed"),
        new("/.git/HEAD", @"^ref:\s*refs/", SensitiveFile, Severity.Critical, "Git repository metadata"),
        new("/.env", @"(?m)^[A-Z_][A-Z0-9_]*\s*=", SensitiveFile, Severity.Critical, "Environment file with configuration/secrets"),
        new("/appsettings.json", @"""(?:Logging|ConnectionStrings|AllowedHosts)""", SensitiveFile, Severity.High, "Application settings file"),
        new("/appsettings.Development.json", @"""(?:Logging|ConnectionStrings)""", SensitiveFile, Severity.High, "Development settings file"),
        new("/appsettings.Production.json", @"""(?:Logging|ConnectionStrings)""", SensitiveFile, Severity.High, "Production settings file"),
        new("/web.config", @"<configuration", SensitiveFile, Severity.High, "web.config"),
        new("/elmah.axd", @"(?i)error log for", SensitiveFile, Severity.High, "ELMAH error log"),
        new("/trace.axd", @"(?i)application trace", SensitiveFile, Severity.High, "ASP.NET trace viewer"),
        new("/hangfire", @"(?i)hangfire", SensitiveFile, Severity.Medium, "Hangfire dashboard"),
        new("/backup.zip", @"^PK\x03\x04", SensitiveFile, Severity.High, "Backup archive"),
        new("/site.zip", @"^PK\x03\x04", SensitiveFile, Severity.High, "Site archive"),
        new("/.DS_Store", @"Bud1", SensitiveFile, Severity.Low, "macOS folder metadata (leaks file names)"),
        new("/metrics", @"(?m)^# (?:HELP|TYPE) ", SensitiveFile, Severity.Low, "Prometheus metrics"),
        new("/swagger/index.html", @"(?i)swagger-ui", ApiDocs, Severity.Low, "Swagger UI"),
        new("/swagger/v1/swagger.json", @"""(?:openapi|swagger)""\s*:", ApiDocs, Severity.Low, "OpenAPI document"),
        new("/openapi/v1.json", @"""openapi""\s*:", ApiDocs, Severity.Low, "OpenAPI document"),
    };

    private static readonly Regex StackTraceSignature = new(
        @"(?:\s+at\s+(?:System|Microsoft)\.[\w.`]+\(|Stack Trace:|DeveloperExceptionPage|Server Error in '/' Application|An unhandled exception occurred while processing the request|System\.(?:NullReference|InvalidOperation|FormatException|Data\.SqlClient\.SqlException)|Microsoft\.Data\.SqlClient\.SqlException|Npgsql\.PostgresException)",
        RegexOptions.Compiled);

    private readonly DastOptions _opt;
    private readonly HttpClient _http;
    private readonly ScanResult _result;
    private int _requests;
    private readonly List<string> _certErrors = new();

    public WebScanner(DastOptions options)
    {
        _opt = options;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            SslOptions = new SslClientAuthenticationOptions
            {
                // Record certificate problems as findings but keep scanning so the rest of the report is useful.
                RemoteCertificateValidationCallback = (_, _, _, errors) =>
                {
                    if (errors != SslPolicyErrors.None) lock (_certErrors) _certErrors.Add(errors.ToString());
                    return true;
                }
            }
        };
        _http = new HttpClient(handler) { Timeout = options.Timeout };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("VaptScanner/1.0 (+authorised security baseline scan)");
        foreach (var (k, v) in options.Headers) _http.DefaultRequestHeaders.TryAddWithoutValidation(k, v);
        _result = new ScanResult { Target = options.Target.ToString(), StartedAt = DateTimeOffset.Now };
    }

    public async Task<ScanResult> RunAsync(Action<string>? progress = null)
    {
        var target = _opt.Target;
        progress?.Invoke($"Baseline request to {target}");
        var (main, body) = await Send(HttpMethod.Get, target, followRedirects: true);
        if (main is null)
        {
            _result.Notes.Add("Target did not respond - check the URL, VPN and that the app is running.");
            return Finish();
        }

        var finalUri = main.RequestMessage?.RequestUri ?? target;
        bool isHtml = main.Content.Headers.ContentType?.MediaType?.Contains("html", StringComparison.OrdinalIgnoreCase) == true;

        await CheckTransport(target, finalUri, main, progress);
        CheckHeaders(finalUri, main, isHtml);
        CheckCookies(finalUri, main);
        await CheckCors(finalUri, progress);
        await CheckTrace(finalUri);
        await CheckSensitivePaths(finalUri, progress);
        await CheckErrorDisclosure(finalUri, progress);
        await CheckReflection(finalUri, progress);
        await CheckDirectoryListing(finalUri, body);

        lock (_certErrors)
            if (_certErrors.Count > 0)
                Add(TlsProblem, finalUri.GetLeftPart(UriPartial.Authority), $"Certificate validation errors: {string.Join(", ", _certErrors.Distinct())}");

        _result.Notes.Add($"{_requests} HTTP requests sent.");
        return Finish();
    }

    private ScanResult Finish()
    {
        _result.FinishedAt = DateTimeOffset.Now;
        var deduped = _result.Findings
            .GroupBy(f => (f.RuleId, f.Location, f.Snippet))
            .Select(g => g.First())
            .OrderByDescending(f => f.Severity).ToList();
        _result.Findings.Clear();
        _result.Findings.AddRange(deduped);
        return _result;
    }

    // ───────────────────────── checks ─────────────────────────

    private async Task CheckTransport(Uri original, Uri final, HttpResponseMessage main, Action<string>? progress)
    {
        bool local = final.IsLoopback || final.Host.EndsWith(".local", StringComparison.OrdinalIgnoreCase);
        if (final.Scheme == Uri.UriSchemeHttp)
        {
            if (!local) Add(Cleartext, final.ToString(), "Final URL is http:// - no redirect to HTTPS happened.", Severity.High);
            return;
        }

        // HSTS
        if (main.Headers.TryGetValues("Strict-Transport-Security", out var hsts))
        {
            var m = Regex.Match(string.Join(",", hsts), @"max-age\s*=\s*""?(\d+)", RegexOptions.IgnoreCase);
            if (!m.Success || long.Parse(m.Groups[1].Value) < 15_552_000)
                Add(NoHsts, final.ToString(), $"Strict-Transport-Security: {string.Join(",", hsts)}");
        }
        else Add(NoHsts, final.ToString(), "Strict-Transport-Security header not present.");

        // Does plain HTTP redirect to HTTPS?
        if (!local)
        {
            var httpUri = new UriBuilder(final) { Scheme = Uri.UriSchemeHttp, Port = 80 }.Uri;
            var (resp, _) = await Send(HttpMethod.Get, httpUri, followRedirects: false);
            if (resp is not null && (int)resp.StatusCode < 300)
                Add(Cleartext, httpUri.ToString(), $"HTTP request returned {(int)resp.StatusCode} instead of redirecting to HTTPS.");
            else if (resp is not null && (int)resp.StatusCode is >= 300 and < 400 &&
                     resp.Headers.Location is { } loc && !loc.ToString().StartsWith("https", StringComparison.OrdinalIgnoreCase) && loc.IsAbsoluteUri)
                Add(Cleartext, httpUri.ToString(), $"HTTP redirects to a non-HTTPS location: {loc}");
        }

        progress?.Invoke("Checking TLS certificate and protocol versions");
        await CheckTls(final);
    }

    private async Task CheckTls(Uri uri)
    {
        var port = uri.Port > 0 ? uri.Port : 443;
        try
        {
            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await tcp.ConnectAsync(uri.Host, port, cts.Token);
            SslPolicyErrors errors = SslPolicyErrors.None;
            X509Certificate2? cert = null;
            using var ssl = new SslStream(tcp.GetStream(), false, (_, c, _, e) => { errors = e; cert = c is null ? null : new X509Certificate2(c); return true; });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = uri.Host }, cts.Token);

            if (cert is not null)
            {
                var daysLeft = (cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays;
                if (daysLeft < 0) Add(TlsProblem, uri.GetLeftPart(UriPartial.Authority), $"Certificate expired on {cert.NotAfter:yyyy-MM-dd}.", Severity.High);
                else if (daysLeft < 21) Add(TlsProblem, uri.GetLeftPart(UriPartial.Authority), $"Certificate expires in {daysLeft:0} days ({cert.NotAfter:yyyy-MM-dd}).", Severity.Medium);
            }
            if (errors != SslPolicyErrors.None)
                Add(TlsProblem, uri.GetLeftPart(UriPartial.Authority), $"Certificate validation failed: {errors}.");
        }
        catch (Exception ex)
        {
            _result.Notes.Add($"TLS inspection skipped: {ex.Message}");
        }

#pragma warning disable SYSLIB0039 // deliberately probing obsolete protocols
        foreach (var (proto, label) in new[] { (SslProtocols.Tls, "TLS 1.0"), (SslProtocols.Tls11, "TLS 1.1") })
#pragma warning restore SYSLIB0039
        {
            try
            {
                using var tcp = new TcpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                await tcp.ConnectAsync(uri.Host, port, cts.Token);
                using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = uri.Host, EnabledSslProtocols = proto }, cts.Token);
                Add(LegacyTls, uri.GetLeftPart(UriPartial.Authority), $"Server completed a {label} handshake.");
            }
            catch
            {
                // Refused by the server (good) or not supported by this client's OS - either way nothing to report.
            }
        }
    }

    private void CheckHeaders(Uri uri, HttpResponseMessage resp, bool isHtml)
    {
        string? H(string name) =>
            resp.Headers.TryGetValues(name, out var v) ? string.Join(", ", v) :
            resp.Content.Headers.TryGetValues(name, out var c) ? string.Join(", ", c) : null;

        var csp = H("Content-Security-Policy");
        if (isHtml)
        {
            if (csp is null)
                Add(NoCsp, uri.ToString(), H("Content-Security-Policy-Report-Only") is not null ? "Only a Report-Only CSP is set (not enforced)." : "Content-Security-Policy header not present.");
            else if (Regex.IsMatch(csp, @"'unsafe-(?:inline|eval)'") && !Regex.IsMatch(csp, @"'nonce-|'sha(?:256|384|512)-|'strict-dynamic'"))
                Add(NoCsp, uri.ToString(), $"CSP allows unsafe-inline/unsafe-eval: {Truncate(csp, 160)}", Severity.Low);

            var xfo = H("X-Frame-Options");
            if (xfo is null && (csp is null || !csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase)))
                Add(NoFrameOptions, uri.ToString(), "No X-Frame-Options and no CSP frame-ancestors.");

            if (H("Referrer-Policy") is null) Add(NoReferrer, uri.ToString(), "Referrer-Policy header not present.");
        }

        if (!string.Equals(H("X-Content-Type-Options"), "nosniff", StringComparison.OrdinalIgnoreCase))
            Add(NoSniff, uri.ToString(), "X-Content-Type-Options: nosniff not present.");

        var leaks = new[] { "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-SourceFiles" }
            .Select(n => (n, v: H(n))).Where(x => x.v is not null).ToList();
        if (leaks.Count > 0)
            Add(VersionHeaders, uri.ToString(), string.Join("; ", leaks.Select(l => $"{l.n}: {l.v}")),
                leaks.Any(l => l.n is "X-AspNet-Version" or "X-AspNetMvc-Version" or "X-SourceFiles" || Regex.IsMatch(l.v!, @"\d+\.\d+")) ? Severity.Low : Severity.Info);
    }

    private void CheckCookies(Uri uri, HttpResponseMessage resp)
    {
        if (!resp.Headers.TryGetValues("Set-Cookie", out var cookies)) return;
        foreach (var c in cookies)
        {
            var name = c.Split('=')[0].Trim();
            var attrs = c.ToLowerInvariant();
            var missing = new List<string>();
            if (uri.Scheme == Uri.UriSchemeHttps && !Regex.IsMatch(attrs, @";\s*secure\b")) missing.Add("Secure");
            if (!Regex.IsMatch(attrs, @";\s*httponly\b")) missing.Add("HttpOnly");
            if (!Regex.IsMatch(attrs, @";\s*samesite\s*=")) missing.Add("SameSite");
            if (missing.Count == 0) continue;

            bool sensitive = Regex.IsMatch(name, @"(?i)session|auth|token|identity|\.aspnetcore\.|sid|jwt|remember|login|antiforgery|xsrf|csrf");
            var sev = sensitive && (missing.Contains("Secure") || missing.Contains("HttpOnly")) ? Severity.Medium : Severity.Low;
            if (name.Contains("xsrf", StringComparison.OrdinalIgnoreCase) && missing.SequenceEqual(new[] { "HttpOnly" })) continue; // JS-readable CSRF cookies are by design
            Add(CookieFlags, uri.ToString(), $"Cookie '{name}' is missing: {string.Join(", ", missing)}", sev);
        }
    }

    private async Task CheckCors(Uri uri, Action<string>? progress)
    {
        progress?.Invoke("Checking CORS policy");
        foreach (var origin in new[] { "https://vapt-cors-probe.example", "null" })
        {
            var (resp, _) = await Send(HttpMethod.Get, uri, extraHeaders: new() { ["Origin"] = origin });
            if (resp is null) continue;
            var acao = resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var a) ? a.First() : null;
            var acac = resp.Headers.TryGetValues("Access-Control-Allow-Credentials", out var c) && c.First().Equals("true", StringComparison.OrdinalIgnoreCase);
            if (acao is null) continue;
            if (acao == origin)
                Add(CorsReflect, uri.ToString(), $"Origin '{origin}' was reflected{(acac ? " with Access-Control-Allow-Credentials: true" : "")}.",
                    acac ? Severity.High : Severity.Medium);
            else if (acao == "*" && origin != "null")
                Add(CorsReflect, uri.ToString(), "Access-Control-Allow-Origin: * (any site can read unauthenticated responses).", Severity.Low);
        }
    }

    private async Task CheckTrace(Uri uri)
    {
        var (resp, body) = await Send(new HttpMethod("TRACE"), uri, extraHeaders: new() { ["X-Vapt-Trace"] = "probe" });
        if (resp is not null && resp.StatusCode == HttpStatusCode.OK && body.Contains("X-Vapt-Trace", StringComparison.OrdinalIgnoreCase))
            Add(TraceEnabled, uri.ToString(), "TRACE request was echoed back.");
    }

    private async Task CheckSensitivePaths(Uri baseUri, Action<string>? progress)
    {
        progress?.Invoke("Probing for exposed files and diagnostic endpoints");
        var probes = Probes.ToList();
        probes.AddRange(_opt.ExtraPaths.Select(p => new Probe(p.StartsWith('/') ? p : "/" + p, ".", SensitiveFile, Severity.Medium, "Custom path from --path")));

        foreach (var probe in probes)
        {
            var uri = new Uri(baseUri, probe.Path);
            var (resp, body) = await Send(HttpMethod.Get, uri, maxBody: 65536);
            if (resp is null || resp.StatusCode != HttpStatusCode.OK) continue;
            if (!Regex.IsMatch(body, probe.Signature)) continue; // avoids soft-404 false positives
            Add(probe.Rule, uri.ToString(), $"Publicly readable: {probe.What} (HTTP 200, content verified).", probe.Severity);
        }
    }

    private async Task CheckErrorDisclosure(Uri baseUri, Action<string>? progress)
    {
        progress?.Invoke("Checking error handling");
        var probes = new[]
        {
            new Uri(baseUri, $"/vapt-{Guid.NewGuid():N}/%2e%2e%5c?id=%27%22%3E"),
            AppendQuery(baseUri, "id", "'\"<vapt>"),
            AppendQuery(baseUri, "page", "-1e999"),
        };
        foreach (var uri in probes)
        {
            var (resp, body) = await Send(HttpMethod.Get, uri, maxBody: 262144);
            if (resp is null) continue;
            var m = StackTraceSignature.Match(body);
            if (m.Success) { Add(ErrorLeak, uri.ToString(), $"HTTP {(int)resp.StatusCode}; response contains \"{Truncate(m.Value.Trim(), 80)}\"."); break; }
        }
    }

    private async Task CheckReflection(Uri baseUri, Action<string>? progress)
    {
        progress?.Invoke("Checking for unencoded reflection of input");
        var query = System.Web.HttpUtility.ParseQueryString(baseUri.Query);
        var names = query.AllKeys.Where(k => !string.IsNullOrEmpty(k)).Cast<string>().ToList();
        if (names.Count == 0) names.AddRange(new[] { "q", "search", "returnUrl" });

        foreach (var name in names.Take(10))
        {
            var token = "vapt" + Guid.NewGuid().ToString("N")[..8];
            var payload = $"\"'><i>{token}</i>";
            var uri = AppendQuery(baseUri, name, payload);
            var (resp, body) = await Send(HttpMethod.Get, uri, maxBody: 524288);
            if (resp is null) continue;
            bool html = resp.Content.Headers.ContentType?.MediaType?.Contains("html", StringComparison.OrdinalIgnoreCase) == true;
            if (html && body.Contains($"<i>{token}</i>", StringComparison.Ordinal))
                Add(Reflected, uri.ToString(), $"Parameter '{name}' was reflected as live markup (<i>{token}</i>).");
        }
    }

    private async Task CheckDirectoryListing(Uri baseUri, string homeBody)
    {
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "/css/", "/js/", "/lib/", "/images/", "/uploads/", "/files/", "/content/" };
        foreach (Match m in Regex.Matches(homeBody, @"(?:src|href)\s*=\s*[""'](/[\w\-./]+/)[\w\-.]+\.(?:css|js|png|jpg|svg)", RegexOptions.IgnoreCase))
            dirs.Add(m.Groups[1].Value);

        foreach (var dir in dirs.Take(12))
        {
            var uri = new Uri(baseUri, dir);
            var (resp, body) = await Send(HttpMethod.Get, uri, maxBody: 65536);
            if (resp?.StatusCode == HttpStatusCode.OK && Regex.IsMatch(body, @"(?i)<title>\s*(?:Index of|Directory Listing|[^<]*- /)|\[To Parent Directory\]"))
                Add(DirListing, uri.ToString(), "Directory index returned.");
        }
    }

    // ───────────────────────── plumbing ─────────────────────────

    private async Task<(HttpResponseMessage? resp, string body)> Send(HttpMethod method, Uri uri, bool followRedirects = false,
        Dictionary<string, string>? extraHeaders = null, int maxBody = 131072)
    {
        for (int hop = 0; hop < 6; hop++)
        {
            if (Interlocked.Increment(ref _requests) > _opt.MaxRequests)
            {
                if (_requests == _opt.MaxRequests + 1) _result.Notes.Add($"Request budget of {_opt.MaxRequests} reached; remaining checks skipped. Raise it with --max-requests.");
                return (null, "");
            }
            if (_opt.DelayMs > 0) await Task.Delay(_opt.DelayMs);

            try
            {
                using var req = new HttpRequestMessage(method, uri);
                if (extraHeaders is not null) foreach (var (k, v) in extraHeaders) req.Headers.TryAddWithoutValidation(k, v);
                var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
                if (followRedirects && (int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
                {
                    uri = loc.IsAbsoluteUri ? loc : new Uri(uri, loc);
                    resp.Dispose();
                    continue;
                }
                var body = await ReadLimited(resp, maxBody);
                return (resp, body);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
            {
                lock (_result.Notes) _result.Notes.Add($"{method} {uri} failed: {ex.Message}");
                return (null, "");
            }
        }
        return (null, "");
    }

    private static async Task<string> ReadLimited(HttpResponseMessage resp, int max)
    {
        await using var stream = await resp.Content.ReadAsStreamAsync();
        var buffer = new byte[max];
        int total = 0, read;
        while (total < max && (read = await stream.ReadAsync(buffer.AsMemory(total, max - total))) > 0) total += read;
        return System.Text.Encoding.Latin1.GetString(buffer, 0, total);
    }

    private static Uri AppendQuery(Uri uri, string name, string value)
    {
        var builder = new UriBuilder(uri);
        var q = System.Web.HttpUtility.ParseQueryString(builder.Query);
        q[name] = value;
        builder.Query = q.ToString();
        return builder.Uri;
    }

    private void Add(RuleInfo rule, string location, string evidence, Severity? severity = null)
    {
        lock (_result.Findings)
            _result.Findings.Add(Finding.From(rule, location, 0, 0, evidence, "dast", severity));
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    public void Dispose() => _http.Dispose();
}
