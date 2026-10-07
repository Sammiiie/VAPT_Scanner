using System.Text.RegularExpressions;
using VaptScanner.Core;

namespace VaptScanner.Analyzers;

/// <summary>
/// Detects credentials committed to the repository: provider-specific token formats,
/// connection strings with passwords, private keys and generic high-entropy secrets.
/// Matching runs on raw text (comments included) because secrets in comments still leak.
/// </summary>
public sealed class SecretsAnalyzer : IFileAnalyzer
{
    public string Source => "secrets";

    private const string Fix =
        "Remove it from source, ROTATE the credential (assume it is compromised - it lives in git history), and load it from User Secrets in development and a vault (Azure Key Vault, AWS Secrets Manager, environment variables) in production. Purge history with git filter-repo if the repo is shared.";

    private sealed record SecretPattern(RuleInfo Info, Regex Regex, string? ValueGroup = null);

    private static RuleInfo Info(string id, string title, Severity sev, string what) =>
        new(id, title, sev, "Hard-coded Secret", $"{what} was found in a committed file.", Fix, "CWE-798", "A07:2021 Identification and Authentication Failures");

    private static Regex Rx(string p) => new(p, RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));

    private static readonly SecretPattern[] Patterns =
    {
        new(Info("VAPT-SECRET-001", "Private key", Severity.Critical, "A PEM-encoded private key"),
            Rx(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
        new(Info("VAPT-SECRET-002", "AWS access key ID", Severity.High, "An AWS access key ID"),
            Rx(@"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
        new(Info("VAPT-SECRET-003", "AWS secret access key", Severity.Critical, "An AWS secret access key"),
            Rx(@"(?i)aws.{0,25}(?:secret|private).{0,25}?[=:>]\s*[""']?(?<v>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), "v"),
        new(Info("VAPT-SECRET-004", "GitHub token", Severity.Critical, "A GitHub personal access / OAuth token"),
            Rx(@"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
        new(Info("VAPT-SECRET-005", "GitLab token", Severity.Critical, "A GitLab personal access token"),
            Rx(@"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
        new(Info("VAPT-SECRET-006", "Slack token or webhook", Severity.High, "A Slack token or incoming webhook"),
            Rx(@"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
        new(Info("VAPT-SECRET-007", "Stripe live key", Severity.Critical, "A Stripe live secret/restricted key"),
            Rx(@"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
        new(Info("VAPT-SECRET-008", "Google API key", Severity.High, "A Google API key"),
            Rx(@"\bAIza[0-9A-Za-z\-_]{35}\b")),
        new(Info("VAPT-SECRET-009", "Azure storage / Service Bus key", Severity.Critical, "An Azure storage account key or shared access key"),
            Rx(@"(?:AccountKey|SharedAccessKey)\s*=\s*(?<v>[A-Za-z0-9+/]{40,}={0,2})"), "v"),
        new(Info("VAPT-SECRET-010", "Azure SAS token", Severity.High, "An Azure shared access signature"),
            Rx(@"[?&]sv=\d{4}-\d{2}-\d{2}[^""'\s]*?&sig=(?<v>[A-Za-z0-9%+/=]{30,})"), "v"),
        new(Info("VAPT-SECRET-011", "SendGrid API key", Severity.Critical, "A SendGrid API key"),
            Rx(@"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
        new(Info("VAPT-SECRET-012", "AI provider API key", Severity.High, "An OpenAI / Anthropic style API key"),
            Rx(@"\bsk-(?:proj-|ant-(?:api|admin)\d{2}-)?[A-Za-z0-9_\-]{32,}\b")),
        new(Info("VAPT-SECRET-013", "Package registry token", Severity.High, "An npm or NuGet API key"),
            Rx(@"\bnpm_[A-Za-z0-9]{36}\b|\boy2[a-z0-9]{43}\b")),
        new(Info("VAPT-SECRET-014", "JSON Web Token", Severity.Medium, "A signed JWT (may grant access until it expires)"),
            Rx(@"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
        new(Info("VAPT-SECRET-015", "Database connection string with password", Severity.High, "A connection string containing a password"),
            Rx(@"(?i)(?:Server|Data Source|Host|Address|Addr|Network Address)\s*=[^;""'\n]+;[^""'\n]*?\b(?:Password|Pwd)\s*=\s*(?<v>[^;""'\n]{3,})"), "v"),
        new(Info("VAPT-SECRET-016", "Credentials embedded in URI", Severity.High, "A connection URI with an embedded username and password"),
            Rx(@"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|amqps?|mssql|sqlserver|ftp|sftp|smtp)://[^:\s/""'@]+:(?<v>[^@\s/""']{3,})@"), "v"),
        new(Info("VAPT-SECRET-017", "Hard-coded password or secret", Severity.Medium, "A value assigned to a password/secret/key-like name"),
            Rx(@"(?i)(?<name>\b[A-Za-z0-9_.\-]*(?:password|passwd|pwd|passphrase|secret|apikey|api_key|api-key|accesskey|access_key|clientsecret|client_secret|authtoken|auth_token|accesstoken|access_token|privatekey|private_key|signingkey|signing_key|jwtkey|jwt_key|jwtsecret|encryptionkey|encryption_key|token))[""']?\s*(?:=|:|=>)\s*[@$]?[""'](?<v>[^""'\s]{6,})[""']"), "v"),
    };

    private static readonly RuleInfo KeyFile = Info("VAPT-SECRET-020", "Private key / certificate file committed", Severity.High,
        "A private key or PKCS#12 certificate store");

    private static readonly RuleInfo EnvFile = new("VAPT-SECRET-021", ".env file committed", Severity.Low, "Hard-coded Secret",
        "An environment file with values is tracked in the repository. These usually hold credentials.",
        "Add .env to .gitignore, commit a .env.example with blank values instead, and rotate anything real that was committed.",
        "CWE-538", "A05:2021 Security Misconfiguration");

    private static readonly string[] PlaceholderFragments =
    {
        "changeme", "change_me", "change-me", "example", "placeholder", "your", "xxxx", "****", "redacted", "replace",
        "dummy", "sample", "<", ">", "${", "#{", "{{", "__", "todo", "fixme", "insert", "enter", "secretsmanager", "keyvault",
        "$(", "%", "env:", "process.env", "configuration[", "getenvironmentvariable", "fake", "mock", "notreal", "not-a-real"
    };

    private static readonly HashSet<string> PlaceholderValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "secret", "token", "apikey", "api_key", "string", "null", "none", "empty", "required", "optional",
        "bearer", "basic", "true", "false", "undefined", "default", "unknown", "value", "test", "testing", "n/a"
    };

    public IEnumerable<RuleInfo> Rules => Patterns.Select(p => p.Info).Append(KeyFile).Append(EnvFile);

    public IEnumerable<Finding> Analyze(SourceText src)
    {
        var lowerPath = src.RelativePath.ToLowerInvariant();
        bool isTestOrDoc = Regex.IsMatch(lowerPath, @"(^|/)(tests?|specs?|__tests__|samples?|examples?|docs?)/|\.tests?/|tests?\.cs$|\.md$");

        if (src.Extension is ".pfx" or ".p12" or ".key" || (src.Extension == ".pem" && src.Raw.Contains("PRIVATE KEY")))
        {
            yield return Finding.From(KeyFile, src.RelativePath, 1, 1, $"[{src.FileName}]", Source);
            yield break;
        }

        if (src.FileName.StartsWith(".env", StringComparison.OrdinalIgnoreCase) &&
            !src.FileName.Contains("example", StringComparison.OrdinalIgnoreCase) &&
            !src.FileName.Contains("sample", StringComparison.OrdinalIgnoreCase) &&
            !src.FileName.Contains("template", StringComparison.OrdinalIgnoreCase) &&
            Regex.IsMatch(src.Raw, @"^\s*[A-Z_][A-Z0-9_]*\s*=\s*\S+", RegexOptions.Multiline))
        {
            yield return Finding.From(EnvFile, src.RelativePath, 1, 1, $"[{src.FileName}]", Source);
        }

        if (FileWalker.LooksBinary(src.Raw)) yield break;

        var reported = new HashSet<int>(); // one secret finding per line
        foreach (var p in Patterns)
        {
            MatchCollection matches;
            try { matches = p.Regex.Matches(src.Raw); _ = matches.Count; }
            catch (RegexMatchTimeoutException) { continue; }

            foreach (Match m in matches)
            {
                var value = p.ValueGroup is not null && m.Groups[p.ValueGroup].Success ? m.Groups[p.ValueGroup].Value : m.Value;
                if (IsPlaceholder(value)) continue;

                Severity? sev = null;
                string? detail = null;

                if (p.Info.Id == "VAPT-SECRET-017")
                {
                    var name = m.Groups["name"].Value;
                    if (Regex.IsMatch(name, @"(?i)(label|message|hint|text|description|header|type|name|field|prompt|policy|purpose|path|url|uri|endpoint|format|validator|regex|pattern|length|hash|confirm|placeholder)")) continue;
                    if (Regex.IsMatch(value, @"^[A-Za-z]+(?::[A-Za-z0-9_]+)+$")) continue; // config path like "Jwt:Key"
                    if (Regex.IsMatch(value, @"^[A-Z][A-Za-z]+$") && value.Length < 16) continue; // PascalCase identifier e.g. "ResetPassword"
                    if (Regex.IsMatch(value, @"^(?:\{[^}]*\}|@\w+|:\w+)$")) continue;
                    double entropy = ShannonEntropy(value);
                    if (entropy >= 3.5 && value.Length >= 16) { sev = Severity.High; detail = "The value looks random (high entropy), so it is likely a real credential."; }
                    else if (entropy < 2.2) continue; // e.g. "aaaaaa"
                }

                if (p.Info.Id == "VAPT-SECRET-015" && Regex.IsMatch(value, @"^\s*$")) continue;

                var (line, col) = src.Position(m.Index);
                if (!reported.Add(line)) continue;

                var finding = Finding.From(p.Info, src.RelativePath, line, col, Mask(src.Snippet(line), value), Source, sev, detail);
                if (isTestOrDoc && finding.Severity > Severity.Low)
                    finding.Severity = finding.Severity - 1; // still worth knowing, but less likely to be live
                yield return finding;
            }
        }
    }

    private static bool IsPlaceholder(string value)
    {
        var v = value.Trim().Trim('"', '\'');
        if (v.Length == 0) return true;
        if (PlaceholderValues.Contains(v)) return true;
        var lower = v.ToLowerInvariant();
        if (PlaceholderFragments.Any(lower.Contains)) return true;
        if (Regex.IsMatch(v, @"^(.)\1+$")) return true; // "aaaaaaa" / "*******"
        return false;
    }

    private static string Mask(string snippet, string secret)
    {
        secret = secret.Trim();
        if (secret.Length < 4) return snippet;
        var visible = secret.Length > 12 ? 4 : 2;
        var masked = secret[..visible] + new string('*', Math.Min(12, secret.Length - visible));
        return snippet.Replace(secret, masked);
    }

    public static double ShannonEntropy(string s)
    {
        if (s.Length == 0) return 0;
        return -s.GroupBy(c => c)
                 .Select(g => (double)g.Count() / s.Length)
                 .Sum(p => p * Math.Log2(p));
    }
}
