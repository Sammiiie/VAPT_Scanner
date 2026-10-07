using System.Text.RegularExpressions;
using VaptScanner.Core;
using static VaptScanner.Analyzers.CodeHelpers;

namespace VaptScanner.Analyzers;

/// <summary>
/// Static analysis rules for C#, Razor and JavaScript. Each rule maps to a CWE and an OWASP Top 10 (2021) category.
/// </summary>
public static class CodeRules
{
    private static readonly string[] Cs = { ".cs" };
    private static readonly string[] CsAndViews = { ".cs", ".cshtml", ".razor" };
    private static readonly string[] Views = { ".cshtml", ".razor" };
    private static readonly string[] Script = { ".js", ".ts", ".jsx", ".tsx", ".cshtml", ".razor", ".html" };

    private const string A01 = "A01:2021 Broken Access Control";
    private const string A02 = "A02:2021 Cryptographic Failures";
    private const string A03 = "A03:2021 Injection";
    private const string A04 = "A04:2021 Insecure Design";
    private const string A05 = "A05:2021 Security Misconfiguration";
    private const string A07 = "A07:2021 Identification and Authentication Failures";
    private const string A08 = "A08:2021 Software and Data Integrity Failures";
    private const string A09 = "A09:2021 Security Logging and Monitoring Failures";
    private const string A10 = "A10:2021 Server-Side Request Forgery";

    private static readonly Regex SensitiveContext = new(
        @"(?i)(token|password|passwd|\botp|salt\b|secret|nonce|apikey|api_key|resetcode|verification|\bpin\b|\bkey\b|sessionid|captcha)",
        RegexOptions.Compiled);

    public static IReadOnlyList<PatternRule> All { get; } = Build();

    private static PatternRule R(string id, string title, Severity sev, string category, string cwe, string owasp,
        string description, string remediation, string pattern, string[] extensions,
        Func<SourceText, Match, RuleCheck?>? check = null, bool raw = false) => new()
    {
        Info = new RuleInfo(id, title, sev, category, description, remediation, cwe, owasp),
        Pattern = PatternRule.Rx(pattern),
        Extensions = extensions,
        Check = check,
        MatchRaw = raw
    };

    private static Func<SourceText, Match, RuleCheck?> FirstArgDynamic(bool requireSql = false, bool assignment = false) =>
        (src, m) =>
        {
            var arg = ExtractArgument(src.NoComments, m.Index + m.Length, assignment);
            if (!IsDynamicString(arg)) return null;
            if (requireSql && !ContainsSqlKeyword(arg)) return null;
            return RuleCheck.Accept;
        };

    private static Func<SourceText, Match, RuleCheck?> NotPrecededBy(string pattern, int window = 400)
    {
        var rx = new Regex(pattern, RegexOptions.Compiled);
        return (src, m) => rx.IsMatch(Window(src.NoComments, m.Index, window, 0)) ? null : RuleCheck.Accept;
    }

    private static List<PatternRule> Build() => new()
    {
        // ───────────────────────────── Injection ─────────────────────────────
        R("VAPT-SQL-001", "SQL query built from runtime values passed to a database API", Severity.Critical, "SQL Injection",
            "CWE-89", A03,
            "A SQL command/raw query receives a string assembled with concatenation, interpolation or string.Format. If any part comes from user input an attacker can change the query.",
            "Use parameters: SqlCommand.Parameters.Add/AddWithValue, Dapper anonymous-object parameters, or EF Core FromSql/FromSqlInterpolated/ExecuteSql (which parameterise interpolation holes). Never use FromSqlRaw/ExecuteSqlRaw with concatenated input.",
            @"\bnew\s+(?:Sql|Npgsql|MySql|Oracle|Sqlite|SQLite|SqlCe|OleDb|Odbc|DB2|Fb)Command\s*\(|\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw)\s*(?:<[^>()]*>)?\s*\(",
            Cs, FirstArgDynamic()),

        R("VAPT-SQL-002", "SQL CommandText assigned from a runtime-built string", Severity.Critical, "SQL Injection",
            "CWE-89", A03,
            "CommandText is set to a string built from variables, so the statement shape can be controlled by input.",
            "Keep CommandText a constant with @parameters and bind values through command.Parameters.",
            @"\.CommandText\s*=(?!=)", Cs, FirstArgDynamic(assignment: true)),

        R("VAPT-SQL-003", "Dapper / micro-ORM query built from runtime values", Severity.Critical, "SQL Injection",
            "CWE-89", A03,
            "A Query/Execute call receives SQL assembled from variables.",
            "Pass values as parameters: connection.Query<T>(\"... WHERE Id = @id\", new { id }).",
            @"\.(?:Query|QueryAsync|QueryFirst|QueryFirstOrDefault|QuerySingle|QuerySingleOrDefault|QueryMultiple|Execute|ExecuteScalar|ExecuteReader)(?:Async)?\s*(?:<[^>()]*>)?\s*\(",
            Cs, FirstArgDynamic(requireSql: true)),

        R("VAPT-SQL-004", "SQL statement assembled with string interpolation", Severity.High, "SQL Injection",
            "CWE-89", A03,
            "An interpolated string that starts with a SQL statement inserts values directly into the SQL text.",
            "Move values into parameters. With EF Core, pass the interpolated string straight to FromSql/ExecuteSql (they parameterise holes); never store it in a variable first.",
            @"(?:\$@?|@\$)""\s*(?i:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|EXEC(?:UTE)?|MERGE)\b[^""]*\{[^}]+\}",
            Cs, NotPrecededBy(@"\b(?:FromSql|FromSqlInterpolated|ExecuteSql|ExecuteSqlInterpolated|ExecuteSqlAsync|ExecuteSqlInterpolatedAsync|SqlQuery)\s*(?:<[^>()]*>)?\s*\(\s*$", 80)),

        R("VAPT-SQL-005", "SQL statement assembled with string concatenation or string.Format", Severity.High, "SQL Injection",
            "CWE-89", A03,
            "A SQL statement is concatenated with a variable or formatted with string.Format.",
            "Use a constant SQL string with @parameters and bind values separately.",
            @"""\s*(?i:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|EXEC(?:UTE)?)\b[^""\n]*""\s*\+\s*(?!\s*"")[A-Za-z_@(]|\b(?:string|String)\.Format\s*\(\s*@?""\s*(?i:SELECT|INSERT|UPDATE|DELETE|EXEC)\b",
            Cs, (src, m) => IsConstLike(src.NoComments, m) ? null : RuleCheck.Accept),

        R("VAPT-CMD-001", "OS command built from runtime values", Severity.High, "Command Injection",
            "CWE-78", A03,
            "Process.Start / ProcessStartInfo receives a command or arguments assembled at runtime. Shell metacharacters in input can run arbitrary commands.",
            "Avoid shells (cmd /c, sh -c). Use ProcessStartInfo.ArgumentList to pass each argument separately, and validate input against a strict allowlist.",
            @"\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\s*\(|\.Arguments\s*=(?!=)",
            Cs, (src, m) =>
            {
                bool assignment = m.Value.Contains("Arguments");
                var text = src.NoComments;
                var args = assignment
                    ? new List<string> { ExtractArgument(text, m.Index + m.Length, true) }
                    : ExtractArguments(text, m.Index + m.Length - 1);
                if (!args.Take(2).Any(IsDynamicString)) return null;
                var stmt = Statement(text, m.Index);
                bool shell = Regex.IsMatch(Window(text, m.Index, 300, 300), @"(?i)""(?:cmd(?:\.exe)?|/bin/(?:ba)?sh|sh|bash|powershell(?:\.exe)?|pwsh)""");
                return shell ? new RuleCheck(Severity.Critical, "A shell interpreter is invoked, so injection is directly exploitable.") : RuleCheck.Accept;
            }),

        R("VAPT-PATH-001", "Uploaded file name used to build a file path", Severity.High, "Path Traversal",
            "CWE-22", A01,
            "IFormFile.FileName is attacker-controlled (e.g. \"../../web.config\"). Using it in a path lets uploads overwrite files outside the target folder.",
            "Generate the stored name yourself (Path.GetRandomFileName() + allowlisted extension) and keep the original name only as metadata. Validate the final full path starts with the upload root.",
            @"(?:\bPath\.(?:Combine|Join)|\bFile\.\w+|\bnew\s+FileStream)\s*\([^;]{0,300}?\.FileName\b",
            Cs, (src, m) => Regex.IsMatch(m.Value, @"GetFileName\s*\(|GetRandomFileName|GetFileNameWithoutExtension") ? null : RuleCheck.Accept),

        R("VAPT-PATH-002", "Request data used directly in a file system path", Severity.High, "Path Traversal",
            "CWE-22", A01,
            "Query string, form or route values flow straight into a file API, allowing ../ traversal to read or write arbitrary files.",
            "Map user input to an allowlist of known files or IDs. If a name is unavoidable, use Path.GetFileName, combine with a fixed root, call Path.GetFullPath and verify the result starts with the root.",
            @"(?:\bPath\.(?:Combine|Join)|\bFile\.\w+|\bDirectory\.\w+|\bnew\s+FileStream|\bPhysicalFile|\bFile\s*\()\s*\([^;]{0,300}?Request\.(?:Query|Form|Headers|RouteValues|Cookies)",
            Cs),

        R("VAPT-PATH-003", "Archive entry path used without validation (Zip Slip)", Severity.Medium, "Path Traversal",
            "CWE-22", A01,
            "Combining an extraction folder with ZipArchiveEntry.FullName lets crafted archives write outside the folder.",
            "After Path.Combine, call Path.GetFullPath and reject entries whose full path doesn't start with the destination directory.",
            @"\bPath\.(?:Combine|Join)\s*\([^;]{0,200}?\.FullName\b",
            Cs, (src, m) =>
            {
                if (!Regex.IsMatch(src.NoComments, @"\bZip(?:Archive|File)\b|\bTarEntry\b|\bIArchiveEntry\b")) return null;
                var after = Window(src.NoComments, m.Index, 0, 600);
                return Regex.IsMatch(after, @"GetFullPath[\s\S]{0,300}StartsWith") ? null : RuleCheck.Accept;
            }),

        R("VAPT-LDAP-001", "LDAP filter built from runtime values", Severity.High, "LDAP Injection",
            "CWE-90", A03,
            "An LDAP search filter is assembled from variables; characters like *)( can widen the query or bypass authentication.",
            "Escape values per RFC 4515 (\\2a, \\28, \\29, \\5c, \\00) before inserting them into filters, or validate against a strict pattern.",
            @"\bnew\s+DirectorySearcher\s*\(|\.Filter\s*=(?!=)",
            Cs, (src, m) =>
            {
                bool assignment = m.Value.Contains("Filter");
                if (assignment && !Regex.IsMatch(src.NoComments, @"\bDirectorySearcher\b|System\.DirectoryServices")) return null;
                var arg = ExtractArgument(src.NoComments, m.Index + m.Length, assignment);
                return IsDynamicString(arg) && arg.Contains('=') ? RuleCheck.Accept : null;
            }),

        R("VAPT-XPATH-001", "XPath expression built from runtime values", Severity.High, "XPath Injection",
            "CWE-643", A03,
            "An XPath query is assembled from variables, letting input change which nodes are selected.",
            "Use XPath variables via XsltArgumentList / a custom XsltContext, or validate input against a strict allowlist.",
            @"\.(?:SelectNodes|SelectSingleNode|XPathSelectElements?|XPathEvaluate|Compile)\s*\(",
            Cs, (src, m) =>
            {
                var arg = ExtractArgument(src.NoComments, m.Index + m.Length);
                return IsDynamicString(arg) && Regex.IsMatch(arg, @"[/@\[]") ? RuleCheck.Accept : null;
            }),

        R("VAPT-REGEX-001", "Regular expression built from runtime input without a timeout", Severity.Medium, "Denial of Service",
            "CWE-1333", A04,
            "A regex pattern assembled from input can be crafted to backtrack catastrophically (ReDoS) and pin CPU.",
            "Regex.Escape user input, pass a matchTimeout (e.g. TimeSpan.FromSeconds(1)), or use RegexOptions.NonBacktracking on .NET 7+.",
            @"\bnew\s+Regex\s*\(|\bRegex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\(",
            Cs, (src, m) =>
            {
                var args = ExtractArguments(src.NoComments, m.Index + m.Length - 1);
                int patternIndex = m.Value.StartsWith("new") ? 0 : 1;
                if (args.Count <= patternIndex) return null;
                var pattern = args[patternIndex];
                if (pattern.Contains("Regex.Escape")) return null;
                if (!IsDynamicString(pattern)) return null;
                return args.Any(a => a.Contains("TimeSpan") || a.Contains("NonBacktracking")) ? null : RuleCheck.Accept;
            }),

        R("VAPT-CODE-001", "Dynamic code evaluation", Severity.High, "Code Injection",
            "CWE-94", A03,
            "Runtime compilation/evaluation of a string built from variables can execute attacker-supplied code.",
            "Don't evaluate user-provided code. Use a data-driven approach (expression trees, rule tables) or a sandboxed interpreter with strict limits.",
            @"\bCSharpScript\.(?:EvaluateAsync|RunAsync|Create)\s*(?:<[^>()]*>)?\s*\(|\bCSharpSyntaxTree\.ParseText\s*\(",
            Cs, FirstArgDynamic()),

        // ───────────────────────────── XSS ─────────────────────────────
        R("VAPT-XSS-001", "Html.Raw renders unencoded HTML", Severity.Medium, "Cross-Site Scripting",
            "CWE-79", A03,
            "Html.Raw bypasses Razor's automatic HTML encoding. If the value contains user data, scripts can be injected.",
            "Remove Html.Raw and let Razor encode output. If HTML is genuinely required, sanitise it with an allowlist sanitiser such as HtmlSanitizer (Ganss.Xss) first.",
            @"@?Html\.Raw\s*\(",
            Views, (src, m) =>
            {
                var arg = ExtractArgument(src.NoComments, m.Index + m.Length);
                if (IsPureLiteral(arg)) return null;
                if (Regex.IsMatch(arg, @"(?i)Sanitiz")) return null;
                return Regex.IsMatch(arg, @"\b(?:Model|ViewBag|ViewData|Request|TempData)\b")
                    ? new RuleCheck(Severity.High, "The value comes from the model/request, which is commonly user-influenced.")
                    : RuleCheck.Accept;
            }),

        R("VAPT-XSS-002", "Unencoded HTML/markup string created from runtime value", Severity.Medium, "Cross-Site Scripting",
            "CWE-79", A03,
            "HtmlString / MarkupString marks content as already-safe, so it's rendered without encoding.",
            "Only wrap content you generated and sanitised. Prefer plain strings so Razor/Blazor encodes them.",
            @"\bnew\s+(?:HtmlString|MarkupString)\s*\(|\(\s*MarkupString\s*\)\s*",
            CsAndViews, (src, m) =>
            {
                var arg = m.Value.StartsWith("(") ? ExtractArgument(src.NoComments, m.Index + m.Length, true) : ExtractArgument(src.NoComments, m.Index + m.Length);
                return IsPureLiteral(arg) || Regex.IsMatch(arg, @"(?i)Sanitiz|Encode") ? null : RuleCheck.Accept;
            }),

        R("VAPT-XSS-003", "Request data written directly to the response", Severity.High, "Cross-Site Scripting",
            "CWE-79", A03,
            "Values from the request are written to the response without encoding, a classic reflected XSS.",
            "Encode with HtmlEncoder.Default.Encode / WebUtility.HtmlEncode, or return the value through a Razor view or JSON result.",
            @"\bResponse\.Write(?:Async)?\s*\([^;]{0,200}?Request\.(?:Query|Form|QueryString|Params|Headers|Cookies)|\bContent\s*\([^;]{0,200}?Request\.(?:Query|Form)[^;]*text/html",
            Cs, (src, m) => Regex.IsMatch(m.Value, @"(?i)Encode") ? null : RuleCheck.Accept),

        R("VAPT-XSS-004", "DOM sink assigned dynamic HTML", Severity.Medium, "Cross-Site Scripting",
            "CWE-79", A03,
            "innerHTML/outerHTML/insertAdjacentHTML/document.write interpret strings as HTML; untrusted data becomes executable script.",
            "Use textContent / innerText, create elements with DOM APIs, or sanitise with DOMPurify before inserting HTML.",
            @"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\.insertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(",
            Script, (src, m) =>
            {
                var rest = Window(src.NoComments, m.Index + m.Length, 0, 300);
                var expr = rest.Split(';', '\n')[0].Trim();
                if (Regex.IsMatch(expr, @"^(['""`])[^'""`$+]*\1\s*\)?$")) return null; // plain literal, e.g. innerHTML = ''
                if (Regex.IsMatch(expr, @"(?i)DOMPurify|sanitiz|escapeHtml|encode")) return null;
                return RuleCheck.Accept;
            }),

        R("VAPT-JS-001", "JavaScript eval / Function constructor", Severity.Medium, "Code Injection",
            "CWE-95", A03,
            "eval, new Function and string arguments to setTimeout/setInterval execute strings as code.",
            "Parse data with JSON.parse and pass functions, not strings, to timers.",
            @"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['""`]",
            Script),

        R("VAPT-JS-002", "Auth token stored in Web Storage", Severity.Low, "Sensitive Data Exposure",
            "CWE-922", A07,
            "Tokens in localStorage/sessionStorage are readable by any script on the page, so a single XSS steals the session.",
            "Prefer HttpOnly, Secure, SameSite cookies for session tokens, or keep tokens in memory with short lifetimes.",
            @"\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*['""`][^'""`]*(?i:token|jwt|auth|session|bearer)",
            Script),

        // ───────────────────────────── Deserialization ─────────────────────────────
        R("VAPT-DESER-001", "Insecure formatter (BinaryFormatter and friends)", Severity.Critical, "Insecure Deserialization",
            "CWE-502", A08,
            "BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter and ObjectStateFormatter can execute code when deserialising untrusted data. BinaryFormatter is removed from .NET 9.",
            "Replace with System.Text.Json or a schema-bound serializer (DataContractSerializer with known types, protobuf). Never deserialize untrusted data with these types.",
            @"\b(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\b(?!\s*\.\s*nameof)",
            Cs, (src, m) => src.LineText(src.Position(m.Index).line).TrimStart().StartsWith("using ") ? null : RuleCheck.Accept),

        R("VAPT-DESER-002", "Json.NET TypeNameHandling enabled", Severity.High, "Insecure Deserialization",
            "CWE-502", A08,
            "TypeNameHandling other than None lets the JSON payload pick the .NET type to instantiate, enabling gadget-chain RCE.",
            "Use TypeNameHandling.None. If polymorphism is required, use a custom ISerializationBinder that allowlists exact types, or System.Text.Json [JsonDerivedType].",
            @"\bTypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b",
            Cs, (src, m) => Regex.IsMatch(Window(src.NoComments, m.Index, 600, 600), @"SerializationBinder\s*=") ? new RuleCheck(Severity.Medium, "A SerializationBinder is set nearby - verify it allowlists exact types.") : RuleCheck.Accept),

        R("VAPT-DESER-003", "JavaScriptSerializer with type resolver", Severity.High, "Insecure Deserialization",
            "CWE-502", A08,
            "JavaScriptSerializer with SimpleTypeResolver allows the payload to choose arbitrary types.",
            "Drop the type resolver or move to System.Text.Json.",
            @"\bnew\s+JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver",
            Cs),

        R("VAPT-DESER-004", "Serializer type chosen from runtime string", Severity.Medium, "Insecure Deserialization",
            "CWE-502", A08,
            "Creating a serializer for Type.GetType(input) lets callers deserialize into unexpected types.",
            "Map allowed type names to types through an explicit dictionary.",
            @"\bnew\s+(?:XmlSerializer|DataContractSerializer|DataContractJsonSerializer)\s*\(\s*Type\.GetType\s*\(",
            Cs),

        R("VAPT-XXE-001", "XML parser allows DTDs / external entities", Severity.High, "XML External Entities",
            "CWE-611", A05,
            "Enabling DTD processing or an XmlUrlResolver lets crafted XML read local files or make server-side requests (XXE).",
            "Keep DtdProcessing = DtdProcessing.Prohibit (default) and XmlResolver = null.",
            @"\bDtdProcessing\s*=\s*DtdProcessing\.Parse\b|\bXmlResolver\s*=\s*new\s+XmlUrlResolver\b|\bProhibitDtd\s*=\s*false\b",
            Cs),

        // ───────────────────────────── Cryptography ─────────────────────────────
        R("VAPT-CRYPTO-001", "Weak hash algorithm (MD5 / SHA-1)", Severity.Medium, "Weak Cryptography",
            "CWE-328", A02,
            "MD5 and SHA-1 are broken for collision resistance and far too fast for password storage.",
            "Use SHA-256+ for integrity. For passwords use ASP.NET Core Identity's PasswordHasher, PBKDF2 (Rfc2898DeriveBytes.Pbkdf2, SHA-256, ≥600k iterations), bcrypt or Argon2.",
            @"\b(?:MD5|SHA1)\.(?:Create|HashData|HashDataAsync)\b|\bnew\s+(?:MD5CryptoServiceProvider|SHA1CryptoServiceProvider|SHA1Managed|MD5Cng|SHA1Cng|HMACMD5|HMACSHA1)\b|\bHashAlgorithmName\.(?:MD5|SHA1)\b",
            Cs, (src, m) =>
            {
                if (Regex.IsMatch(Window(src.NoComments, m.Index, 500, 500), @"(?i)password|passwd|pwd"))
                    return new RuleCheck(Severity.High, "It appears to be used for passwords.");
                return RuleCheck.Accept;
            }),

        R("VAPT-CRYPTO-002", "Broken cipher (DES / 3DES / RC2)", Severity.High, "Weak Cryptography",
            "CWE-327", A02,
            "DES, TripleDES and RC2 have small block or key sizes and are deprecated.",
            "Use AES-GCM (AesGcm) or AES-CBC with HMAC (encrypt-then-MAC). Prefer ASP.NET Core Data Protection for app-level encryption.",
            @"\b(?:DES|TripleDES|RC2)\.Create\b|\bnew\s+(?:DES|TripleDES|RC2)CryptoServiceProvider\b",
            Cs),

        R("VAPT-CRYPTO-003", "ECB cipher mode", Severity.High, "Weak Cryptography",
            "CWE-327", A02,
            "ECB encrypts identical blocks to identical ciphertext, leaking data patterns.",
            "Use AesGcm, or CBC with a random IV per message plus an HMAC.",
            @"\bCipherMode\.ECB\b|\.(?:EncryptEcb|DecryptEcb)\s*\(",
            Cs),

        R("VAPT-CRYPTO-004", "Hard-coded encryption key or IV", Severity.High, "Weak Cryptography",
            "CWE-321", A02,
            "Keys/IVs embedded in source are visible to anyone with the code or binaries and can't be rotated.",
            "Load keys from a secret store (Azure Key Vault, AWS KMS, Data Protection key ring) and generate a fresh random IV per encryption with RandomNumberGenerator.",
            @"\.(?:Key|IV)\s*=\s*(?:Encoding\.\w+\.GetBytes\s*\(\s*@?""|new\s+byte\s*\[\s*\d*\s*\]\s*\{|Convert\.From(?:Base64|Hex)String\s*\(\s*"")|\bnew\s+(?:AesGcm|AesCcm|ChaCha20Poly1305|HMACSHA256|HMACSHA512)\s*\(\s*(?:Encoding\.\w+\.GetBytes\s*\(\s*""|new\s+byte\s*\[\s*\d*\s*\]\s*\{|Convert\.FromBase64String\s*\(\s*"")",
            Cs),

        R("VAPT-CRYPTO-005", "Non-cryptographic random used for security value", Severity.Medium, "Weak Randomness",
            "CWE-338", A02,
            "System.Random is predictable. Tokens, OTPs, salts, keys or reset codes generated with it can be guessed.",
            "Use RandomNumberGenerator.GetBytes / RandomNumberGenerator.GetInt32 for anything security-sensitive.",
            @"\bnew\s+Random\s*\(|\bRandom\.Shared\b",
            Cs, (src, m) =>
            {
                var text = src.NoComments;
                var context = new System.Text.StringBuilder(RemoveStringLiterals(Statement(text, m.Index)));
                // Statements that use the variable holding the Random instance.
                var decl = Regex.Match(Window(text, m.Index, 80, 0), @"(\w+)\s*=\s*$");
                if (decl.Success)
                {
                    var after = Window(text, m.Index, 0, 600);
                    foreach (Match use in Regex.Matches(after, $@"[^;{{}}]*\b{Regex.Escape(decl.Groups[1].Value)}\b[^;]*;"))
                        context.Append(' ').Append(RemoveStringLiterals(use.Value));
                }
                // Name of the enclosing member, e.g. GenerateResetToken().
                var member = Regex.Matches(Window(text, m.Index, 800, 0), @"\b(\w+)\s*\([^()]*\)\s*(?:=>|\{)");
                if (member.Count > 0) context.Append(' ').Append(member[^1].Groups[1].Value);
                return SensitiveContext.IsMatch(context.ToString()) ? RuleCheck.Accept : null;
            }),

        R("VAPT-CRYPTO-006", "Weak PBKDF2 configuration", Severity.Medium, "Weak Cryptography",
            "CWE-916", A02,
            "Rfc2898DeriveBytes without an explicit hash defaults to SHA-1, and low iteration counts make offline cracking cheap.",
            "Use Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32) or ASP.NET Core Identity's PasswordHasher.",
            @"\bnew\s+Rfc2898DeriveBytes\s*\(|\bRfc2898DeriveBytes\.Pbkdf2\s*\(",
            Cs, (src, m) =>
            {
                var args = ExtractArguments(src.NoComments, m.Index + m.Length - 1);
                var problems = new List<string>();
                if (!args.Any(a => a.Contains("HashAlgorithmName"))) problems.Add("no hash algorithm specified (defaults to SHA-1)");
                else if (args.Any(a => Regex.IsMatch(a, @"HashAlgorithmName\.(?:SHA1|MD5)\b"))) problems.Add("uses SHA-1/MD5");
                if (args.Count == 2) problems.Add("default of 1,000 iterations (OWASP recommends ≥600,000 for SHA-256)");
                else if (args.Count >= 3 && int.TryParse(args[2].Replace("_", ""), out int n) && n < 100_000)
                    problems.Add($"only {n:N0} iterations (OWASP recommends ≥600,000 for SHA-256)");
                return problems.Count == 0 ? null : new RuleCheck(Detail: "Problem: " + string.Join("; ", problems) + ".");
            }),

        // ───────────────────────────── Transport / TLS ─────────────────────────────
        R("VAPT-TLS-001", "TLS certificate validation disabled", Severity.High, "Insecure Transport",
            "CWE-295", A07,
            "Accepting every server certificate makes HTTPS trivially interceptable (man-in-the-middle).",
            "Remove the callback. For self-signed dev certs, trust the cert on the machine or pin the specific certificate thumbprint, and only in Development.",
            @"\b(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|RemoteCertificateValidationCallback)\s*\+?=\s*[^;]*?=>\s*(?:true\b|\{\s*return\s+true\s*;)|\bDangerousAcceptAnyServerCertificateValidator\b|\bCheckCertificateRevocationList\s*=\s*false\b",
            Cs, (src, m) => m.Value.Contains("CheckCertificateRevocationList") ? new RuleCheck(Severity.Low, "Revocation checking is disabled.") : RuleCheck.Accept),

        R("VAPT-TLS-002", "Obsolete SSL/TLS protocol enabled", Severity.High, "Insecure Transport",
            "CWE-326", A02,
            "SSL 3.0, TLS 1.0 and TLS 1.1 are deprecated and vulnerable (POODLE, BEAST).",
            "Don't pin protocols - let the OS choose (SslProtocols.None / SystemDefault), or require Tls12 | Tls13.",
            @"\b(?:SecurityProtocolType|SslProtocols)\.(?:Ssl2|Ssl3|Tls|Tls11)\b",
            Cs),

        R("VAPT-TLS-003", "Cleartext HTTP endpoint in code", Severity.Low, "Insecure Transport",
            "CWE-319", A02,
            "Hard-coded http:// URLs send data, cookies and tokens unencrypted.",
            "Use https:// and move endpoints into configuration.",
            @"""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\+|\*|schemas\.|www\.w3\.org|json-schema\.org|tempuri\.org|purl\.org|ns\.adobe|xmlns\.)[^""\s]+""",
            Cs),

        // ───────────────────────────── ASP.NET Core configuration ─────────────────────────────
        R("VAPT-WEB-001", "CORS allows any origin", Severity.Medium, "Security Misconfiguration",
            "CWE-942", A05,
            "AllowAnyOrigin lets every website call this API from a victim's browser.",
            "Restrict with WithOrigins(\"https://app.example.com\") per environment.",
            @"\.AllowAnyOrigin\s*\(\s*\)",
            Cs, (src, m) => Regex.IsMatch(src.NoComments, @"\.AllowCredentials\s*\(") ? new RuleCheck(Severity.High, "Credentials are also allowed in this file.") : RuleCheck.Accept),

        R("VAPT-WEB-002", "CORS reflects every origin", Severity.High, "Security Misconfiguration",
            "CWE-942", A05,
            "SetIsOriginAllowed(_ => true) or a wildcard origin echoes any Origin header - with credentials this lets any site act as the logged-in user.",
            "Validate origins against an explicit allowlist.",
            @"\.SetIsOriginAllowed\s*\(\s*\(?\s*\w*\s*\)?\s*=>\s*true\s*\)|\.WithOrigins\s*\(\s*""\*""\s*\)",
            Cs),

        R("VAPT-WEB-003", "Developer exception page not limited to Development", Severity.Medium, "Information Disclosure",
            "CWE-209", A05,
            "The developer exception page shows stack traces, source snippets and configuration to anyone who triggers an error.",
            "Wrap it: if (app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage(); else app.UseExceptionHandler(\"/error\");",
            @"\.UseDeveloperExceptionPage\s*\(\s*\)",
            Cs, NotPrecededBy(@"IsDevelopment\s*\(\s*\)|IsEnvironment\s*\(\s*""Development""", 400)),

        R("VAPT-WEB-004", "EF Core sensitive data logging enabled", Severity.Medium, "Information Disclosure",
            "CWE-532", A09,
            "EnableSensitiveDataLogging writes parameter values (passwords, PII) to logs.",
            "Only enable it under IsDevelopment().",
            @"\.EnableSensitiveDataLogging\s*\(\s*(?:true\s*)?\)",
            Cs, NotPrecededBy(@"IsDevelopment\s*\(\s*\)", 600)),

        R("VAPT-WEB-005", "Anti-forgery validation disabled", Severity.Medium, "Cross-Site Request Forgery",
            "CWE-352", A01,
            "Endpoints without anti-forgery validation can be triggered from another site using the victim's cookies.",
            "Remove [IgnoreAntiforgeryToken]/.DisableAntiforgery() for cookie-authenticated endpoints; use [AutoValidateAntiforgeryToken] globally.",
            @"\[\s*IgnoreAntiforgeryToken\b|\.DisableAntiforgery\s*\(",
            Cs),

        R("VAPT-WEB-006", "Insecure cookie flags", Severity.Medium, "Session Management",
            "CWE-614", A05,
            "Cookies without HttpOnly can be stolen by XSS; without Secure they travel over HTTP.",
            "Set HttpOnly = true, Secure = true (CookieSecurePolicy.Always) and SameSite = Lax or Strict.",
            @"\bHttpOnly\s*=\s*false\b|(?<![\w.])Secure\s*=\s*false\b|\bCookieSecurePolicy\.None\b|\bSameSite\s*=\s*SameSiteMode\.None\b|\bHttpOnly\s*=\s*HttpOnlyPolicy\.None\b",
            Cs, (src, m) => m.Value.Contains("SameSite") ? new RuleCheck(Severity.Low, "SameSite=None weakens CSRF protection; make sure it's required and paired with Secure.") : RuleCheck.Accept),

        R("VAPT-WEB-007", "JWT signature or lifetime validation disabled", Severity.Critical, "Broken Authentication",
            "CWE-347", A07,
            "With signing-key or lifetime validation off, forged or expired tokens are accepted.",
            "Set ValidateIssuerSigningKey, ValidateLifetime, RequireSignedTokens and RequireExpirationTime to true.",
            @"\b(?:ValidateIssuerSigningKey|ValidateLifetime|RequireSignedTokens|RequireExpirationTime)\s*=\s*false\b",
            Cs),

        R("VAPT-WEB-008", "JWT issuer / audience validation disabled", Severity.Medium, "Broken Authentication",
            "CWE-287", A07,
            "Tokens minted for other apps or issuers sharing the key would be accepted.",
            "Validate issuer and audience against configured values.",
            @"\b(?:ValidateIssuer|ValidateAudience)\s*=\s*false\b",
            Cs),

        R("VAPT-WEB-009", "HTTPS metadata requirement disabled", Severity.Medium, "Broken Authentication",
            "CWE-319", A07,
            "RequireHttpsMetadata = false lets signing keys be fetched over HTTP, where they can be tampered with.",
            "Only disable in Development.",
            @"\bRequireHttpsMetadata\s*=\s*false\b",
            Cs, NotPrecededBy(@"IsDevelopment\s*\(", 600)),

        R("VAPT-WEB-010", "Possible open redirect", Severity.Medium, "Open Redirect",
            "CWE-601", A01,
            "Redirecting to a caller-supplied URL lets attackers bounce users from your trusted domain to phishing pages.",
            "Use LocalRedirect(returnUrl) or check Url.IsLocalUrl(returnUrl) before Redirect.",
            @"\bRedirect(?:Permanent)?\s*\(\s*(?:(?i:returnurl|redirecturl|redirecturi|returnto|url|next|target|goto|dest|destination|continue)\b|Request\.)",
            Cs, NotPrecededBy(@"IsLocalUrl\s*\(|IsWellFormedUriString|IsAllowedRedirect|AllowedRedirect", 600)),

        R("VAPT-WEB-011", "Exception details returned to the client", Severity.Medium, "Information Disclosure",
            "CWE-209", A05,
            "Stack traces and exception text reveal internals (paths, SQL, library versions) that help attackers.",
            "Log the exception server-side and return a generic ProblemDetails with a correlation id.",
            @"\breturn\s+(?:Ok|BadRequest|StatusCode|Content|Problem|Json|NotFound|UnprocessableEntity|Results\.\w+|TypedResults\.\w+)\s*\([^;]{0,300}?\b(?:ex|e|exc|exception|err|error)\.(?:StackTrace|ToString\s*\(\s*\)|Message|InnerException)",
            Cs, (src, m) => Regex.IsMatch(m.Value, @"\.Message\b") && !Regex.IsMatch(m.Value, @"StackTrace|ToString|InnerException")
                ? new RuleCheck(Severity.Low, "Only the message is exposed, which still can leak internals.") : RuleCheck.Accept),

        R("VAPT-WEB-012", "Request validation disabled", Severity.Medium, "Cross-Site Scripting",
            "CWE-20", A03,
            "[ValidateInput(false)] / [AllowHtml] lets raw HTML through model binding.",
            "Remove it, or sanitise the specific field with an HTML sanitiser.",
            @"\[\s*ValidateInput\s*\(\s*false\s*\)\s*\]|\[\s*AllowHtml\s*\]",
            Cs),

        R("VAPT-WEB-013", "Sensitive data written to logs", Severity.Medium, "Information Disclosure",
            "CWE-532", A09,
            "Passwords, tokens or card data in logs are visible to anyone with log access and usually kept for a long time.",
            "Log identifiers, not secrets. Use [LogProperties]/redaction (Microsoft.Extensions.Compliance.Redaction) for sensitive fields.",
            @"\b(?:_?logger|_?log|Log|logger)\w*\.(?:Log\w*|Information|Debug|Warning|Error|Trace|Fatal|Verbose|Critical|Info|Warn)\s*\(",
            Cs, (src, m) =>
            {
                var stmt = ExtractArgument(src.NoComments, m.Index + m.Length, true);
                var codeOnly = RemoveStringLiterals(stmt);
                return Regex.IsMatch(codeOnly, @"(?i)\b\w*(?:password|passwd|pwd|secret|apikey|api_key|accesstoken|access_token|refreshtoken|bearertoken|creditcard|cardnumber|cvv|ssn)\w*\b") ? RuleCheck.Accept : null;
            }),

        R("VAPT-SSRF-001", "Outbound request to a URL taken from the request", Severity.High, "Server-Side Request Forgery",
            "CWE-918", A10,
            "The server fetches a URL supplied by the caller, which can be pointed at internal services or cloud metadata endpoints (169.254.169.254).",
            "Allowlist hosts/schemes, resolve and block private IP ranges, and disable redirects for user-supplied URLs.",
            @"\b(?:GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|PutAsync|SendAsync|DownloadString\w*|DownloadData\w*|DownloadFile\w*|OpenRead\w*)\s*\(\s*(?:new\s+Uri\s*\(\s*)?Request\.(?:Query|Form|Headers|RouteValues)",
            Cs),

        R("VAPT-AUTH-001", "Hard-coded credential comparison", Severity.High, "Hard-coded Credentials",
            "CWE-798", A07,
            "Comparing a password/key to a literal embeds a backdoor credential in the code.",
            "Store credential hashes in a user store and verify with a slow hash; keep API keys in a secret manager.",
            @"\b\w*(?i:password|passwd|pwd|apikey|api_key|secret)\w*\s*==\s*""[^""]+""|""[^""]+""\s*==\s*\w*(?i:password|passwd|pwd|apikey|secret)\w*\b|\b\w*(?i:password|passwd|pwd|apikey|secret)\w*\.Equals\s*\(\s*""[^""]+""",
            Cs),

        R("VAPT-AUTH-002", "Weak password policy", Severity.Medium, "Broken Authentication",
            "CWE-521", A07,
            "Identity password options are set below sensible minimums.",
            "Require at least 12 characters (NIST 800-63B), and enable lockout (Lockout.MaxFailedAccessAttempts ≤ 10).",
            @"\bRequiredLength\s*=\s*(?<n>\d+)\b|\bLockoutEnabled\s*=\s*false\b|\bAllowedForNewUsers\s*=\s*false\b",
            Cs, (src, m) =>
            {
                if (m.Groups["n"].Success) return int.Parse(m.Groups["n"].Value) < 8 ? RuleCheck.Accept : null;
                return Regex.IsMatch(src.NoComments, @"IdentityOptions|AddIdentity|AddDefaultIdentity|Lockout") ? RuleCheck.Accept : null;
            }),

        R("VAPT-AUTH-003", "Authorization check missing on mutating endpoint (heuristic)", Severity.Low, "Broken Access Control",
            "CWE-862", A01,
            "This controller has state-changing actions but neither the class nor the action declares [Authorize], and no global fallback policy was found in this file.",
            "Add [Authorize] at controller level (opt out with [AllowAnonymous]) or configure a FallbackPolicy requiring authenticated users.",
            @"\[\s*Http(?:Post|Put|Delete|Patch)\b",
            Cs, (src, m) =>
            {
                var text = src.NoComments;
                if (!Regex.IsMatch(text, @":\s*(?:Controller|ControllerBase|ApiController)\b")) return null;
                if (Regex.IsMatch(text, @"\[\s*Authorize\b")) return null;
                if (Regex.IsMatch(Window(text, m.Index, 200, 200), @"\[\s*AllowAnonymous\b")) return null;
                return RuleCheck.Accept;
            }),
    };

    // A concatenation of only SCREAMING_CASE constants is not dynamic.
    private static bool IsConstLike(string text, Match m)
    {
        if (m.Value.Contains("Format")) return false;
        var tail = Window(text, m.Index + m.Length - 1, 0, 120);
        var ident = Regex.Match(tail, @"^[A-Za-z_@][\w.]*");
        if (!ident.Success) return false;
        var name = ident.Value.Split('.').Last();
        if (Regex.IsMatch(name, @"^[A-Z][A-Z0-9_]*$")) return true;            // SCREAMING_CASE
        if (ident.Value.StartsWith("nameof")) return true;
        return Regex.IsMatch(text, $@"\bconst\s+\w+\s+{Regex.Escape(name)}\s*=");  // declared const in this file
    }
}
