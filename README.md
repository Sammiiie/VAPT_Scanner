# VAPT Scanner for .NET

[![CI](https://github.com/Sammiiie/VAPT_Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Sammiiie/VAPT_Scanner/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/VaptScanner.svg)](https://www.nuget.org/packages/VaptScanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A command-line security gate for .NET applications. Run it on your code before a release (locally or in CI) and it
fails the build when it finds serious vulnerabilities, with a clear explanation and fix for each one.

| Module | What it checks |
|---|---|
| **SAST** (code) | SQL / command / LDAP / XPath injection, path traversal & Zip Slip, XSS (Razor, Blazor, JS), insecure deserialization, XXE, weak crypto & randomness, TLS validation bypass, CORS, JWT validation, cookies, open redirect, SSRF, sensitive logging, error leakage, missing HTTPS/HSTS |
| **Secrets** | Private keys, cloud/API tokens (AWS, Azure, GitHub, Stripe, Slack, SendGrid, OpenAI…), connection strings with passwords, high-entropy values assigned to password/secret/key names |
| **Config** | `web.config`, `appsettings*.json`, Dockerfiles, docker-compose, `.csproj` (end-of-support frameworks, disabled security analyzers) |
| **Dependencies** | Vulnerable NuGet packages (direct and transitive) via `dotnet list package --vulnerable`, with an offline fallback list |
| **DAST** (optional) | Safe baseline scan of a *running* staging site: security headers, TLS, cookies, CORS, exposed files (`.git`, `appsettings.json`, Swagger…), error pages, reflected input, directory listing |

112 rules, each mapped to a CWE and the OWASP Top 10 (2021). See [RULES.md](RULES.md).

No NuGet dependencies — it only needs the .NET 8 SDK or newer.

---

## Install

```bash
dotnet tool install --global VaptScanner
vapt scan path/to/YourApp
```

Update later with `dotnet tool update --global VaptScanner`.

## Build from source

```powershell
git clone https://github.com/Sammiiie/VAPT_Scanner.git
cd VAPT_Scanner
dotnet build -c Release

# Scan a project or solution folder
dotnet src\VaptScanner\bin\Release\net8.0\vapt.dll scan "C:\path\to\YourApp"
```

Or use the wrapper, which builds on first run and can open the HTML report:

```powershell
.\scan.ps1 -Path "C:\path\to\YourApp" -Open
```

Reports are written to `.\vapt-reports\` (`vapt-report.html` by default; add `--format all` for JSON and SARIF too).

Try it on the bundled samples to see what it finds:

```powershell
dotnet src\VaptScanner\bin\Release\net8.0\vapt.dll scan samples\VulnerableApp   # ~60 findings
dotnet src\VaptScanner\bin\Release\net8.0\vapt.dll scan samples\SafeApp         # clean
```

### Install a locally built package (optional)

```powershell
dotnet pack src\VaptScanner -c Release -o nupkg
dotnet tool install --global VaptScanner --add-source .\nupkg
vapt scan C:\path\to\YourApp
```

---

## Commands

```
vapt scan [path]                 Static scan (SAST + secrets + config + NuGet audit)
vapt dast <url> --authorized     Baseline scan of a running deployment you own
vapt baseline [path]             Accept current findings; later scans report only new ones
vapt init [path]                 Create .vaptconfig.json
vapt rules [--format md]         List all rules
```

Common options:

| Option | Default | Meaning |
|---|---|---|
| `--format` | `console,html` | Any of `console`, `html`, `json`, `sarif`, or `all` |
| `--out <dir>` | `vapt-reports` | Where report files go |
| `--fail-on <sev>` | `High` | Exit code 1 when any finding is at/above this. `None` never fails |
| `--min-severity <sev>` | `Low` | Hide findings below this |
| `--exclude <glob>` | | Skip paths, e.g. `"**/Migrations/**"` (repeatable) |
| `--disable <RULE>` | | Turn a rule off (repeatable) |
| `--no-deps` / `--offline` | | Skip the NuGet audit / use the built-in advisory list only |
| `-v`, `--verbose` | | Print the explanation and fix for each finding in the console |

**Exit codes:** `0` passed · `1` findings at/above `--fail-on` · `2` usage or runtime error.

---

## Using it as a release gate

1. **First run on an existing codebase:** fix what you can, then run `vapt baseline .` and commit
   `.vapt-baseline.json`. From then on the gate only fails on *new* issues, so you can pay down the rest over time.
2. **Add it to CI:** templates are in [`ci/`](ci/) for GitHub Actions (uploads SARIF to the Security tab) and
   Azure DevOps (works with the *SARIF SAST Scans Tab* extension).
3. **Before go-live:** deploy to staging and run `vapt dast https://staging.yourapp.com --authorized`.

### Handling false positives

Suppress a single line with a comment on that line or the one above — always say why:

```csharp
// vapt-ignore VAPT-SQL-005: table name comes from a compile-time enum, not user input
var sql = "SELECT COUNT(*) FROM " + tableName;
```

Or tune the whole project with `.vaptconfig.json` (create one with `vapt init`):

```jsonc
{
  "exclude": ["**/Migrations/**", "**/wwwroot/lib/**"],
  "disabledRules": ["VAPT-AUTH-003"],
  "severityOverrides": { "VAPT-WEB-022": "Low" },
  "failOn": "High"
}
```

---

## The DAST module

`vapt dast` sends real HTTP requests, so it **requires `--authorized`** and is meant for systems you own or have
written permission to test — ideally staging/UAT, not production. It is deliberately non-destructive: only
GET/HEAD/OPTIONS/TRACE requests, a 120-request budget, a 100 ms delay between requests, no brute force and no
exploitation attempts.

```powershell
vapt dast https://staging.yourapp.com --authorized
vapt dast https://staging.yourapp.com/search?q=test --authorized --header "Authorization: Bearer <test-user-token>"
vapt dast https://staging.yourapp.com --authorized --path /admin --path /internal/health
```

---

## What this tool is (and isn't)

It is a fast, opinionated first line of defence that catches the common, high-impact mistakes in .NET apps before
they ship. It is pattern-based rather than a full data-flow engine, so:

- It can miss vulnerabilities where tainted data travels across several methods or files.
- It reports some "review this" findings (e.g. `AUTH-003`) that may be fine in your context.
- DAST covers configuration and surface issues; it is not a substitute for an authenticated, manual penetration test.

For a production release of a sensitive system, pair it with the built-in .NET security analyzers
(`<AnalysisMode>Recommended</AnalysisMode>`), a data-flow SAST tool (e.g. CodeQL or Semgrep), and a periodic
manual pentest.

## Project layout

```
src/VaptScanner/
  Program.cs              CLI
  Core/                   Models, file walking, comment masking, suppressions, baseline, config
  Analyzers/              CodeRules (SAST), SecretsAnalyzer, ConfigAnalyzer, DependencyAnalyzer
  Dast/WebScanner.cs      Running-site baseline scanner
  Reporting/              Console, JSON, SARIF 2.1.0 and HTML reports
tests/VaptScanner.Tests/  xUnit suite (see below)
samples/                  VulnerableApp (deliberately insecure) and SafeApp (secure equivalents)
ci/                       GitHub Actions and Azure DevOps templates
```

## Tests

```powershell
dotnet test
```

The suite runs fully offline and covers:

- **Sample apps (end to end):** `samples/VulnerableApp` must produce exactly the expected set of rule IDs, so a
  missed detection and a new false positive both fail. `samples/SafeApp` must produce zero findings.
- **Rules:** a vulnerable snippet and its secure equivalent for each major rule (SQL, command injection,
  deserialization, crypto, path traversal, SSRF, XSS, TLS, secrets, config), plus commented-out code.
- **Rule catalogue:** unique IDs, CWE and OWASP mapping for every rule, and `RULES.md` kept in sync.
- **Gate behaviour:** inline `vapt-ignore`, baselines (stable fingerprints, new issues still reported),
  disabled rules, severity overrides, excludes.
- **CLI contract:** exit codes `0`/`1`/`2`, JSON and SARIF 2.1.0 output, and DAST refusing to run without
  `--authorized`.

CI runs the suite on Linux and Windows for every PR, and a release can't publish if any test fails.

Adding a rule: append an `R(...)` entry in `Analyzers/CodeRules.cs` with an ID, severity, CWE, OWASP category,
a regex that finds the candidate, and an optional check that discards safe usages. Then:

1. Add a positive case to `samples/VulnerableApp` and a negative case to `samples/SafeApp`.
2. Add the ID to `ExpectedVulnerableAppRules` in `tests/VaptScanner.Tests/SampleAppTests.cs`.
3. Add a pair to `RuleTests`, regenerate `RULES.md` with `vapt rules --format md`, and run `dotnet test`.

## License

[MIT](LICENSE)
