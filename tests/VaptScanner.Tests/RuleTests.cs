namespace VaptScanner.Tests;

/// <summary>
/// Focused rule tests: each vulnerable snippet must trigger its rule, and the secure
/// equivalent (taken from SafeApp) must not.
/// </summary>
public class RuleTests
{
    private static string InClass(string body) => $$"""
        using System.Diagnostics;
        using System.Security.Cryptography;
        public class C : Controller
        {
            public object M(string username, string password, string term, string host, Stream body, IFormFile file)
            {
                {{body}}
                return null;
            }
        }
        """;

    public static TheoryData<string, string> VulnerableCode => new()
    {
        { "VAPT-SQL-001", """var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + username + "'", conn);""" },
        { "VAPT-SQL-002", """cmd.CommandText = "SELECT * FROM Orders WHERE Ref = '" + term + "'";""" },
        { "VAPT-SQL-004", """var sql = $"SELECT * FROM Products WHERE Name LIKE '%{term}%'";""" },
        { "VAPT-CMD-001", """Process.Start("cmd.exe", "/c ping " + host);""" },
        { "VAPT-DESER-001", """var formatter = new BinaryFormatter(); formatter.Deserialize(body);""" },
        { "VAPT-DESER-002", """var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };""" },
        { "VAPT-CRYPTO-001", """using var md5 = MD5.Create();""" },
        { "VAPT-CRYPTO-003", """aes.Mode = CipherMode.ECB;""" },
        { "VAPT-CRYPTO-005", """var random = new Random(); var token = random.Next(100000, 999999).ToString();""" },
        { "VAPT-PATH-001", """var path = Path.Combine("wwwroot/uploads", file.FileName);""" },
        { "VAPT-SSRF-001", """var s = new HttpClient().GetStringAsync(Request.Query["url"]);""" },
        { "VAPT-AUTH-001", """if (password == "SuperAdmin123") return null;""" },
        { "VAPT-WEB-011", """try { } catch (Exception ex) { return BadRequest(ex.ToString()); }""" },
    };

    public static TheoryData<string, string> SafeCode => new()
    {
        { "VAPT-SQL-001", """var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn); cmd.Parameters.AddWithValue("@name", username);""" },
        { "VAPT-SQL-004", """var products = _db.Products.FromSql($"SELECT * FROM Products WHERE Name LIKE {term}");""" },
        { "VAPT-CMD-001", """var psi = new ProcessStartInfo("ping"); psi.ArgumentList.Add(host); Process.Start(psi);""" },
        { "VAPT-CRYPTO-001", """var h = Convert.ToHexString(SHA256.HashData(data));""" },
        { "VAPT-CRYPTO-005", """var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));""" },
        { "VAPT-PATH-001", """var path = Path.Combine("uploads", Path.GetRandomFileName() + ".png");""" },
        { "VAPT-WEB-011", """try { } catch (Exception ex) { _logger.LogError(ex, "failed"); return Problem("Something went wrong."); }""" },
        // Commented-out code must never be reported.
        { "VAPT-SQL-001", """// var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + username + "'", conn);""" },
        { "VAPT-DESER-001", """/* var formatter = new BinaryFormatter(); */""" },
    };

    [Theory]
    [MemberData(nameof(VulnerableCode))]
    public void VulnerableCode_IsDetected(string ruleId, string code)
    {
        var ids = Scan.RuleIds("Controllers/C.cs", InClass(code));
        Assert.True(ids.Contains(ruleId), $"Expected {ruleId}, got [{string.Join(", ", ids)}] for:\n{code}");
    }

    [Theory]
    [MemberData(nameof(SafeCode))]
    public void SafeCode_IsNotFlagged(string ruleId, string code)
    {
        var ids = Scan.RuleIds("Controllers/C.cs", InClass(code));
        Assert.False(ids.Contains(ruleId), $"False positive {ruleId} for:\n{code}");
    }

    [Fact]
    public void RazorHtmlRaw_IsXss()
    {
        Assert.Contains("VAPT-XSS-001", Scan.RuleIds("Views/Home/Index.cshtml", """<div class="bio">@Html.Raw(Model.Bio)</div>"""));
        Assert.DoesNotContain("VAPT-XSS-001", Scan.RuleIds("Views/Home/Index.cshtml", """<div class="bio">@Model.Bio</div>"""));
    }

    [Fact]
    public void TlsValidationBypass_IsDetected()
    {
        const string code = """
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
            };
            """;
        Assert.Contains("VAPT-TLS-001", Scan.RuleIds("Program.cs", code));
    }

    // Secret-shaped values are assembled at runtime so this file never contains a literal credential
    // (keeps GitHub push protection and the scanner itself quiet when the repo is scanned).
    [Fact]
    public void HardCodedApiKey_IsCriticalAndMasked()
    {
        var key = "sk_" + "live_" + "51HxQzLKj3n8Vq2mPq9RtYbWc4Xa7Ze";
        var findings = Scan.Text("Controllers/C.cs", $"""private const string ApiKey = "{key}";""");
        var f = Assert.Single(findings, x => x.RuleId == "VAPT-SECRET-007");
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.DoesNotContain(key, f.Snippet);
    }

    [Fact]
    public void ConnectionStringWithPassword_IsDetected_ButConfigLookupIsNot()
    {
        var pwd = "Pr0d!" + "Passw0rd2024";
        Assert.Contains("VAPT-SECRET-015",
            Scan.RuleIds("Data.cs", $"""var cs = "Server=prod-sql;Database=Shop;User Id=sa;Password={pwd};";"""));
        Assert.DoesNotContain("VAPT-SECRET-015",
            Scan.RuleIds("Data.cs", """var cs = _config.GetConnectionString("Default");"""));
    }

    [Fact]
    public void WebConfig_DebugAndCustomErrorsOff_AreDetected()
    {
        const string xml = """
            <configuration>
              <system.web>
                <compilation debug="true" targetFramework="4.8" />
                <customErrors mode="Off" />
              </system.web>
            </configuration>
            """;
        var ids = Scan.RuleIds("web.config", xml);
        Assert.Contains("VAPT-CFG-002", ids);
        Assert.Contains("VAPT-CFG-001", ids);

        var safe = xml.Replace("debug=\"true\"", "debug=\"false\"").Replace("mode=\"Off\"", "mode=\"RemoteOnly\"");
        var safeIds = Scan.RuleIds("web.config", safe);
        Assert.DoesNotContain("VAPT-CFG-002", safeIds);
        Assert.DoesNotContain("VAPT-CFG-001", safeIds);
    }

    [Fact]
    public void Dockerfile_LatestTagAndDevelopmentEnvironment_AreDetected()
    {
        const string docker = """
            FROM mcr.microsoft.com/dotnet/sdk:latest AS build
            ENV ASPNETCORE_ENVIRONMENT=Development
            """;
        var ids = Scan.RuleIds("Dockerfile", docker);
        Assert.Contains("VAPT-CFG-021", ids);
        Assert.Contains("VAPT-CFG-022", ids);
    }
}
