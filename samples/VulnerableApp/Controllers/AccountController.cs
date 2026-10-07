// DELIBERATELY VULNERABLE sample used to demonstrate and test VaptScanner. Do not deploy.
using System.Data.SqlClient;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace VulnerableApp.Controllers;

public class AccountController : Controller
{
    private readonly ILogger<AccountController> _logger;
    private const string ApiKey = "sk_live_51HxQzLKj3n8Vq2mPq9RtYbWc4Xa7Ze";
    private readonly string _connectionString = "Server=prod-sql.internal;Database=Shop;User Id=sa;Password=Pr0d!Passw0rd2024;";

    public AccountController(ILogger<AccountController> logger) => _logger = logger;

    [HttpPost]
    public IActionResult Login(string username, string password, string returnUrl)
    {
        _logger.LogInformation("Login attempt {User} with {Password}", username, password);

        using var conn = new SqlConnection(_connectionString);
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + username + "' AND Pwd = '" + password + "'", conn);
        conn.Open();
        var reader = cmd.ExecuteReader();

        if (password == "SuperAdmin123")
            return Redirect(returnUrl);

        return Redirect(returnUrl);
    }

    public IActionResult Search(string term)
    {
        var sql = $"SELECT * FROM Products WHERE Name LIKE '%{term}%'";
        using var conn = new SqlConnection(_connectionString);
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM Orders WHERE Ref = '" + term + "'";
        return View();
    }

    public IActionResult Ping(string host)
    {
        Process.Start("cmd.exe", "/c ping " + host);
        return Ok();
    }

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        var path = Path.Combine("wwwroot/uploads", file.FileName);
        await using var stream = new FileStream(path, FileMode.Create);
        await file.CopyToAsync(stream);
        return Ok();
    }

    public IActionResult Download()
    {
        var bytes = System.IO.File.ReadAllBytes(Path.Combine("files", Request.Query["name"]));
        return File(bytes, "application/octet-stream");
    }

    public string HashPassword(string password)
    {
        using var md5 = MD5.Create();
        return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
    }

    public string ResetToken()
    {
        var random = new Random();
        var token = random.Next(100000, 999999).ToString();
        return token;
    }

    public object Load(Stream body)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(body);
    }

    public object Parse(string json) => JsonConvert.DeserializeObject(json, new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.All
    });

    public IActionResult Fail()
    {
        try { throw new InvalidOperationException(); }
        catch (Exception ex) { return BadRequest(ex.ToString()); }
    }

    public byte[] Encrypt(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef");
        aes.Mode = CipherMode.ECB;
        return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
    }

    public byte[] Derive(string password, byte[] salt) => new Rfc2898DeriveBytes(password, salt, 1000).GetBytes(32);

    public async Task<string> Fetch() =>
        await new HttpClient().GetStringAsync(Request.Query["url"]);
}
