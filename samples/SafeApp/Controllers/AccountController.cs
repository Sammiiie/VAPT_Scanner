// Secure counterpart to VulnerableApp - the scanner should report (almost) nothing here.
using System.Diagnostics;
using System.Security.Cryptography;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace SafeApp.Controllers;

[Authorize]
public class AccountController : Controller
{
    private readonly ILogger<AccountController> _logger;
    private readonly IConfiguration _config;
    private readonly ShopDb _db;
    private const string TableName = "Products";
    private const string ResetTokenPurpose = "ResetPassword";

    public AccountController(ILogger<AccountController> logger, IConfiguration config, ShopDb db)
    {
        _logger = logger; _config = config; _db = db;
    }

    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken]
    public IActionResult Login(string username, string password, string returnUrl)
    {
        _logger.LogInformation("Login attempt for {User}", username);
        // Password reset emails mention the word password but that's fine.
        _logger.LogWarning("Password reset requested for {User}", username);

        using var conn = new SqlConnection(_config.GetConnectionString("Default"));
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", username);

        if (Url.IsLocalUrl(returnUrl)) return Redirect(returnUrl);
        return LocalRedirect("/");
    }

    public async Task<IActionResult> Search(string term)
    {
        // EF Core parameterises interpolation holes in FromSql / ExecuteSql.
        var products = await _db.Products.FromSql($"SELECT * FROM Products WHERE Name LIKE {term}").ToListAsync();
        await _db.Database.ExecuteSqlAsync($"UPDATE Stats SET Hits = Hits + 1 WHERE Term = {term}");

        using var conn = new SqlConnection(_config.GetConnectionString("Default"));
        var rows = await conn.QueryAsync<Product>("SELECT * FROM Products WHERE Name = @term", new { term });
        var countSql = "SELECT COUNT(*) FROM " + TableName;
        return View(products);
    }

    public IActionResult Ping(string host)
    {
        if (!System.Net.IPAddress.TryParse(host, out var ip)) return BadRequest();
        var psi = new ProcessStartInfo("ping");
        psi.ArgumentList.Add(ip.ToString());
        Process.Start(psi);
        return Ok();
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        var safeName = Path.GetRandomFileName() + ".png";
        var path = Path.Combine("uploads", safeName);
        await using var stream = new FileStream(path, FileMode.Create);
        await file.CopyToAsync(stream);
        return Ok();
    }

    public string ResetToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public int PickTip() => new Random().Next(0, 10); // non-security use (UI tip of the day)

    public byte[] Derive(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);

    public string Checksum(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

    public IActionResult Fail()
    {
        try { throw new InvalidOperationException(); }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Operation failed");
            return Problem("Something went wrong.");
        }
    }

    // Commented-out legacy code should not be flagged:
    // var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + username + "'", conn);
    /* var formatter = new BinaryFormatter(); */
}
