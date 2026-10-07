// DELIBERATELY VULNERABLE sample used to demonstrate and test VaptScanner. Do not deploy.
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.SetIsOriginAllowed(_ => true).AllowCredentials().AllowAnyHeader()));
builder.Services.AddAuthentication().AddJwtBearer(o =>
{
    o.RequireHttpsMetadata = false;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = false
    };
});
builder.Services.AddHttpClient("insecure").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
});
builder.Services.ConfigureApplicationCookie(o =>
{
    o.Cookie.HttpOnly = false;
    o.Cookie.SecurePolicy = CookieSecurePolicy.None;
});

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseCors();
app.MapControllers();
app.Run();
