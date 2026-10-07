var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews(o => o.Filters.Add(new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute()));
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins("https://app.example.com").AllowCredentials()));
builder.Services.AddRateLimiter(_ => { });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseCors();
app.MapControllers();
app.Run();
