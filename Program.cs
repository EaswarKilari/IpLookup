using IpLookup.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// Register cache service (Redis with in-memory fallback)
builder.Services.AddSingleton<ICacheService>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var loggerRedis = sp.GetRequiredService<ILogger<RedisCacheService>>();
    var loggerMemory = sp.GetRequiredService<ILogger<MemoryCacheService>>();

    var redisConnectionString = config["Redis:ConnectionString"];
    if (!string.IsNullOrEmpty(redisConnectionString))
    {
        try
        {
            var redisCache = new RedisCacheService(config, loggerRedis);
            return redisCache;
        }
        catch
        {
            // Fall back to memory cache
        }
    }

    return new MemoryCacheService(loggerMemory);
});

// Register HTTP clients for external APIs
builder.Services.AddHttpClient<IIpInfoService, IpInfoService>();
builder.Services.AddHttpClient<IAbuseIpDbService, AbuseIpDbService>();
builder.Services.AddHttpClient<IIpApiService, IpApiService>();
builder.Services.AddHttpClient<IVirusTotalService, VirusTotalService>();
builder.Services.AddHttpClient<IRdapService, RdapService>();
builder.Services.AddHttpClient<IShodanService, ShodanService>();
builder.Services.AddHttpClient<IHackerTargetService, HackerTargetService>();

// Register main lookup service
builder.Services.AddScoped<IIpLookupService, IpLookupService>();

// Configure CORS for frontend
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Configure middleware
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseCors();
app.UseStaticFiles();

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }))
    .WithName("HealthCheck")
    .WithTags("System");

// Main IP lookup endpoint
app.MapGet("/api/lookup/{ip}", async (string ip, IIpLookupService lookupService) =>
{
    var result = await lookupService.LookupAsync(ip);
    return Results.Ok(result);
})
.WithName("LookupIp")
.WithTags("Lookup")
.WithDescription("Get comprehensive intelligence data for an IP address");

// Simple lookup for just basic info
app.MapGet("/api/lookup/{ip}/basic", async (string ip, IIpInfoService ipInfoService) =>
{
    var (data, status) = await ipInfoService.GetIpInfoAsync(ip);
    if (!status.Success)
    {
        return Results.BadRequest(new { error = status.Error });
    }
    return Results.Ok(data);
})
.WithName("LookupIpBasic")
.WithTags("Lookup")
.WithDescription("Get basic geo/ASN info for an IP address");

// Fallback to serve index.html for SPA routing
app.MapFallbackToFile("index.html");

app.Run();
