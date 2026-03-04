using System.Diagnostics;
using System.Net.Http.Json;
using IpLookup.Models;

namespace IpLookup.Services;

public interface IAbuseIpDbService
{
    Task<(AbuseIpDbData? Data, ApiStatus Status)> CheckIpAsync(string ipAddress);
}

public class AbuseIpDbService : IAbuseIpDbService
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;
    private readonly ILogger<AbuseIpDbService> _logger;

    public AbuseIpDbService(HttpClient httpClient, IConfiguration configuration, ILogger<AbuseIpDbService> logger)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("https://api.abuseipdb.com/");
        _httpClient.Timeout = TimeSpan.FromSeconds(10);
        _apiKey = configuration["ApiKeys:AbuseIpDb"];
        _logger = logger;

        if (!string.IsNullOrEmpty(_apiKey))
        {
            _httpClient.DefaultRequestHeaders.Add("Key", _apiKey);
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        }
    }

    public async Task<(AbuseIpDbData? Data, ApiStatus Status)> CheckIpAsync(string ipAddress)
    {
        var sw = Stopwatch.StartNew();
        var status = new ApiStatus();

        if (string.IsNullOrEmpty(_apiKey))
        {
            status.Success = false;
            status.Error = "API key not configured";
            return (null, status);
        }

        try
        {
            var url = $"api/v2/check?ipAddress={ipAddress}&maxAgeInDays=90&verbose=true";
            var response = await _httpClient.GetAsync(url);
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;

            if (!response.IsSuccessStatusCode)
            {
                status.Success = false;
                var errorContent = await response.Content.ReadAsStringAsync();
                status.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";
                _logger.LogWarning("AbuseIPDB API error for {Ip}: {Error}", ipAddress, status.Error);
                return (null, status);
            }

            var result = await response.Content.ReadFromJsonAsync<AbuseIpDbResponse>();
            status.Success = true;
            return (result?.Data, status);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = "Request timeout";
            _logger.LogWarning("AbuseIPDB API timeout for {Ip}", ipAddress);
            return (null, status);
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = ex.Message;
            _logger.LogError(ex, "AbuseIPDB API error for {Ip}", ipAddress);
            return (null, status);
        }
    }
}
