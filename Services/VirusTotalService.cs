using System.Diagnostics;
using System.Net.Http.Json;
using IpLookup.Models;

namespace IpLookup.Services;

public interface IVirusTotalService
{
    Task<(VirusTotalAttributes? Data, ApiStatus Status)> GetIpReportAsync(string ipAddress);
}

public class VirusTotalService : IVirusTotalService
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;
    private readonly ILogger<VirusTotalService> _logger;

    public VirusTotalService(HttpClient httpClient, IConfiguration configuration, ILogger<VirusTotalService> logger)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("https://www.virustotal.com/");
        _httpClient.Timeout = TimeSpan.FromSeconds(15);
        _apiKey = configuration["ApiKeys:VirusTotal"];
        _logger = logger;

        if (!string.IsNullOrEmpty(_apiKey))
        {
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
        }
    }

    public async Task<(VirusTotalAttributes? Data, ApiStatus Status)> GetIpReportAsync(string ipAddress)
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
            var url = $"api/v3/ip_addresses/{ipAddress}";
            var response = await _httpClient.GetAsync(url);
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;

            if (!response.IsSuccessStatusCode)
            {
                status.Success = false;
                status.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";

                if ((int)response.StatusCode == 429)
                {
                    status.Error = "Rate limit exceeded (500/day or 4/min)";
                }

                _logger.LogWarning("VirusTotal API error for {Ip}: {Error}", ipAddress, status.Error);
                return (null, status);
            }

            var result = await response.Content.ReadFromJsonAsync<VirusTotalResponse>();
            status.Success = true;
            return (result?.Data?.Attributes, status);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = "Request timeout";
            _logger.LogWarning("VirusTotal API timeout for {Ip}", ipAddress);
            return (null, status);
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = ex.Message;
            _logger.LogError(ex, "VirusTotal API error for {Ip}", ipAddress);
            return (null, status);
        }
    }
}
