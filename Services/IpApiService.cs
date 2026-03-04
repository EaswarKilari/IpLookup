using System.Diagnostics;
using System.Net.Http.Json;
using IpLookup.Models;

namespace IpLookup.Services;

public interface IIpApiService
{
    Task<(IpApiResponse? Data, ApiStatus Status)> GetIpDataAsync(string ipAddress);
}

public class IpApiService : IIpApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<IpApiService> _logger;

    public IpApiService(HttpClient httpClient, ILogger<IpApiService> logger)
    {
        _httpClient = httpClient;
        // Note: ip-api.com free tier only supports HTTP (not HTTPS)
        _httpClient.BaseAddress = new Uri("http://ip-api.com/");
        _httpClient.Timeout = TimeSpan.FromSeconds(10);
        _logger = logger;
    }

    public async Task<(IpApiResponse? Data, ApiStatus Status)> GetIpDataAsync(string ipAddress)
    {
        var sw = Stopwatch.StartNew();
        var status = new ApiStatus();

        try
        {
            // Request all fields including proxy/hosting detection
            // fields parameter is a bitmask: 66846719 = all fields
            var url = $"json/{ipAddress}?fields=66846719";
            var response = await _httpClient.GetAsync(url);
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;

            if (!response.IsSuccessStatusCode)
            {
                status.Success = false;
                status.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";
                _logger.LogWarning("ip-api.com error for {Ip}: {Error}", ipAddress, status.Error);
                return (null, status);
            }

            var data = await response.Content.ReadFromJsonAsync<IpApiResponse>();

            if (data?.Status == "fail")
            {
                status.Success = false;
                status.Error = "IP lookup failed (possibly private/reserved IP)";
                return (null, status);
            }

            status.Success = true;
            return (data, status);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = "Request timeout";
            _logger.LogWarning("ip-api.com timeout for {Ip}", ipAddress);
            return (null, status);
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = ex.Message;
            _logger.LogError(ex, "ip-api.com error for {Ip}", ipAddress);
            return (null, status);
        }
    }
}
