using System.Diagnostics;
using System.Net.Http.Json;
using IpLookup.Models;

namespace IpLookup.Services;

public interface IIpInfoService
{
    Task<(IpInfoResponse? Data, ApiStatus Status)> GetIpInfoAsync(string ipAddress);
}

public class IpInfoService : IIpInfoService
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiToken;
    private readonly ILogger<IpInfoService> _logger;

    public IpInfoService(HttpClient httpClient, IConfiguration configuration, ILogger<IpInfoService> logger)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("https://ipinfo.io/");
        _httpClient.Timeout = TimeSpan.FromSeconds(10);
        _apiToken = configuration["ApiKeys:IpInfo"];
        _logger = logger;
    }

    public async Task<(IpInfoResponse? Data, ApiStatus Status)> GetIpInfoAsync(string ipAddress)
    {
        var sw = Stopwatch.StartNew();
        var status = new ApiStatus();

        try
        {
            var url = string.IsNullOrEmpty(_apiToken)
                ? $"{ipAddress}/json"
                : $"{ipAddress}/json?token={_apiToken}";

            var response = await _httpClient.GetAsync(url);
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;

            if (!response.IsSuccessStatusCode)
            {
                status.Success = false;
                status.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";
                _logger.LogWarning("IPinfo API error for {Ip}: {Error}", ipAddress, status.Error);
                return (null, status);
            }

            var data = await response.Content.ReadFromJsonAsync<IpInfoResponse>();
            status.Success = true;
            return (data, status);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = "Request timeout";
            _logger.LogWarning("IPinfo API timeout for {Ip}", ipAddress);
            return (null, status);
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = ex.Message;
            _logger.LogError(ex, "IPinfo API error for {Ip}", ipAddress);
            return (null, status);
        }
    }
}
