using System.Diagnostics;
using IpLookup.Models;

namespace IpLookup.Services;

public interface IHackerTargetService
{
    Task<(DomainsData? Data, ApiStatus Status)> GetReverseIpAsync(string ipAddress);
}

public class HackerTargetService : IHackerTargetService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<HackerTargetService> _logger;

    public HackerTargetService(HttpClient httpClient, ILogger<HackerTargetService> logger)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("https://api.hackertarget.com/");
        _httpClient.Timeout = TimeSpan.FromSeconds(15);
        _logger = logger;
    }

    public async Task<(DomainsData? Data, ApiStatus Status)> GetReverseIpAsync(string ipAddress)
    {
        var sw = Stopwatch.StartNew();
        var status = new ApiStatus();

        try
        {
            var url = $"reverseiplookup/?q={ipAddress}";
            var response = await _httpClient.GetAsync(url);
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;

            if (!response.IsSuccessStatusCode)
            {
                status.Success = false;
                status.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";
                _logger.LogWarning("HackerTarget API error for {Ip}: {Error}", ipAddress, status.Error);
                return (null, status);
            }

            var content = await response.Content.ReadAsStringAsync();

            // HackerTarget returns plain text, one domain per line
            // Or error messages like "error check your search parameter" or "API count exceeded"
            if (content.StartsWith("error", StringComparison.OrdinalIgnoreCase))
            {
                status.Success = false;
                status.Error = content;
                return (null, status);
            }

            if (content.Contains("API count exceeded"))
            {
                status.Success = false;
                status.Error = "Rate limit exceeded (100/day free tier)";
                return (null, status);
            }

            // "No DNS A records found" is a valid response
            if (content.Contains("No DNS") || content.Contains("No records"))
            {
                status.Success = true;
                return (new DomainsData { HostedDomains = new List<string>(), TotalCount = 0 }, status);
            }

            var domains = content
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Select(d => d.Trim())
                .Distinct()
                .ToList();

            status.Success = true;
            return (new DomainsData
            {
                HostedDomains = domains,
                TotalCount = domains.Count
            }, status);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = "Request timeout";
            _logger.LogWarning("HackerTarget API timeout for {Ip}", ipAddress);
            return (null, status);
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = ex.Message;
            _logger.LogError(ex, "HackerTarget API error for {Ip}", ipAddress);
            return (null, status);
        }
    }
}
