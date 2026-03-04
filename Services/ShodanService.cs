using System.Diagnostics;
using System.Net.Http.Json;
using IpLookup.Models;

namespace IpLookup.Services;

public interface IShodanService
{
    Task<(PortsData? Data, ApiStatus Status)> GetHostInfoAsync(string ipAddress);
}

public class ShodanService : IShodanService
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;
    private readonly ILogger<ShodanService> _logger;

    public ShodanService(HttpClient httpClient, IConfiguration configuration, ILogger<ShodanService> logger)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("https://api.shodan.io/");
        _httpClient.Timeout = TimeSpan.FromSeconds(15);
        _apiKey = configuration["ApiKeys:Shodan"];
        _logger = logger;
    }

    public async Task<(PortsData? Data, ApiStatus Status)> GetHostInfoAsync(string ipAddress)
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
            var url = $"shodan/host/{ipAddress}?key={_apiKey}";
            var response = await _httpClient.GetAsync(url);
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;

            if (!response.IsSuccessStatusCode)
            {
                status.Success = false;

                if ((int)response.StatusCode == 404)
                {
                    status.Error = "No data available for this IP";
                }
                else if ((int)response.StatusCode == 401)
                {
                    status.Error = "Invalid API key";
                }
                else if ((int)response.StatusCode == 429)
                {
                    status.Error = "Rate limit exceeded (100/month free tier)";
                }
                else
                {
                    status.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";
                }

                _logger.LogWarning("Shodan API error for {Ip}: {Error}", ipAddress, status.Error);
                return (null, status);
            }

            var shodanResponse = await response.Content.ReadFromJsonAsync<ShodanResponse>();
            var portsData = ParseShodanResponse(shodanResponse);

            status.Success = true;
            return (portsData, status);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = "Request timeout";
            _logger.LogWarning("Shodan API timeout for {Ip}", ipAddress);
            return (null, status);
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = ex.Message;
            _logger.LogError(ex, "Shodan API error for {Ip}", ipAddress);
            return (null, status);
        }
    }

    private PortsData? ParseShodanResponse(ShodanResponse? shodan)
    {
        if (shodan == null) return null;

        var portsData = new PortsData
        {
            Vulnerabilities = shodan.Vulns ?? new List<string>()
        };

        if (!string.IsNullOrEmpty(shodan.LastUpdate) &&
            DateTime.TryParse(shodan.LastUpdate, out var lastScan))
        {
            portsData.LastScan = lastScan;
        }

        if (shodan.Data != null)
        {
            foreach (var service in shodan.Data)
            {
                portsData.OpenPorts.Add(new PortInfo
                {
                    Port = service.Port,
                    Protocol = service.Transport,
                    Product = service.Product,
                    Version = service.Version,
                    Banner = service.Data?.Length > 200
                        ? service.Data.Substring(0, 200) + "..."
                        : service.Data
                });
            }
        }
        else if (shodan.Ports != null)
        {
            // Fallback if detailed data not available
            foreach (var port in shodan.Ports)
            {
                portsData.OpenPorts.Add(new PortInfo { Port = port });
            }
        }

        return portsData;
    }
}
