using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using IpLookup.Models;

namespace IpLookup.Services;

public interface IRdapService
{
    Task<(RegistrationData? Data, ApiStatus Status)> GetWhoisAsync(string ipAddress);
}

public class RdapService : IRdapService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RdapService> _logger;

    // RDAP bootstrap - different RIRs for different IP ranges
    private static readonly Dictionary<string, string> RdapEndpoints = new()
    {
        { "arin", "https://rdap.arin.net/registry/ip/" },
        { "ripe", "https://rdap.db.ripe.net/ip/" },
        { "apnic", "https://rdap.apnic.net/ip/" },
        { "afrinic", "https://rdap.afrinic.net/rdap/ip/" },
        { "lacnic", "https://rdap.lacnic.net/rdap/ip/" }
    };

    public RdapService(HttpClient httpClient, ILogger<RdapService> logger)
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromSeconds(15);
        _httpClient.DefaultRequestHeaders.Accept.Add(
            new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/rdap+json"));
        _logger = logger;
    }

    public async Task<(RegistrationData? Data, ApiStatus Status)> GetWhoisAsync(string ipAddress)
    {
        var sw = Stopwatch.StartNew();
        var status = new ApiStatus();

        try
        {
            // Try ARIN first (covers most of North America), then bootstrap
            var rdapUrl = GetRdapUrl(ipAddress);
            var response = await _httpClient.GetAsync(rdapUrl);
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;

            if (!response.IsSuccessStatusCode)
            {
                // Try bootstrap URL if direct fails
                var bootstrapUrl = $"https://rdap-bootstrap.arin.net/bootstrap/ip/{ipAddress}";
                response = await _httpClient.GetAsync(bootstrapUrl);

                if (!response.IsSuccessStatusCode)
                {
                    status.Success = false;
                    status.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";
                    _logger.LogWarning("RDAP error for {Ip}: {Error}", ipAddress, status.Error);
                    return (null, status);
                }
            }

            var rdapResponse = await response.Content.ReadFromJsonAsync<RdapResponse>();
            var registrationData = ParseRdapResponse(rdapResponse);

            // Add self link as registry URL
            var selfLink = rdapResponse?.Links?.FirstOrDefault(l => l.Rel == "self");
            if (selfLink != null && registrationData != null)
            {
                registrationData.RegistryUrl = selfLink.Href;
            }

            status.Success = true;
            return (registrationData, status);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = "Request timeout";
            _logger.LogWarning("RDAP timeout for {Ip}", ipAddress);
            return (null, status);
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.ResponseTimeMs = (int)sw.ElapsedMilliseconds;
            status.Success = false;
            status.Error = ex.Message;
            _logger.LogError(ex, "RDAP error for {Ip}", ipAddress);
            return (null, status);
        }
    }

    private string GetRdapUrl(string ipAddress)
    {
        // Simple heuristic to pick RIR based on first octet
        // This is a simplification - real implementation would use IANA bootstrap
        if (!IPAddress.TryParse(ipAddress, out var ip))
            return RdapEndpoints["arin"] + ipAddress;

        var bytes = ip.GetAddressBytes();
        var firstOctet = bytes[0];

        // Very rough allocation (not comprehensive)
        return firstOctet switch
        {
            >= 1 and <= 126 => RdapEndpoints["arin"] + ipAddress,  // Class A (mostly ARIN)
            >= 128 and <= 191 => RdapEndpoints["ripe"] + ipAddress, // Class B (often RIPE)
            >= 192 and <= 223 => RdapEndpoints["arin"] + ipAddress, // Class C (mixed)
            _ => $"https://rdap-bootstrap.arin.net/bootstrap/ip/{ipAddress}" // Use bootstrap
        };
    }

    private RegistrationData? ParseRdapResponse(RdapResponse? rdap)
    {
        if (rdap == null) return null;

        var data = new RegistrationData
        {
            NetworkHandle = rdap.Handle,
            NetworkName = rdap.Name,
            StartAddress = rdap.StartAddress,
            EndAddress = rdap.EndAddress
        };

        // Parse events for dates
        if (rdap.Events != null)
        {
            var registration = rdap.Events.FirstOrDefault(e => e.EventAction == "registration");
            if (registration?.EventDate != null && DateTime.TryParse(registration.EventDate, out var regDate))
            {
                data.RegistrationDate = regDate;
            }

            var lastChanged = rdap.Events.FirstOrDefault(e => e.EventAction == "last changed");
            if (lastChanged?.EventDate != null && DateTime.TryParse(lastChanged.EventDate, out var updateDate))
            {
                data.LastUpdated = updateDate;
            }
        }

        // Parse entities for registrant info
        if (rdap.Entities != null)
        {
            var registrant = rdap.Entities.FirstOrDefault(e =>
                e.Roles?.Contains("registrant") == true ||
                e.Roles?.Contains("administrative") == true);

            if (registrant?.VcardArray is { Length: >= 2 } vcard)
            {
                try
                {
                    // vCard is a complex nested structure
                    // vcardArray: ["vcard", [[...fields...]]]
                    if (vcard[1] is JsonElement fields)
                    {
                        foreach (var field in fields.EnumerateArray())
                        {
                            if (field.GetArrayLength() >= 4)
                            {
                                var fieldName = field[0].GetString();
                                var fieldValue = field[3];

                                if (fieldName == "fn" && fieldValue.ValueKind == JsonValueKind.String)
                                {
                                    data.RegistrantName = fieldValue.GetString();
                                }
                            }
                        }
                    }
                }
                catch
                {
                    // vCard parsing is complex, fail gracefully
                }
            }
        }

        return data;
    }
}
