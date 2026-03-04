using System.Text.RegularExpressions;
using IpLookup.Models;
using IpLookup.Utils;

namespace IpLookup.Services;

public interface IIpLookupService
{
    Task<IpIntelligence> LookupAsync(string ipAddress);
}

public class IpLookupService : IIpLookupService
{
    private readonly ICacheService _cache;
    private readonly IIpInfoService _ipInfoService;
    private readonly IAbuseIpDbService _abuseIpDbService;
    private readonly IIpApiService _ipApiService;
    private readonly IVirusTotalService _virusTotalService;
    private readonly IRdapService _rdapService;
    private readonly IShodanService _shodanService;
    private readonly IHackerTargetService _hackerTargetService;
    private readonly ILogger<IpLookupService> _logger;

    // Cache TTLs
    private static readonly TimeSpan GeoTtl = TimeSpan.FromDays(7);
    private static readonly TimeSpan AbuseTtl = TimeSpan.FromHours(24);
    private static readonly TimeSpan ProxyTtl = TimeSpan.FromHours(24);
    private static readonly TimeSpan VirusTotalTtl = TimeSpan.FromHours(6);
    private static readonly TimeSpan WhoisTtl = TimeSpan.FromDays(30);
    private static readonly TimeSpan ShodanTtl = TimeSpan.FromHours(12);
    private static readonly TimeSpan DomainsTtl = TimeSpan.FromHours(24);

    public IpLookupService(
        ICacheService cache,
        IIpInfoService ipInfoService,
        IAbuseIpDbService abuseIpDbService,
        IIpApiService ipApiService,
        IVirusTotalService virusTotalService,
        IRdapService rdapService,
        IShodanService shodanService,
        IHackerTargetService hackerTargetService,
        ILogger<IpLookupService> logger)
    {
        _cache = cache;
        _ipInfoService = ipInfoService;
        _abuseIpDbService = abuseIpDbService;
        _ipApiService = ipApiService;
        _virusTotalService = virusTotalService;
        _rdapService = rdapService;
        _shodanService = shodanService;
        _hackerTargetService = hackerTargetService;
        _logger = logger;
    }

    public async Task<IpIntelligence> LookupAsync(string ipAddress)
    {
        var validation = IpValidator.Validate(ipAddress);

        if (!validation.IsValid)
        {
            return new IpIntelligence
            {
                IpAddress = ipAddress ?? "",
                ApiStatuses = new Dictionary<string, ApiStatus>
                {
                    ["validation"] = new ApiStatus { Success = false, Error = validation.ErrorMessage }
                }
            };
        }

        ipAddress = ipAddress!.Trim();

        var result = new IpIntelligence
        {
            IpAddress = ipAddress,
            IpVersion = validation.IpVersion ?? "Unknown",
            IsPrivate = validation.IsPrivate,
            LookupTime = DateTime.UtcNow
        };

        if (validation.IsPrivate)
        {
            result.ApiStatuses["info"] = new ApiStatus
            {
                Success = false,
                Error = "Private/reserved IP address - external lookups not available"
            };
            return result;
        }

        // Check for fully cached result
        var cacheKey = $"ip:full:{ipAddress}";
        var cachedResult = await _cache.GetAsync<IpIntelligence>(cacheKey);
        if (cachedResult != null)
        {
            cachedResult.FromCache = true;
            cachedResult.LookupTime = DateTime.UtcNow;
            foreach (var status in cachedResult.ApiStatuses.Values)
            {
                status.FromCache = true;
            }
            return cachedResult;
        }

        // Fetch all data in parallel
        var tasks = new List<Task>
        {
            FetchIpInfoAsync(ipAddress, result),
            FetchAbuseDataAsync(ipAddress, result),
            FetchIpApiAsync(ipAddress, result),
            FetchVirusTotalAsync(ipAddress, result),
            FetchRdapAsync(ipAddress, result),
            FetchShodanAsync(ipAddress, result),
            FetchDomainsAsync(ipAddress, result)
        };

        await Task.WhenAll(tasks);

        // Cache the full result with shortest TTL
        await _cache.SetAsync(cacheKey, result, VirusTotalTtl);

        return result;
    }

    private async Task FetchIpInfoAsync(string ip, IpIntelligence result)
    {
        var cacheKey = $"ip:ipinfo:{ip}";
        var cached = await _cache.GetAsync<IpInfoResponse>(cacheKey);

        if (cached != null)
        {
            ApplyIpInfoData(cached, result);
            result.ApiStatuses["ipinfo"] = new ApiStatus { Success = true, FromCache = true };
            return;
        }

        var (data, status) = await _ipInfoService.GetIpInfoAsync(ip);
        result.ApiStatuses["ipinfo"] = status;

        if (data != null)
        {
            ApplyIpInfoData(data, result);
            await _cache.SetAsync(cacheKey, data, GeoTtl);
        }
    }

    private void ApplyIpInfoData(IpInfoResponse data, IpIntelligence result)
    {
        result.Location ??= new LocationData();
        result.Location.City = data.City;
        result.Location.Region = data.Region;
        result.Location.Country = GetCountryName(data.Country);
        result.Location.CountryCode = data.Country;
        result.Location.PostalCode = data.Postal;
        result.Location.Timezone = data.Timezone;

        if (!string.IsNullOrEmpty(data.Location))
        {
            var coords = data.Location.Split(',');
            if (coords.Length == 2 &&
                double.TryParse(coords[0], out var lat) &&
                double.TryParse(coords[1], out var lon))
            {
                result.Location.Latitude = lat;
                result.Location.Longitude = lon;
            }
        }

        result.Network ??= new NetworkData();
        result.Network.Hostname = data.Hostname;

        if (!string.IsNullOrEmpty(data.Org))
        {
            // Parse "AS15169 Google LLC" format
            var match = Regex.Match(data.Org, @"AS(\d+)\s+(.+)");
            if (match.Success)
            {
                result.Network.Asn = int.Parse(match.Groups[1].Value);
                result.Network.AsnName = match.Groups[2].Value;
                result.Network.Organization = match.Groups[2].Value;
            }
            else
            {
                result.Network.Organization = data.Org;
            }
        }
    }

    private async Task FetchAbuseDataAsync(string ip, IpIntelligence result)
    {
        var cacheKey = $"ip:abuse:{ip}";
        var cached = await _cache.GetAsync<AbuseIpDbData>(cacheKey);

        if (cached != null)
        {
            ApplyAbuseData(cached, result);
            result.ApiStatuses["abuseipdb"] = new ApiStatus { Success = true, FromCache = true };
            return;
        }

        var (data, status) = await _abuseIpDbService.CheckIpAsync(ip);
        result.ApiStatuses["abuseipdb"] = status;

        if (data != null)
        {
            ApplyAbuseData(data, result);
            await _cache.SetAsync(cacheKey, data, AbuseTtl);
        }
    }

    private void ApplyAbuseData(AbuseIpDbData data, IpIntelligence result)
    {
        result.Security ??= new SecurityData();
        result.Security.AbuseConfidenceScore = data.AbuseConfidenceScore;
        result.Security.TotalReports = data.TotalReports;
        result.Security.DistinctReporters = data.NumDistinctUsers;
        result.Security.LastReportedAt = data.LastReportedAt;
        result.Security.UsageType = data.UsageType;

        result.Network ??= new NetworkData();
        result.Network.Isp ??= data.Isp;
    }

    private async Task FetchIpApiAsync(string ip, IpIntelligence result)
    {
        var cacheKey = $"ip:ipapi:{ip}";
        var cached = await _cache.GetAsync<IpApiResponse>(cacheKey);

        if (cached != null)
        {
            ApplyIpApiData(cached, result);
            result.ApiStatuses["ip-api"] = new ApiStatus { Success = true, FromCache = true };
            return;
        }

        var (data, status) = await _ipApiService.GetIpDataAsync(ip);
        result.ApiStatuses["ip-api"] = status;

        if (data != null)
        {
            ApplyIpApiData(data, result);
            await _cache.SetAsync(cacheKey, data, ProxyTtl);
        }
    }

    private void ApplyIpApiData(IpApiResponse data, IpIntelligence result)
    {
        result.Security ??= new SecurityData();
        result.Security.IsVpn = data.Proxy; // ip-api "proxy" includes VPN
        result.Security.IsProxy = data.Proxy;
        result.Security.IsHosting = data.Hosting;
        result.Security.IsMobile = data.Mobile;

        // Fill in location if not already set
        result.Location ??= new LocationData();
        result.Location.City ??= data.City;
        result.Location.Region ??= data.RegionName;
        result.Location.Country ??= data.Country;
        result.Location.CountryCode ??= data.CountryCode;
        result.Location.PostalCode ??= data.Zip;
        result.Location.Timezone ??= data.Timezone;
        result.Location.Latitude ??= data.Lat;
        result.Location.Longitude ??= data.Lon;

        result.Network ??= new NetworkData();
        result.Network.Isp ??= data.Isp;
        result.Network.Organization ??= data.Org;

        if (!string.IsNullOrEmpty(data.As))
        {
            var match = Regex.Match(data.As, @"AS(\d+)");
            if (match.Success && result.Network.Asn == null)
            {
                result.Network.Asn = int.Parse(match.Groups[1].Value);
            }
        }
    }

    private async Task FetchVirusTotalAsync(string ip, IpIntelligence result)
    {
        var cacheKey = $"ip:vt:{ip}";
        var cached = await _cache.GetAsync<VirusTotalAttributes>(cacheKey);

        if (cached != null)
        {
            ApplyVirusTotalData(cached, result);
            result.ApiStatuses["virustotal"] = new ApiStatus { Success = true, FromCache = true };
            return;
        }

        var (data, status) = await _virusTotalService.GetIpReportAsync(ip);
        result.ApiStatuses["virustotal"] = status;

        if (data != null)
        {
            ApplyVirusTotalData(data, result);
            await _cache.SetAsync(cacheKey, data, VirusTotalTtl);
        }
    }

    private void ApplyVirusTotalData(VirusTotalAttributes data, IpIntelligence result)
    {
        result.Security ??= new SecurityData();
        result.Security.Reputation = data.Reputation;

        if (data.LastAnalysisStats != null)
        {
            var stats = data.LastAnalysisStats;
            result.Security.MaliciousDetections = stats.Malicious;
            result.Security.SuspiciousDetections = stats.Suspicious;
            result.Security.HarmlessDetections = stats.Harmless;
            result.Security.TotalEngines = stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected;
        }

        // Get list of vendors that flagged as malicious
        if (data.LastAnalysisResults != null && data.LastAnalysisStats?.Malicious > 0)
        {
            result.Security.MaliciousVendors = data.LastAnalysisResults
                .Where(r => r.Value.Category == "malicious")
                .Select(r => r.Key)
                .Take(10) // Limit to top 10
                .ToList();
        }

        result.Network ??= new NetworkData();
        result.Network.NetworkRange ??= data.Network;
    }

    private async Task FetchRdapAsync(string ip, IpIntelligence result)
    {
        var cacheKey = $"ip:rdap:{ip}";
        var cached = await _cache.GetAsync<RegistrationData>(cacheKey);

        if (cached != null)
        {
            result.Registration = cached;
            result.ApiStatuses["rdap"] = new ApiStatus { Success = true, FromCache = true };
            return;
        }

        var (data, status) = await _rdapService.GetWhoisAsync(ip);
        result.ApiStatuses["rdap"] = status;

        if (data != null)
        {
            result.Registration = data;
            await _cache.SetAsync(cacheKey, data, WhoisTtl);
        }
    }

    private async Task FetchShodanAsync(string ip, IpIntelligence result)
    {
        var cacheKey = $"ip:shodan:{ip}";
        var cached = await _cache.GetAsync<PortsData>(cacheKey);

        if (cached != null)
        {
            result.Ports = cached;
            result.ApiStatuses["shodan"] = new ApiStatus { Success = true, FromCache = true };
            return;
        }

        var (data, status) = await _shodanService.GetHostInfoAsync(ip);
        result.ApiStatuses["shodan"] = status;

        if (data != null)
        {
            result.Ports = data;
            await _cache.SetAsync(cacheKey, data, ShodanTtl);
        }
    }

    private async Task FetchDomainsAsync(string ip, IpIntelligence result)
    {
        var cacheKey = $"ip:domains:{ip}";
        var cached = await _cache.GetAsync<DomainsData>(cacheKey);

        if (cached != null)
        {
            result.Domains = cached;
            result.ApiStatuses["hackertarget"] = new ApiStatus { Success = true, FromCache = true };
            return;
        }

        var (data, status) = await _hackerTargetService.GetReverseIpAsync(ip);
        result.ApiStatuses["hackertarget"] = status;

        if (data != null)
        {
            result.Domains = data;
            await _cache.SetAsync(cacheKey, data, DomainsTtl);
        }
    }

    private static string? GetCountryName(string? countryCode)
    {
        if (string.IsNullOrEmpty(countryCode)) return null;

        // Common country codes - expand as needed
        return countryCode.ToUpper() switch
        {
            "US" => "United States",
            "GB" => "United Kingdom",
            "CA" => "Canada",
            "AU" => "Australia",
            "DE" => "Germany",
            "FR" => "France",
            "JP" => "Japan",
            "CN" => "China",
            "IN" => "India",
            "BR" => "Brazil",
            "RU" => "Russia",
            "NL" => "Netherlands",
            "SG" => "Singapore",
            "KR" => "South Korea",
            "IT" => "Italy",
            "ES" => "Spain",
            "SE" => "Sweden",
            "NO" => "Norway",
            "FI" => "Finland",
            "DK" => "Denmark",
            "PL" => "Poland",
            "IE" => "Ireland",
            "NZ" => "New Zealand",
            "CH" => "Switzerland",
            "AT" => "Austria",
            "BE" => "Belgium",
            "HK" => "Hong Kong",
            "TW" => "Taiwan",
            "MX" => "Mexico",
            "AR" => "Argentina",
            "ZA" => "South Africa",
            _ => countryCode
        };
    }
}
