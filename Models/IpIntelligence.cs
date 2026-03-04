namespace IpLookup.Models;

/// <summary>
/// Unified response model containing all IP intelligence data
/// </summary>
public class IpIntelligence
{
    public string IpAddress { get; set; } = string.Empty;
    public string IpVersion { get; set; } = string.Empty;
    public bool IsPrivate { get; set; }
    public DateTime LookupTime { get; set; } = DateTime.UtcNow;
    public bool FromCache { get; set; }

    // Location data (IPinfo.io)
    public LocationData? Location { get; set; }

    // Network data (IPinfo.io + ip-api)
    public NetworkData? Network { get; set; }

    // Security data (AbuseIPDB + ip-api + VirusTotal)
    public SecurityData? Security { get; set; }

    // Registration/Whois data (RDAP)
    public RegistrationData? Registration { get; set; }

    // Open ports (Shodan)
    public PortsData? Ports { get; set; }

    // Hosted domains (HackerTarget)
    public DomainsData? Domains { get; set; }

    // API status indicators
    public Dictionary<string, ApiStatus> ApiStatuses { get; set; } = new();
}

public class LocationData
{
    public string? City { get; set; }
    public string? Region { get; set; }
    public string? Country { get; set; }
    public string? CountryCode { get; set; }
    public string? PostalCode { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string? Timezone { get; set; }
    public string? MapUrl => Latitude.HasValue && Longitude.HasValue
        ? $"https://www.google.com/maps?q={Latitude},{Longitude}"
        : null;
}

public class NetworkData
{
    public string? Hostname { get; set; }
    public string? Isp { get; set; }
    public string? Organization { get; set; }
    public int? Asn { get; set; }
    public string? AsnName { get; set; }
    public string? NetworkRange { get; set; }
}

public class SecurityData
{
    // AbuseIPDB
    public int? AbuseConfidenceScore { get; set; }
    public int? TotalReports { get; set; }
    public int? DistinctReporters { get; set; }
    public DateTime? LastReportedAt { get; set; }
    public string? UsageType { get; set; }

    // ip-api flags
    public bool? IsVpn { get; set; }
    public bool? IsProxy { get; set; }
    public bool? IsTor { get; set; }
    public bool? IsHosting { get; set; }
    public bool? IsMobile { get; set; }

    // VirusTotal
    public int? MaliciousDetections { get; set; }
    public int? SuspiciousDetections { get; set; }
    public int? HarmlessDetections { get; set; }
    public int? TotalEngines { get; set; }
    public int? Reputation { get; set; }
    public List<string>? MaliciousVendors { get; set; }
}

public class RegistrationData
{
    public string? NetworkHandle { get; set; }
    public string? NetworkName { get; set; }
    public string? StartAddress { get; set; }
    public string? EndAddress { get; set; }
    public string? RegistrantName { get; set; }
    public string? RegistrantAddress { get; set; }
    public DateTime? RegistrationDate { get; set; }
    public DateTime? LastUpdated { get; set; }
    public string? RegistryUrl { get; set; }
}

public class PortsData
{
    public List<PortInfo> OpenPorts { get; set; } = new();
    public DateTime? LastScan { get; set; }
    public List<string>? Vulnerabilities { get; set; }
}

public class PortInfo
{
    public int Port { get; set; }
    public string? Protocol { get; set; }
    public string? Service { get; set; }
    public string? Product { get; set; }
    public string? Version { get; set; }
    public string? Banner { get; set; }
}

public class DomainsData
{
    public List<string> HostedDomains { get; set; } = new();
    public int TotalCount { get; set; }
}

public class ApiStatus
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public int? ResponseTimeMs { get; set; }
    public bool FromCache { get; set; }
}
