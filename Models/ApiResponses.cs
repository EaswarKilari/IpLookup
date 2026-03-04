using System.Text.Json.Serialization;

namespace IpLookup.Models;

// IPinfo.io response
public class IpInfoResponse
{
    [JsonPropertyName("ip")]
    public string? Ip { get; set; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    [JsonPropertyName("city")]
    public string? City { get; set; }

    [JsonPropertyName("region")]
    public string? Region { get; set; }

    [JsonPropertyName("country")]
    public string? Country { get; set; }

    [JsonPropertyName("loc")]
    public string? Location { get; set; }

    [JsonPropertyName("org")]
    public string? Org { get; set; }

    [JsonPropertyName("postal")]
    public string? Postal { get; set; }

    [JsonPropertyName("timezone")]
    public string? Timezone { get; set; }
}

// AbuseIPDB response
public class AbuseIpDbResponse
{
    [JsonPropertyName("data")]
    public AbuseIpDbData? Data { get; set; }
}

public class AbuseIpDbData
{
    [JsonPropertyName("ipAddress")]
    public string? IpAddress { get; set; }

    [JsonPropertyName("isPublic")]
    public bool IsPublic { get; set; }

    [JsonPropertyName("ipVersion")]
    public int IpVersion { get; set; }

    [JsonPropertyName("isWhitelisted")]
    public bool? IsWhitelisted { get; set; }

    [JsonPropertyName("abuseConfidenceScore")]
    public int AbuseConfidenceScore { get; set; }

    [JsonPropertyName("countryCode")]
    public string? CountryCode { get; set; }

    [JsonPropertyName("usageType")]
    public string? UsageType { get; set; }

    [JsonPropertyName("isp")]
    public string? Isp { get; set; }

    [JsonPropertyName("domain")]
    public string? Domain { get; set; }

    [JsonPropertyName("totalReports")]
    public int TotalReports { get; set; }

    [JsonPropertyName("numDistinctUsers")]
    public int NumDistinctUsers { get; set; }

    [JsonPropertyName("lastReportedAt")]
    public DateTime? LastReportedAt { get; set; }
}

// ip-api.com response
public class IpApiResponse
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("country")]
    public string? Country { get; set; }

    [JsonPropertyName("countryCode")]
    public string? CountryCode { get; set; }

    [JsonPropertyName("region")]
    public string? Region { get; set; }

    [JsonPropertyName("regionName")]
    public string? RegionName { get; set; }

    [JsonPropertyName("city")]
    public string? City { get; set; }

    [JsonPropertyName("zip")]
    public string? Zip { get; set; }

    [JsonPropertyName("lat")]
    public double? Lat { get; set; }

    [JsonPropertyName("lon")]
    public double? Lon { get; set; }

    [JsonPropertyName("timezone")]
    public string? Timezone { get; set; }

    [JsonPropertyName("isp")]
    public string? Isp { get; set; }

    [JsonPropertyName("org")]
    public string? Org { get; set; }

    [JsonPropertyName("as")]
    public string? As { get; set; }

    [JsonPropertyName("mobile")]
    public bool Mobile { get; set; }

    [JsonPropertyName("proxy")]
    public bool Proxy { get; set; }

    [JsonPropertyName("hosting")]
    public bool Hosting { get; set; }
}

// VirusTotal response
public class VirusTotalResponse
{
    [JsonPropertyName("data")]
    public VirusTotalData? Data { get; set; }
}

public class VirusTotalData
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("attributes")]
    public VirusTotalAttributes? Attributes { get; set; }
}

public class VirusTotalAttributes
{
    [JsonPropertyName("as_owner")]
    public string? AsOwner { get; set; }

    [JsonPropertyName("asn")]
    public int? Asn { get; set; }

    [JsonPropertyName("country")]
    public string? Country { get; set; }

    [JsonPropertyName("network")]
    public string? Network { get; set; }

    [JsonPropertyName("reputation")]
    public int? Reputation { get; set; }

    [JsonPropertyName("last_analysis_stats")]
    public VirusTotalAnalysisStats? LastAnalysisStats { get; set; }

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, VirusTotalAnalysisResult>? LastAnalysisResults { get; set; }
}

public class VirusTotalAnalysisStats
{
    [JsonPropertyName("harmless")]
    public int Harmless { get; set; }

    [JsonPropertyName("malicious")]
    public int Malicious { get; set; }

    [JsonPropertyName("suspicious")]
    public int Suspicious { get; set; }

    [JsonPropertyName("undetected")]
    public int Undetected { get; set; }

    [JsonPropertyName("timeout")]
    public int Timeout { get; set; }
}

public class VirusTotalAnalysisResult
{
    [JsonPropertyName("category")]
    public string? Category { get; set; }

    [JsonPropertyName("result")]
    public string? Result { get; set; }

    [JsonPropertyName("method")]
    public string? Method { get; set; }

    [JsonPropertyName("engine_name")]
    public string? EngineName { get; set; }
}

// Shodan response
public class ShodanResponse
{
    [JsonPropertyName("ip_str")]
    public string? IpStr { get; set; }

    [JsonPropertyName("ports")]
    public List<int>? Ports { get; set; }

    [JsonPropertyName("hostnames")]
    public List<string>? Hostnames { get; set; }

    [JsonPropertyName("org")]
    public string? Org { get; set; }

    [JsonPropertyName("isp")]
    public string? Isp { get; set; }

    [JsonPropertyName("asn")]
    public string? Asn { get; set; }

    [JsonPropertyName("last_update")]
    public string? LastUpdate { get; set; }

    [JsonPropertyName("data")]
    public List<ShodanServiceData>? Data { get; set; }

    [JsonPropertyName("vulns")]
    public List<string>? Vulns { get; set; }
}

public class ShodanServiceData
{
    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("transport")]
    public string? Transport { get; set; }

    [JsonPropertyName("product")]
    public string? Product { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("data")]
    public string? Data { get; set; }
}

// RDAP response (simplified)
public class RdapResponse
{
    [JsonPropertyName("handle")]
    public string? Handle { get; set; }

    [JsonPropertyName("startAddress")]
    public string? StartAddress { get; set; }

    [JsonPropertyName("endAddress")]
    public string? EndAddress { get; set; }

    [JsonPropertyName("ipVersion")]
    public string? IpVersion { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("entities")]
    public List<RdapEntity>? Entities { get; set; }

    [JsonPropertyName("events")]
    public List<RdapEvent>? Events { get; set; }

    [JsonPropertyName("links")]
    public List<RdapLink>? Links { get; set; }
}

public class RdapEntity
{
    [JsonPropertyName("handle")]
    public string? Handle { get; set; }

    [JsonPropertyName("roles")]
    public List<string>? Roles { get; set; }

    [JsonPropertyName("vcardArray")]
    public object[]? VcardArray { get; set; }
}

public class RdapEvent
{
    [JsonPropertyName("eventAction")]
    public string? EventAction { get; set; }

    [JsonPropertyName("eventDate")]
    public string? EventDate { get; set; }
}

public class RdapLink
{
    [JsonPropertyName("rel")]
    public string? Rel { get; set; }

    [JsonPropertyName("href")]
    public string? Href { get; set; }
}
