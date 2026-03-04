# IP Intelligence Lookup

A comprehensive IP address intelligence tool that aggregates data from multiple sources to provide detailed information about any IPv4 or IPv6 address.

![Screenshot](docs/screenshot.png)

## Features

- **Geolocation**: City, region, country, coordinates, timezone
- **Network Info**: ASN, ISP, organization, hostname
- **Security Assessment**: 
  - Abuse confidence score (AbuseIPDB)
  - VPN/Proxy/Tor detection
  - Datacenter/hosting detection
  - VirusTotal threat analysis
- **WHOIS Data**: Registration info, network range, registrant
- **Open Ports**: Shodan integration for port scanning data
- **Hosted Domains**: Reverse IP lookup for domains on the IP

## Data Sources

| Source | Data Provided | Free Tier |
|--------|--------------|-----------|
| [IPinfo.io](https://ipinfo.io) | Geo, ASN, hostname | 50K/month |
| [AbuseIPDB](https://abuseipdb.com) | Abuse score, reports | 1K/day |
| [ip-api.com](http://ip-api.com) | VPN/proxy/hosting flags | 45/min |
| [VirusTotal](https://virustotal.com) | Threat intelligence | 500/day |
| [Shodan](https://shodan.io) | Open ports, services | 100/month |
| [HackerTarget](https://hackertarget.com) | Reverse IP domains | 100/day |
| RDAP | WHOIS registration | Unlimited |

## Getting Started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- API keys (see below)
- Optional: [Upstash Redis](https://upstash.com) for caching

### API Keys

1. **IPinfo.io** - https://ipinfo.io/signup (free, 50K/month)
2. **AbuseIPDB** - https://abuseipdb.com/register (free, 1K/day)
3. **VirusTotal** - https://virustotal.com/gui/join-us (free, 500/day)
4. **Shodan** - https://account.shodan.io/register (free, 100/month)
5. **Upstash Redis** - https://upstash.com (free, 10K commands/day)

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/IpLookup.git
   cd IpLookup
   ```

2. Create `appsettings.Development.json` from the example:
   ```bash
   cp appsettings.Development.json.example appsettings.Development.json
   ```

3. Add your API keys to `appsettings.Development.json`

4. Run the application:
   ```bash
   dotnet run
   ```

5. Open https://localhost:5001 in your browser

### Using Docker

```bash
# Build the image
docker build -t iplookup .

# Run with environment variables
docker run -p 8080:8080 \
  -e ApiKeys__IpInfo=YOUR_KEY \
  -e ApiKeys__AbuseIpDb=YOUR_KEY \
  -e ApiKeys__VirusTotal=YOUR_KEY \
  -e ApiKeys__Shodan=YOUR_KEY \
  -e Redis__ConnectionString=YOUR_REDIS_URL \
  iplookup
```

## Azure Deployment

### Azure Container Apps (Recommended)

1. Create a resource group:
   ```bash
   az group create --name rg-iplookup --location eastus
   ```

2. Create Azure Container Registry:
   ```bash
   az acr create --name acriplookup --resource-group rg-iplookup --sku Basic
   az acr login --name acriplookup
   ```

3. Build and push the image:
   ```bash
   docker build -t acriplookup.azurecr.io/iplookup:latest .
   docker push acriplookup.azurecr.io/iplookup:latest
   ```

4. Deploy to Container Apps:
   ```bash
   az containerapp up \
     --name iplookup \
     --resource-group rg-iplookup \
     --image acriplookup.azurecr.io/iplookup:latest \
     --target-port 8080 \
     --ingress external \
     --env-vars \
       ApiKeys__IpInfo=YOUR_KEY \
       ApiKeys__AbuseIpDb=YOUR_KEY \
       ApiKeys__VirusTotal=YOUR_KEY \
       ApiKeys__Shodan=YOUR_KEY \
       Redis__ConnectionString=YOUR_REDIS_URL
   ```

### Environment Variables

For production, use Azure secrets or environment variables:

| Variable | Description |
|----------|-------------|
| `ApiKeys__IpInfo` | IPinfo.io API token |
| `ApiKeys__AbuseIpDb` | AbuseIPDB API key |
| `ApiKeys__VirusTotal` | VirusTotal API key |
| `ApiKeys__Shodan` | Shodan API key |
| `Redis__ConnectionString` | Upstash Redis connection string |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/lookup/{ip}` | Full IP intelligence lookup |
| `GET /api/lookup/{ip}/basic` | Basic geo/ASN info only |
| `GET /health` | Health check endpoint |

### Example Response

```json
{
  "ipAddress": "8.8.8.8",
  "ipVersion": "IPv4",
  "isPrivate": false,
  "fromCache": false,
  "location": {
    "city": "Mountain View",
    "region": "California",
    "country": "United States",
    "countryCode": "US",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "timezone": "America/Los_Angeles"
  },
  "network": {
    "hostname": "dns.google",
    "isp": "Google LLC",
    "asn": 15169,
    "asnName": "Google LLC"
  },
  "security": {
    "abuseConfidenceScore": 0,
    "isVpn": false,
    "isProxy": false,
    "isHosting": true,
    "maliciousDetections": 0
  }
}
```

## Caching Strategy

Results are cached with staggered TTLs to optimize API usage:

| Data Type | TTL | Reason |
|-----------|-----|--------|
| Geo/ASN | 7 days | Rarely changes |
| Abuse score | 24 hours | Updates frequently |
| VPN/Proxy flags | 24 hours | Can change |
| VirusTotal | 6 hours | Threat data dynamic |
| WHOIS | 30 days | Rarely changes |
| Shodan | 12 hours | Services can change |
| Domains | 24 hours | Moderate change rate |

## Cost Estimate

| Component | Monthly Cost |
|-----------|--------------|
| Azure Container Apps (Consumption) | $0-5 |
| Upstash Redis (Free Tier) | $0 |
| All APIs (Free Tiers) | $0 |
| **Total** | **~$0-5/month** |

## License

MIT License - see [LICENSE](LICENSE) for details.
