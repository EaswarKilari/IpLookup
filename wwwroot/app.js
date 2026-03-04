// IP Intelligence Lookup - Frontend JavaScript

const API_BASE = '/api';

// DOM Elements
const searchForm = document.getElementById('searchForm');
const ipInput = document.getElementById('ipInput');
const searchBtn = document.getElementById('searchBtn');
const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const errorMessage = document.getElementById('errorMessage');
const resultsContainer = document.getElementById('resultsContainer');

// Event Listeners
searchForm.addEventListener('submit', handleSearch);
document.querySelectorAll('.example-ip').forEach(btn => {
    btn.addEventListener('click', () => {
        ipInput.value = btn.dataset.ip;
        searchForm.dispatchEvent(new Event('submit'));
    });
});

// Handle URL parameters on page load
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const ip = params.get('ip');
    if (ip) {
        ipInput.value = ip;
        lookupIp(ip);
    }
});

async function handleSearch(e) {
    e.preventDefault();
    const ip = ipInput.value.trim();
    if (!ip) return;

    // Update URL
    const url = new URL(window.location);
    url.searchParams.set('ip', ip);
    window.history.pushState({}, '', url);

    await lookupIp(ip);
}

async function lookupIp(ip) {
    showLoading();
    hideError();
    hideResults();

    try {
        const response = await fetch(`${API_BASE}/lookup/${encodeURIComponent(ip)}`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to lookup IP');
        }

        if (data.isPrivate) {
            showError('This is a private/reserved IP address. External lookups are not available for private IPs.');
            return;
        }

        displayResults(data);
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

function displayResults(data) {
    // Summary Header
    document.getElementById('resultIp').textContent = data.ipAddress;
    document.getElementById('ipVersionBadge').textContent = data.ipVersion;
    
    const cacheBadge = document.getElementById('cacheBadge');
    if (data.fromCache) {
        cacheBadge.classList.remove('hidden');
    } else {
        cacheBadge.classList.add('hidden');
    }

    // Location summary
    const loc = data.location;
    if (loc) {
        const parts = [loc.city, loc.region, loc.country].filter(Boolean);
        document.getElementById('resultLocation').textContent = parts.join(', ') || 'Location unknown';
    }

    // Abuse Score
    const abuseScoreEl = document.getElementById('abuseScore');
    const score = data.security?.abuseConfidenceScore;
    if (score !== null && score !== undefined) {
        abuseScoreEl.textContent = score + '%';
        abuseScoreEl.className = 'threat-score ' + getThreatClass(score);
    } else {
        abuseScoreEl.textContent = '--';
        abuseScoreEl.className = 'threat-score text-gray-500';
    }

    // Populate sections
    populateLocationSection(data.location, data.apiStatuses);
    populateNetworkSection(data.network, data.apiStatuses);
    populateSecuritySection(data.security, data.apiStatuses);
    populateRegistrationSection(data.registration, data.apiStatuses);
    populatePortsSection(data.ports, data.apiStatuses);
    populateDomainsSection(data.domains, data.apiStatuses);
    populateApiStatuses(data.apiStatuses);

    showResults();
}

function populateLocationSection(location, apiStatuses) {
    const content = document.getElementById('locationContent');
    const status = document.getElementById('locationStatus');
    
    setStatusIndicator(status, apiStatuses?.ipinfo);

    if (!location) {
        content.innerHTML = '<p class="text-gray-500">No location data available</p>';
        return;
    }

    content.innerHTML = `
        ${field('Country', location.country ? `${getFlagEmoji(location.countryCode)} ${location.country}` : null)}
        ${field('City', location.city)}
        ${field('Region', location.region)}
        ${field('Postal Code', location.postalCode)}
        ${field('Coordinates', location.latitude && location.longitude ? 
            `<a href="${location.mapUrl}" target="_blank" class="text-primary hover:underline">${location.latitude}, ${location.longitude}</a>` : null)}
        ${field('Timezone', location.timezone)}
    `;
}

function populateNetworkSection(network, apiStatuses) {
    const content = document.getElementById('networkContent');
    const status = document.getElementById('networkStatus');
    
    setStatusIndicator(status, apiStatuses?.ipinfo);

    if (!network) {
        content.innerHTML = '<p class="text-gray-500">No network data available</p>';
        return;
    }

    content.innerHTML = `
        ${field('Hostname', network.hostname)}
        ${field('ISP', network.isp)}
        ${field('Organization', network.organization)}
        ${field('ASN', network.asn ? `AS${network.asn}` : null)}
        ${field('AS Name', network.asnName)}
        ${field('Network Range', network.networkRange)}
    `;
}

function populateSecuritySection(security, apiStatuses) {
    const content = document.getElementById('securityContent');
    const status = document.getElementById('securityStatus');
    
    // Check if any security API succeeded
    const anySuccess = ['abuseipdb', 'ip-api', 'virustotal'].some(api => apiStatuses?.[api]?.success);
    setStatusIndicator(status, { success: anySuccess });

    if (!security) {
        content.innerHTML = '<p class="text-gray-500">No security data available</p>';
        return;
    }

    // Build flags list
    const flags = [];
    if (security.isVpn) flags.push({ label: 'VPN', color: 'yellow' });
    if (security.isProxy) flags.push({ label: 'Proxy', color: 'yellow' });
    if (security.isTor) flags.push({ label: 'Tor', color: 'red' });
    if (security.isHosting) flags.push({ label: 'Datacenter/Hosting', color: 'blue' });
    if (security.isMobile) flags.push({ label: 'Mobile', color: 'green' });

    const flagsHtml = flags.length > 0 
        ? flags.map(f => `<span class="badge bg-${f.color}-900 text-${f.color}-400">${f.label}</span>`).join(' ')
        : '<span class="text-gray-500">None detected</span>';

    // VirusTotal detections
    let vtHtml = '';
    if (security.totalEngines !== null && security.totalEngines !== undefined) {
        const malicious = security.maliciousDetections || 0;
        const suspicious = security.suspiciousDetections || 0;
        const total = security.totalEngines;
        
        vtHtml = `
            <div class="flex items-center gap-2">
                <span class="text-${malicious > 0 ? 'red' : 'green'}-400 font-semibold">${malicious}/${total}</span>
                <span class="text-gray-500">engines flagged as malicious</span>
            </div>
        `;

        if (security.maliciousVendors && security.maliciousVendors.length > 0) {
            vtHtml += `<div class="text-sm text-gray-500">Flagged by: ${security.maliciousVendors.join(', ')}</div>`;
        }
    }

    content.innerHTML = `
        ${field('Abuse Score', security.abuseConfidenceScore !== null ? 
            `<span class="${getThreatClass(security.abuseConfidenceScore)}">${security.abuseConfidenceScore}%</span>` : null)}
        ${field('Total Reports', security.totalReports)}
        ${field('Reporters', security.distinctReporters)}
        ${field('Last Reported', security.lastReportedAt ? new Date(security.lastReportedAt).toLocaleDateString() : null)}
        ${field('Usage Type', security.usageType)}
        <div class="pt-2 border-t border-gray-700">
            <div class="text-gray-400 text-sm mb-2">Detection Flags</div>
            <div class="flex flex-wrap gap-2">${flagsHtml}</div>
        </div>
        ${security.totalEngines !== null && security.totalEngines !== undefined ? `
        <div class="pt-2 border-t border-gray-700">
            <div class="text-gray-400 text-sm mb-2">VirusTotal</div>
            ${vtHtml}
        </div>
        ` : ''}
    `;
}

function populateRegistrationSection(registration, apiStatuses) {
    const content = document.getElementById('registrationContent');
    const status = document.getElementById('registrationStatus');
    
    setStatusIndicator(status, apiStatuses?.rdap);

    if (!registration) {
        content.innerHTML = '<p class="text-gray-500">No WHOIS data available</p>';
        return;
    }

    content.innerHTML = `
        ${field('Network Handle', registration.networkHandle)}
        ${field('Network Name', registration.networkName)}
        ${field('IP Range', registration.startAddress && registration.endAddress ? 
            `${registration.startAddress} - ${registration.endAddress}` : null)}
        ${field('Registrant', registration.registrantName)}
        ${field('Registered', registration.registrationDate ? new Date(registration.registrationDate).toLocaleDateString() : null)}
        ${field('Last Updated', registration.lastUpdated ? new Date(registration.lastUpdated).toLocaleDateString() : null)}
        ${registration.registryUrl ? `
        <div class="pt-2">
            <a href="${registration.registryUrl}" target="_blank" class="text-primary hover:underline text-sm">View in Registry →</a>
        </div>` : ''}
    `;
}

function populatePortsSection(ports, apiStatuses) {
    const content = document.getElementById('portsContent');
    const status = document.getElementById('portsStatus');
    
    setStatusIndicator(status, apiStatuses?.shodan);

    if (!ports || !ports.openPorts || ports.openPorts.length === 0) {
        const error = apiStatuses?.shodan?.error;
        content.innerHTML = `<p class="text-gray-500">${error || 'No open ports detected'}</p>`;
        return;
    }

    const portsHtml = ports.openPorts.map(p => `
        <div class="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
            <div>
                <span class="font-mono text-primary">${p.port}</span>
                <span class="text-gray-500">/${p.protocol || 'tcp'}</span>
            </div>
            <div class="text-right">
                <div class="text-gray-300">${p.product || p.service || 'Unknown'}</div>
                ${p.version ? `<div class="text-gray-500 text-sm">${p.version}</div>` : ''}
            </div>
        </div>
    `).join('');

    content.innerHTML = `
        <div class="space-y-1">${portsHtml}</div>
        ${ports.lastScan ? `<div class="text-gray-500 text-sm mt-3">Last scanned: ${new Date(ports.lastScan).toLocaleDateString()}</div>` : ''}
        ${ports.vulnerabilities && ports.vulnerabilities.length > 0 ? `
        <div class="pt-2 mt-2 border-t border-gray-700">
            <div class="text-red-400 text-sm">⚠️ Vulnerabilities: ${ports.vulnerabilities.join(', ')}</div>
        </div>` : ''}
    `;
}

function populateDomainsSection(domains, apiStatuses) {
    const content = document.getElementById('domainsContent');
    const status = document.getElementById('domainsStatus');
    
    setStatusIndicator(status, apiStatuses?.hackertarget);

    if (!domains || !domains.hostedDomains || domains.hostedDomains.length === 0) {
        const error = apiStatuses?.hackertarget?.error;
        content.innerHTML = `<p class="text-gray-500">${error || 'No hosted domains found'}</p>`;
        return;
    }

    const domainsHtml = domains.hostedDomains.slice(0, 10).map(d => `
        <a href="https://${d}" target="_blank" class="block text-primary hover:underline">${d}</a>
    `).join('');

    content.innerHTML = `
        <div class="space-y-1">${domainsHtml}</div>
        ${domains.totalCount > 10 ? `<div class="text-gray-500 text-sm mt-2">...and ${domains.totalCount - 10} more</div>` : ''}
        <div class="text-gray-500 text-sm mt-2">Total: ${domains.totalCount} domain(s)</div>
    `;
}

function populateApiStatuses(statuses) {
    const container = document.getElementById('apiStatuses');
    if (!statuses) {
        container.innerHTML = '';
        return;
    }

    const apis = [
        { key: 'ipinfo', name: 'IPinfo' },
        { key: 'abuseipdb', name: 'AbuseIPDB' },
        { key: 'ip-api', name: 'ip-api' },
        { key: 'virustotal', name: 'VirusTotal' },
        { key: 'rdap', name: 'RDAP' },
        { key: 'shodan', name: 'Shodan' },
        { key: 'hackertarget', name: 'HackerTarget' }
    ];

    container.innerHTML = apis.map(api => {
        const status = statuses[api.key];
        if (!status) return '';
        
        const isSuccess = status.success;
        const isCached = status.fromCache;
        const color = isSuccess ? (isCached ? 'green' : 'blue') : 'red';
        const icon = isSuccess ? '✓' : '✗';
        const suffix = isCached ? ' (cached)' : (status.responseTimeMs ? ` (${status.responseTimeMs}ms)` : '');
        
        return `
            <span class="badge bg-${color}-900/50 text-${color}-400" title="${status.error || 'Success'}">
                ${icon} ${api.name}${suffix}
            </span>
        `;
    }).join('');
}

// Helper Functions
function field(label, value) {
    if (value === null || value === undefined) return '';
    return `
        <div class="flex justify-between">
            <span class="text-gray-400">${label}</span>
            <span class="text-gray-100">${value}</span>
        </div>
    `;
}

function setStatusIndicator(element, status) {
    if (!status) {
        element.innerHTML = '';
        return;
    }
    
    if (status.fromCache) {
        element.innerHTML = '<span class="badge bg-green-900/50 text-green-400 text-xs">Cached</span>';
    } else if (status.success) {
        element.innerHTML = '<span class="badge bg-blue-900/50 text-blue-400 text-xs">Live</span>';
    } else {
        element.innerHTML = `<span class="badge bg-red-900/50 text-red-400 text-xs" title="${status.error}">Error</span>`;
    }
}

function getThreatClass(score) {
    if (score === null || score === undefined) return '';
    if (score <= 25) return 'threat-low';
    if (score <= 75) return 'threat-medium';
    return 'threat-high';
}

function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}

// UI State Functions
function showLoading() {
    loadingState.classList.remove('hidden');
    searchBtn.disabled = true;
}

function hideLoading() {
    loadingState.classList.add('hidden');
    searchBtn.disabled = false;
}

function showError(message) {
    errorMessage.textContent = message;
    errorState.classList.remove('hidden');
}

function hideError() {
    errorState.classList.add('hidden');
}

function showResults() {
    resultsContainer.classList.remove('hidden');
}

function hideResults() {
    resultsContainer.classList.add('hidden');
}
