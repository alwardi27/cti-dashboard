import axios from 'axios';
import { getSeverity, insertIoc, insertOrUpdateCve, updateFeedStatus } from '../db/database.js';

const DEFAULT_GREYNOISE_QUERY = process.env.GREYNOISE_QUERY || 'classification:malicious last_seen:1d';
const DEFAULT_SHODAN_QUERY = process.env.SHODAN_QUERY || 'has_vuln:true';
const DEFAULT_CENSYS_QUERY = process.env.CENSYS_QUERY || 'services.software.uniform_resource_identifier:*';

export async function fetchVulnCheckCves(token) {
    if (!token) return skipFeed('vulncheck', 'Skipped: VULNCHECK_API_TOKEN is not configured');

    try {
        const response = await axios.get('https://api.vulncheck.com/v3/index/nist-nvd2', {
            headers: {
                Accept: 'application/json',
                Authorization: `Bearer ${token}`
            },
            params: { limit: 200 },
            timeout: 30000
        });

        const records = arrayFrom(response.data?.data, response.data?.results, response.data);
        let count = 0;

        for (const record of records) {
            const parsed = parseCveRecord(record, 'vulncheck');
            if (!parsed) continue;
            insertOrUpdateCve(parsed);
            count++;
        }

        await updateFeedStatus('vulncheck', 'success', count);
        console.log(`[VulnCheck] Fetched ${count} CVEs`);
        return count;
    } catch (error) {
        await failFeed('vulncheck', error);
        throw error;
    }
}

export async function fetchOtxPulses(apiKey) {
    if (!apiKey) return skipFeed('otx', 'Skipped: OTX_API_KEY is not configured');

    try {
        const response = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed', {
            headers: { 'X-OTX-API-KEY': apiKey },
            params: { limit: 20 },
            timeout: 30000
        });

        const pulses = arrayFrom(response.data?.results, response.data);
        let count = 0;

        for (const pulse of pulses) {
            const indicators = arrayFrom(pulse.indicators);
            for (const indicator of indicators) {
                const value = indicator.indicator;
                if (!value) continue;

                if (/^CVE-\d{4}-\d+$/i.test(value)) {
                    insertOrUpdateCve({
                        id: value.toUpperCase(),
                        source: 'otx',
                        description: pulse.name || pulse.description || `OTX pulse indicator ${value}`,
                        cvss_score: 5,
                        cvss_vector: null,
                        severity: 'medium',
                        published_at: pulse.modified || pulse.created || new Date().toISOString()
                    });
                } else {
                    const type = mapOtxType(indicator.type, value);
                    if (!type) continue;
                    insertIoc({
                        type,
                        value,
                        source: 'otx',
                        threat_type: pulse.name || 'otx-pulse',
                        confidence: 70,
                        first_seen: pulse.created,
                        last_seen: pulse.modified || pulse.created,
                        metadata: JSON.stringify({
                            pulse_id: pulse.id,
                            pulse_name: pulse.name,
                            indicator_type: indicator.type,
                            tags: pulse.tags
                        })
                    });
                }
                count++;
            }
        }

        await updateFeedStatus('otx', 'success', count);
        console.log(`[OTX] Fetched ${count} indicators`);
        return count;
    } catch (error) {
        await failFeed('otx', error);
        throw error;
    }
}

export async function fetchAbuseIpdbBlacklist(apiKey) {
    if (!apiKey) return skipFeed('abuseipdb', 'Skipped: ABUSEIPDB_API_KEY is not configured');

    try {
        const response = await axios.get('https://api.abuseipdb.com/api/v2/blacklist', {
            headers: {
                Accept: 'application/json',
                Key: apiKey
            },
            params: {
                confidenceMinimum: process.env.ABUSEIPDB_CONFIDENCE_MINIMUM || 90,
                limit: process.env.ABUSEIPDB_LIMIT || 1000
            },
            timeout: 30000
        });

        const rows = arrayFrom(response.data?.data);
        let count = 0;
        for (const row of rows) {
            const ip = row.ipAddress || row.ip;
            if (!ip) continue;
            insertIoc({
                type: 'ip',
                value: ip,
                source: 'abuseipdb',
                threat_type: 'abusive-ip',
                confidence: clampConfidence(row.abuseConfidenceScore || 90),
                first_seen: row.lastReportedAt,
                last_seen: row.lastReportedAt,
                metadata: JSON.stringify({
                    country: row.countryCode,
                    usage_type: row.usageType,
                    isp: row.isp,
                    domain: row.domain
                })
            });
            count++;
        }

        await updateFeedStatus('abuseipdb', 'success', count);
        console.log(`[AbuseIPDB] Fetched ${count} IPs`);
        return count;
    } catch (error) {
        await failFeed('abuseipdb', error);
        throw error;
    }
}

export async function fetchGreyNoise(apiKey, query = DEFAULT_GREYNOISE_QUERY) {
    if (!apiKey) return skipFeed('greynoise', 'Skipped: GREYNOISE_API_KEY is not configured');

    try {
        const response = await axios.get('https://api.greynoise.io/v3/gnql', {
            headers: { key: apiKey },
            params: { query, size: 1000 },
            timeout: 30000
        });

        const rows = arrayFrom(response.data?.data);
        let count = 0;
        for (const row of rows) {
            if (row.ip) {
                insertIoc({
                    type: 'ip',
                    value: row.ip,
                    source: 'greynoise',
                    threat_type: row.classification || 'scanner',
                    confidence: row.classification === 'malicious' ? 85 : 60,
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                    metadata: JSON.stringify({
                        actor: row.actor,
                        tags: row.tags,
                        asn: row.metadata?.asn,
                        country: row.metadata?.country,
                        organization: row.metadata?.organization
                    })
                });
                count++;
            }

            for (const cveId of arrayFrom(row.cve)) {
                insertOrUpdateCve({
                    id: cveId,
                    source: 'greynoise',
                    description: `GreyNoise observed scanning activity associated with ${cveId}`,
                    cvss_score: 5,
                    cvss_vector: null,
                    severity: 'medium',
                    published_at: row.last_seen || new Date().toISOString()
                });
            }
        }

        await updateFeedStatus('greynoise', 'success', count);
        console.log(`[GreyNoise] Fetched ${count} IPs`);
        return count;
    } catch (error) {
        await failFeed('greynoise', error);
        throw error;
    }
}

export async function fetchShodan(apiKey, query = DEFAULT_SHODAN_QUERY) {
    if (!apiKey) return skipFeed('shodan', 'Skipped: SHODAN_API_KEY is not configured');

    try {
        const response = await axios.get('https://api.shodan.io/shodan/host/search', {
            params: { key: apiKey, query, limit: 100 },
            timeout: 30000
        });

        const matches = arrayFrom(response.data?.matches);
        let count = 0;
        for (const match of matches) {
            const ip = match.ip_str;
            if (ip) {
                insertIoc({
                    type: 'ip',
                    value: ip,
                    source: 'shodan',
                    threat_type: 'internet-exposure',
                    confidence: 55,
                    first_seen: match.timestamp,
                    last_seen: match.timestamp,
                    metadata: JSON.stringify({
                        port: match.port,
                        transport: match.transport,
                        org: match.org,
                        hostnames: match.hostnames,
                        product: match.product,
                        vulns: Object.keys(match.vulns || {})
                    })
                });
                count++;
            }

            for (const cveId of Object.keys(match.vulns || {})) {
                const vuln = match.vulns[cveId] || {};
                const score = Number(vuln.cvss) || 5;
                insertOrUpdateCve({
                    id: cveId,
                    source: 'shodan',
                    description: vuln.summary || `Shodan observed exposed service associated with ${cveId}`,
                    cvss_score: score,
                    cvss_vector: null,
                    severity: getSeverity(score),
                    published_at: match.timestamp || new Date().toISOString()
                });
            }
        }

        await updateFeedStatus('shodan', 'success', count);
        console.log(`[Shodan] Fetched ${count} exposed hosts`);
        return count;
    } catch (error) {
        await failFeed('shodan', error);
        throw error;
    }
}

export async function fetchCensys(apiId, apiSecret, query = DEFAULT_CENSYS_QUERY) {
    if (!apiId || !apiSecret) return skipFeed('censys', 'Skipped: CENSYS_API_ID and CENSYS_API_SECRET are not configured');

    try {
        const response = await axios.post(
            'https://search.censys.io/api/v2/hosts/search',
            {
                q: query,
                per_page: 100,
                virtual_hosts: 'EXCLUDE',
                sort: 'RELEVANCE',
                fields: ['ip', 'services.port', 'services.service_name', 'services.software', 'location.country', 'autonomous_system.name']
            },
            {
                auth: { username: apiId, password: apiSecret },
                timeout: 30000
            }
        );

        const hits = arrayFrom(response.data?.result?.hits);
        let count = 0;
        for (const hit of hits) {
            if (!hit.ip) continue;
            insertIoc({
                type: 'ip',
                value: hit.ip,
                source: 'censys',
                threat_type: 'internet-exposure',
                confidence: 50,
                first_seen: null,
                last_seen: new Date().toISOString(),
                metadata: JSON.stringify({
                    services: hit.services,
                    location: hit.location,
                    autonomous_system: hit.autonomous_system
                })
            });
            count++;
        }

        await updateFeedStatus('censys', 'success', count);
        console.log(`[Censys] Fetched ${count} hosts`);
        return count;
    } catch (error) {
        await failFeed('censys', error);
        throw error;
    }
}

export async function fetchVirusTotal(apiKey, query = process.env.VIRUSTOTAL_QUERY || null) {
    if (!apiKey) return skipFeed('virustotal', 'Skipped: VIRUSTOTAL_API_KEY is not configured');
    if (!query) return skipFeed('virustotal', 'Skipped: VIRUSTOTAL_QUERY is not configured; VirusTotal is available for query/enrichment workflows');

    try {
        const response = await axios.get('https://www.virustotal.com/api/v3/intelligence/search', {
            headers: { 'x-apikey': apiKey },
            params: { query, limit: 100 },
            timeout: 30000
        });

        const rows = arrayFrom(response.data?.data);
        let count = 0;
        for (const row of rows) {
            const attrs = row.attributes || {};
            const value = row.id;
            const type = mapVirusTotalType(row.type, value);
            if (!type || !value) continue;
            insertIoc({
                type,
                value,
                source: 'virustotal',
                threat_type: attrs.popular_threat_classification?.suggested_threat_label || row.type || 'virustotal',
                confidence: confidenceFromVotes(attrs.last_analysis_stats),
                first_seen: toIso(attrs.first_submission_date),
                last_seen: toIso(attrs.last_analysis_date || attrs.last_modification_date),
                metadata: JSON.stringify({
                    type: row.type,
                    meaningful_name: attrs.meaningful_name,
                    tags: attrs.tags,
                    last_analysis_stats: attrs.last_analysis_stats
                })
            });
            count++;
        }

        await updateFeedStatus('virustotal', 'success', count);
        console.log(`[VirusTotal] Fetched ${count} indicators`);
        return count;
    } catch (error) {
        await failFeed('virustotal', error);
        throw error;
    }
}

function parseCveRecord(record, source) {
    const cve = record.cve || record;
    const id = cve.id || cve.cve_id || record.id || record.cveId;
    if (!id || !/^CVE-\d{4}-\d+$/i.test(id)) return null;

    const metrics = cve.metrics || record.metrics || {};
    const metric = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0] || {};
    const cvssData = metric.cvssData || metric;
    const score = Number(cve.cvss_score || record.cvss_score || cvssData.baseScore || record.cvss?.score || 0);
    const description = cve.descriptions?.find?.(d => d.lang === 'en')?.value || cve.description || record.description || record.summary || 'No description';

    return {
        id: id.toUpperCase(),
        source,
        description: String(description).substring(0, 5000),
        cvss_score: score,
        cvss_vector: cvssData.vectorString || record.cvss?.vector_string || null,
        severity: getSeverity(score),
        published_at: cve.published || record.published || record.published_at || new Date().toISOString()
    };
}

function mapOtxType(type, value) {
    const normalized = String(type || '').toLowerCase();
    if (normalized.includes('ipv4') || normalized.includes('ipv6')) return 'ip';
    if (normalized.includes('domain') || normalized.includes('hostname')) return 'domain';
    if (normalized.includes('url')) return 'url';
    if (normalized.includes('file') || normalized.includes('hash')) return 'hash';
    return inferIocType(value);
}

function mapVirusTotalType(type, value) {
    if (type === 'ip_address') return 'ip';
    if (type === 'domain') return 'domain';
    if (type === 'url') return 'url';
    if (type === 'file') return 'hash';
    return inferIocType(value);
}

function inferIocType(value) {
    if (!value) return null;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[a-fA-F0-9:]{3,}$/.test(value) && value.includes(':')) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(value) || /^[a-fA-F0-9]{40}$/.test(value) || /^[a-fA-F0-9]{64}$/.test(value)) return 'hash';
    if (value.includes('://')) return 'url';
    if (value.includes('.')) return 'domain';
    return null;
}

function arrayFrom(...candidates) {
    for (const candidate of candidates) {
        if (Array.isArray(candidate)) return candidate;
    }
    return [];
}

function clampConfidence(value) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return 50;
    return Math.max(0, Math.min(100, parsed));
}

function confidenceFromVotes(stats = {}) {
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const total = malicious + suspicious + harmless + Number(stats.undetected || 0);
    if (!total) return 50;
    return clampConfidence(Math.round(((malicious + suspicious * 0.5) / total) * 100));
}

function toIso(epochSeconds) {
    if (!epochSeconds) return null;
    const date = new Date(Number(epochSeconds) * 1000);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

async function skipFeed(source, message) {
    await updateFeedStatus(source, 'skipped', 0, message);
    console.log(`[${source}] ${message}`);
    throw new Error(message);
}

async function failFeed(source, error) {
    const message = error.response?.data?.message || error.response?.data?.error?.message || error.message;
    await updateFeedStatus(source, 'error', 0, message);
    console.error(`[${source}] Error: ${message}`);
}
