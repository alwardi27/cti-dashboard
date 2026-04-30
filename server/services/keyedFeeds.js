import { getIocs, getSeverity, insertIoc, insertOrUpdateCve, updateFeedStatus } from '../db/database.js';
import { feedGet, feedPost } from '../utils/feedHttp.js';

const DEFAULT_GREYNOISE_QUERY = process.env.GREYNOISE_QUERY || 'classification:malicious last_seen:1d';
const DEFAULT_SHODAN_QUERY = process.env.SHODAN_QUERY || 'has_vuln:true';
const DEFAULT_CENSYS_QUERY = process.env.CENSYS_QUERY || 'services.software.uniform_resource_identifier:*';
const DEFAULT_VULNCHECK_INDEX = 'vulncheck-nvd2';

export async function fetchVulnCheckCves(token, options = {}) {
    if (!token) return skipFeed('vulncheck', 'Skipped: VULNCHECK_API_TOKEN is not configured');

    try {
        const requestedIndex = options.index || process.env.VULNCHECK_INDEX || null;
        const index = requestedIndex || await chooseVulnCheckIndex(token);
        if (!index) {
            return skipFeed('vulncheck', 'Skipped: no accessible VulnCheck CVE index found for this token');
        }

        const response = await fetchVulnCheckIndex(token, index, options.limit);

        const records = parseVulnCheckPayload(response.data);
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
        if (isVulnCheckAccessError(error)) {
            const status = error.response?.status;
            const index = options.index || process.env.VULNCHECK_INDEX || DEFAULT_VULNCHECK_INDEX;
            return skipFeed('vulncheck', `Skipped: VulnCheck token does not have access to ${index} (HTTP ${status})`);
        }
        await failFeed('vulncheck', error);
        throw error;
    }
}

async function fetchVulnCheckIndex(token, index, limit) {
    return feedGet(`https://api.vulncheck.com/v3/index/${encodeURIComponent(index)}`, {
        headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${token}`
        },
        params: { limit: boundedInt(limit ?? process.env.VULNCHECK_LIMIT, 1, 500, 200) },
        timeout: Number.parseInt(process.env.VULNCHECK_TIMEOUT_MS || '90000', 10)
    }, { retries: Number.parseInt(process.env.VULNCHECK_RETRIES || '3', 10) });
}

async function chooseVulnCheckIndex(token) {
    try {
        const response = await feedGet('https://api.vulncheck.com/v3/index', {
            headers: {
                Accept: 'application/json',
                Authorization: `Bearer ${token}`
            },
            timeout: Number.parseInt(process.env.VULNCHECK_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.VULNCHECK_RETRIES || '3', 10) });
        const accessible = parseVulnCheckIndexes(response.data);
        return [
            DEFAULT_VULNCHECK_INDEX,
            'nist-nvd2',
            'nvd2',
            'nist-nvd',
            'vulncheck-nvd'
        ].find(index => accessible.has(index)) || null;
    } catch (error) {
        if (isVulnCheckAccessError(error)) return null;
        throw error;
    }
}

export function parseVulnCheckIndexes(payload) {
    const records = arrayFrom(payload?.data, payload?.results, payload);
    return new Set(records.map(record => String(record.name || record.index || '').trim()).filter(Boolean));
}

function isVulnCheckAccessError(error) {
    return [401, 402, 403].includes(Number(error.response?.status));
}

export async function fetchOtxPulses(apiKey, options = {}) {
    if (!apiKey) return skipFeed('otx', 'Skipped: OTX_API_KEY is not configured');

    try {
        const modifiedSince = options.modifiedSince || getOtxModifiedSince();
        const response = await feedGet('https://otx.alienvault.com/api/v1/pulses/subscribed', {
            headers: { 'X-OTX-API-KEY': apiKey },
            params: cleanParams({
                limit: boundedInt(options.limit ?? process.env.OTX_LIMIT, 1, 50, 50),
                page: boundedInt(options.page ?? process.env.OTX_PAGE, 1, 50, 1),
                modified_since: modifiedSince
            }),
            timeout: Number.parseInt(process.env.OTX_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.OTX_RETRIES || '3', 10) });

        const pulses = parseOtxPayload(response.data);
        let count = 0;

        for (const pulse of pulses) {
            const indicators = arrayFrom(pulse.indicators);
            for (const indicator of indicators) {
                const normalized = normalizeOtxIndicator(indicator);
                if (!normalized) continue;

                if (normalized.type === 'cve') {
                    insertOrUpdateCve({
                        id: normalized.value.toUpperCase(),
                        source: 'otx',
                        description: String(pulse.name || pulse.description || `OTX pulse indicator ${normalized.value}`).substring(0, 5000),
                        cvss_score: 5,
                        cvss_vector: null,
                        severity: 'medium',
                        published_at: pulse.modified || pulse.created || new Date().toISOString(),
                        search_text: buildOtxSearchText(pulse, indicator)
                    });
                } else {
                    insertIoc({
                        type: normalized.type,
                        value: normalized.value,
                        source: 'otx',
                        threat_type: pulse.name || 'otx-pulse',
                        confidence: 70,
                        first_seen: pulse.created,
                        last_seen: pulse.modified || pulse.created,
                        metadata: JSON.stringify({
                            pulse_id: pulse.id,
                            pulse_name: pulse.name,
                            indicator_type: indicator.type,
                            indicator_description: indicator.description,
                            tags: pulse.tags
                        }),
                        search_text: buildOtxSearchText(pulse, indicator)
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

export async function fetchAbuseIpdbBlacklist(apiKey, options = {}) {
    if (!apiKey) return skipFeed('abuseipdb', 'Skipped: ABUSEIPDB_API_KEY is not configured');

    try {
        const response = await feedGet('https://api.abuseipdb.com/api/v2/blacklist', {
            headers: {
                Accept: 'application/json',
                Key: apiKey
            },
            params: cleanParams({
                confidenceMinimum: boundedInt(options.confidenceMinimum ?? process.env.ABUSEIPDB_CONFIDENCE_MINIMUM, 25, 100, 90),
                limit: boundedInt(options.limit ?? process.env.ABUSEIPDB_LIMIT, 1, 500000, 1000),
                ipVersion: parseIpVersion(options.ipVersion ?? process.env.ABUSEIPDB_IP_VERSION)
            }),
            timeout: Number.parseInt(process.env.ABUSEIPDB_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.ABUSEIPDB_RETRIES || '3', 10) });

        const rows = parseAbuseIpdbBlacklist(response.data);
        let count = 0;
        for (const row of rows) {
            const ip = row.ipAddress || row.ip;
            if (!isIp(ip)) continue;
            insertIoc({
                type: 'ip',
                value: ip,
                source: 'abuseipdb',
                threat_type: 'abusive-ip',
                confidence: clampConfidence(row.abuseConfidenceScore ?? row.confidence ?? 90),
                first_seen: row.lastReportedAt,
                last_seen: row.lastReportedAt,
                metadata: JSON.stringify({
                    country: row.countryCode,
                    usage_type: row.usageType,
                    isp: row.isp,
                    domain: row.domain,
                    total_reports: row.totalReports,
                    num_distinct_users: row.numDistinctUsers,
                    is_tor: row.isTor
                }),
                search_text: [row.countryCode, row.usageType, row.isp, row.domain].join(' ')
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
        const response = await feedGet('https://api.greynoise.io/v3/gnql', {
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

export async function fetchShodan(apiKey, query = DEFAULT_SHODAN_QUERY, options = {}) {
    if (!apiKey) return skipFeed('shodan', 'Skipped: SHODAN_API_KEY is not configured');

    try {
        const response = await feedGet('https://api.shodan.io/shodan/host/search', {
            params: cleanParams({
                key: apiKey,
                query,
                page: boundedInt(options.page ?? process.env.SHODAN_PAGE, 1, 100, 1),
                minify: booleanOption(options.minify ?? process.env.SHODAN_MINIFY, false),
                fields: options.fields ?? process.env.SHODAN_FIELDS
            }),
            timeout: Number.parseInt(process.env.GREYNOISE_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.GREYNOISE_RETRIES || '3', 10) });

        const matches = parseShodanResults(response.data);
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
                        domains: match.domains,
                        product: match.product,
                        version: match.version,
                        tags: match.tags,
                        vulns: Object.keys(match.vulns || {})
                    }),
                    search_text: [
                        query,
                        match.port,
                        match.transport,
                        match.org,
                        match.product,
                        match.version,
                        ...listFrom(match.hostnames),
                        ...listFrom(match.domains),
                        ...listFrom(match.tags),
                        ...Object.keys(match.vulns || {})
                    ].join(' ')
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
                    published_at: match.timestamp || new Date().toISOString(),
                    search_text: [
                        query,
                        ip,
                        match.port,
                        match.org,
                        match.product,
                        match.version,
                        ...listFrom(match.hostnames),
                        ...listFrom(match.domains)
                    ].join(' ')
                });
                count++;
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

export function parseVulnCheckPayload(payload) {
    return arrayFrom(payload?.data, payload?.results, payload);
}

export function parseOtxPayload(payload) {
    return arrayFrom(payload?.results, payload);
}

export function normalizeOtxIndicator(indicator = {}) {
    const value = String(indicator.indicator || indicator.value || '').trim();
    if (!value) return null;
    if (/^CVE-\d{4}-\d+$/i.test(value) || String(indicator.type || '').toLowerCase() === 'cve') {
        return { type: 'cve', value };
    }

    const type = mapOtxType(indicator.type, value);
    return type ? { type, value } : null;
}

export function parseAbuseIpdbBlacklist(payload) {
    if (typeof payload === 'string') {
        return payload
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(Boolean)
            .map(ipAddress => ({ ipAddress }));
    }
    return arrayFrom(payload?.data, payload);
}

export function parseShodanResults(payload) {
    return arrayFrom(payload?.matches, payload);
}

export async function fetchCensys(apiId, apiSecret, query = DEFAULT_CENSYS_QUERY) {
    if (!apiId || !apiSecret) return skipFeed('censys', 'Skipped: CENSYS_API_ID and CENSYS_API_SECRET are not configured');

    try {
        const response = await feedPost(
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
                timeout: Number.parseInt(process.env.CENSYS_TIMEOUT_MS || '90000', 10)
            },
            { retries: Number.parseInt(process.env.CENSYS_RETRIES || '3', 10) }
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

    try {
        if (!query) {
            return enrichVirusTotalFromLocalIocs(apiKey);
        }

        const response = await feedGet('https://www.virustotal.com/api/v3/intelligence/search', {
            headers: { 'x-apikey': apiKey },
            params: { query, limit: boundedInt(process.env.VIRUSTOTAL_LIMIT, 1, 300, 100) },
            timeout: Number.parseInt(process.env.VIRUSTOTAL_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.VIRUSTOTAL_RETRIES || '3', 10) });

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
        if (query && [401, 403, 404].includes(Number(error.response?.status))) {
            console.warn(`[VirusTotal] Intelligence search unavailable (${error.message}); falling back to local IOC enrichment.`);
            return enrichVirusTotalFromLocalIocs(apiKey);
        }
        await failFeed('virustotal', error);
        throw error;
    }
}

async function enrichVirusTotalFromLocalIocs(apiKey) {
    const limit = boundedInt(process.env.VIRUSTOTAL_ENRICH_LIMIT, 1, 100, 25);
    const candidates = getIocs({ limit: 500 })
        .filter(ioc => ioc.source !== 'virustotal')
        .slice(0, limit);

    if (!candidates.length) {
        await updateFeedStatus('virustotal', 'success', 0);
        console.log('[VirusTotal] No local IOCs available for enrichment');
        return 0;
    }

    let count = 0;
    for (const ioc of candidates) {
        const endpoint = virusTotalEndpointForIoc(ioc);
        if (!endpoint) continue;

        try {
            const response = await feedGet(endpoint, {
                headers: { 'x-apikey': apiKey },
                timeout: Number.parseInt(process.env.VIRUSTOTAL_TIMEOUT_MS || '90000', 10)
            }, { retries: Number.parseInt(process.env.VIRUSTOTAL_RETRIES || '2', 10) });
            const attrs = response.data?.data?.attributes || {};
            insertIoc({
                type: ioc.type,
                value: ioc.value,
                source: 'virustotal',
                threat_type: attrs.popular_threat_classification?.suggested_threat_label || ioc.threat_type || 'virustotal-enriched',
                confidence: confidenceFromVotes(attrs.last_analysis_stats),
                first_seen: toIso(attrs.first_submission_date) || ioc.first_seen,
                last_seen: toIso(attrs.last_analysis_date || attrs.last_modification_date) || ioc.last_seen,
                metadata: JSON.stringify({
                    enriched_from_source: ioc.source,
                    reputation: attrs.reputation,
                    tags: attrs.tags,
                    last_analysis_stats: attrs.last_analysis_stats
                })
            });
            count++;
        } catch (error) {
            const status = Number(error.response?.status);
            if (![404, 400].includes(status)) {
                console.warn(`[VirusTotal] Failed to enrich ${ioc.type}:${ioc.value}: ${error.message}`);
            }
        }
    }

    await updateFeedStatus('virustotal', 'success', count);
    console.log(`[VirusTotal] Enriched ${count} local IOCs`);
    return count;
}

function virusTotalEndpointForIoc(ioc) {
    const value = String(ioc.value || '').trim();
    if (!value) return null;
    if (ioc.type === 'ip') return `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
    if (ioc.type === 'domain') return `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
    if (ioc.type === 'hash') return `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`;
    if (ioc.type === 'url') {
        const id = Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        return `https://www.virustotal.com/api/v3/urls/${id}`;
    }
    return null;
}

export function parseCveRecord(record, source) {
    const cve = record.cve || record;
    const id = cve.id || cve.cve_id || record.id || record.cveId;
    if (!id || !/^CVE-\d{4}-\d+$/i.test(id)) return null;

    const metrics = cve.metrics || record.metrics || {};
    const metric = firstCvssMetric(metrics);
    const cvssData = metric.cvssData || metric;
    const score = Number(
        cve.cvss_score ||
        record.cvss_score ||
        cvssData.baseScore ||
        metrics.temporalCVSSV31?.associatedBaseMetricV3?.baseScore ||
        record.cvss?.score ||
        0
    );
    const description = cve.descriptions?.find?.(d => d.lang === 'en')?.value || cve.description || record.description || record.summary || 'No description';
    const cpes = arrayFrom(record.vcVulnerableCPEs, record.vulnerableCPEs, cve.vulnerableCPEs).slice(0, 50);
    const tags = arrayFrom(record.categorization?.tags, cve.categorization?.tags);
    const references = arrayFrom(record.references, cve.references).slice(0, 20);

    return {
        id: id.toUpperCase(),
        source,
        description: String(description).substring(0, 5000),
        cvss_score: score,
        cvss_vector: cvssData.vectorString || record.cvss?.vector_string || null,
        severity: getSeverity(score),
        published_at: cve.published || record.published || record.published_at || record.lastModified || new Date().toISOString(),
        search_text: [
            record.sourceIdentifier,
            record.vulnStatus || record.STATUS,
            record.cisaVulnerabilityName,
            record.cisaRequiredAction,
            record.vulncheckExploitAdd || record.vulncheckKEVExploitAdd,
            ...tags,
            ...cpes,
            ...references.map(ref => [ref.name, ref.url, ref.refsource, ...(ref.tags || [])].join(' '))
        ].join(' '),
        search_metadata: {
            vuln_status: record.vulnStatus || record.STATUS || null,
            cisa_exploit_add: record.cisaExploitAdd || null,
            vulncheck_exploit_add: record.vulncheckExploitAdd || record.vulncheckKEVExploitAdd || null,
            tags,
            vulnerable_cpes: cpes
        }
    };
}

function firstCvssMetric(metrics = {}) {
    return metrics.cvssMetricV40?.[0] ||
        metrics.cvssMetricV31?.[0] ||
        metrics.cvssMetricV30?.[0] ||
        metrics.cvssMetricV2?.[0] ||
        metrics.cvssMetricV4?.[0] ||
        {};
}

function mapOtxType(type, value) {
    const normalized = String(type || '').toLowerCase();
    if (normalized.includes('ipv4') || normalized.includes('ipv6') || normalized === 'ip') return 'ip';
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
    if (isIp(value)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(value) || /^[a-fA-F0-9]{40}$/.test(value) || /^[a-fA-F0-9]{64}$/.test(value)) return 'hash';
    if (value.includes('://')) return 'url';
    if (value.includes('.')) return 'domain';
    return null;
}

function isIp(value) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(String(value || '')) ||
        (/^[a-fA-F0-9:]{3,}$/.test(String(value || '')) && String(value || '').includes(':'));
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

function listFrom(value) {
    if (Array.isArray(value)) return value;
    if (value === undefined || value === null || value === '') return [];
    return [value];
}

function boundedInt(value, min, max, fallback) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
}

function parseIpVersion(value) {
    const parsed = Number.parseInt(value, 10);
    return [4, 6].includes(parsed) ? parsed : null;
}

function booleanOption(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'boolean') return value;
    const normalized = String(value).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
    return fallback;
}

function cleanParams(params) {
    return Object.fromEntries(Object.entries(params).filter(([, value]) => value !== null && value !== undefined && value !== ''));
}

function getOtxModifiedSince() {
    const hours = Number.parseInt(process.env.OTX_MODIFIED_SINCE_HOURS || '', 10);
    if (!Number.isFinite(hours) || hours <= 0) return null;
    return new Date(Date.now() - Math.min(hours, 168) * 60 * 60 * 1000).toISOString();
}

function buildOtxSearchText(pulse = {}, indicator = {}) {
    return [
        pulse.name,
        pulse.description,
        pulse.author_name,
        pulse.tlp || pulse.TLP,
        ...listFrom(pulse.tags),
        ...listFrom(pulse.adversary),
        indicator.description,
        indicator.type
    ].join(' ');
}

async function skipFeed(source, message) {
    await updateFeedStatus(source, 'skipped', 0, message);
    console.log(`[${source}] ${message}`);
    return 0;
}

async function failFeed(source, error) {
    const message = error.response?.data?.message || error.response?.data?.error?.message || error.message;
    await updateFeedStatus(source, 'error', 0, message);
    console.error(`[${source}] Error: ${message}`);
}

export default {
    fetchVulnCheckCves,
    fetchOtxPulses,
    fetchAbuseIpdbBlacklist,
    fetchGreyNoise,
    fetchShodan,
    fetchCensys,
    fetchVirusTotal,
    parseVulnCheckIndexes,
    parseVulnCheckPayload,
    parseOtxPayload,
    normalizeOtxIndicator,
    parseAbuseIpdbBlacklist,
    parseShodanResults,
    parseCveRecord
};
