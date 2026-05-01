import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import axios from 'axios';
import { parseCveFilters, parseSearchFilters, validateRefreshOverrides } from '../server/utils/validation.js';
import { buildRefreshSummary, runWithRefreshLock } from '../server/workers/scheduler.js';
import { meetsSeverityThreshold } from '../server/services/alerts.js';
import { importCveProgressItems, normalizeImportItem } from '../server/services/cveImport.js';
import { matchAssetToCve, normalizeCompanyAssetInput, parseCompanyAssetCsv } from '../server/services/companyAssets.js';
import { parseMalwareBazaarRecentResponse, queryMalwareBazaarByHash } from '../server/services/malwareBazaar.js';
import { buildTeamsPayload, buildTeamsTextPayload, notifyTeamsProgress } from '../server/services/teams.js';
import { parseFeodoCsv } from '../server/services/feodo.js';
import { parseSslblCertCsv, parseSslblIpCsv } from '../server/services/sslbl.js';
import { parseEpssResponse } from '../server/services/epss.js';
import { extractNvdVulnerableCpes } from '../server/services/nvd.js';
import { collectGithubPackages } from '../server/services/githubAdvisories.js';
import { parseOsvModifiedCsv, parseOsvRecord } from '../server/services/osv.js';
import {
    fetchAbuseIpdbBlacklist,
    fetchOtxPulses,
    fetchShodan,
    fetchVulnCheckCves,
    normalizeOtxIndicator,
    parseAbuseIpdbBlacklist,
    parseCveRecord,
    parseOtxPayload,
    parseShodanResults,
    parseVulnCheckIndexes,
    parseVulnCheckPayload
} from '../server/services/keyedFeeds.js';

test('severity mapping follows CVSS thresholds', async () => {
    const { getSeverity } = await import('../server/db/database.js');

    assert.equal(getSeverity(9), 'critical');
    assert.equal(getSeverity(7), 'high');
    assert.equal(getSeverity(4), 'medium');
    assert.equal(getSeverity(3.9), 'low');
});

test('CVE query validation accepts known filters and rejects bad values', () => {
    const filters = parseCveFilters({
        source: 'nvd',
        severity: 'critical,high',
        needsReview: 'true',
        limit: '25',
        offset: '5',
        sort: 'triage',
        fromDate: '2026-04-30T00:00:00Z'
    });

    assert.equal(filters.source, 'nvd');
    assert.equal(filters.severity, 'critical,high');
    assert.equal(filters.needsReview, true);
    assert.equal(filters.limit, 25);
    assert.equal(filters.offset, 5);
    assert.throws(() => parseCveFilters({ limit: 'nope' }), /limit must be an integer/);
    assert.throws(() => parseCveFilters({ severity: 'urgent' }), /severity must contain only/);
});

test('refresh override validation rejects unsupported body keys', () => {
    assert.deepEqual(validateRefreshOverrides({ nvdApiKey: 'test' }), { nvdApiKey: 'test' });
    assert.deepEqual(validateRefreshOverrides({ feodoEnabled: false, sslblEnabled: false }), { feodoEnabled: false, sslblEnabled: false });
    assert.throws(() => validateRefreshOverrides({ surprise: true }), /Unsupported refresh override/);
    assert.throws(() => validateRefreshOverrides({ whatsapp: { surprise: true } }), /Unsupported WhatsApp override/);
});

test('search query validation accepts global search filters', () => {
    const filters = parseSearchFilters({
        q: 'type:ioc source:sslbl botnet',
        type: 'ioc',
        source: 'sslbl',
        limit: '25',
        offset: '5'
    });

    assert.equal(filters.q, 'type:ioc source:sslbl botnet');
    assert.equal(filters.type, 'ioc');
    assert.equal(filters.source, 'sslbl');
    assert.equal(filters.limit, 25);
    assert.equal(filters.offset, 5);
    assert.throws(() => parseSearchFilters({ type: 'advisory' }), /type must be one of/);
});

test('progress import validation accepts flexible fields and rejects bad rows', () => {
    assert.deepEqual(normalizeImportItem({
        cve_id: 'cve-2026-1234',
        status: 'assigned',
        note: 'Review started',
        description: 'Manual context',
        severity: 'high',
        cvss_score: '8.2'
    }, 0), {
        index: 0,
        id: 'CVE-2026-1234',
        status: 'assigned',
        note: 'Review started',
        description: 'Manual context',
        severity: 'high',
        cvss_score: 8.2,
        valid: true
    });

    assert.equal(normalizeImportItem({ id: 'not-a-cve' }, 1).valid, false);
    assert.match(normalizeImportItem({ id: 'CVE-2026-1234', status: 'todo' }, 2).error, /status must be one of/);
    assert.match(normalizeImportItem({ id: 'CVE-2026-1234', cvss_score: '11' }, 3).error, /cvss_score/);
});

test('company asset validation and CSV import normalize inventory rows', () => {
    const asset = normalizeCompanyAssetInput({
        name: 'Exchange Online',
        type: 'service',
        vendor: 'Microsoft',
        product: 'Exchange Server',
        version: '2019',
        aliases: 'OWA; Outlook Web Access',
        cpe_uris: 'cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*',
        packages: 'npm:@microsoft/mgt',
        criticality: 'high',
        enabled: 'yes'
    });

    assert.equal(asset.type, 'service');
    assert.equal(asset.enabled, true);
    assert.deepEqual(asset.aliases, ['OWA', 'Outlook Web Access']);
    assert.equal(asset.cpe_uris[0], 'cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*');
    assert.deepEqual(asset.packages, [{ name: '@microsoft/mgt', ecosystem: 'npm', vulnerable_version_range: null }]);

    assert.deepEqual(parseCompanyAssetCsv(`name,type,vendor,product,criticality,enabled\n"Fortinet VPN",service,Fortinet,FortiOS,high,true\n`), [{
        index: 0,
        name: 'Fortinet VPN',
        type: 'service',
        vendor: 'Fortinet',
        product: 'FortiOS',
        criticality: 'high',
        enabled: 'true'
    }]);
    assert.throws(() => normalizeCompanyAssetInput({ name: 'Bad', type: 'device' }), /type must be one of/);
});

test('company asset matcher ranks CPE and package matches ahead of text matches', () => {
    const cve = {
        id: 'CVE-2026-8888',
        description: 'Remote code execution in Microsoft Exchange Server OWA components',
        cvss_score: 9.8,
        severity: 'critical'
    };
    const exchange = normalizeCompanyAssetInput({
        name: 'Exchange',
        vendor: 'Microsoft',
        product: 'Exchange Server',
        criticality: 'high',
        cpe_uris: 'cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*'
    });
    const nginx = normalizeCompanyAssetInput({
        name: 'Nginx',
        vendor: 'F5',
        product: 'NGINX',
        criticality: 'medium'
    });

    const cpeMatch = matchAssetToCve(exchange, cve, {
        vulnerable_cpes: ['cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*']
    });
    const textMatch = matchAssetToCve(exchange, cve, {});
    const noMatch = matchAssetToCve(nginx, cve, {});

    assert.equal(cpeMatch.match_type, 'cpe_exact');
    assert.equal(cpeMatch.score > textMatch.score, true);
    assert.equal(textMatch.match_type, 'vendor_product');
    assert.equal(noMatch, null);
});

test('company asset matcher supports optional versions and guards generic keywords', () => {
    const asset = normalizeCompanyAssetInput({
        name: 'Django Portal',
        product: 'Django',
        packages: [{ ecosystem: 'PyPI', name: 'django' }],
        version: '4.2',
        aliases: 'app; portal'
    });
    const matched = matchAssetToCve(asset, {
        id: 'CVE-2026-7777',
        description: 'Django SQL injection in contrib admin',
        severity: 'high'
    }, {
        packages: [{ ecosystem: 'PyPI', name: 'django', vulnerable_version_range: '<4.2.8' }]
    });

    assert.equal(matched.match_type, 'package_exact');
    assert.equal(matched.confidence >= 0.9, true);

    const genericOnly = normalizeCompanyAssetInput({ name: 'Internal App', product: 'App', aliases: 'api; web' });
    assert.equal(matchAssetToCve(genericOnly, { id: 'CVE-2026-1', description: 'An API web service fails' }, {}), null);
});

test('feed metadata extractors expose NVD CPEs and GitHub packages', () => {
    assert.deepEqual(extractNvdVulnerableCpes([{
        nodes: [{
            cpeMatch: [
                { vulnerable: true, criteria: 'cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*' },
                { vulnerable: false, criteria: 'cpe:2.3:a:ignored:product:*:*:*:*:*:*:*:*' }
            ]
        }]
    }]), ['cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*']);

    assert.deepEqual(collectGithubPackages([{
        package: { ecosystem: 'npm', name: 'lodash' },
        vulnerableVersionRange: '<4.17.21'
    }]), [{ name: 'lodash', ecosystem: 'npm', vulnerable_version_range: '<4.17.21' }]);
});

test('MalwareBazaar parser handles ok and no_results responses', () => {
    assert.deepEqual(parseMalwareBazaarRecentResponse({ query_status: 'no_results' }), []);
    assert.deepEqual(
        parseMalwareBazaarRecentResponse({
            query_status: 'ok',
            data: [{ sha256_hash: 'a'.repeat(64), file_name: 'payload.exe' }]
        }),
        [{ sha256_hash: 'a'.repeat(64), file_name: 'payload.exe' }]
    );
    assert.throws(() => parseMalwareBazaarRecentResponse({ query_status: 'illegal_query' }), /illegal_query/);
});

test('MalwareBazaar hash lookup sends form data and handles array-shaped data', async (t) => {
    const originalRequest = axios.request;
    const sha256 = 'b'.repeat(64);
    t.after(() => {
        axios.request = originalRequest;
    });

    axios.request = async (options) => {
        assert.equal(options.url, 'https://mb-api.abuse.ch/api/v1/');
        assert.equal(options.method, 'post');
        assert.equal(options.data.get('query'), 'get_info');
        assert.equal(options.data.get('hash'), sha256);
        assert.equal(options.headers['Auth-Key'], 'test-key');
        assert.equal(options.headers['Content-Type'], 'application/x-www-form-urlencoded');
        return {
            data: {
                query_status: 'ok',
                data: [{
                    sha256_hash: sha256,
                    sha1_hash: 'c'.repeat(40),
                    md5_hash: 'd'.repeat(32),
                    file_type: 'exe',
                    signature: 'Lumma'
                }]
            }
        };
    };

    const result = await queryMalwareBazaarByHash(sha256, 'test-key');
    assert.equal(result.sha256, sha256);
    assert.equal(result.sha1, 'c'.repeat(40));
    assert.equal(result.md5, 'd'.repeat(32));
    assert.equal(result.signature, 'Lumma');
});

test('free feed parsers extract expected IOC and CVE enrichment fields', () => {
    const feodo = parseFeodoCsv(`
# first_seen,dst_ip,dst_port,status,last_online,malware
2026-04-30 00:00:00,203.0.113.10,443,online,2026-04-30,emotet
bad,row
`);
    assert.deepEqual(feodo, [{
        first_seen: '2026-04-30 00:00:00',
        ip: '203.0.113.10',
        port: '443',
        status: 'online',
        last_online: '2026-04-30',
        malware: 'emotet'
    }]);

    assert.deepEqual(parseSslblIpCsv('2026-04-30 01:00:00,198.51.100.20,8443'), [{
        first_seen: '2026-04-30 01:00:00',
        ip: '198.51.100.20',
        port: '8443'
    }]);
    assert.deepEqual(parseSslblCertCsv(`2026-04-30 02:00:00,${'a'.repeat(40)},dridex certificate`), [{
        first_seen: '2026-04-30 02:00:00',
        sha1: 'a'.repeat(40),
        reason: 'dridex certificate'
    }]);

    assert.deepEqual(parseEpssResponse({
        data: [{ cve: 'cve-2026-1234', epss: '0.91234', percentile: '0.99', date: '2026-04-30' }]
    }), [{
        cve: 'CVE-2026-1234',
        epss: 0.91234,
        percentile: 0.99,
        date: '2026-04-30'
    }]);

    assert.deepEqual(parseOsvModifiedCsv('2026-04-30T00:00:00Z,PyPI/PYSEC-2026-1'), [{
        modified: '2026-04-30T00:00:00Z',
        path: 'PyPI/PYSEC-2026-1'
    }]);
});

test('keyed feed parsers support OTX, AbuseIPDB, Shodan, and VulnCheck shapes', () => {
    const vulncheckPayload = {
        data: [{
            id: 'CVE-2026-3333',
            published: '2026-04-30T00:00:00Z',
            descriptions: [{ lang: 'en', value: 'VulnCheck enriched issue' }],
            metrics: {
                cvssMetricV31: [{ cvssData: { baseScore: 9.1, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }]
            },
            categorization: { tags: ['internet-facing'] },
            vcVulnerableCPEs: ['cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*']
        }]
    };
    const vulncheck = parseCveRecord(parseVulnCheckPayload(vulncheckPayload)[0], 'vulncheck');
    assert.equal(vulncheck.id, 'CVE-2026-3333');
    assert.equal(vulncheck.source, 'vulncheck');
    assert.equal(vulncheck.severity, 'critical');
    assert.match(vulncheck.search_text, /internet-facing/);
    assert.deepEqual(
        [...parseVulnCheckIndexes({ data: [{ name: 'nist-nvd2' }, { name: 'vulncheck-nvd2' }] })],
        ['nist-nvd2', 'vulncheck-nvd2']
    );

    assert.deepEqual(parseOtxPayload({ results: [{ id: 'pulse-1', indicators: [] }] }), [{ id: 'pulse-1', indicators: [] }]);
    assert.deepEqual(normalizeOtxIndicator({ type: 'IPv4', indicator: '203.0.113.55' }), { type: 'ip', value: '203.0.113.55' });
    assert.deepEqual(normalizeOtxIndicator({ type: 'FileHash-SHA256', indicator: 'a'.repeat(64) }), { type: 'hash', value: 'a'.repeat(64) });
    assert.deepEqual(normalizeOtxIndicator({ type: 'CVE', indicator: 'CVE-2026-4444' }), { type: 'cve', value: 'CVE-2026-4444' });

    assert.deepEqual(parseAbuseIpdbBlacklist({
        data: [{ ipAddress: '198.51.100.44', abuseConfidenceScore: 100 }]
    }), [{ ipAddress: '198.51.100.44', abuseConfidenceScore: 100 }]);
    assert.deepEqual(parseAbuseIpdbBlacklist('198.51.100.45\n198.51.100.46\n'), [
        { ipAddress: '198.51.100.45' },
        { ipAddress: '198.51.100.46' }
    ]);

    assert.deepEqual(parseShodanResults({
        matches: [{ ip_str: '203.0.113.77', vulns: { 'CVE-2026-5555': { cvss: 8.8 } } }]
    }), [{ ip_str: '203.0.113.77', vulns: { 'CVE-2026-5555': { cvss: 8.8 } } }]);
});

test('keyed feed fetchers ingest mocked OTX, AbuseIPDB, Shodan, and VulnCheck data', async (t) => {
    const previousDbPath = process.env.CTI_DB_PATH;
    const previousVulnCheckIndex = process.env.VULNCHECK_INDEX;
    const tempDir = mkdtempSync(join(tmpdir(), 'cti-dashboard-keyed-feeds-'));
    const originalRequest = axios.request;
    process.env.CTI_DB_PATH = join(tempDir, 'cti.db');
    delete process.env.VULNCHECK_INDEX;

    t.after(() => {
        axios.request = originalRequest;
        if (previousDbPath === undefined) {
            delete process.env.CTI_DB_PATH;
        } else {
            process.env.CTI_DB_PATH = previousDbPath;
        }
        if (previousVulnCheckIndex === undefined) {
            delete process.env.VULNCHECK_INDEX;
        } else {
            process.env.VULNCHECK_INDEX = previousVulnCheckIndex;
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    axios.request = async (options = {}) => {
        const url = options.url;
        if (url === 'https://api.vulncheck.com/v3/index') {
            assert.equal(options.headers.Authorization, 'Bearer vc-key');
            return { data: { data: [{ name: 'vulncheck-nvd2' }] } };
        }
        if (url.includes('/v3/index/vulncheck-nvd2')) {
            assert.equal(options.headers.Authorization, 'Bearer vc-key');
            return {
                data: {
                    data: [{
                        id: 'CVE-2026-3333',
                        descriptions: [{ lang: 'en', value: 'VulnCheck mocked CVE' }],
                        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.8 } }] },
                        published: '2026-04-30T00:00:00Z'
                    }]
                }
            };
        }
        if (url.includes('/pulses/subscribed')) {
            assert.equal(options.headers['X-OTX-API-KEY'], 'otx-key');
            return {
                data: {
                    results: [{
                        id: 'pulse-1',
                        name: 'Mock OTX Pulse',
                        tags: ['ransomware'],
                        created: '2026-04-30T00:00:00Z',
                        modified: '2026-04-30T01:00:00Z',
                        indicators: [
                            { type: 'IPv4', indicator: '203.0.113.55' },
                            { type: 'CVE', indicator: 'CVE-2026-4444' }
                        ]
                    }]
                }
            };
        }
        if (url.includes('/api/v2/blacklist')) {
            assert.equal(options.headers.Key, 'abuse-key');
            return {
                data: {
                    data: [{
                        ipAddress: '198.51.100.44',
                        abuseConfidenceScore: 95,
                        countryCode: 'US',
                        lastReportedAt: '2026-04-30T02:00:00Z'
                    }]
                }
            };
        }
        if (url.includes('/shodan/host/search')) {
            assert.equal(options.params.key, 'shodan-key');
            assert.equal(options.params.minify, false);
            return {
                data: {
                    matches: [{
                        ip_str: '203.0.113.77',
                        port: 443,
                        org: 'Example Org',
                        product: 'nginx',
                        timestamp: '2026-04-30T03:00:00Z',
                        vulns: {
                            'CVE-2026-5555': {
                                cvss: 9.8,
                                summary: 'Mock exposed service CVE'
                            }
                        }
                    }]
                }
            };
        }
        throw new Error(`Unexpected URL ${url}`);
    };

    const { getCveById, getIocs, initializeDb, searchDocuments } = await import('../server/db/database.js');
    await initializeDb();

    assert.equal(await fetchVulnCheckCves('vc-key', { limit: 1 }), 1);
    assert.equal(await fetchOtxPulses('otx-key', { limit: 1, modifiedSince: null }), 2);
    assert.equal(await fetchAbuseIpdbBlacklist('abuse-key', { limit: 1 }), 1);
    assert.equal(await fetchShodan('shodan-key', 'has_vuln:true', { page: 1 }), 2);

    assert.equal(getCveById('CVE-2026-3333').source, 'vulncheck');
    assert.equal(getCveById('CVE-2026-4444').source, 'otx');
    assert.equal(getCveById('CVE-2026-5555').source, 'shodan');
    assert.equal(getIocs({ source: 'otx' })[0].value, '203.0.113.55');
    assert.equal(getIocs({ source: 'abuseipdb' })[0].value, '198.51.100.44');
    assert.equal(getIocs({ source: 'shodan' })[0].value, '203.0.113.77');
    assert.equal(searchDocuments({ q: 'source:vulncheck CVE-2026-3333' })[0].source, 'vulncheck');
});

test('VulnCheck 402 access response is recorded as skipped, not feed failure', async (t) => {
    const previousDbPath = process.env.CTI_DB_PATH;
    const previousVulnCheckIndex = process.env.VULNCHECK_INDEX;
    const tempDir = mkdtempSync(join(tmpdir(), 'cti-dashboard-vulncheck-skip-'));
    const originalRequest = axios.request;
    process.env.CTI_DB_PATH = join(tempDir, 'cti.db');
    process.env.VULNCHECK_INDEX = 'vulncheck-nvd2';

    t.after(() => {
        axios.request = originalRequest;
        if (previousDbPath === undefined) {
            delete process.env.CTI_DB_PATH;
        } else {
            process.env.CTI_DB_PATH = previousDbPath;
        }
        if (previousVulnCheckIndex === undefined) {
            delete process.env.VULNCHECK_INDEX;
        } else {
            process.env.VULNCHECK_INDEX = previousVulnCheckIndex;
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    axios.request = async () => {
        const error = new Error('Request failed with status code 402');
        error.response = { status: 402, data: { message: 'Payment Required' } };
        throw error;
    };

    const { getDb, initializeDb } = await import('../server/db/database.js');
    await initializeDb();

    assert.equal(await fetchVulnCheckCves('vc-key'), 0);

    const stmt = getDb().prepare('SELECT status, error_message FROM feed_status WHERE source = ?');
    stmt.bind(['vulncheck']);
    assert.equal(stmt.step(), true);
    const row = stmt.getAsObject();
    stmt.free();
    assert.equal(row.status, 'skipped');
    assert.match(row.error_message, /HTTP 402/);
});

test('OSV parser creates searchable CVE/GHSA rows from advisories', () => {
    const parsed = parseOsvRecord({
        id: 'PYSEC-2026-1',
        aliases: ['CVE-2026-2222', 'GHSA-abcd-efgh-ijkl'],
        summary: 'Django package issue',
        details: 'Long advisory details',
        published: '2026-04-29T00:00:00Z',
        database_specific: { severity: 'HIGH' },
        affected: [{
            package: { ecosystem: 'PyPI', name: 'django' }
        }]
    });

    assert.equal(parsed.id, 'CVE-2026-2222');
    assert.equal(parsed.source, 'osv');
    assert.equal(parsed.severity, 'high');
    assert.match(parsed.search_text, /django/);
    assert.deepEqual(parsed.search_metadata.packages, [{ name: 'django', ecosystem: 'PyPI' }]);
});

test('CVE source merging keeps canonical NVD data and source history', async (t) => {
    const previousDbPath = process.env.CTI_DB_PATH;
    const tempDir = mkdtempSync(join(tmpdir(), 'cti-dashboard-unit-'));
    process.env.CTI_DB_PATH = join(tempDir, 'cti.db');
    t.after(() => {
        if (previousDbPath === undefined) {
            delete process.env.CTI_DB_PATH;
        } else {
            process.env.CTI_DB_PATH = previousDbPath;
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    const { initializeDb, insertOrUpdateCve, getCveById } = await import('../server/db/database.js');
    await initializeDb();

    insertOrUpdateCve({
        id: 'CVE-2026-0001',
        source: 'cisa_kev',
        description: 'Known exploited entry',
        cvss_score: 9.8,
        severity: 'critical',
        published_at: '2026-04-29T00:00:00Z'
    });
    insertOrUpdateCve({
        id: 'CVE-2026-0001',
        source: 'nvd',
        description: 'Canonical NVD description',
        cvss_score: 7.5,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        severity: 'high',
        published_at: '2026-04-30T00:00:00Z'
    });

    const cve = getCveById('CVE-2026-0001');
    assert.equal(cve.source, 'nvd');
    assert.equal(cve.description, 'Canonical NVD description');
    assert.equal(cve.cvss_score, 7.5);
    assert.equal(cve.is_kev, true);
    assert.deepEqual(cve.sources, ['nvd', 'cisa_kev']);
});

test('progress import creates manual placeholders, skips duplicates, and records row failures', async (t) => {
    const previousDbPath = process.env.CTI_DB_PATH;
    const tempDir = mkdtempSync(join(tmpdir(), 'cti-dashboard-import-'));
    process.env.CTI_DB_PATH = join(tempDir, 'cti.db');
    t.after(() => {
        if (previousDbPath === undefined) {
            delete process.env.CTI_DB_PATH;
        } else {
            process.env.CTI_DB_PATH = previousDbPath;
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    const { getCveProgressDetail, initializeDb } = await import('../server/db/database.js');
    await initializeDb();

    const result = await importCveProgressItems([
        {
            id: 'CVE-2026-7000',
            description: 'Manual placeholder CVE',
            severity: 'high',
            cvss_score: 8.1,
            note: 'Imported from analyst request'
        },
        { id: 'CVE-2026-7000' },
        { id: 'not-a-cve' },
        { id: 'CVE-2026-7001', status: 'todo' }
    ], {
        fetchCveById: async () => null
    });

    assert.deepEqual(result.summary, {
        total: 4,
        imported: 1,
        updated: 0,
        placeholders: 1,
        duplicates: 1,
        failed: 2
    });

    const detail = getCveProgressDetail('CVE-2026-7000');
    assert.equal(detail.source, 'manual');
    assert.equal(detail.progress_status, 'open');
    assert.equal(detail.severity, 'high');
    assert.equal(detail.notes[0].note, 'Imported from analyst request');
});

test('progress import resolves missing CVEs before falling back to placeholders', async (t) => {
    const previousDbPath = process.env.CTI_DB_PATH;
    const tempDir = mkdtempSync(join(tmpdir(), 'cti-dashboard-import-resolve-'));
    process.env.CTI_DB_PATH = join(tempDir, 'cti.db');
    t.after(() => {
        if (previousDbPath === undefined) {
            delete process.env.CTI_DB_PATH;
        } else {
            process.env.CTI_DB_PATH = previousDbPath;
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    const { getCveProgressDetail, initializeDb } = await import('../server/db/database.js');
    await initializeDb();

    const result = await importCveProgressItems([{ id: 'CVE-2026-7002' }], {
        fetchCveById: async () => ({
            id: 'CVE-2026-7002',
            source: 'nvd',
            description: 'Resolved NVD CVE',
            cvss_score: 9.8,
            severity: 'critical',
            published_at: '2026-04-30T00:00:00Z'
        })
    });

    assert.equal(result.summary.imported, 1);
    assert.equal(result.summary.placeholders, 0);
    const detail = getCveProgressDetail('CVE-2026-7002');
    assert.equal(detail.source, 'nvd');
    assert.equal(detail.progress_status, 'open');
    assert.equal(detail.description, 'Resolved NVD CVE');
});

test('search index ranks exact matches and honors type/source filters', async (t) => {
    const previousDbPath = process.env.CTI_DB_PATH;
    const tempDir = mkdtempSync(join(tmpdir(), 'cti-dashboard-search-'));
    process.env.CTI_DB_PATH = join(tempDir, 'cti.db');
    t.after(() => {
        if (previousDbPath === undefined) {
            delete process.env.CTI_DB_PATH;
        } else {
            process.env.CTI_DB_PATH = previousDbPath;
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    const { initializeDb, insertIoc, insertOrUpdateCve, searchDocuments } = await import('../server/db/database.js');
    await initializeDb();

    insertOrUpdateCve({
        id: 'CVE-2026-2000',
        source: 'nvd',
        description: 'OpenSSL packet parser memory corruption',
        cvss_score: 9.8,
        severity: 'critical',
        published_at: '2026-04-30T00:00:00Z'
    });
    insertIoc({
        type: 'hash',
        value: 'f'.repeat(64),
        source: 'malwarebazaar',
        threat_type: 'Lumma Stealer',
        confidence: 85,
        first_seen: '2026-04-30T00:00:00Z',
        last_seen: '2026-04-30T00:00:00Z',
        metadata: JSON.stringify({ file_name: 'invoice-loader.exe', tags: ['lumma', 'stealer'] })
    });
    insertIoc({
        type: 'ip',
        value: '203.0.113.88',
        source: 'feodo',
        threat_type: 'botnet_c2',
        confidence: 85,
        first_seen: '2026-04-30T00:00:00Z',
        last_seen: '2026-04-30T00:00:00Z',
        metadata: JSON.stringify({ malware: 'emotet' })
    });

    assert.equal(searchDocuments({ q: 'CVE-2026-2000' })[0].id, 'CVE-2026-2000');
    assert.equal(searchDocuments({ q: 'f'.repeat(64) })[0].source, 'malwarebazaar');

    const filtered = searchDocuments({ q: 'type:ioc source:feodo emotet' });
    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].source, 'feodo');
    assert.equal(filtered[0].ioc_type, 'ip');

    const partial = searchDocuments({ q: 'lumm', type: 'ioc' });
    assert.equal(partial[0].source, 'malwarebazaar');
    assert.equal(partial[0].threat_type, 'Lumma Stealer');
});

test('refresh summary counts success, failure, and processed items', () => {
    const summary = buildRefreshSummary(
        {
            nvd: { success: true, count: 5 },
            github: { success: false, count: 0 },
            alerts: { sent: 0 }
        },
        {
            started_at: '2026-04-30T00:00:00Z',
            finished_at: '2026-04-30T00:01:00Z',
            cves: { new: 2, updated: 3 },
            iocs: { new: 1, updated: 0 },
            by_source: {}
        }
    );

    assert.equal(summary.feeds.total, 2);
    assert.equal(summary.feeds.successful, 1);
    assert.equal(summary.feeds.failed, 1);
    assert.equal(summary.processed, 5);
});

test('manual refresh lock rejects overlapping runs', async () => {
    const first = runWithRefreshLock(async () => {
        await new Promise(resolve => setTimeout(resolve, 30));
        return 'done';
    });

    await assert.rejects(
        () => runWithRefreshLock(async () => 'overlap'),
        error => error.statusCode === 409 && /Refresh already running/.test(error.message)
    );
    assert.equal(await first, 'done');
});

test('alert severity threshold compares severity rank', () => {
    assert.equal(meetsSeverityThreshold('critical', 'high'), true);
    assert.equal(meetsSeverityThreshold('medium', 'high'), false);
    assert.equal(meetsSeverityThreshold('high', 'critical'), false);
});

test('Teams progress notifications build adaptive cards and report webhook failures', async (t) => {
    const originalPost = axios.post;
    t.after(() => {
        axios.post = originalPost;
    });

    const payload = buildTeamsPayload('import_summary', {
        summary: {
            total: 3,
            imported: 2,
            updated: 1,
            placeholders: 1,
            duplicates: 0,
            failed: 0
        }
    });
    assert.equal(payload.type, 'message');
    assert.equal(payload.attachments[0].contentType, 'application/vnd.microsoft.card.adaptive');
    assert.match(buildTeamsTextPayload('note_added', {
        cve: { id: 'CVE-2026-1234', progress_status: 'open' },
        note: 'Needs review'
    }).text, /CVE-2026-1234/);

    let attempts = 0;
    axios.post = async (url, body, options) => {
        attempts++;
        assert.equal(url, 'https://example.com/teams');
        assert.equal(body.type, 'message');
        assert.equal(options.headers['Content-Type'], 'application/json');
        return { status: 200 };
    };
    assert.deepEqual(await notifyTeamsProgress('status_changed', {
        cve: { id: 'CVE-2026-1234', progress_status: 'open', severity: 'high', cvss_score: 8.5 }
    }, {
        enabled: true,
        webhookUrl: 'https://example.com/teams',
        retryDelayMs: 0
    }), { attempted: true, sent: true, attempts: 1, format: 'adaptive_card' });
    assert.equal(attempts, 1);

    attempts = 0;
    axios.post = async () => {
        attempts++;
        if (attempts === 1) {
            const error = new Error('rate limited');
            error.response = { status: 429, headers: { 'retry-after': '0' } };
            throw error;
        }
        return { status: 200 };
    };
    assert.deepEqual(await notifyTeamsProgress('status_changed', {
        cve: { id: 'CVE-2026-1234', progress_status: 'assigned' }
    }, {
        enabled: true,
        webhookUrl: 'https://example.com/teams',
        maxAttempts: 2,
        retryDelayMs: 0
    }), { attempted: true, sent: true, attempts: 2, format: 'adaptive_card' });

    axios.post = async () => {
        throw new Error('webhook unavailable');
    };
    const failed = await notifyTeamsProgress('note_added', {
        cve: { id: 'CVE-2026-1234', progress_status: 'open' },
        note: 'Needs review'
    }, {
        enabled: true,
        webhookUrl: 'https://example.com/teams',
        format: 'text',
        maxAttempts: 1
    });
    assert.equal(failed.attempted, true);
    assert.equal(failed.sent, false);
    assert.equal(failed.format, 'text');
    assert.match(failed.error, /webhook unavailable/);
});

test('CSV utilities escape quotes and empty values', () => {
    const code = readFileSync(join(process.cwd(), 'public', 'app-utils.js'), 'utf8');
    const context = { globalThis: null };
    context.globalThis = context;
    vm.createContext(context);
    vm.runInContext(code, context);

    const csv = context.CtiDashboardUtils.buildCsv(
        [{ name: 'quote "inside"', empty: null }],
        ['name', 'empty']
    );

    assert.equal(csv, 'name,empty\n"quote ""inside""",""');

    assert.deepEqual(JSON.parse(JSON.stringify(context.CtiDashboardUtils.parseProgressImportText('CVE-2026-1000, cve-2026-1001'))), [
        { id: 'CVE-2026-1000' },
        { id: 'CVE-2026-1001' }
    ]);
    assert.deepEqual(
        JSON.parse(JSON.stringify(context.CtiDashboardUtils.parseProgressImportCsv('cve_id,status,note,cvss\n"CVE-2026-1002",assigned,"quoted, note",7.1\n'))),
        [{ id: 'CVE-2026-1002', status: 'assigned', note: 'quoted, note', cvss_score: '7.1' }]
    );
    assert.deepEqual(
        JSON.parse(JSON.stringify(context.CtiDashboardUtils.parseCompanyAssetCsv('name,type,vendor,product,packages\nDjango,application,DSF,Django,PyPI:django\n'))),
        [{ name: 'Django', type: 'application', vendor: 'DSF', product: 'Django', packages: 'PyPI:django' }]
    );
});
