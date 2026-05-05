import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import axios from 'axios';

test('health, stats, and CVE list endpoints run against a temp DB', async (t) => {
    const { baseUrl, insertOrUpdateCve } = await startTestServer(t);
    insertOrUpdateCve({
        id: 'CVE-2026-1000',
        source: 'nvd',
        description: 'Integration test CVE',
        cvss_score: 8.1,
        severity: 'high',
        published_at: '2026-04-30T00:00:00Z'
    });

    const health = await fetchJson(`${baseUrl}/api/health`);
    assert.equal(health.status, 'ok');

    const stats = await fetchJson(`${baseUrl}/api/stats`);
    assert.equal(stats.success, true);
    assert.equal(stats.data.cves.total, 1);

    const cves = await fetchJson(`${baseUrl}/api/cves?limit=10`);
    assert.equal(cves.success, true);
    assert.equal(cves.data[0].id, 'CVE-2026-1000');
    assert.deepEqual(cves.data[0].sources, ['nvd']);
    assert.equal(cves.data[0].is_kev, false);
});

test('progress status and notes round-trip through the API', async (t) => {
    const { baseUrl, insertOrUpdateCve } = await startTestServer(t);
    insertOrUpdateCve({
        id: 'CVE-2026-1001',
        source: 'nvd',
        description: 'Progress test CVE',
        cvss_score: 9.1,
        severity: 'critical',
        published_at: '2026-04-30T00:00:00Z'
    });

    const progress = await fetchJson(`${baseUrl}/api/cves/CVE-2026-1001/progress`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'open' })
    });
    assert.equal(progress.data.progress_status, 'open');

    const note = await fetchJson(`${baseUrl}/api/cves/CVE-2026-1001/progress/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: 'Review assigned to local analyst.' })
    });
    assert.equal(note.data.notes.length, 1);

    const detail = await fetchJson(`${baseUrl}/api/cves/CVE-2026-1001/progress`);
    assert.equal(detail.data.notes[0].note, 'Review assigned to local analyst.');
});

test('bad CVE query input returns a normalized 400 error', async (t) => {
    const { baseUrl } = await startTestServer(t);
    const response = await fetch(`${baseUrl}/api/cves?limit=banana`);
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.deepEqual(body, {
        success: false,
        error: 'limit must be an integer'
    });
});

test('CORS defaults do not grant arbitrary website access', async (t) => {
    const { baseUrl } = await startTestServer(t);

    const blocked = await fetch(`${baseUrl}/api/health`, {
        headers: { Origin: 'https://example.com' }
    });
    assert.equal(blocked.headers.get('access-control-allow-origin'), null);

    const local = await fetch(`${baseUrl}/api/health`, {
        headers: { Origin: 'http://localhost:3000' }
    });
    assert.equal(local.headers.get('access-control-allow-origin'), 'http://localhost:3000');
});

test('feed status endpoint shows newly integrated feeds before keys are configured', async (t) => {
    const { baseUrl } = await startTestServer(t);
    const feeds = await fetchJson(`${baseUrl}/api/stats/feeds`);
    const sources = feeds.data.map(feed => feed.source);

    for (const source of ['vulncheck', 'shodan', 'abuseipdb', 'otx', 'feodo', 'sslbl', 'epss', 'osv']) {
        assert.equal(sources.includes(source), true, `${source} should be visible in feed status`);
    }
    assert.equal(sources.includes('urlhaus_hosts'), false);
});

test('manual refresh endpoint rejects overlapping refreshes with 409', async (t) => {
    const { baseUrl } = await startTestServer(t, {
        refreshFeeds: async () => {
            await new Promise(resolve => setTimeout(resolve, 100));
            return {
                summary: {
                    feeds: { total: 1, successful: 1, failed: 0 },
                    cves: { new: 0, updated: 0 },
                    iocs: { new: 0, updated: 0 }
                }
            };
        }
    });

    const first = fetch(`${baseUrl}/api/stats/feeds/refresh`, { method: 'POST' });
    await new Promise(resolve => setTimeout(resolve, 20));
    const second = await fetch(`${baseUrl}/api/stats/feeds/refresh`, { method: 'POST' });
    const secondBody = await second.json();
    const firstResponse = await first;

    assert.equal(second.status, 409);
    assert.deepEqual(secondBody, {
        success: false,
        error: 'Refresh already running'
    });
    assert.equal(firstResponse.status, 200);
});

test('progress import endpoint imports existing CVEs into the progress tab', async (t) => {
    const { baseUrl, insertOrUpdateCve } = await startTestServer(t);
    insertOrUpdateCve({
        id: 'CVE-2026-2001',
        source: 'nvd',
        description: 'Existing import target',
        cvss_score: 8.2,
        severity: 'high',
        published_at: '2026-04-30T00:00:00Z'
    });

    const imported = await fetchJson(`${baseUrl}/api/cves/progress/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            items: [{ id: 'CVE-2026-2001', note: 'Imported existing CVE' }]
        })
    });

    assert.equal(imported.data.summary.imported, 1);
    assert.equal(imported.data.summary.failed, 0);

    const progress = await fetchJson(`${baseUrl}/api/cves/progress?search=CVE-2026-2001`);
    assert.equal(progress.data.length, 1);
    assert.equal(progress.data[0].id, 'CVE-2026-2001');
    assert.equal(progress.data[0].progress_status, 'open');
    assert.equal(progress.data[0].latest_note, 'Imported existing CVE');
});

test('progress import endpoint resolves missing CVEs from NVD and creates placeholders when unresolved', async (t) => {
    const originalRequest = axios.request;
    t.after(() => {
        axios.request = originalRequest;
    });

    axios.request = async (options = {}) => {
        if (options.params?.cveId === 'CVE-2026-2002') {
            return {
                data: {
                    vulnerabilities: [{
                        cve: {
                            id: 'CVE-2026-2002',
                            published: '2026-04-30T00:00:00Z',
                            descriptions: [{ lang: 'en', value: 'Resolved by mocked NVD' }],
                            metrics: {
                                cvssMetricV31: [{
                                    cvssData: {
                                        baseScore: 9.1,
                                        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                                    }
                                }]
                            }
                        }
                    }]
                }
            };
        }
        if (options.params?.cveId === 'CVE-2026-2003') {
            return { data: { vulnerabilities: [] } };
        }
        throw new Error(`Unexpected NVD request ${options.params?.cveId}`);
    };

    const { baseUrl } = await startTestServer(t);
    const imported = await fetchJson(`${baseUrl}/api/cves/progress/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            items: [
                { id: 'CVE-2026-2002' },
                { id: 'CVE-2026-2003', description: 'Manual unresolved CVE', severity: 'medium' }
            ]
        })
    });

    assert.equal(imported.data.summary.imported, 2);
    assert.equal(imported.data.summary.placeholders, 1);

    const resolved = await fetchJson(`${baseUrl}/api/cves/CVE-2026-2002/progress`);
    assert.equal(resolved.data.source, 'nvd');
    assert.equal(resolved.data.progress_status, 'open');
    assert.equal(resolved.data.description, 'Resolved by mocked NVD');

    const placeholder = await fetchJson(`${baseUrl}/api/cves/CVE-2026-2003/progress`);
    assert.equal(placeholder.data.source, 'manual');
    assert.equal(placeholder.data.progress_status, 'open');
    assert.equal(placeholder.data.description, 'Manual unresolved CVE');
});

test('progress Teams notifications are best-effort for imports, status changes, and notes', async (t) => {
    const previousEnabled = process.env.TEAMS_ALERTS_ENABLED;
    const previousUrl = process.env.TEAMS_WEBHOOK_URL;
    const originalPost = axios.post;
    process.env.TEAMS_ALERTS_ENABLED = 'true';
    process.env.TEAMS_WEBHOOK_URL = 'https://example.com/teams';
    const posts = [];

    t.after(() => {
        axios.post = originalPost;
        if (previousEnabled === undefined) {
            delete process.env.TEAMS_ALERTS_ENABLED;
        } else {
            process.env.TEAMS_ALERTS_ENABLED = previousEnabled;
        }
        if (previousUrl === undefined) {
            delete process.env.TEAMS_WEBHOOK_URL;
        } else {
            process.env.TEAMS_WEBHOOK_URL = previousUrl;
        }
    });

    axios.post = async (url, body) => {
        posts.push({ url, body });
        return { status: 200 };
    };

    const { baseUrl, insertOrUpdateCve } = await startTestServer(t);
    insertOrUpdateCve({
        id: 'CVE-2026-2004',
        source: 'nvd',
        description: 'Teams integration target',
        cvss_score: 7.7,
        severity: 'high',
        published_at: '2026-04-30T00:00:00Z'
    });

    const imported = await fetchJson(`${baseUrl}/api/cves/progress/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ items: [{ id: 'CVE-2026-2004' }] })
    });
    assert.deepEqual(imported.notifications.teams, {
        attempted: true,
        sent: true,
        attempts: 1,
        format: 'adaptive_card'
    });

    await fetchJson(`${baseUrl}/api/cves/CVE-2026-2004/progress`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'assigned' })
    });
    await fetchJson(`${baseUrl}/api/cves/CVE-2026-2004/progress/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: 'Posted to Teams' })
    });

    assert.equal(posts.length, 3);
    assert.equal(posts.every(post => post.url === 'https://example.com/teams'), true);

    axios.post = async () => {
        throw new Error('Teams down');
    };
    const failedNote = await fetchJson(`${baseUrl}/api/cves/CVE-2026-2004/progress/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: 'Still stored locally' })
    });
    assert.equal(failedNote.notifications.teams.attempted, true);
    assert.equal(failedNote.notifications.teams.sent, false);
    assert.equal(failedNote.notifications.teams.format, 'adaptive_card');
    assert.match(failedNote.notifications.teams.error, /Teams down/);
});

test('company assets API creates matches, filters CVEs, and boosts triage order', async (t) => {
    const { baseUrl, insertOrUpdateCve } = await startTestServer(t);
    insertOrUpdateCve({
        id: 'CVE-2026-3001',
        source: 'nvd',
        description: 'Medium severity issue in Microsoft Exchange Server',
        cvss_score: 5.5,
        severity: 'medium',
        published_at: '2026-04-30T00:00:00Z',
        search_metadata: {
            vulnerable_cpes: ['cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*']
        }
    });
    insertOrUpdateCve({
        id: 'CVE-2026-3002',
        source: 'nvd',
        description: 'Critical issue in unrelated product',
        cvss_score: 9.8,
        severity: 'critical',
        published_at: '2026-04-30T01:00:00Z'
    });

    const created = await fetchJson(`${baseUrl}/api/company-assets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: 'Corporate Exchange',
            type: 'application',
            vendor: 'Microsoft',
            product: 'Exchange Server',
            cpe_uris: ['cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*'],
            criticality: 'high'
        })
    });
    assert.equal(created.data.match_count, 1);

    const companyCves = await fetchJson(`${baseUrl}/api/cves?companyAffected=true&limit=10`);
    assert.equal(companyCves.data.length, 1);
    assert.equal(companyCves.data[0].id, 'CVE-2026-3001');
    assert.equal(companyCves.data[0].company_match_count, 1);
    assert.equal(companyCves.data[0].company_matches[0].asset_name, 'Corporate Exchange');

    const byAsset = await fetchJson(`${baseUrl}/api/cves?assetId=${created.data.id}&limit=10`);
    assert.deepEqual(byAsset.data.map(cve => cve.id), ['CVE-2026-3001']);

    const triage = await fetchJson(`${baseUrl}/api/cves?sort=triage&limit=10`);
    assert.equal(triage.data[0].id, 'CVE-2026-3001');

    const recalculated = await fetchJson(`${baseUrl}/api/company-assets/recalculate`, { method: 'POST' });
    assert.equal(recalculated.data.matches, 1);
});

test('company asset CSV import endpoint updates inventory and recalculates matches', async (t) => {
    const { baseUrl, insertOrUpdateCve } = await startTestServer(t);
    insertOrUpdateCve({
        id: 'CVE-2026-3003',
        source: 'github',
        description: 'Django package vulnerability',
        cvss_score: 8,
        severity: 'high',
        published_at: '2026-04-30T00:00:00Z',
        search_metadata: {
            packages: [{ ecosystem: 'PyPI', name: 'django', vulnerable_version_range: '<4.2.8' }]
        }
    });

    const imported = await fetchJson(`${baseUrl}/api/company-assets/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            csv: 'name,type,vendor,product,packages,criticality,enabled\nCustomer Portal,application,DSF,Django,PyPI:django,high,true\n'
        })
    });

    assert.equal(imported.data.summary.imported, 1);
    assert.equal(imported.data.recalculation.matches, 1);

    const assets = await fetchJson(`${baseUrl}/api/company-assets`);
    assert.equal(assets.data[0].name, 'Customer Portal');
    assert.equal(assets.data[0].match_count, 1);

    const cves = await fetchJson(`${baseUrl}/api/cves?companyAffected=true&limit=10`);
    assert.equal(cves.data[0].id, 'CVE-2026-3003');
    assert.equal(cves.data[0].company_matches[0].match_type, 'package_exact');
});

async function startTestServer(t, options = {}) {
    const previousDbPath = process.env.CTI_DB_PATH;
    const previousScheduler = process.env.CTI_DISABLE_SCHEDULER;
    const tempDir = mkdtempSync(join(tmpdir(), 'cti-dashboard-integration-'));
    process.env.CTI_DB_PATH = join(tempDir, 'cti.db');
    process.env.CTI_DISABLE_SCHEDULER = 'true';

    const { initializeDb, insertOrUpdateCve } = await import('../server/db/database.js');
    const { createApp } = await import('../server/app.js');

    await initializeDb();
    const server = createApp(options).listen(0);
    await once(server, 'listening');

    t.after(async () => {
        await new Promise(resolve => server.close(resolve));
        if (previousDbPath === undefined) {
            delete process.env.CTI_DB_PATH;
        } else {
            process.env.CTI_DB_PATH = previousDbPath;
        }
        if (previousScheduler === undefined) {
            delete process.env.CTI_DISABLE_SCHEDULER;
        } else {
            process.env.CTI_DISABLE_SCHEDULER = previousScheduler;
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    return {
        baseUrl: `http://127.0.0.1:${server.address().port}`,
        insertOrUpdateCve
    };
}

async function fetchJson(url, options) {
    const response = await fetch(url, options);
    const body = await response.json();
    assert.equal(response.ok, true, `${response.status}: ${JSON.stringify(body)}`);
    return body;
}
