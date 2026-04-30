import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';

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
