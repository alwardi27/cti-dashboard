import { enrichCveSearch, updateFeedStatus } from '../db/database.js';
import { feedGet } from '../utils/feedHttp.js';

const EPSS_API = 'https://api.first.org/data/v1/epss';

export async function fetchEpss(minScore = process.env.EPSS_MIN_SCORE || '0.05', limit = process.env.EPSS_LIMIT || '1000') {
    if (!isEnabled('EPSS_ENABLED')) return skipFeed('epss', 'Skipped: EPSS_ENABLED is false');

    try {
        const response = await feedGet(EPSS_API, {
            params: {
                'epss-gt': normalizeProbability(minScore),
                limit: normalizeLimit(limit)
            },
            timeout: Number.parseInt(process.env.EPSS_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.EPSS_RETRIES || '3', 10) });

        const records = parseEpssResponse(response.data);
        let count = 0;
        for (const record of records) {
            const enriched = enrichCveSearch(record.cve, {
                epss: record.epss,
                epss_percentile: record.percentile,
                epss_date: record.date
            }, `epss ${record.epss} percentile ${record.percentile} exploit probability`);
            if (enriched) count++;
        }

        await updateFeedStatus('epss', 'success', count);
        console.log(`[EPSS] Enriched ${count} local CVEs`);
        return count;
    } catch (error) {
        const message = error.message;
        await updateFeedStatus('epss', 'error', 0, message);
        console.error(`[EPSS] Error: ${message}`);
        throw error;
    }
}

export function parseEpssResponse(payload) {
    return (Array.isArray(payload?.data) ? payload.data : [])
        .map(row => ({
            cve: String(row.cve || '').toUpperCase(),
            epss: Number.parseFloat(row.epss),
            percentile: Number.parseFloat(row.percentile),
            date: row.date || null
        }))
        .filter(row => /^CVE-\d{4}-\d+$/i.test(row.cve));
}

function normalizeProbability(value) {
    const parsed = Number.parseFloat(value);
    if (!Number.isFinite(parsed) || parsed < 0) return 0.05;
    return Math.min(parsed, 1);
}

function normalizeLimit(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return 1000;
    return Math.min(parsed, 5000);
}

function isEnabled(name) {
    return !['0', 'false', 'no', 'off'].includes(String(process.env[name] ?? 'true').trim().toLowerCase());
}

async function skipFeed(source, message) {
    await updateFeedStatus(source, 'skipped', 0, message);
    console.log(`[${source}] ${message}`);
    return 0;
}

export default { fetchEpss, parseEpssResponse };
