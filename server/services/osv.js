import { getSeverity, insertOrUpdateCve, updateFeedStatus } from '../db/database.js';
import { feedGet } from '../utils/feedHttp.js';

const OSV_MODIFIED_CSV = 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv';
const OSV_RECORD_BASE = 'https://osv-vulnerabilities.storage.googleapis.com/';

export async function fetchOsvAdvisories(limit = process.env.OSV_LIMIT || '50', modifiedUrl = OSV_MODIFIED_CSV) {
    if (!isEnabled('OSV_ENABLED')) return skipFeed('osv', 'Skipped: OSV_ENABLED is false');

    try {
        const boundedLimit = normalizeLimit(limit);
        const response = await feedGet(modifiedUrl, {
            timeout: Number.parseInt(process.env.OSV_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.OSV_RETRIES || '3', 10) });
        const entries = parseOsvModifiedCsv(response.data).slice(0, boundedLimit);
        let count = 0;

        for (const entry of entries) {
            const record = await fetchOsvRecord(entry.path).catch(error => {
                console.warn(`[OSV] Failed to fetch ${entry.path}: ${error.message}`);
                return null;
            });
            const parsed = record ? parseOsvRecord(record) : null;
            if (!parsed) continue;
            insertOrUpdateCve(parsed);
            count++;
        }

        await updateFeedStatus('osv', 'success', count);
        console.log(`[OSV] Fetched ${count} open-source advisories`);
        return count;
    } catch (error) {
        const message = error.message;
        await updateFeedStatus('osv', 'error', 0, message);
        console.error(`[OSV] Error: ${message}`);
        throw error;
    }
}

async function fetchOsvRecord(path) {
    const response = await feedGet(`${OSV_RECORD_BASE}${encodeURI(path)}.json`, {
        timeout: Number.parseInt(process.env.OSV_TIMEOUT_MS || '90000', 10)
    }, { retries: Number.parseInt(process.env.OSV_RETRIES || '3', 10) });
    return response.data;
}

export function parseOsvModifiedCsv(csv) {
    return String(csv || '')
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .map(line => {
            const separator = line.indexOf(',');
            return {
                modified: separator === -1 ? null : line.slice(0, separator),
                path: separator === -1 ? line : line.slice(separator + 1)
            };
        })
        .filter(entry => entry.path && !entry.path.includes('..'));
}

export function parseOsvRecord(record) {
    const id = chooseOsvIdentifier(record);
    if (!id) return null;

    const packages = collectPackages(record);
    const score = scoreFromOsvSeverity(record);
    const summary = record.summary || record.details || `OSV advisory ${id}`;

    return {
        id,
        source: 'osv',
        description: String(summary).substring(0, 5000),
        cvss_score: score,
        cvss_vector: vectorFromOsvSeverity(record),
        severity: getSeverity(score),
        published_at: record.published || record.modified || new Date().toISOString(),
        search_text: [
            record.id,
            ...(record.aliases || []),
            packages.map(pkg => `${pkg.ecosystem || ''} ${pkg.name || ''}`).join(' '),
            record.details,
            record.summary
        ].join(' '),
        search_metadata: {
            osv_id: record.id,
            aliases: record.aliases || [],
            packages
        }
    };
}

function chooseOsvIdentifier(record) {
    const aliases = Array.isArray(record.aliases) ? record.aliases : [];
    return aliases.find(alias => /^CVE-\d{4}-\d+$/i.test(alias)) ||
        aliases.find(alias => /^GHSA-/i.test(alias)) ||
        (/^GHSA-/i.test(record.id || '') ? record.id : null);
}

function collectPackages(record) {
    const packages = [];
    for (const affected of record.affected || []) {
        if (affected.package?.name || affected.package?.ecosystem) {
            packages.push({
                name: affected.package?.name || null,
                ecosystem: affected.package?.ecosystem || null
            });
        }
    }
    return packages;
}

function scoreFromOsvSeverity(record) {
    for (const severity of record.severity || []) {
        if (String(severity.type || '').toUpperCase().startsWith('CVSS')) {
            const match = String(severity.score || '').match(/\/AV:|^CVSS:/) ? null : String(severity.score || '').match(/\d+(?:\.\d+)?/);
            if (match) return Number.parseFloat(match[0]);
        }
    }
    if ((record.database_specific?.severity || '').toUpperCase() === 'CRITICAL') return 9.5;
    if ((record.database_specific?.severity || '').toUpperCase() === 'HIGH') return 8;
    if ((record.database_specific?.severity || '').toUpperCase() === 'MEDIUM') return 5.5;
    return 3;
}

function vectorFromOsvSeverity(record) {
    return (record.severity || []).find(severity => String(severity.score || '').startsWith('CVSS:'))?.score || null;
}

function normalizeLimit(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return 50;
    return Math.min(parsed, 250);
}

function isEnabled(name) {
    return !['0', 'false', 'no', 'off'].includes(String(process.env[name] ?? 'true').trim().toLowerCase());
}

async function skipFeed(source, message) {
    await updateFeedStatus(source, 'skipped', 0, message);
    console.log(`[${source}] ${message}`);
    return 0;
}

export default { fetchOsvAdvisories, parseOsvModifiedCsv, parseOsvRecord };
