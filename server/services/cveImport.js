import {
    addCveProgressNote,
    getCveById,
    getSeverity,
    insertOrUpdateCve,
    setCveProgressStatus
} from '../db/database.js';
import { fetchNvdById } from './nvd.js';

const PROGRESS_STATUSES = ['open', 'assigned', 'closed'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const MAX_IMPORT_ITEMS = 500;

export async function importCveProgressItems(items, options = {}) {
    const rows = normalizeImportItems(items);
    const resolver = options.fetchCveById || fetchNvdById;
    const seen = new Set();
    const summary = {
        total: rows.length,
        imported: 0,
        updated: 0,
        placeholders: 0,
        duplicates: 0,
        failed: 0
    };
    const results = [];

    for (const row of rows) {
        const result = await importOneCveProgressRow(row, { resolver, seen });
        results.push(result);

        if (result.status === 'duplicate') {
            summary.duplicates++;
        } else if (!result.success) {
            summary.failed++;
        } else {
            if (result.action === 'updated') summary.updated++;
            else summary.imported++;
            if (result.placeholder) summary.placeholders++;
        }
    }

    return { summary, results };
}

export function normalizeImportItems(items) {
    if (!Array.isArray(items)) {
        const error = new Error('items must be an array');
        error.statusCode = 400;
        throw error;
    }
    if (items.length === 0) {
        const error = new Error('At least one CVE is required');
        error.statusCode = 400;
        throw error;
    }
    if (items.length > MAX_IMPORT_ITEMS) {
        const error = new Error(`Import is limited to ${MAX_IMPORT_ITEMS} CVEs at a time`);
        error.statusCode = 400;
        throw error;
    }

    return items.map((item, index) => normalizeImportItem(item, index));
}

export function normalizeImportItem(item, index = 0) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
        return invalidRow(index, null, 'Import row must be an object');
    }

    const rawId = item.id ?? item.cve_id ?? item.cve;
    const id = normalizeCveId(rawId);
    if (!id) return invalidRow(index, rawId, 'CVE ID must look like CVE-YYYY-NNNN');

    const status = normalizeProgressStatus(item.status);
    if (!status) return invalidRow(index, id, 'status must be one of: open, assigned, closed');

    const severity = normalizeSeverity(item.severity);
    if (item.severity && !severity) return invalidRow(index, id, 'severity must be one of: critical, high, medium, low');

    const cvssScore = normalizeCvssScore(item.cvss_score ?? item.cvssScore);
    if ((item.cvss_score ?? item.cvssScore) !== undefined && cvssScore === null) {
        return invalidRow(index, id, 'cvss_score must be a number between 0 and 10');
    }

    const note = normalizeOptionalText(item.note, 2000);
    if (item.note && note === null) return invalidRow(index, id, 'note must be 2000 characters or fewer');

    const description = normalizeOptionalText(item.description, 5000);
    if (item.description && description === null) return invalidRow(index, id, 'description must be 5000 characters or fewer');

    return {
        index,
        id,
        status,
        note,
        description,
        severity,
        cvss_score: cvssScore,
        valid: true
    };
}

async function importOneCveProgressRow(row, context) {
    if (!row.valid) {
        return {
            index: row.index,
            id: row.id || null,
            success: false,
            error: row.error
        };
    }

    if (context.seen.has(row.id)) {
        return {
            index: row.index,
            id: row.id,
            success: false,
            status: 'duplicate',
            error: 'Duplicate CVE in import payload'
        };
    }
    context.seen.add(row.id);

    try {
        const existing = getCveById(row.id);
        const cve = existing || await createMissingCve(row, context.resolver);
        const action = existing?.progress_status ? 'updated' : 'imported';

        const progress = setCveProgressStatus(row.id, row.status);
        const withNote = row.note ? addCveProgressNote(row.id, row.note) : progress;

        return {
            index: row.index,
            id: row.id,
            success: true,
            action,
            placeholder: cve.source === 'manual',
            data: withNote
        };
    } catch (error) {
        return {
            index: row.index,
            id: row.id,
            success: false,
            error: error.message
        };
    }
}

async function createMissingCve(row, resolver) {
    const resolved = await resolver(row.id);
    if (resolved?.id) {
        insertOrUpdateCve({
            ...resolved,
            id: row.id,
            source: resolved.source || 'nvd'
        });
        return getCveById(row.id);
    }

    const score = row.cvss_score ?? 0;
    insertOrUpdateCve({
        id: row.id,
        source: 'manual',
        description: row.description || `Manual progress import placeholder for ${row.id}; NVD details were unavailable.`,
        cvss_score: score,
        cvss_vector: null,
        severity: row.severity || getSeverity(score),
        published_at: new Date().toISOString(),
        search_text: 'manual import placeholder nvd unavailable',
        search_metadata: { imported_manually: true, nvd_unavailable: true }
    });
    return getCveById(row.id);
}

function invalidRow(index, id, error) {
    return {
        index,
        id: id ? String(id).trim().toUpperCase() : null,
        valid: false,
        error
    };
}

function normalizeCveId(value) {
    const id = String(value || '').trim().toUpperCase();
    return /^CVE-\d{4}-\d{4,}$/.test(id) ? id : null;
}

function normalizeProgressStatus(value) {
    if (value === undefined || value === null || String(value).trim() === '') return 'open';
    const status = String(value).trim().toLowerCase();
    return PROGRESS_STATUSES.includes(status) ? status : null;
}

function normalizeSeverity(value) {
    if (value === undefined || value === null || String(value).trim() === '') return null;
    const severity = String(value).trim().toLowerCase();
    return SEVERITIES.includes(severity) ? severity : null;
}

function normalizeCvssScore(value) {
    if (value === undefined || value === null || String(value).trim() === '') return undefined;
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 10) return null;
    return parsed;
}

function normalizeOptionalText(value, maxLength) {
    if (value === undefined || value === null) return null;
    const text = String(value).trim();
    if (!text) return null;
    if (text.length > maxLength) return null;
    return text;
}

export default { importCveProgressItems, normalizeImportItems, normalizeImportItem };
