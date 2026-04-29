import initSqlJs from 'sql.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DB_PATH = join(__dirname, '../../data/cti.db');
const SCHEMA_PATH = join(__dirname, 'schema.sql');
const CVE_PROGRESS_STATUSES = ['open', 'assigned', 'closed'];
const CVE_PROGRESS_SELECT = `
    cves.*,
    progress.status AS progress_status,
    progress.created_at AS progress_created_at,
    progress.updated_at AS progress_updated_at,
    COALESCE(note_counts.note_count, 0) AS progress_note_count
`;
const CVE_PROGRESS_JOINS = `
    LEFT JOIN cve_progress_tags progress ON progress.cve_id = cves.id
    LEFT JOIN (
        SELECT cve_id, COUNT(*) AS note_count
        FROM cve_progress_notes
        GROUP BY cve_id
    ) note_counts ON note_counts.cve_id = cves.id
`;

let db = null;
let SQL = null;
let activeRefreshMetrics = null;

export async function initializeDb() {
    SQL = await initSqlJs();

    if (existsSync(DB_PATH)) {
        const buffer = readFileSync(DB_PATH);
        db = new SQL.Database(buffer);
    } else {
        db = new SQL.Database();
    }

    const schema = readFileSync(SCHEMA_PATH, 'utf-8');
    db.run(schema);
    migrateSchema();
    db.run('CREATE INDEX IF NOT EXISTS idx_cve_alerts_status ON cve_alerts(status);');
    saveDb();
    return db;
}

function migrateSchema() {
    const cvesSchema = getTableSql('cves');
    const hasExpandedCveSources = cvesSchema && cvesSchema.includes('vulncheck') && cvesSchema.includes('greynoise') && cvesSchema.includes('otx');

    if (!hasExpandedCveSources) {
        db.run(`
            CREATE TABLE cves_new (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL CHECK(source IN ('nvd', 'github', 'cisa_kev', 'vulncheck', 'shodan', 'censys', 'virustotal', 'greynoise', 'otx')),
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low')),
                published_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);
        db.run(`
            INSERT OR REPLACE INTO cves_new
            SELECT id, source, description, cvss_score, cvss_vector, severity, published_at, created_at, updated_at
            FROM cves;
        `);
        db.run('DROP TABLE cves;');
        db.run('ALTER TABLE cves_new RENAME TO cves;');
        db.run('CREATE INDEX IF NOT EXISTS idx_cves_source ON cves(source);');
        db.run('CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);');
        db.run('CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at);');
    }
}

function getTableSql(tableName) {
    const stmt = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1");
    stmt.bind([tableName]);
    const sql = stmt.step() ? stmt.getAsObject().sql : null;
    stmt.free();
    return sql;
}

function getCveProgressTag(cveId) {
    const database = getDb();
    const stmt = database.prepare('SELECT * FROM cve_progress_tags WHERE cve_id = ? LIMIT 1');
    stmt.bind([cveId]);
    const result = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return result;
}

function getCveProgressNotes(cveId) {
    const database = getDb();
    const stmt = database.prepare(`
        SELECT id, cve_id, note, created_at
        FROM cve_progress_notes
        WHERE cve_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
    `);
    stmt.bind([cveId]);
    const notes = [];
    while (stmt.step()) {
        notes.push(stmt.getAsObject());
    }
    stmt.free();
    return notes;
}

function getIocByValueSource(value, source) {
    if (!value || !source) return null;

    const database = getDb();
    const stmt = database.prepare('SELECT id, created_at FROM iocs WHERE value = ? AND source = ? LIMIT 1');
    stmt.bind([value, source]);
    const result = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return result;
}

function recordRefreshWrite(source, category, inserted) {
    if (!activeRefreshMetrics) return;

    const normalizedSource = source || 'unknown';
    const bucket = inserted ? 'new' : 'updated';
    activeRefreshMetrics[category][bucket]++;

    if (!activeRefreshMetrics.by_source[normalizedSource]) {
        activeRefreshMetrics.by_source[normalizedSource] = {
            cves: { new: 0, updated: 0 },
            iocs: { new: 0, updated: 0 }
        };
    }
    activeRefreshMetrics.by_source[normalizedSource][category][bucket]++;
}

export function saveDb() {
    if (!db) return;
    mkdirSync(dirname(DB_PATH), { recursive: true });
    const data = db.export();
    const buffer = Buffer.from(data);
    writeFileSync(DB_PATH, buffer);
}

export function startRefreshMetrics() {
    activeRefreshMetrics = {
        started_at: new Date().toISOString(),
        finished_at: null,
        cves: { new: 0, updated: 0 },
        iocs: { new: 0, updated: 0 },
        by_source: {}
    };
}

export function finishRefreshMetrics() {
    if (!activeRefreshMetrics) return null;
    activeRefreshMetrics.finished_at = new Date().toISOString();
    const metrics = activeRefreshMetrics;
    activeRefreshMetrics = null;
    return metrics;
}

export function getSeverity(score) {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
}

export function insertOrUpdateCve(cve) {
    const database = getDb();
    const existing = getCveById(cve.id);

    if (existing) {
        const stmt = database.prepare(`
            UPDATE cves
            SET source = ?,
                description = ?,
                cvss_score = ?,
                cvss_vector = ?,
                severity = ?,
                published_at = ?,
                updated_at = datetime('now')
            WHERE id = ?
        `);
        stmt.run([cve.source, cve.description, cve.cvss_score, cve.cvss_vector, cve.severity, cve.published_at, cve.id]);
        stmt.free();
    } else {
        const stmt = database.prepare(`
            INSERT INTO cves (id, source, description, cvss_score, cvss_vector, severity, published_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `);
        stmt.run([cve.id, cve.source, cve.description, cve.cvss_score, cve.cvss_vector, cve.severity, cve.published_at]);
        stmt.free();
    }

    if (!existing && shouldQueueCveAlert(cve)) {
        queueCveAlert(cve);
    }

    recordRefreshWrite(cve.source, 'cves', !existing);
    saveDb();
    return { changes: 1, inserted: !existing, updated: Boolean(existing) };
}

export function insertIoc(ioc) {
    const database = getDb();
    const existing = getIocByValueSource(ioc.value, ioc.source);
    const stmt = database.prepare(`
        INSERT OR REPLACE INTO iocs (type, value, source, threat_type, confidence, first_seen, last_seen, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))
    `);
    stmt.run([ioc.type, ioc.value, ioc.source, ioc.threat_type, ioc.confidence, ioc.first_seen, ioc.last_seen, ioc.metadata, existing?.created_at || null]);
    stmt.free();
    recordRefreshWrite(ioc.source, 'iocs', !existing);
    saveDb();
    return { changes: 1, inserted: !existing, updated: Boolean(existing) };
}

export function linkCveIoc(cveId, iocId, relationship = 'related') {
    const database = getDb();
    try {
        database.run(`INSERT OR IGNORE INTO cve_ioc_links (cve_id, ioc_id, relationship) VALUES (?, ?, ?)`, [cveId, iocId, relationship]);
        saveDb();
    } catch (e) { /* ignore */ }
    return { changes: 1 };
}

export function updateFeedStatus(source, status, count = 0, error = null) {
    const database = getDb();
    database.run(`
        INSERT OR REPLACE INTO feed_status (source, last_fetch, last_count, status, error_message, updated_at)
        VALUES (?, datetime('now'), ?, ?, ?, datetime('now'))
    `, [source, count, status, error]);
    saveDb();
    return { changes: 1 };
}

export function getPendingCveAlerts(limit = 10) {
    const database = getDb();
    const stmt = database.prepare(`
        SELECT alerts.cve_id, alerts.severity, alerts.attempts, cves.source, cves.description, cves.cvss_score, cves.published_at
        FROM cve_alerts alerts
        JOIN cves ON cves.id = alerts.cve_id
        WHERE alerts.status IN ('pending', 'error') AND alerts.attempts < 5
        ORDER BY alerts.queued_at ASC
        LIMIT ?
    `);
    stmt.bind([normalizeLimit(limit)]);

    const alerts = [];
    while (stmt.step()) {
        alerts.push(stmt.getAsObject());
    }
    stmt.free();
    return alerts;
}

export function markCveAlertSent(cveId) {
    const database = getDb();
    database.run(`
        UPDATE cve_alerts
        SET status = 'sent', sent_at = datetime('now'), updated_at = datetime('now'), last_error = NULL
        WHERE cve_id = ?
    `, [cveId]);
    saveDb();
    return { changes: database.getRowsModified() };
}

export function markCveAlertError(cveId, error) {
    const database = getDb();
    database.run(`
        UPDATE cve_alerts
        SET status = 'error', attempts = attempts + 1, last_error = ?, updated_at = datetime('now')
        WHERE cve_id = ?
    `, [String(error || 'Unknown error').substring(0, 500), cveId]);
    saveDb();
    return { changes: database.getRowsModified() };
}

export function getCveProgressItems(filters = {}) {
    const database = getDb();
    let query = `
        SELECT ${CVE_PROGRESS_SELECT},
            latest_notes.note AS latest_note,
            latest_notes.created_at AS latest_note_at
        FROM cve_progress_tags tagged
        JOIN cves ON cves.id = tagged.cve_id
        ${CVE_PROGRESS_JOINS}
        LEFT JOIN cve_progress_notes latest_notes ON latest_notes.id = (
            SELECT id
            FROM cve_progress_notes
            WHERE cve_id = tagged.cve_id
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 1
        )
        WHERE 1=1
    `;
    const params = [];

    if (filters.status) {
        query += ' AND tagged.status = ?';
        params.push(normalizeCveProgressStatus(filters.status));
    }
    if (filters.search) {
        query += ' AND (cves.id LIKE ? OR cves.description LIKE ? OR latest_notes.note LIKE ?)';
        params.push(`%${filters.search}%`, `%${filters.search}%`, `%${filters.search}%`);
    }

    query += ' ORDER BY datetime(tagged.updated_at) DESC LIMIT ? OFFSET ?';
    params.push(normalizeLimit(filters.limit), normalizeOffset(filters.offset));

    const stmt = database.prepare(query);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
}

export function getCveProgressDetail(cveId) {
    const cve = getCveById(cveId);
    if (!cve) return null;

    return {
        ...cve,
        notes: getCveProgressNotes(cveId)
    };
}

export function setCveProgressStatus(cveId, status) {
    const database = getDb();
    const cve = getCveById(cveId);
    if (!cve) {
        const error = new Error('CVE not found');
        error.statusCode = 404;
        throw error;
    }

    const normalizedStatus = normalizeCveProgressStatus(status, { allowEmpty: true });
    if (!normalizedStatus) {
        database.run('DELETE FROM cve_progress_tags WHERE cve_id = ?', [cveId]);
        saveDb();
        return getCveProgressDetail(cveId);
    }

    const existing = getCveProgressTag(cveId);
    if (existing) {
        database.run(`
            UPDATE cve_progress_tags
            SET status = ?, updated_at = datetime('now')
            WHERE cve_id = ?
        `, [normalizedStatus, cveId]);
    } else {
        database.run(`
            INSERT INTO cve_progress_tags (cve_id, status, created_at, updated_at)
            VALUES (?, ?, datetime('now'), datetime('now'))
        `, [cveId, normalizedStatus]);
    }

    saveDb();
    return getCveProgressDetail(cveId);
}

export function addCveProgressNote(cveId, note) {
    const database = getDb();
    const cve = getCveById(cveId);
    if (!cve) {
        const error = new Error('CVE not found');
        error.statusCode = 404;
        throw error;
    }

    if (!getCveProgressTag(cveId)) {
        const error = new Error('Set a progress tag before adding notes');
        error.statusCode = 400;
        throw error;
    }

    const normalizedNote = String(note || '').trim();
    if (!normalizedNote) {
        const error = new Error('Note is required');
        error.statusCode = 400;
        throw error;
    }
    if (normalizedNote.length > 2000) {
        const error = new Error('Note must be 2000 characters or fewer');
        error.statusCode = 400;
        throw error;
    }

    database.run(`
        INSERT INTO cve_progress_notes (cve_id, note, created_at)
        VALUES (?, ?, datetime('now'))
    `, [cveId, normalizedNote]);
    database.run(`
        UPDATE cve_progress_tags
        SET updated_at = datetime('now')
        WHERE cve_id = ?
    `, [cveId]);
    saveDb();

    return getCveProgressDetail(cveId);
}

export function getCves(filters = {}) {
    const database = getDb();
    let query = `
        SELECT ${CVE_PROGRESS_SELECT}
        FROM cves
        ${CVE_PROGRESS_JOINS}
        WHERE 1=1
    `;
    const params = [];

    if (filters.source) {
        query += ' AND cves.source = ?';
        params.push(filters.source);
    }
    if (filters.severity) {
        query += ' AND cves.severity = ?';
        params.push(filters.severity);
    }
    if (filters.search) {
        query += ' AND (cves.id LIKE ? OR cves.description LIKE ?)';
        params.push(`%${filters.search}%`, `%${filters.search}%`);
    }
    if (filters.fromDate) {
        query += ' AND datetime(cves.published_at) >= datetime(?)';
        params.push(filters.fromDate);
    }

    query += ' ORDER BY datetime(cves.published_at) DESC LIMIT ? OFFSET ?';
    params.push(normalizeLimit(filters.limit), normalizeOffset(filters.offset));

    const stmt = database.prepare(query);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
}

export function getCveById(id) {
    if (!id) return null;

    const database = getDb();
    const stmt = database.prepare(`
        SELECT ${CVE_PROGRESS_SELECT}
        FROM cves
        ${CVE_PROGRESS_JOINS}
        WHERE cves.id = ?
        LIMIT 1
    `);
    stmt.bind([id]);

    const result = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return result;
}

export function getIocs(filters = {}) {
    const database = getDb();
    let query = 'SELECT * FROM iocs WHERE 1=1';
    const params = [];

    if (filters.type) {
        query += ' AND type = ?';
        params.push(filters.type);
    }
    if (filters.source) {
        query += ' AND source = ?';
        params.push(filters.source);
    }
    if (filters.threatType) {
        query += ' AND threat_type = ?';
        params.push(filters.threatType);
    }
    if (filters.search) {
        query += ' AND value LIKE ?';
        params.push(`%${filters.search}%`);
    }
    if (filters.fromDate) {
        query += ' AND datetime(COALESCE(last_seen, first_seen, created_at)) >= datetime(?)';
        params.push(filters.fromDate);
    }

    query += ' ORDER BY datetime(COALESCE(last_seen, first_seen, created_at)) DESC LIMIT ? OFFSET ?';
    params.push(normalizeLimit(filters.limit), normalizeOffset(filters.offset));

    const stmt = database.prepare(query);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
}

export function getStats() {
    const database = getDb();

    const cveStmt = database.prepare(`
        SELECT
            COUNT(*) as total,
            COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0) as critical,
            COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0) as high,
            COALESCE(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END), 0) as medium,
            COALESCE(SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END), 0) as low
        FROM cves
    `);
    cveStmt.step();
    const cveStats = cveStmt.getAsObject();
    cveStmt.free();

    const iocStmt = database.prepare(`SELECT type, COUNT(*) as count FROM iocs GROUP BY type`);
    const iocStats = [];
    while (iocStmt.step()) {
        iocStats.push(iocStmt.getAsObject());
    }
    iocStmt.free();

    const recentStmt = database.prepare(`SELECT COUNT(*) as count FROM cves WHERE published_at >= datetime('now', '-24 hours')`);
    recentStmt.step();
    const recentCves = recentStmt.getAsObject().count;
    recentStmt.free();

    const sourceStmt = database.prepare(`SELECT source, COUNT(*) as count FROM cves GROUP BY source`);
    const sourceStats = [];
    while (sourceStmt.step()) {
        sourceStats.push(sourceStmt.getAsObject());
    }
    sourceStmt.free();

    return {
        cves: cveStats,
        iocs: iocStats,
        recent24h: recentCves,
        sources: sourceStats
    };
}

export function pruneOldData(days = 90) {
    const database = getDb();
    database.run(`DELETE FROM cves WHERE created_at < datetime('now', '-${days} days')`);
    database.run(`DELETE FROM iocs WHERE created_at < datetime('now', '-${days} days')`);
    saveDb();
    return { changes: database.getRowsModified() };
}

export function searchAll(query) {
    const database = getDb();

    const cveStmt = database.prepare(`
        SELECT 'cve' as type, id, description as name, severity, source, published_at as date
        FROM cves
        WHERE id LIKE ? OR description LIKE ?
        LIMIT 20
    `);
    cveStmt.bind([`%${query}%`, `%${query}%`]);
    const cves = [];
    while (cveStmt.step()) {
        cves.push(cveStmt.getAsObject());
    }
    cveStmt.free();

    const iocStmt = database.prepare(`
        SELECT 'ioc' as type, id, value as name, type as ioc_type, source, threat_type, last_seen as date
        FROM iocs
        WHERE value LIKE ?
        LIMIT 20
    `);
    iocStmt.bind([`%${query}%`]);
    const iocs = [];
    while (iocStmt.step()) {
        iocs.push(iocStmt.getAsObject());
    }
    iocStmt.free();

    return [...cves, ...iocs];
}

export function getDb() {
    if (!db) throw new Error('Database not initialized');
    return db;
}

function normalizeLimit(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return 100;
    return Math.min(parsed, 500);
}

function normalizeOffset(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed < 0) return 0;
    return parsed;
}

function normalizeCveProgressStatus(status, options = {}) {
    const value = String(status || '').trim().toLowerCase();
    if (options.allowEmpty && !value) return null;
    if (CVE_PROGRESS_STATUSES.includes(value)) return value;

    const error = new Error(`Progress status must be one of: ${CVE_PROGRESS_STATUSES.join(', ')}`);
    error.statusCode = 400;
    throw error;
}

function shouldQueueCveAlert(cve) {
    if (!cve?.id || !['critical', 'high'].includes(String(cve.severity || '').toLowerCase())) {
        return false;
    }

    const maxAgeDays = Number.parseFloat(process.env.WHATSAPP_ALERT_MAX_AGE_DAYS || '1');
    if (!Number.isFinite(maxAgeDays) || maxAgeDays <= 0) return true;

    const publishedAt = new Date(cve.published_at);
    if (Number.isNaN(publishedAt.getTime())) return true;

    const oldestAlertable = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
    return publishedAt.getTime() >= oldestAlertable;
}

function queueCveAlert(cve) {
    db.run(`
        INSERT OR IGNORE INTO cve_alerts (cve_id, severity, status, queued_at, updated_at)
        VALUES (?, ?, 'pending', datetime('now'), datetime('now'))
    `, [cve.id, String(cve.severity || '').toLowerCase()]);
}

export default {
    initializeDb,
    getDb,
    getSeverity,
    startRefreshMetrics,
    finishRefreshMetrics,
    insertOrUpdateCve,
    getCveById,
    insertIoc,
    linkCveIoc,
    updateFeedStatus,
    getPendingCveAlerts,
    markCveAlertSent,
    markCveAlertError,
    getCveProgressItems,
    getCveProgressDetail,
    setCveProgressStatus,
    addCveProgressNote,
    getCves,
    getIocs,
    getStats,
    pruneOldData,
    searchAll
};
