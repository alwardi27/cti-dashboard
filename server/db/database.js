import initSqlJs from 'sql.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { copyFileSync, readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, unlinkSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
import { matchAssetToCve, normalizeCompanyAssetInput } from '../services/companyAssets.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DEFAULT_DB_PATH = join(__dirname, '../../data/cti.db');
const SCHEMA_PATH = join(__dirname, 'schema.sql');
const CVE_PROGRESS_STATUSES = ['open', 'assigned', 'closed'];
const CVE_SOURCE_PRIORITIES = {
    nvd: 100,
    cisa_kev: 90,
    vulncheck: 85,
    github: 80,
    shodan: 55,
    censys: 55,
    virustotal: 50,
    greynoise: 45,
    otx: 40,
    osv: 75,
    manual: 10
};
const KNOWN_FEED_SOURCES = [
    'nvd',
    'cisa_kev',
    'github',
    'vulncheck',
    'urlhaus',
    'threatfox',
    'malwarebazaar',
    'feodo',
    'sslbl',
    'epss',
    'osv',
    'virustotal',
    'greynoise',
    'shodan',
    'censys',
    'abuseipdb',
    'otx'
];
const CVE_PROGRESS_SELECT = `
    cves.*,
    COALESCE(source_summary.sources_csv, cves.source) AS sources_csv,
    COALESCE(source_summary.is_kev, CASE WHEN cves.source = 'cisa_kev' THEN 1 ELSE 0 END) AS is_kev,
    progress.status AS progress_status,
    progress.created_at AS progress_created_at,
    progress.updated_at AS progress_updated_at,
    COALESCE(note_counts.note_count, 0) AS progress_note_count,
    COALESCE(company_summary.match_count, 0) AS company_match_count,
    COALESCE(company_summary.priority_score, 0) AS company_priority_score
`;
const CVE_PROGRESS_JOINS = `
    LEFT JOIN (
        SELECT
            cve_id,
            GROUP_CONCAT(source) AS sources_csv,
            MAX(CASE WHEN source = 'cisa_kev' THEN 1 ELSE 0 END) AS is_kev
        FROM cve_sources
        GROUP BY cve_id
    ) source_summary ON source_summary.cve_id = cves.id
    LEFT JOIN cve_progress_tags progress ON progress.cve_id = cves.id
    LEFT JOIN (
        SELECT cve_id, COUNT(*) AS note_count
        FROM cve_progress_notes
        GROUP BY cve_id
    ) note_counts ON note_counts.cve_id = cves.id
    LEFT JOIN (
        SELECT
            cve_id,
            COUNT(*) AS match_count,
            MAX(score) AS priority_score
        FROM cve_asset_matches
        GROUP BY cve_id
    ) company_summary ON company_summary.cve_id = cves.id
`;

let db = null;
let SQL = null;
let fallbackRefreshMetrics = null;
let deferredSaveDepth = 0;
let deferredSavePending = false;
let saveSequence = 0;
const refreshMetricsStore = new AsyncLocalStorage();

export async function initializeDb() {
    SQL = await initSqlJs();
    const dbPath = getDbPath();

    if (existsSync(dbPath)) {
        const buffer = readFileSync(dbPath);
        db = new SQL.Database(buffer);
    } else {
        db = new SQL.Database();
    }

    const schema = readFileSync(SCHEMA_PATH, 'utf-8');
    db.run(schema);
    migrateSchema();
    backfillSearchIndexIfEmpty();
    markSchemaVersion(1);
    db.run('CREATE INDEX IF NOT EXISTS idx_cve_alerts_status ON cve_alerts(status);');
    saveDb();
    return db;
}

function migrateSchema() {
    ensureSchemaMigrationTable();
    const cvesSchema = getTableSql('cves');
    const hasExpandedCveSources = cvesSchema && cvesSchema.includes('vulncheck') && cvesSchema.includes('greynoise') && cvesSchema.includes('otx') && cvesSchema.includes('osv') && cvesSchema.includes('manual');

    if (!hasExpandedCveSources) {
        db.run(`
            CREATE TABLE cves_new (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL CHECK(source IN ('nvd', 'github', 'cisa_kev', 'vulncheck', 'shodan', 'censys', 'virustotal', 'greynoise', 'otx', 'osv', 'manual')),
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

    addColumnIfMissing('feed_status', 'last_successful_fetch', 'DATETIME');
    addColumnIfMissing('feed_status', 'last_successful_count', 'INTEGER DEFAULT 0');
    ensureFeedStatusRows();
    db.run(`
        CREATE TABLE IF NOT EXISTS cve_sources (
            cve_id TEXT NOT NULL,
            source TEXT NOT NULL CHECK(source IN ('nvd', 'github', 'cisa_kev', 'vulncheck', 'shodan', 'censys', 'virustotal', 'greynoise', 'otx', 'osv', 'manual')),
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, source),
            FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
        );
    `);
    migrateCveSourcesSchema();
    db.run('CREATE INDEX IF NOT EXISTS idx_cve_sources_source ON cve_sources(source);');
    db.run(`
        CREATE TABLE IF NOT EXISTS search_documents (
            doc_id TEXT PRIMARY KEY,
            entity_type TEXT NOT NULL CHECK(entity_type IN ('cve', 'ioc')),
            entity_id TEXT NOT NULL,
            source TEXT,
            title TEXT,
            summary TEXT,
            url TEXT,
            metadata TEXT,
            date DATETIME,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS search_terms (
            doc_id TEXT NOT NULL,
            term TEXT NOT NULL,
            weight INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (doc_id, term),
            FOREIGN KEY (doc_id) REFERENCES search_documents(doc_id) ON DELETE CASCADE
        );
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_search_documents_type ON search_documents(entity_type);');
    db.run('CREATE INDEX IF NOT EXISTS idx_search_documents_source ON search_documents(source);');
    db.run('CREATE INDEX IF NOT EXISTS idx_search_documents_date ON search_documents(date);');
    db.run('CREATE INDEX IF NOT EXISTS idx_search_terms_term ON search_terms(term);');
    db.run(`
        INSERT OR IGNORE INTO cve_sources (cve_id, source, first_seen, last_seen)
        SELECT id, source, COALESCE(created_at, datetime('now')), COALESCE(updated_at, datetime('now'))
        FROM cves
        WHERE source IS NOT NULL
    `);
    db.run(`
        UPDATE feed_status
        SET last_successful_fetch = COALESCE(last_successful_fetch, last_fetch),
            last_successful_count = CASE
                WHEN COALESCE(last_successful_count, 0) = 0 THEN last_count
                ELSE last_successful_count
            END
        WHERE status = 'success'
    `);
    ensureCompanyAssetTables();
}

function ensureSchemaMigrationTable() {
    db.run(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);
}

function markSchemaVersion(version) {
    db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, datetime(\'now\'))', [version]);
}

function migrateCveSourcesSchema() {
    const cveSourcesSchema = getTableSql('cve_sources');
    if (!cveSourcesSchema || cveSourcesSchema.includes('manual')) return;

    db.run(`
        CREATE TABLE cve_sources_new (
            cve_id TEXT NOT NULL,
            source TEXT NOT NULL CHECK(source IN ('nvd', 'github', 'cisa_kev', 'vulncheck', 'shodan', 'censys', 'virustotal', 'greynoise', 'otx', 'osv', 'manual')),
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, source),
            FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
        );
    `);
    db.run(`
        INSERT OR IGNORE INTO cve_sources_new (cve_id, source, first_seen, last_seen)
        SELECT cve_id, source, first_seen, last_seen
        FROM cve_sources;
    `);
    db.run('DROP TABLE cve_sources;');
    db.run('ALTER TABLE cve_sources_new RENAME TO cve_sources;');
}

function ensureCompanyAssetTables() {
    db.run(`
        CREATE TABLE IF NOT EXISTS company_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'application' CHECK(type IN ('service', 'application')),
            vendor TEXT,
            product TEXT,
            version TEXT,
            aliases TEXT,
            cpe_uris TEXT,
            packages TEXT,
            criticality TEXT NOT NULL DEFAULT 'medium' CHECK(criticality IN ('low', 'medium', 'high')),
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS cve_asset_matches (
            cve_id TEXT NOT NULL,
            asset_id INTEGER NOT NULL,
            match_type TEXT NOT NULL,
            match_reason TEXT NOT NULL,
            matched_value TEXT,
            confidence REAL NOT NULL,
            score INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, asset_id),
            FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES company_assets(id) ON DELETE CASCADE
        );
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_company_assets_enabled ON company_assets(enabled);');
    db.run('CREATE INDEX IF NOT EXISTS idx_company_assets_type ON company_assets(type);');
    db.run('CREATE INDEX IF NOT EXISTS idx_company_assets_criticality ON company_assets(criticality);');
    db.run('CREATE INDEX IF NOT EXISTS idx_cve_asset_matches_cve ON cve_asset_matches(cve_id);');
    db.run('CREATE INDEX IF NOT EXISTS idx_cve_asset_matches_asset ON cve_asset_matches(asset_id);');
    db.run('CREATE INDEX IF NOT EXISTS idx_cve_asset_matches_score ON cve_asset_matches(score);');
}

function getTableSql(tableName) {
    const stmt = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1");
    stmt.bind([tableName]);
    const sql = stmt.step() ? stmt.getAsObject().sql : null;
    stmt.free();
    return sql;
}

function addColumnIfMissing(tableName, columnName, definition) {
    const columns = getTableColumns(tableName);
    if (!columns.includes(columnName)) {
        db.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition};`);
    }
}

function getTableColumns(tableName) {
    const stmt = db.prepare(`PRAGMA table_info(${tableName})`);
    const columns = [];
    while (stmt.step()) {
        columns.push(stmt.getAsObject().name);
    }
    stmt.free();
    return columns;
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

function setAppState(key, value) {
    const database = getDb();
    database.run(`
        INSERT OR REPLACE INTO app_state (key, value, updated_at)
        VALUES (?, ?, datetime('now'))
    `, [key, JSON.stringify(value)]);
    saveDb();
}

function getAppState(key) {
    const database = getDb();
    const stmt = database.prepare('SELECT value FROM app_state WHERE key = ? LIMIT 1');
    stmt.bind([key]);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();

    if (!row?.value) return null;
    try {
        return JSON.parse(row.value);
    } catch (error) {
        return null;
    }
}

function recordRefreshWrite(source, category, inserted) {
    const activeRefreshMetrics = refreshMetricsStore.getStore() || fallbackRefreshMetrics;
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

export function saveDb(options = {}) {
    if (!db) return;
    if (!options.force && deferredSaveDepth > 0) {
        deferredSavePending = true;
        return;
    }

    const dbPath = getDbPath();
    mkdirSync(dirname(dbPath), { recursive: true });
    const data = db.export();
    const buffer = Buffer.from(data);
    const tempPath = `${dbPath}.tmp-${process.pid}-${Date.now()}-${saveSequence++}`;
    try {
        writeFileSync(tempPath, buffer);
        renameSync(tempPath, dbPath);
    } catch (error) {
        if (shouldFallbackToCopy(error)) {
            try {
                copyFileSync(tempPath, dbPath);
                cleanupTempFile(tempPath);
                return;
            } catch (fallbackError) {
                cleanupTempFile(tempPath);
                fallbackError.message = `${fallbackError.message}; fallback after atomic rename failed: ${error.message}`;
                throw fallbackError;
            }
        }
        cleanupTempFile(tempPath);
        throw error;
    }
}

function cleanupTempFile(tempPath) {
    if (existsSync(tempPath)) {
        try {
            unlinkSync(tempPath);
        } catch {
            // Best effort cleanup; keep the original database file intact.
        }
    }
}

function shouldFallbackToCopy(error) {
    return process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error?.code);
}

function ensureFeedStatusRows() {
    for (const source of KNOWN_FEED_SOURCES) {
        db.run(`
            INSERT OR IGNORE INTO feed_status (
                source,
                status,
                last_count,
                last_successful_count,
                updated_at
            )
            VALUES (?, 'pending', 0, 0, datetime('now'))
        `, [source]);
    }
}

export function getDbPath() {
    return resolve(process.env.CTI_DB_PATH || DEFAULT_DB_PATH);
}

function createRefreshMetrics() {
    return {
        started_at: new Date().toISOString(),
        finished_at: null,
        cves: { new: 0, updated: 0 },
        iocs: { new: 0, updated: 0 },
        by_source: {}
    };
}

async function withDeferredDbSave(callback) {
    deferredSaveDepth++;
    try {
        return await callback();
    } finally {
        deferredSaveDepth--;
        if (deferredSaveDepth === 0 && deferredSavePending) {
            deferredSavePending = false;
            saveDb({ force: true });
        }
    }
}

export async function withRefreshMetrics(callback) {
    const metrics = createRefreshMetrics();

    return refreshMetricsStore.run(metrics, async () => {
        return withDeferredDbSave(async () => {
            try {
                const result = await callback(metrics);
                return { result, metrics: finishRefreshMetrics(metrics) };
            } catch (error) {
                finishRefreshMetrics(metrics);
                error.refreshMetrics = metrics;
                throw error;
            }
        });
    });
}

export function startRefreshMetrics() {
    fallbackRefreshMetrics = createRefreshMetrics();
    return fallbackRefreshMetrics;
}

export function finishRefreshMetrics(metrics = fallbackRefreshMetrics) {
    if (!metrics) return null;
    if (!metrics.finished_at) {
        metrics.finished_at = new Date().toISOString();
    }
    if (fallbackRefreshMetrics === metrics) {
        fallbackRefreshMetrics = null;
    }
    return metrics;
}

export function saveLastRefreshSummary(summary) {
    setAppState('last_refresh_summary', summary || {});
    return summary;
}

export function getLastRefreshSummary() {
    return getAppState('last_refresh_summary');
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
    const normalizedCve = normalizeCveInput(cve);

    if (existing) {
        const merged = mergeCveRecords(existing, normalizedCve);
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
        stmt.run(dbValues([
            merged.source,
            merged.description,
            merged.cvss_score,
            merged.cvss_vector,
            merged.severity,
            merged.published_at,
            normalizedCve.id
        ]));
        stmt.free();
    } else {
        const stmt = database.prepare(`
            INSERT INTO cves (id, source, description, cvss_score, cvss_vector, severity, published_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `);
        stmt.run(dbValues([
            normalizedCve.id,
            normalizedCve.source,
            normalizedCve.description,
            normalizedCve.cvss_score,
            normalizedCve.cvss_vector,
            normalizedCve.severity,
            normalizedCve.published_at
        ]));
        stmt.free();
    }

    upsertCveSource(normalizedCve.id, normalizedCve.source);

    if (!existing && shouldQueueCveAlert(normalizedCve)) {
        queueCveAlert(normalizedCve);
    }

    indexCveSearch(getCveById(normalizedCve.id), normalizedCve.search_text, normalizedCve.search_metadata);
    recalculateCompanyAssetMatches({ cveId: normalizedCve.id, save: false });
    recordRefreshWrite(normalizedCve.source, 'cves', !existing);
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
    stmt.run(dbValues([ioc.type, ioc.value, ioc.source, ioc.threat_type, ioc.confidence, ioc.first_seen, ioc.last_seen, ioc.metadata, existing?.created_at || null]));
    stmt.free();
    indexIocSearch(getIocSearchRow(ioc.value, ioc.source), ioc.search_text, ioc.search_metadata);
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
    const existing = getFeedStatusBySource(source);

    if (existing) {
        database.run(`
            UPDATE feed_status
            SET last_fetch = datetime('now'),
                last_count = ?,
                status = ?,
                error_message = ?,
                updated_at = datetime('now'),
                last_successful_fetch = CASE WHEN ? = 'success' THEN datetime('now') ELSE last_successful_fetch END,
                last_successful_count = CASE WHEN ? = 'success' THEN ? ELSE last_successful_count END
            WHERE source = ?
        `, [count, status, error, status, status, count, source]);
    } else {
        database.run(`
            INSERT INTO feed_status (
                source,
                last_fetch,
                last_count,
                last_successful_fetch,
                last_successful_count,
                status,
                error_message,
                updated_at
            )
            VALUES (
                ?,
                datetime('now'),
                ?,
                CASE WHEN ? = 'success' THEN datetime('now') ELSE NULL END,
                CASE WHEN ? = 'success' THEN ? ELSE 0 END,
                ?,
                ?,
                datetime('now')
            )
        `, [source, count, status, status, count, status, error]);
    }

    saveDb();
    return { changes: 1 };
}

function getFeedStatusBySource(source) {
    const database = getDb();
    const stmt = database.prepare('SELECT source FROM feed_status WHERE source = ? LIMIT 1');
    stmt.bind([source]);
    const result = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return result;
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
        results.push(hydrateCveRow(stmt.getAsObject()));
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

export function getCompanyAssets(filters = {}) {
    const database = getDb();
    let query = `
        SELECT
            company_assets.*,
            COALESCE(match_counts.match_count, 0) AS match_count
        FROM company_assets
        LEFT JOIN (
            SELECT asset_id, COUNT(*) AS match_count
            FROM cve_asset_matches
            GROUP BY asset_id
        ) match_counts ON match_counts.asset_id = company_assets.id
        WHERE 1=1
    `;
    const params = [];

    if (filters.enabled !== undefined && filters.enabled !== null && filters.enabled !== '') {
        query += ' AND company_assets.enabled = ?';
        params.push(filters.enabled ? 1 : 0);
    }
    if (filters.search) {
        query += ' AND (company_assets.name LIKE ? OR company_assets.vendor LIKE ? OR company_assets.product LIKE ? OR company_assets.aliases LIKE ? OR company_assets.notes LIKE ?)';
        params.push(...Array(5).fill(`%${filters.search}%`));
    }

    query += `
        ORDER BY
            company_assets.enabled DESC,
            CASE company_assets.criticality
                WHEN 'high' THEN 0
                WHEN 'medium' THEN 1
                WHEN 'low' THEN 2
                ELSE 3
            END,
            company_assets.name ASC
        LIMIT ? OFFSET ?
    `;
    params.push(normalizeLimit(filters.limit), normalizeOffset(filters.offset));

    const stmt = database.prepare(query);
    stmt.bind(params);
    const assets = [];
    while (stmt.step()) {
        assets.push(formatCompanyAsset(stmt.getAsObject()));
    }
    stmt.free();
    return assets;
}

export function getCompanyAssetById(id) {
    const assetId = normalizeAssetId(id);
    if (!assetId) return null;

    const stmt = getDb().prepare(`
        SELECT
            company_assets.*,
            COALESCE(match_counts.match_count, 0) AS match_count
        FROM company_assets
        LEFT JOIN (
            SELECT asset_id, COUNT(*) AS match_count
            FROM cve_asset_matches
            GROUP BY asset_id
        ) match_counts ON match_counts.asset_id = company_assets.id
        WHERE company_assets.id = ?
        LIMIT 1
    `);
    stmt.bind([assetId]);
    const asset = stmt.step() ? formatCompanyAsset(stmt.getAsObject()) : null;
    stmt.free();
    return asset;
}

export function createCompanyAsset(input) {
    const normalized = normalizeCompanyAssetInput(input);
    const asset = insertCompanyAsset(normalized);
    const recalculation = recalculateCompanyAssetMatches({ assetId: asset.id, save: false });
    saveDb();
    return { ...getCompanyAssetById(asset.id), recalculation };
}

export function updateCompanyAsset(id, input) {
    const assetId = normalizeAssetId(id);
    const existing = getCompanyAssetById(assetId);
    if (!existing) {
        const error = new Error('Asset not found');
        error.statusCode = 404;
        throw error;
    }

    const normalized = normalizeCompanyAssetInput({ ...existing, ...input, id: assetId });
    getDb().run(`
        UPDATE company_assets
        SET name = ?,
            type = ?,
            vendor = ?,
            product = ?,
            version = ?,
            aliases = ?,
            cpe_uris = ?,
            packages = ?,
            criticality = ?,
            enabled = ?,
            notes = ?,
            updated_at = datetime('now')
        WHERE id = ?
    `, assetDbValues(normalized, assetId));

    const recalculation = recalculateCompanyAssetMatches({ assetId, save: false });
    saveDb();
    return { ...getCompanyAssetById(assetId), recalculation };
}

export function deleteCompanyAsset(id) {
    const assetId = normalizeAssetId(id);
    const asset = getCompanyAssetById(assetId);
    if (!asset) {
        const error = new Error('Asset not found');
        error.statusCode = 404;
        throw error;
    }

    const database = getDb();
    database.run('DELETE FROM cve_asset_matches WHERE asset_id = ?', [assetId]);
    database.run('DELETE FROM company_assets WHERE id = ?', [assetId]);
    saveDb();
    return { deleted: true, asset };
}

export function importCompanyAssets(items = []) {
    if (!Array.isArray(items)) {
        const error = new Error('items must be an array');
        error.statusCode = 400;
        throw error;
    }
    if (!items.length) {
        const error = new Error('At least one asset is required');
        error.statusCode = 400;
        throw error;
    }
    if (items.length > 500) {
        const error = new Error('Asset import is limited to 500 rows at a time');
        error.statusCode = 400;
        throw error;
    }

    const summary = { total: items.length, imported: 0, updated: 0, failed: 0 };
    const results = [];

    for (const [index, item] of items.entries()) {
        try {
            const normalized = normalizeCompanyAssetInput(item);
            const existing = findCompanyAssetByIdentity(normalized);
            const asset = existing
                ? updateCompanyAsset(existing.id, normalized)
                : createCompanyAsset(normalized);
            if (existing) summary.updated++;
            else summary.imported++;
            results.push({ index, success: true, action: existing ? 'updated' : 'imported', id: asset.id, name: asset.name });
        } catch (error) {
            summary.failed++;
            results.push({ index, success: false, error: error.message });
        }
    }

    const recalculation = recalculateCompanyAssetMatches({ save: false });
    saveDb();
    return { summary, recalculation, results };
}

export function recalculateCompanyAssetMatches(options = {}) {
    const database = getDb();
    const assetId = normalizeAssetId(options.assetId);
    const cveId = options.cveId ? String(options.cveId).trim().toUpperCase() : null;
    clearCompanyAssetMatches({ assetId, cveId });

    const assets = getAssetsForMatching(assetId);
    const cves = getCvesForMatching(cveId);
    let matches = 0;

    for (const cve of cves) {
        const metadata = getCveSearchMetadata(cve.id);
        for (const asset of assets) {
            const match = matchAssetToCve(asset, cve, metadata);
            if (!match) continue;
            database.run(`
                INSERT OR REPLACE INTO cve_asset_matches (
                    cve_id,
                    asset_id,
                    match_type,
                    match_reason,
                    matched_value,
                    confidence,
                    score,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            `, [
                cve.id,
                asset.id,
                match.match_type,
                match.match_reason,
                match.matched_value || null,
                match.confidence,
                match.score
            ]);
            matches++;
        }
    }

    if (options.save !== false) saveDb();
    return { assets: assets.length, cves: cves.length, matches };
}

function insertCompanyAsset(asset) {
    const database = getDb();
    database.run(`
        INSERT INTO company_assets (
            name,
            type,
            vendor,
            product,
            version,
            aliases,
            cpe_uris,
            packages,
            criticality,
            enabled,
            notes,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
    `, assetDbValues(asset));

    return getCompanyAssetById(lastInsertId());
}

function assetDbValues(asset, id = null) {
    const values = [
        asset.name,
        asset.type,
        asset.vendor || null,
        asset.product || null,
        asset.version || null,
        JSON.stringify(asset.aliases || []),
        JSON.stringify(asset.cpe_uris || []),
        JSON.stringify(asset.packages || []),
        asset.criticality,
        asset.enabled ? 1 : 0,
        asset.notes || null
    ];
    if (id !== null) values.push(id);
    return values;
}

function lastInsertId() {
    const stmt = getDb().prepare('SELECT last_insert_rowid() AS id');
    stmt.step();
    const id = Number(stmt.getAsObject().id);
    stmt.free();
    return id;
}

function findCompanyAssetByIdentity(asset) {
    const stmt = getDb().prepare(`
        SELECT id
        FROM company_assets
        WHERE LOWER(name) = LOWER(?)
          AND LOWER(COALESCE(vendor, '')) = LOWER(?)
          AND LOWER(COALESCE(product, '')) = LOWER(?)
        LIMIT 1
    `);
    stmt.bind([asset.name, asset.vendor || '', asset.product || '']);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return row ? getCompanyAssetById(row.id) : null;
}

function clearCompanyAssetMatches(filters = {}) {
    const conditions = [];
    const params = [];
    if (filters.assetId) {
        conditions.push('asset_id = ?');
        params.push(filters.assetId);
    }
    if (filters.cveId) {
        conditions.push('cve_id = ?');
        params.push(filters.cveId);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    getDb().run(`DELETE FROM cve_asset_matches ${where}`, params);
}

function getAssetsForMatching(assetId = null) {
    const params = [];
    let query = 'SELECT * FROM company_assets WHERE enabled = 1';
    if (assetId) {
        query += ' AND id = ?';
        params.push(assetId);
    }
    query += ' ORDER BY id ASC';

    const stmt = getDb().prepare(query);
    stmt.bind(params);
    const assets = [];
    while (stmt.step()) {
        assets.push(formatCompanyAsset(stmt.getAsObject()));
    }
    stmt.free();
    return assets;
}

function getCvesForMatching(cveId = null) {
    const params = [];
    let query = 'SELECT * FROM cves';
    if (cveId) {
        query += ' WHERE id = ?';
        params.push(cveId);
    }
    query += ' ORDER BY id ASC';

    const stmt = getDb().prepare(query);
    stmt.bind(params);
    const cves = [];
    while (stmt.step()) {
        cves.push(stmt.getAsObject());
    }
    stmt.free();
    return cves;
}

function getCveSearchMetadata(cveId) {
    const document = getSearchDocument(`cve:${cveId}`);
    return parseJson(document?.metadata) || {};
}

function formatCompanyAsset(row) {
    if (!row) return null;
    return {
        id: Number(row.id),
        name: row.name,
        type: row.type,
        vendor: row.vendor || null,
        product: row.product || null,
        version: row.version || null,
        aliases: parseJson(row.aliases) || [],
        cpe_uris: parseJson(row.cpe_uris) || [],
        packages: parseJson(row.packages) || [],
        criticality: row.criticality || 'medium',
        enabled: Boolean(Number(row.enabled)),
        notes: row.notes || null,
        created_at: row.created_at,
        updated_at: row.updated_at,
        match_count: Number(row.match_count || 0)
    };
}

function normalizeAssetId(value) {
    const id = Number.parseInt(value, 10);
    return Number.isFinite(id) && id > 0 ? id : null;
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
        const severities = normalizeSeverityFilter(filters.severity);
        query += ` AND cves.severity IN (${severities.map(() => '?').join(', ')})`;
        params.push(...severities);
    }
    if (filters.search) {
        query += ' AND (cves.id LIKE ? OR cves.description LIKE ?)';
        params.push(`%${filters.search}%`, `%${filters.search}%`);
    }
    if (filters.fromDate) {
        query += ' AND datetime(cves.published_at) >= datetime(?)';
        params.push(filters.fromDate);
    }
    if (filters.progressStatus) {
        const progressStatus = normalizeCveProgressStatus(filters.progressStatus, { allowEmpty: true });
        if (progressStatus) {
            query += ' AND progress.status = ?';
            params.push(progressStatus);
        } else {
            query += ' AND progress.status IS NULL';
        }
    }
    if (filters.needsReview) {
        query += " AND cves.severity IN ('critical', 'high') AND progress.status IS NULL";
    }
    if (filters.companyAffected) {
        query += ' AND COALESCE(company_summary.match_count, 0) > 0';
    }
    if (filters.assetId) {
        query += ' AND EXISTS (SELECT 1 FROM cve_asset_matches asset_filter WHERE asset_filter.cve_id = cves.id AND asset_filter.asset_id = ?)';
        params.push(filters.assetId);
    }

    query += cveSortClause(filters.sort);
    params.push(normalizeLimit(filters.limit), normalizeOffset(filters.offset));

    const stmt = database.prepare(query);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(hydrateCveRow(stmt.getAsObject()));
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

    const result = stmt.step() ? hydrateCveRow(stmt.getAsObject()) : null;
    stmt.free();
    return result;
}

function getIocSearchRow(value, source) {
    if (!value || !source) return null;

    const database = getDb();
    const stmt = database.prepare('SELECT * FROM iocs WHERE value = ? AND source = ? LIMIT 1');
    stmt.bind([value, source]);
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

export function getIocById(id) {
    const parsed = Number.parseInt(id, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return null;

    const database = getDb();
    const stmt = database.prepare('SELECT * FROM iocs WHERE id = ? LIMIT 1');
    stmt.bind([parsed]);
    const result = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return result;
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

    const sourceStmt = database.prepare(`
        SELECT source, COUNT(DISTINCT cve_id) as count
        FROM cve_sources
        GROUP BY source
        ORDER BY count DESC, source
    `);
    const sourceStats = [];
    while (sourceStmt.step()) {
        sourceStats.push(sourceStmt.getAsObject());
    }
    sourceStmt.free();

    const assetStmt = database.prepare(`
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END), 0) AS enabled,
            COALESCE(SUM(CASE WHEN criticality = 'high' THEN 1 ELSE 0 END), 0) AS high,
            (SELECT COUNT(DISTINCT cve_id) FROM cve_asset_matches) AS matched_cves
        FROM company_assets
    `);
    assetStmt.step();
    const assetStats = assetStmt.getAsObject();
    assetStmt.free();

    return {
        cves: cveStats,
        iocs: iocStats,
        assets: assetStats,
        recent24h: recentCves,
        sources: sourceStats,
        triage: getTriageStats()
    };
}

export function getTriageStats() {
    const database = getDb();
    const cveStmt = database.prepare(`
        SELECT
            COALESCE(SUM(CASE WHEN cves.severity IN ('critical', 'high') AND progress.status IS NULL THEN 1 ELSE 0 END), 0) AS needsReview,
            COALESCE(SUM(CASE WHEN progress.status = 'open' THEN 1 ELSE 0 END), 0) AS open,
            COALESCE(SUM(CASE WHEN progress.status = 'assigned' THEN 1 ELSE 0 END), 0) AS assigned,
            COALESCE(SUM(CASE WHEN progress.status = 'closed' THEN 1 ELSE 0 END), 0) AS closed
        FROM cves
        LEFT JOIN cve_progress_tags progress ON progress.cve_id = cves.id
    `);
    cveStmt.step();
    const cveTriage = cveStmt.getAsObject();
    cveStmt.free();

    const feedStmt = database.prepare(`
        SELECT COUNT(*) AS feedErrors
        FROM feed_status
        WHERE status = 'error'
          AND source != 'urlhaus_hosts'
    `);
    feedStmt.step();
    const feedErrors = feedStmt.getAsObject().feedErrors || 0;
    feedStmt.free();

    return {
        needsReview: cveTriage.needsReview || 0,
        open: cveTriage.open || 0,
        assigned: cveTriage.assigned || 0,
        closed: cveTriage.closed || 0,
        feedErrors
    };
}

export function pruneOldData(days = 90) {
    const database = getDb();
    database.run(`DELETE FROM cves WHERE created_at < datetime('now', '-${days} days')`);
    database.run(`DELETE FROM iocs WHERE created_at < datetime('now', '-${days} days')`);
    saveDb();
    return { changes: database.getRowsModified() };
}

export function searchAll(query, options = {}) {
    return searchDocuments({ ...options, q: query });
}

export function searchDocuments(filters = {}) {
    const database = getDb();
    const parsed = parseSearchQuery(filters.q || '');
    const type = normalizeSearchFilter(filters.type || parsed.filters.type);
    const source = normalizeSearchFilter(filters.source || parsed.filters.source);
    const limit = normalizeLimit(filters.limit || 50);
    const offset = normalizeOffset(filters.offset);
    const terms = [...parsed.terms];

    for (const key of ['severity', 'hash', 'ip', 'domain']) {
        if (parsed.filters[key]) terms.push(parsed.filters[key]);
    }

    const conditions = [];
    const params = [];
    if (type) {
        conditions.push('d.entity_type = ?');
        params.push(type);
    }
    if (source) {
        conditions.push('d.source = ?');
        params.push(source);
    }

    const termConditions = [];
    const scoreParts = [];
    for (const term of uniqueTerms(terms)) {
        const normalized = normalizeSearchTerm(term);
        if (!normalized) continue;
        termConditions.push('(t.term = ? OR t.term LIKE ? OR d.title LIKE ? OR d.summary LIKE ?)');
        params.push(normalized, `${normalized}%`, `%${term}%`, `%${term}%`);
        scoreParts.push(`
            CASE
                WHEN t.term = '${escapeSqlLiteral(normalized)}' THEN t.weight * 5
                WHEN t.term LIKE '${escapeSqlLiteral(normalized)}%' THEN t.weight * 2
                ELSE 0
            END
        `);
    }

    if (termConditions.length) {
        conditions.push(`(${termConditions.join(' OR ')})`);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const scoreExpression = scoreParts.length ? scoreParts.join(' + ') : '1';
    const sql = `
        SELECT
            d.doc_id,
            d.entity_type,
            d.entity_id,
            d.source,
            d.title,
            d.summary,
            d.url,
            d.metadata,
            d.date,
            MAX(${scoreExpression}) AS score
        FROM search_documents d
        LEFT JOIN search_terms t ON t.doc_id = d.doc_id
        ${where}
        GROUP BY d.doc_id
        ORDER BY score DESC, datetime(d.date) DESC, d.title ASC
        LIMIT ? OFFSET ?
    `;
    params.push(limit, offset);

    const stmt = database.prepare(sql);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(formatSearchResult(stmt.getAsObject()));
    }
    stmt.free();
    return results;
}

export function enrichCveSearch(cveId, metadata = {}, extraText = '') {
    const cve = getCveById(String(cveId || '').toUpperCase());
    if (!cve) return false;

    const existing = getSearchDocument(`cve:${cve.id}`);
    const existingMetadata = parseJson(existing?.metadata) || {};
    indexCveSearch(cve, extraText, { ...existingMetadata, ...metadata });
    recalculateCompanyAssetMatches({ cveId: cve.id, save: false });
    saveDb();
    return true;
}

function backfillSearchIndexIfEmpty() {
    const stmt = db.prepare('SELECT COUNT(*) AS count FROM search_documents');
    stmt.step();
    const count = stmt.getAsObject().count || 0;
    stmt.free();
    if (count > 0) return;

    const cveStmt = db.prepare(`SELECT ${CVE_PROGRESS_SELECT} FROM cves ${CVE_PROGRESS_JOINS}`);
    while (cveStmt.step()) {
        indexCveSearch(hydrateCveRow(cveStmt.getAsObject()));
    }
    cveStmt.free();

    const iocStmt = db.prepare('SELECT * FROM iocs');
    while (iocStmt.step()) {
        indexIocSearch(iocStmt.getAsObject());
    }
    iocStmt.free();
}

function indexCveSearch(cve, extraText = '', extraMetadata = {}) {
    if (!cve?.id) return;

    const metadata = {
        severity: cve.severity,
        cvss_score: cve.cvss_score,
        sources: cve.sources || [cve.source],
        is_kev: Boolean(cve.is_kev),
        ...extraMetadata
    };
    const text = [
        cve.id,
        cve.source,
        cve.severity,
        cve.description,
        cve.cvss_vector,
        ...(cve.sources || []),
        extraText,
        JSON.stringify(extraMetadata || {})
    ].join(' ');

    upsertSearchDocument({
        doc_id: `cve:${cve.id}`,
        entity_type: 'cve',
        entity_id: cve.id,
        source: cve.source,
        title: cve.id,
        summary: cve.description || '',
        url: sourceUrlForCve(cve.id),
        metadata,
        date: cve.published_at || cve.updated_at || cve.created_at
    }, buildWeightedTerms({
        id: cve.id,
        source: cve.source,
        type: 'cve',
        high: [cve.id, ...(cve.sources || [])],
        medium: [cve.severity, cve.cvss_vector, extraText],
        low: [cve.description, text]
    }));
}

function indexIocSearch(ioc, extraText = '', extraMetadata = {}) {
    if (!ioc?.id || !ioc.value) return;

    const parsedMetadata = parseJson(ioc.metadata) || {};
    const metadata = {
        ioc_type: ioc.type,
        threat_type: ioc.threat_type,
        confidence: ioc.confidence,
        ...parsedMetadata,
        ...extraMetadata
    };
    const text = [
        ioc.value,
        ioc.type,
        ioc.source,
        ioc.threat_type,
        ioc.metadata,
        extraText
    ].join(' ');

    upsertSearchDocument({
        doc_id: `ioc:${ioc.source}:${ioc.value}`,
        entity_type: 'ioc',
        entity_id: String(ioc.id),
        source: ioc.source,
        title: ioc.value,
        summary: ioc.threat_type || ioc.type || '',
        url: null,
        metadata,
        date: ioc.last_seen || ioc.first_seen || ioc.created_at
    }, buildWeightedTerms({
        id: ioc.value,
        source: ioc.source,
        type: 'ioc',
        high: [ioc.value, ioc.source, ioc.type],
        medium: [ioc.threat_type, parsedMetadata.tags, parsedMetadata.signature, parsedMetadata.file_name, parsedMetadata.md5, parsedMetadata.sha1],
        low: [ioc.metadata, extraText, text]
    }));
}

function upsertSearchDocument(document, weightedTerms) {
    const database = getDb();
    database.run(`
        INSERT OR REPLACE INTO search_documents (
            doc_id, entity_type, entity_id, source, title, summary, url, metadata, date, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `, [
        document.doc_id,
        document.entity_type,
        document.entity_id,
        document.source || null,
        document.title || '',
        document.summary || '',
        document.url || null,
        JSON.stringify(document.metadata || {}),
        document.date || null
    ]);
    database.run('DELETE FROM search_terms WHERE doc_id = ?', [document.doc_id]);

    for (const [term, weight] of weightedTerms.entries()) {
        database.run('INSERT INTO search_terms (doc_id, term, weight) VALUES (?, ?, ?)', [document.doc_id, term, weight]);
    }
}

function getSearchDocument(docId) {
    const stmt = getDb().prepare('SELECT * FROM search_documents WHERE doc_id = ? LIMIT 1');
    stmt.bind([docId]);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return row;
}

function buildWeightedTerms(groups) {
    const weighted = new Map();
    addTerms(weighted, groups.type, 10);
    addTerms(weighted, groups.source, 20);
    addTerms(weighted, groups.id, 100);
    addTerms(weighted, groups.high, 60);
    addTerms(weighted, groups.medium, 30);
    addTerms(weighted, groups.low, 10);
    return weighted;
}

function addTerms(weighted, value, weight) {
    for (const term of tokenizeSearchText(value)) {
        weighted.set(term, Math.max(weighted.get(term) || 0, weight));
    }
}

function tokenizeSearchText(value) {
    if (value === undefined || value === null) return [];
    const raw = Array.isArray(value) ? value.join(' ') : String(value);
    const normalized = raw.toLowerCase();
    const tokens = new Set();

    for (const exact of normalized.match(/[a-z0-9][a-z0-9._:/-]{1,}/g) || []) {
        tokens.add(exact);
    }
    for (const part of normalized.split(/[^a-z0-9]+/)) {
        if (part.length >= 2) tokens.add(part);
    }
    return [...tokens].slice(0, 800);
}

function parseSearchQuery(query) {
    const filters = {};
    const terms = [];
    for (const part of String(query || '').match(/"[^"]+"|\S+/g) || []) {
        const cleaned = part.replace(/^"|"$/g, '');
        const separator = cleaned.indexOf(':');
        if (separator > 0) {
            const key = cleaned.slice(0, separator).toLowerCase();
            const value = cleaned.slice(separator + 1).trim();
            if (['type', 'source', 'severity', 'hash', 'ip', 'domain'].includes(key) && value) {
                filters[key] = value.toLowerCase();
                continue;
            }
        }
        terms.push(cleaned);
    }
    return { filters, terms };
}

function normalizeSearchTerm(term) {
    return tokenizeSearchText(term)[0] || null;
}

function normalizeSearchFilter(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return normalized || null;
}

function uniqueTerms(terms) {
    return [...new Set(terms.map(term => String(term || '').trim()).filter(Boolean))];
}

function escapeSqlLiteral(value) {
    return String(value || '').replace(/'/g, "''");
}

function formatSearchResult(row) {
    const metadata = parseJson(row.metadata) || {};
    return {
        type: row.entity_type,
        entity_id: row.entity_id,
        id: row.entity_id,
        title: row.title,
        name: row.title,
        summary: row.summary,
        source: row.source,
        date: row.date,
        url: row.url,
        score: Number(row.score || 0),
        metadata,
        severity: metadata.severity || null,
        ioc_type: metadata.ioc_type || null,
        threat_type: metadata.threat_type || null
    };
}

function sourceUrlForCve(cveId) {
    if (/^CVE-\d{4}-\d+$/i.test(cveId || '')) {
        return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
    }
    if (/^GHSA-/i.test(cveId || '')) {
        return `https://github.com/advisories/${encodeURIComponent(cveId)}`;
    }
    return null;
}

function parseJson(value) {
    if (!value) return null;
    if (typeof value === 'object') return value;
    try {
        return JSON.parse(value);
    } catch {
        return null;
    }
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
    if (options.allowEmpty && (!value || value === 'none')) return null;
    if (CVE_PROGRESS_STATUSES.includes(value)) return value;

    const error = new Error(`Progress status must be one of: ${CVE_PROGRESS_STATUSES.join(', ')}`);
    error.statusCode = 400;
    throw error;
}

function normalizeSeverityFilter(value) {
    const allowed = ['critical', 'high', 'medium', 'low'];
    const severities = String(value || '')
        .split(',')
        .map(item => item.trim().toLowerCase())
        .filter(item => allowed.includes(item));
    return severities.length ? severities : allowed;
}

function cveSortClause(sort) {
    switch (String(sort || 'published').toLowerCase()) {
        case 'triage':
            return `
                ORDER BY
                    CASE WHEN COALESCE(company_summary.priority_score, 0) > 0 THEN 0 ELSE 1 END,
                    COALESCE(company_summary.priority_score, 0) DESC,
                    CASE cves.severity
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    CASE
                        WHEN progress.status IS NULL THEN 0
                        WHEN progress.status = 'open' THEN 1
                        WHEN progress.status = 'assigned' THEN 2
                        WHEN progress.status = 'closed' THEN 3
                        ELSE 4
                    END,
                    datetime(cves.published_at) DESC
                LIMIT ? OFFSET ?
            `;
        case 'cvss':
            return ' ORDER BY cves.cvss_score DESC, datetime(cves.published_at) DESC LIMIT ? OFFSET ?';
        case 'published':
        default:
            return ' ORDER BY datetime(cves.published_at) DESC LIMIT ? OFFSET ?';
    }
}

function dbValues(values) {
    return values.map(value => value === undefined ? null : value);
}

function normalizeCveInput(cve) {
    return {
        ...cve,
        id: String(cve.id || '').toUpperCase(),
        source: String(cve.source || 'nvd').toLowerCase(),
        description: cve.description || null,
        cvss_score: Number.isFinite(Number(cve.cvss_score)) ? Number(cve.cvss_score) : 0,
        cvss_vector: cve.cvss_vector || null,
        severity: cve.severity || getSeverity(Number(cve.cvss_score) || 0),
        published_at: cve.published_at || new Date().toISOString()
    };
}

function mergeCveRecords(existing, incoming) {
    const incomingPriority = sourcePriority(incoming.source);
    const existingPriority = sourcePriority(existing.source);
    const shouldReplaceCanonical = incomingPriority >= existingPriority;

    return {
        source: shouldReplaceCanonical ? incoming.source : existing.source,
        description: chooseField(existing.description, incoming.description, shouldReplaceCanonical),
        cvss_score: chooseScore(existing.cvss_score, incoming.cvss_score, shouldReplaceCanonical),
        cvss_vector: chooseField(existing.cvss_vector, incoming.cvss_vector, shouldReplaceCanonical),
        severity: chooseField(existing.severity, incoming.severity, shouldReplaceCanonical),
        published_at: chooseField(existing.published_at, incoming.published_at, shouldReplaceCanonical)
    };
}

function chooseField(existingValue, incomingValue, shouldReplace) {
    if (shouldReplace && incomingValue !== undefined && incomingValue !== null && incomingValue !== '') {
        return incomingValue;
    }
    if (existingValue !== undefined && existingValue !== null && existingValue !== '') {
        return existingValue;
    }
    return incomingValue ?? null;
}

function chooseScore(existingValue, incomingValue, shouldReplace) {
    const incomingScore = Number(incomingValue);
    const existingScore = Number(existingValue);
    if (shouldReplace && Number.isFinite(incomingScore)) return incomingScore;
    if (Number.isFinite(existingScore) && existingScore > 0) return existingScore;
    return Number.isFinite(incomingScore) ? incomingScore : 0;
}

function upsertCveSource(cveId, source) {
    const normalizedSource = String(source || '').toLowerCase();
    if (!cveId || !normalizedSource) return;

    db.run(`
        INSERT INTO cve_sources (cve_id, source, first_seen, last_seen)
        VALUES (?, ?, datetime('now'), datetime('now'))
        ON CONFLICT(cve_id, source) DO UPDATE SET last_seen = datetime('now')
    `, [cveId, normalizedSource]);
}

function hydrateCveRow(row) {
    if (!row) return row;

    const sources = uniqueSources(row.sources_csv || row.source);
    row.sources = sources;
    row.is_kev = Boolean(Number(row.is_kev) || sources.includes('cisa_kev'));
    row.company_match_count = Number(row.company_match_count || 0);
    row.company_priority_score = Number(row.company_priority_score || 0);
    row.company_matches = row.company_match_count > 0 ? getCveCompanyMatches(row.id) : [];
    delete row.sources_csv;
    return row;
}

function getCveCompanyMatches(cveId) {
    const stmt = getDb().prepare(`
        SELECT
            matches.asset_id,
            assets.name AS asset_name,
            assets.type AS asset_type,
            assets.criticality,
            matches.match_type,
            matches.match_reason,
            matches.matched_value,
            matches.confidence,
            matches.score,
            matches.updated_at
        FROM cve_asset_matches matches
        JOIN company_assets assets ON assets.id = matches.asset_id
        WHERE matches.cve_id = ?
        ORDER BY matches.score DESC, matches.confidence DESC, assets.name ASC
    `);
    stmt.bind([cveId]);
    const matches = [];
    while (stmt.step()) {
        const row = stmt.getAsObject();
        matches.push({
            asset_id: Number(row.asset_id),
            asset_name: row.asset_name,
            asset_type: row.asset_type,
            criticality: row.criticality,
            match_type: row.match_type,
            match_reason: row.match_reason,
            matched_value: row.matched_value || null,
            confidence: Number(row.confidence || 0),
            score: Number(row.score || 0),
            updated_at: row.updated_at
        });
    }
    stmt.free();
    return matches;
}

function uniqueSources(value) {
    const seen = new Set();
    return String(value || '')
        .split(',')
        .map(source => source.trim().toLowerCase())
        .filter(Boolean)
        .filter(source => {
            if (seen.has(source)) return false;
            seen.add(source);
            return true;
        })
        .sort((a, b) => sourcePriority(b) - sourcePriority(a) || a.localeCompare(b));
}

function sourcePriority(source) {
    return CVE_SOURCE_PRIORITIES[String(source || '').toLowerCase()] || 0;
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
    getDbPath,
    getSeverity,
    withRefreshMetrics,
    startRefreshMetrics,
    finishRefreshMetrics,
    saveLastRefreshSummary,
    getLastRefreshSummary,
    insertOrUpdateCve,
    getCveById,
    insertIoc,
    getIocById,
    linkCveIoc,
    updateFeedStatus,
    getPendingCveAlerts,
    markCveAlertSent,
    markCveAlertError,
    getCveProgressItems,
    getCveProgressDetail,
    setCveProgressStatus,
    addCveProgressNote,
    getCompanyAssets,
    getCompanyAssetById,
    createCompanyAsset,
    updateCompanyAsset,
    deleteCompanyAsset,
    importCompanyAssets,
    recalculateCompanyAssetMatches,
    getCves,
    getIocs,
    getStats,
    getTriageStats,
    pruneOldData,
    searchAll,
    searchDocuments,
    enrichCveSearch
};
