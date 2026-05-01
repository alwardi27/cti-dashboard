CREATE TABLE IF NOT EXISTS cves (
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

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK(type IN ('ip', 'domain', 'url', 'hash')),
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT,
    confidence INTEGER DEFAULT 50 CHECK(confidence >= 0 AND confidence <= 100),
    first_seen DATETIME,
    last_seen DATETIME,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(value, source)
);

CREATE TABLE IF NOT EXISTS cve_ioc_links (
    cve_id TEXT NOT NULL,
    ioc_id INTEGER NOT NULL,
    relationship TEXT DEFAULT 'related',
    PRIMARY KEY (cve_id, ioc_id),
    FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_sources (
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('nvd', 'github', 'cisa_kev', 'vulncheck', 'shodan', 'censys', 'virustotal', 'greynoise', 'otx', 'osv', 'manual')),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cve_id, source),
    FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS feed_status (
    source TEXT PRIMARY KEY,
    last_fetch DATETIME,
    last_count INTEGER DEFAULT 0,
    last_successful_fetch DATETIME,
    last_successful_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    error_message TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cve_alerts (
    cve_id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'error')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    queued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_progress_tags (
    cve_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('open', 'assigned', 'closed')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_progress_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
);

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

CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

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

CREATE TABLE IF NOT EXISTS search_terms (
    doc_id TEXT NOT NULL,
    term TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (doc_id, term),
    FOREIGN KEY (doc_id) REFERENCES search_documents(doc_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cves_source ON cves(source);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at);
CREATE INDEX IF NOT EXISTS idx_cve_sources_source ON cve_sources(source);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
CREATE INDEX IF NOT EXISTS idx_iocs_threat_type ON iocs(threat_type);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);
CREATE INDEX IF NOT EXISTS idx_cve_alerts_status ON cve_alerts(status);
CREATE INDEX IF NOT EXISTS idx_cve_progress_tags_status ON cve_progress_tags(status);
CREATE INDEX IF NOT EXISTS idx_cve_progress_tags_updated ON cve_progress_tags(updated_at);
CREATE INDEX IF NOT EXISTS idx_cve_progress_notes_cve ON cve_progress_notes(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_progress_notes_created ON cve_progress_notes(created_at);
CREATE INDEX IF NOT EXISTS idx_company_assets_enabled ON company_assets(enabled);
CREATE INDEX IF NOT EXISTS idx_company_assets_type ON company_assets(type);
CREATE INDEX IF NOT EXISTS idx_company_assets_criticality ON company_assets(criticality);
CREATE INDEX IF NOT EXISTS idx_cve_asset_matches_cve ON cve_asset_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_asset_matches_asset ON cve_asset_matches(asset_id);
CREATE INDEX IF NOT EXISTS idx_cve_asset_matches_score ON cve_asset_matches(score);
CREATE INDEX IF NOT EXISTS idx_search_documents_type ON search_documents(entity_type);
CREATE INDEX IF NOT EXISTS idx_search_documents_source ON search_documents(source);
CREATE INDEX IF NOT EXISTS idx_search_documents_date ON search_documents(date);
CREATE INDEX IF NOT EXISTS idx_search_terms_term ON search_terms(term);
