(function attachDashboardUtils(global) {
    function escapeCsvCell(value) {
        const normalized = value === undefined || value === null ? '' : String(value);
        return `"${normalized.replace(/"/g, '""')}"`;
    }

    function buildCsv(data, fields) {
        const headers = fields.join(',');
        const rows = data.map(item => fields.map(field => escapeCsvCell(item[field])).join(','));
        return [headers, ...rows].join('\n');
    }

    function parseProgressImportText(text) {
        return [...new Set(String(text || '').match(/CVE-\d{4}-\d{4,}/gi) || [])]
            .map(id => ({ id: id.toUpperCase() }));
    }

    function parseProgressImportCsv(text) {
        const rows = parseCsvRows(text);
        if (rows.length < 2) return [];

        const headers = rows[0].map(normalizeHeader);
        return rows.slice(1)
            .map(row => rowToProgressImport(headers, row))
            .filter(item => item.id);
    }

    function parseCompanyAssetCsv(text) {
        const rows = parseCsvRows(text);
        if (rows.length < 2) return [];

        const headers = rows[0].map(normalizeHeader);
        return rows.slice(1)
            .map(row => rowToCompanyAsset(headers, row))
            .filter(item => item.name);
    }

    function parseCsvRows(text) {
        const rows = [];
        let row = [];
        let cell = '';
        let quoted = false;
        const value = String(text || '').replace(/^\uFEFF/, '');

        for (let i = 0; i < value.length; i++) {
            const char = value[i];
            const next = value[i + 1];

            if (char === '"') {
                if (quoted && next === '"') {
                    cell += '"';
                    i++;
                } else {
                    quoted = !quoted;
                }
            } else if (char === ',' && !quoted) {
                row.push(cell.trim());
                cell = '';
            } else if ((char === '\n' || char === '\r') && !quoted) {
                if (char === '\r' && next === '\n') i++;
                row.push(cell.trim());
                if (row.some(Boolean)) rows.push(row);
                row = [];
                cell = '';
            } else {
                cell += char;
            }
        }

        row.push(cell.trim());
        if (row.some(Boolean)) rows.push(row);
        return rows;
    }

    function rowToProgressImport(headers, row) {
        const item = {};
        headers.forEach((header, index) => {
            const value = row[index];
            if (!header || value === undefined || value === '') return;
            if (['cve', 'cve_id', 'id'].includes(header)) item.id = value;
            if (header === 'status') item.status = value;
            if (header === 'note') item.note = value;
            if (header === 'description') item.description = value;
            if (header === 'severity') item.severity = value;
            if (header === 'cvss_score' || header === 'cvss') item.cvss_score = value;
        });
        if (item.id) item.id = String(item.id).trim().toUpperCase();
        return item;
    }

    function rowToCompanyAsset(headers, row) {
        const item = {};
        headers.forEach((header, index) => {
            const value = row[index];
            if (!header || value === undefined || value === '') return;
            if (['name', 'type', 'vendor', 'product', 'version', 'aliases', 'criticality', 'enabled', 'notes'].includes(header)) {
                item[header] = value;
            }
            if (['cpe', 'cpes', 'cpe_uri', 'cpe_uris'].includes(header)) item.cpe_uris = value;
            if (['packages', 'package', 'package_name'].includes(header)) item.packages = value;
            if (['package_ecosystem', 'ecosystem'].includes(header)) item.package_ecosystem = value;
            if (['package_version_range', 'vulnerable_version_range'].includes(header)) item.package_version_range = value;
        });
        return item;
    }

    function normalizeHeader(value) {
        return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
    }

    global.CtiDashboardUtils = {
        escapeCsvCell,
        buildCsv,
        parseProgressImportText,
        parseProgressImportCsv,
        parseCompanyAssetCsv
    };
})(globalThis);

