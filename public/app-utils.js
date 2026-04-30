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

    global.CtiDashboardUtils = {
        escapeCsvCell,
        buildCsv
    };
})(globalThis);

