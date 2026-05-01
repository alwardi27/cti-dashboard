import { httpError } from './http.js';

const CVE_SOURCES = ['nvd', 'github', 'cisa_kev', 'vulncheck', 'shodan', 'censys', 'virustotal', 'greynoise', 'otx', 'osv', 'manual'];
const IOC_TYPES = ['ip', 'domain', 'url', 'hash'];
const IOC_SOURCES = ['urlhaus', 'threatfox', 'malwarebazaar', 'virustotal', 'greynoise', 'shodan', 'censys', 'abuseipdb', 'otx', 'feodo', 'sslbl'];
const SEARCH_TYPES = ['cve', 'ioc'];
const PROGRESS_STATUSES = ['open', 'assigned', 'closed'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SORTS = ['published', 'cvss', 'triage'];
const REFRESH_OVERRIDE_KEYS = new Set([
    'nvdApiKey',
    'githubToken',
    'vulncheckApiToken',
    'threatfoxAuthKey',
    'urlhausAuthKey',
    'malwarebazaarAuthKey',
    'virustotalApiKey',
    'greynoiseApiKey',
    'shodanApiKey',
    'censysApiId',
    'censysApiSecret',
    'abuseipdbApiKey',
    'otxApiKey',
    'whatsapp',
    'teams',
    'enabled',
    'provider',
    'minSeverity',
    'twilioAccountSid',
    'twilioAuthToken',
    'twilioFrom',
    'to',
    'feodoEnabled',
    'sslblEnabled',
    'epssEnabled',
    'osvEnabled'
]);
const WHATSAPP_OVERRIDE_KEYS = new Set([
    'enabled',
    'provider',
    'minSeverity',
    'twilioAccountSid',
    'twilioAuthToken',
    'twilioFrom',
    'to'
]);
const TEAMS_OVERRIDE_KEYS = new Set([
    'enabled',
    'webhookUrl'
]);

export function parseCveFilters(query = {}) {
    return {
        source: parseEnum(query.source, CVE_SOURCES, 'source', { optional: true }),
        severity: parseSeverityList(query.severity),
        search: parseSearch(query.search),
        fromDate: parseIsoDate(query.fromDate, 'fromDate'),
        progressStatus: parseProgressStatus(query.progressStatus, { optional: true, allowNone: true }),
        needsReview: parseBooleanFlag(query.needsReview, 'needsReview'),
        sort: parseEnum(query.sort, SORTS, 'sort', { optional: true }) || null,
        ...parsePaging(query)
    };
}

export function parseProgressFilters(query = {}) {
    return {
        status: parseProgressStatus(query.status, { optional: true }),
        search: parseSearch(query.search),
        ...parsePaging(query)
    };
}

export function parseIocFilters(query = {}) {
    return {
        type: parseEnum(query.type, IOC_TYPES, 'type', { optional: true }),
        source: parseEnum(query.source, IOC_SOURCES, 'source', { optional: true }),
        threatType: parseSearch(query.threatType),
        search: parseSearch(query.search),
        fromDate: parseIsoDate(query.fromDate, 'fromDate'),
        ...parsePaging(query)
    };
}

export function parseSearchFilters(query = {}) {
    return {
        q: parseSearch(query.q),
        type: parseEnum(query.type, SEARCH_TYPES, 'type', { optional: true }),
        source: parseSearch(query.source),
        ...parsePaging(query)
    };
}

export function validateRefreshOverrides(body = {}) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        throw httpError('Refresh overrides must be a JSON object');
    }

    for (const key of Object.keys(body)) {
        if (!REFRESH_OVERRIDE_KEYS.has(key)) {
            throw httpError(`Unsupported refresh override: ${key}`);
        }
    }

    if (body.whatsapp !== undefined) {
        if (!body.whatsapp || typeof body.whatsapp !== 'object' || Array.isArray(body.whatsapp)) {
            throw httpError('whatsapp override must be a JSON object');
        }
        for (const key of Object.keys(body.whatsapp)) {
            if (!WHATSAPP_OVERRIDE_KEYS.has(key)) {
                throw httpError(`Unsupported WhatsApp override: ${key}`);
            }
        }
    }

    if (body.teams !== undefined) {
        if (!body.teams || typeof body.teams !== 'object' || Array.isArray(body.teams)) {
            throw httpError('teams override must be a JSON object');
        }
        for (const key of Object.keys(body.teams)) {
            if (!TEAMS_OVERRIDE_KEYS.has(key)) {
                throw httpError(`Unsupported Teams override: ${key}`);
            }
        }
    }

    return body;
}

export function parseSearch(value) {
    if (value === undefined || value === null || value === '') return null;
    const search = String(value).trim();
    if (!search) return null;
    if (search.length > 200) throw httpError('Search must be 200 characters or fewer');
    return search;
}

function parsePaging(query) {
    return {
        limit: parseInteger(query.limit, 'limit', { min: 1, max: 500, optional: true }),
        offset: parseInteger(query.offset, 'offset', { min: 0, max: 100000, optional: true })
    };
}

function parseInteger(value, name, options = {}) {
    if (value === undefined || value === null || value === '') return undefined;
    if (!/^\d+$/.test(String(value))) {
        throw httpError(`${name} must be an integer`);
    }

    const parsed = Number.parseInt(value, 10);
    if (parsed < options.min || parsed > options.max) {
        throw httpError(`${name} must be between ${options.min} and ${options.max}`);
    }
    return parsed;
}

function parseEnum(value, allowed, name, options = {}) {
    if (value === undefined || value === null || value === '') return null;
    const normalized = String(value).trim().toLowerCase();
    if (options.allowNone && normalized === 'none') return 'none';
    if (!allowed.includes(normalized)) {
        throw httpError(`${name} must be one of: ${allowed.join(', ')}`);
    }
    return normalized;
}

function parseProgressStatus(value, options = {}) {
    return parseEnum(value, PROGRESS_STATUSES, 'progressStatus', options);
}

function parseSeverityList(value) {
    if (value === undefined || value === null || value === '') return null;

    const severities = String(value)
        .split(',')
        .map(item => item.trim().toLowerCase())
        .filter(Boolean);

    if (severities.length === 0) return null;
    const invalid = severities.filter(severity => !SEVERITIES.includes(severity));
    if (invalid.length) {
        throw httpError(`severity must contain only: ${SEVERITIES.join(', ')}`, 400, { invalid });
    }

    return [...new Set(severities)].join(',');
}

function parseIsoDate(value, name) {
    if (value === undefined || value === null || value === '') return null;
    const date = new Date(String(value));
    if (Number.isNaN(date.getTime())) {
        throw httpError(`${name} must be a valid date`);
    }
    return date.toISOString();
}

function parseBooleanFlag(value, name) {
    if (value === undefined || value === null || value === '') return false;
    const normalized = String(value).trim().toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'off'].includes(normalized)) return false;
    throw httpError(`${name} must be a boolean`);
}
