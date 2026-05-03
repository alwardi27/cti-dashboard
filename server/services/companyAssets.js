const ASSET_TYPES = ['service', 'application'];
const CRITICALITIES = ['low', 'medium', 'high'];
const GENERIC_TERMS = new Set([
    'app',
    'api',
    'web',
    'site',
    'service',
    'server',
    'system',
    'platform',
    'portal',
    'application',
    'internal',
    'customer',
    'corporate'
]);

export function normalizeCompanyAssetInput(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throwValidationError('Asset must be an object');
    }

    const name = normalizeRequiredText(input.name, 'name', 160);
    const type = normalizeEnum(input.type, ASSET_TYPES, 'type', 'application');
    const criticality = normalizeEnum(input.criticality, CRITICALITIES, 'criticality', 'medium');
    const packageDefaults = {
        ecosystem: normalizeOptionalText(input.package_ecosystem ?? input.ecosystem, 80),
        vulnerable_version_range: normalizeOptionalText(input.package_version_range ?? input.vulnerable_version_range, 160)
    };

    return {
        name,
        type,
        vendor: normalizeOptionalText(input.vendor, 120),
        product: normalizeOptionalText(input.product, 160),
        version: normalizeOptionalText(input.version, 120),
        aliases: normalizeTextList(input.aliases),
        cpe_uris: normalizeTextList(input.cpe_uris ?? input.cpe ?? input.cpes),
        packages: normalizePackages(input.packages ?? input.package ?? input.package_name, packageDefaults),
        criticality,
        enabled: normalizeBoolean(input.enabled, true),
        notes: normalizeOptionalText(input.notes, 2000)
    };
}

export function parseCompanyAssetCsv(text) {
    const rows = parseCsvRows(text);
    if (rows.length < 2) return [];

    const headers = rows[0].map(normalizeHeader);
    return rows.slice(1)
        .map((row, index) => rowToCompanyAsset(headers, row, index))
        .filter(item => item.name);
}

export function matchAssetToCve(asset, cve, metadata = {}) {
    const normalizedAsset = normalizeCompanyAssetInput(asset);
    const normalizedMetadata = normalizeMetadata(metadata);

    const cpeMatch = matchByCpe(normalizedAsset, normalizedMetadata);
    if (cpeMatch) return buildMatch(normalizedAsset, cve, cpeMatch);

    const packageMatch = matchByPackage(normalizedAsset, normalizedMetadata);
    if (packageMatch) return buildMatch(normalizedAsset, cve, packageMatch);

    const textMatch = matchByText(normalizedAsset, cve);
    if (textMatch) return buildMatch(normalizedAsset, cve, textMatch);

    return null;
}

function matchByCpe(asset, metadata) {
    if (!asset.cpe_uris.length || !metadata.vulnerable_cpes.length) return null;

    const assetCpes = asset.cpe_uris.map(parseCpe).filter(Boolean);
    const vulnerableCpes = metadata.vulnerable_cpes.map(parseCpe).filter(Boolean);

    for (const assetCpe of assetCpes) {
        for (const vulnerableCpe of vulnerableCpes) {
            if (assetCpe.raw === vulnerableCpe.raw) {
                return {
                    match_type: 'cpe_exact',
                    matched_value: vulnerableCpe.original,
                    match_reason: `CPE ${assetCpe.original} is listed as vulnerable`,
                    confidence: 0.98,
                    baseScore: 95
                };
            }

            if (assetCpe.vendor === vulnerableCpe.vendor &&
                assetCpe.product === vulnerableCpe.product &&
                versionsCompatible(assetCpe.version, vulnerableCpe.version)) {
                return {
                    match_type: 'cpe_product',
                    matched_value: vulnerableCpe.original,
                    match_reason: `CPE vendor/product ${assetCpe.vendor}:${assetCpe.product} matched vulnerable metadata`,
                    confidence: 0.9,
                    baseScore: 88
                };
            }
        }
    }

    return null;
}

function matchByPackage(asset, metadata) {
    if (!asset.packages.length || !metadata.packages.length) return null;

    for (const assetPackage of asset.packages) {
        for (const vulnerablePackage of metadata.packages) {
            if (normalizePackageName(assetPackage.name) !== normalizePackageName(vulnerablePackage.name)) continue;
            if (normalizeToken(assetPackage.ecosystem || '') !== normalizeToken(vulnerablePackage.ecosystem || '')) continue;

            const versionRange = vulnerablePackage.vulnerable_version_range || assetPackage.vulnerable_version_range;
            return {
                match_type: 'package_exact',
                matched_value: `${assetPackage.ecosystem}:${assetPackage.name}`,
                match_reason: versionRange
                    ? `Package ${assetPackage.ecosystem}:${assetPackage.name} matched vulnerable range ${versionRange}`
                    : `Package ${assetPackage.ecosystem}:${assetPackage.name} matched vulnerability metadata`,
                confidence: 0.94,
                baseScore: 92
            };
        }
    }

    return null;
}

function matchByText(asset, cve) {
    const text = searchableText(cve);
    if (!text) return null;

    const vendor = meaningfulPhrase(asset.vendor);
    const product = meaningfulPhrase(asset.product);
    if (vendor && product && containsPhrase(text, vendor) && containsPhrase(text, product)) {
        return {
            match_type: 'vendor_product',
            matched_value: `${asset.vendor} ${asset.product}`,
            match_reason: `CVE text mentions vendor ${asset.vendor} and product ${asset.product}`,
            confidence: 0.78,
            baseScore: 72
        };
    }

    const candidates = [
        { source: 'product', value: asset.product },
        { source: 'name', value: asset.name },
        ...asset.aliases.map(value => ({ source: 'alias', value }))
    ];

    for (const candidate of candidates) {
        const phrase = meaningfulPhrase(candidate.value);
        if (!phrase || !containsPhrase(text, phrase)) continue;
        return {
            match_type: `${candidate.source}_text`,
            matched_value: candidate.value,
            match_reason: `CVE text mentions ${candidate.source} ${candidate.value}`,
            confidence: 0.62,
            baseScore: 55
        };
    }

    return null;
}

function buildMatch(asset, cve, match) {
    return {
        match_type: match.match_type,
        match_reason: match.match_reason,
        matched_value: match.matched_value || null,
        confidence: match.confidence,
        score: scoreMatch(match.baseScore, asset.criticality, cve)
    };
}

function scoreMatch(baseScore, criticality, cve) {
    const criticalityBoost = { high: 12, medium: 6, low: 0 }[criticality] || 0;
    const severityBoost = { critical: 5, high: 3, medium: 1, low: 0 }[String(cve?.severity || '').toLowerCase()] || 0;
    return Math.min(100, baseScore + criticalityBoost + severityBoost);
}

function normalizeMetadata(metadata = {}) {
    return {
        vulnerable_cpes: normalizeTextList(metadata.vulnerable_cpes ?? metadata.cpes ?? metadata.cpe_uris),
        packages: normalizePackages(metadata.packages)
    };
}

function normalizePackages(value, defaults = {}) {
    const values = normalizeArrayValue(value);
    const packages = [];

    for (const item of values) {
        if (!item && item !== 0) continue;

        if (typeof item === 'object' && !Array.isArray(item)) {
            const name = normalizeOptionalText(item.name ?? item.package ?? item.package_name, 200);
            if (!name) continue;
            packages.push({
                name,
                ecosystem: normalizeOptionalText(item.ecosystem ?? item.package_ecosystem ?? defaults.ecosystem, 80) || 'unknown',
                vulnerable_version_range: normalizeOptionalText(item.vulnerable_version_range ?? item.package_version_range ?? defaults.vulnerable_version_range, 160)
            });
            continue;
        }

        const parsed = parsePackageString(String(item), defaults);
        if (parsed) packages.push(parsed);
    }

    return dedupeObjects(packages, item => `${normalizeToken(item.ecosystem)}:${normalizePackageName(item.name)}:${item.vulnerable_version_range || ''}`);
}

function parsePackageString(value, defaults = {}) {
    const text = String(value || '').trim();
    if (!text) return null;

    let ecosystem = defaults.ecosystem || null;
    let name = text;
    let vulnerableRange = defaults.vulnerable_version_range || null;
    const parts = text.split(':').map(part => part.trim()).filter(Boolean);

    if (parts.length >= 2) {
        ecosystem = parts[0];
        name = parts[1];
        if (parts.length >= 3) vulnerableRange = parts.slice(2).join(':');
    }

    if (!name) return null;
    return {
        name,
        ecosystem: ecosystem || 'unknown',
        vulnerable_version_range: vulnerableRange
    };
}

function normalizeTextList(value) {
    return dedupeStrings(normalizeArrayValue(value)
        .flatMap(item => String(item || '').split(/[;\n]/))
        .map(item => item.trim())
        .filter(Boolean));
}

function normalizeArrayValue(value) {
    if (value === undefined || value === null || value === '') return [];
    if (Array.isArray(value)) return value;
    return String(value).split(',').map(item => item.trim()).filter(Boolean);
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

function rowToCompanyAsset(headers, row, index) {
    const item = { index };
    headers.forEach((header, headerIndex) => {
        const value = row[headerIndex];
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

function normalizeRequiredText(value, field, maxLength) {
    const text = normalizeOptionalText(value, maxLength);
    if (!text) throwValidationError(`${field} is required`);
    return text;
}

function normalizeOptionalText(value, maxLength) {
    if (value === undefined || value === null) return null;
    const text = String(value).trim();
    if (!text) return null;
    if (text.length > maxLength) throwValidationError(`${maxLength}-character limit exceeded`);
    return text;
}

function normalizeEnum(value, allowed, field, fallback) {
    if (value === undefined || value === null || String(value).trim() === '') return fallback;
    const normalized = String(value).trim().toLowerCase();
    if (!allowed.includes(normalized)) {
        throwValidationError(`${field} must be one of: ${allowed.join(', ')}`);
    }
    return normalized;
}

function normalizeBoolean(value, fallback = true) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value !== 0;
    const normalized = String(value).trim().toLowerCase();
    if (['true', '1', 'yes', 'y', 'enabled', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'n', 'disabled', 'off'].includes(normalized)) return false;
    throwValidationError('enabled must be a boolean value');
}

function parseCpe(value) {
    const original = String(value || '').trim();
    if (!original) return null;
    const parts = original.split(':');
    if (parts.length < 5 || parts[0].toLowerCase() !== 'cpe') return null;
    return {
        original,
        raw: original.toLowerCase(),
        vendor: normalizeCpePart(parts[3]),
        product: normalizeCpePart(parts[4]),
        version: normalizeCpePart(parts[5] || '*')
    };
}

function versionsCompatible(assetVersion, vulnerableVersion) {
    return assetVersion === '*' ||
        assetVersion === '-' ||
        vulnerableVersion === '*' ||
        vulnerableVersion === '-' ||
        assetVersion === vulnerableVersion;
}

function searchableText(cve) {
    return normalizeSearchText([
        cve?.id,
        cve?.description,
        cve?.title,
        cve?.summary
    ].filter(Boolean).join(' '));
}

function containsPhrase(text, phrase) {
    const normalized = normalizeSearchText(phrase);
    if (!normalized) return false;
    const escaped = normalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(^|\\W)${escaped}(\\W|$)`, 'i').test(text);
}

function meaningfulPhrase(value) {
    const phrase = String(value || '').trim();
    if (!phrase) return null;
    const words = tokenize(phrase);
    const meaningful = words.filter(word => !GENERIC_TERMS.has(word));
    if (!meaningful.length) return null;
    if (meaningful.join('').length < 4) return null;
    return phrase;
}

function normalizeSearchText(value) {
    return String(value || '').toLowerCase().replace(/[_:-]+/g, ' ').replace(/\s+/g, ' ').trim();
}

function tokenize(value) {
    return normalizeSearchText(value).split(/\W+/).filter(Boolean);
}

function normalizeCpePart(value) {
    return String(value || '').trim().toLowerCase().replace(/\\:/g, ':');
}

function normalizeToken(value) {
    return String(value || '').trim().toLowerCase();
}

function normalizePackageName(value) {
    return normalizeToken(value).replace(/^@/, '');
}

function dedupeStrings(values) {
    const seen = new Set();
    const result = [];
    for (const value of values) {
        const key = value.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        result.push(value);
    }
    return result;
}

function dedupeObjects(values, keyFor) {
    const seen = new Set();
    const result = [];
    for (const value of values) {
        const key = keyFor(value);
        if (seen.has(key)) continue;
        seen.add(key);
        result.push(value);
    }
    return result;
}

function throwValidationError(message) {
    const error = new Error(message);
    error.statusCode = 400;
    throw error;
}

export default {
    matchAssetToCve,
    normalizeCompanyAssetInput,
    parseCompanyAssetCsv
};
