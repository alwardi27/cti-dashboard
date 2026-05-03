import { Router } from 'express';
import {
    createCompanyAsset,
    deleteCompanyAsset,
    getCompanyAssetById,
    getCompanyAssets,
    importCompanyAssets,
    recalculateCompanyAssetMatches,
    updateCompanyAsset
} from '../db/database.js';
import { parseCompanyAssetCsv } from '../services/companyAssets.js';
import { httpError, sendError } from '../utils/http.js';
import { parseSearch } from '../utils/validation.js';

const router = Router();

router.get('/', async (req, res) => {
    try {
        const assets = getCompanyAssets(parseAssetFilters(req.query));
        res.json({
            success: true,
            count: assets.length,
            data: assets
        });
    } catch (error) {
        console.error('[API /company-assets] Error:', error.message);
        sendError(res, error);
    }
});

router.post('/', async (req, res) => {
    try {
        const asset = createCompanyAsset(req.body || {});
        res.status(201).json({
            success: true,
            data: asset
        });
    } catch (error) {
        console.error('[API /company-assets POST] Error:', error.message);
        sendError(res, error);
    }
});

router.post('/import', async (req, res) => {
    try {
        const items = normalizeImportPayload(req.body || {});
        const result = importCompanyAssets(items);
        res.json({
            success: true,
            data: result
        });
    } catch (error) {
        console.error('[API /company-assets/import] Error:', error.message);
        sendError(res, error);
    }
});

router.post('/recalculate', async (req, res) => {
    try {
        const recalculation = recalculateCompanyAssetMatches({
            assetId: req.body?.assetId ?? req.query?.assetId
        });
        res.json({
            success: true,
            data: recalculation
        });
    } catch (error) {
        console.error('[API /company-assets/recalculate] Error:', error.message);
        sendError(res, error);
    }
});

router.get('/:id', async (req, res) => {
    try {
        const asset = getCompanyAssetById(req.params.id);
        if (!asset) {
            return res.status(404).json({ success: false, error: 'Asset not found' });
        }
        res.json({
            success: true,
            data: asset
        });
    } catch (error) {
        console.error('[API /company-assets/:id] Error:', error.message);
        sendError(res, error);
    }
});

router.patch('/:id', async (req, res) => {
    try {
        const asset = updateCompanyAsset(req.params.id, req.body || {});
        res.json({
            success: true,
            data: asset
        });
    } catch (error) {
        console.error('[API /company-assets/:id PATCH] Error:', error.message);
        sendError(res, error);
    }
});

router.delete('/:id', async (req, res) => {
    try {
        const result = deleteCompanyAsset(req.params.id);
        res.json({
            success: true,
            data: result
        });
    } catch (error) {
        console.error('[API /company-assets/:id DELETE] Error:', error.message);
        sendError(res, error);
    }
});

function parseAssetFilters(query = {}) {
    return {
        search: parseSearch(query.search),
        enabled: parseOptionalBoolean(query.enabled),
        limit: parseInteger(query.limit, 'limit', { min: 1, max: 500 }),
        offset: parseInteger(query.offset, 'offset', { min: 0, max: 100000 })
    };
}

function normalizeImportPayload(body) {
    if (Array.isArray(body.items)) return body.items;
    if (typeof body.csv === 'string') return parseCompanyAssetCsv(body.csv);
    throw httpError('Import requires items or csv');
}

function parseOptionalBoolean(value) {
    if (value === undefined || value === null || value === '') return undefined;
    const normalized = String(value).trim().toLowerCase();
    if (['true', '1', 'yes', 'enabled'].includes(normalized)) return true;
    if (['false', '0', 'no', 'disabled'].includes(normalized)) return false;
    throw httpError('enabled must be a boolean value');
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

export default router;
