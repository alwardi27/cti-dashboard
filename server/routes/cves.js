import { Router } from 'express';
import {
    addCveProgressNote,
    getCveById,
    getCveProgressDetail,
    getCveProgressItems,
    getCves,
    setCveProgressStatus
} from '../db/database.js';
import { fetchNvdById } from '../services/nvd.js';
import { sendError } from '../utils/http.js';
import { parseCveFilters, parseProgressFilters } from '../utils/validation.js';

const router = Router();

router.get('/', async (req, res) => {
    try {
        const cves = getCves(parseCveFilters(req.query));
        res.json({
            success: true,
            count: cves.length,
            data: cves
        });
    } catch (error) {
        console.error('[API /cves] Error:', error.message);
        sendError(res, error);
    }
});

router.get('/progress', async (req, res) => {
    try {
        const progressItems = getCveProgressItems(parseProgressFilters(req.query));

        res.json({
            success: true,
            count: progressItems.length,
            data: progressItems
        });
    } catch (error) {
        console.error('[API /cves/progress] Error:', error.message);
        sendError(res, error);
    }
});

router.get('/:id/progress', async (req, res) => {
    try {
        const { id } = req.params;
        const progress = getCveProgressDetail(id.toUpperCase());

        if (!progress) {
            return res.status(404).json({ success: false, error: 'CVE not found' });
        }

        res.json({
            success: true,
            data: progress
        });
    } catch (error) {
        console.error('[API /cves/:id/progress] Error:', error.message);
        sendError(res, error);
    }
});

router.patch('/:id/progress', async (req, res) => {
    try {
        const { id } = req.params;
        const progress = setCveProgressStatus(id.toUpperCase(), req.body?.status || null);

        res.json({
            success: true,
            data: progress
        });
    } catch (error) {
        console.error('[API /cves/:id/progress PATCH] Error:', error.message);
        sendError(res, error);
    }
});

router.post('/:id/progress/notes', async (req, res) => {
    try {
        const { id } = req.params;
        const progress = addCveProgressNote(id.toUpperCase(), req.body?.note);

        res.status(201).json({
            success: true,
            data: progress
        });
    } catch (error) {
        console.error('[API /cves/:id/progress/notes] Error:', error.message);
        sendError(res, error);
    }
});

router.get('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const normalizedId = id.toUpperCase();

        const localCve = getCveById(normalizedId);
        if (localCve) {
            return res.json({
                success: true,
                data: localCve,
                source: 'local'
            });
        }

        const cve = await fetchNvdById(normalizedId);
        if (cve) {
            return res.json({
                success: true,
                data: cve,
                source: 'nvd'
            });
        }

        res.status(404).json({ success: false, error: 'CVE not found' });
    } catch (error) {
        console.error('[API /cves/:id] Error:', error.message);
        sendError(res, error);
    }
});

export default router;
