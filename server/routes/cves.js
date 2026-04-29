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

const router = Router();

router.get('/', async (req, res) => {
    try {
        const { source, severity, search, fromDate, limit, offset } = req.query;

        const filters = {
            source: source || null,
            severity: severity || null,
            search: search || null,
            fromDate: fromDate || null,
            limit,
            offset
        };

        const cves = getCves(filters);
        res.json({
            success: true,
            count: cves.length,
            data: cves
        });
    } catch (error) {
        console.error('[API /cves] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/progress', async (req, res) => {
    try {
        const { status, search, limit, offset } = req.query;
        const progressItems = getCveProgressItems({
            status: status || null,
            search: search || null,
            limit,
            offset
        });

        res.json({
            success: true,
            count: progressItems.length,
            data: progressItems
        });
    } catch (error) {
        console.error('[API /cves/progress] Error:', error.message);
        res.status(error.statusCode || 500).json({ success: false, error: error.message });
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
        res.status(error.statusCode || 500).json({ success: false, error: error.message });
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
        res.status(error.statusCode || 500).json({ success: false, error: error.message });
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
        res.status(error.statusCode || 500).json({ success: false, error: error.message });
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
        res.status(500).json({ success: false, error: error.message });
    }
});

export default router;
