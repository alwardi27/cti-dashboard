import { Router } from 'express';
import {
    addCveProgressNote,
    getCveById,
    getCveProgressDetail,
    getCveProgressItems,
    getCves,
    setCveProgressStatus
} from '../db/database.js';
import { getTeamsConfig } from '../config/env.js';
import { importCveProgressItems } from '../services/cveImport.js';
import { fetchNvdById } from '../services/nvd.js';
import { notifyTeamsProgress } from '../services/teams.js';
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

router.post('/progress/import', async (req, res) => {
    try {
        const result = await importCveProgressItems(req.body?.items);
        const teams = await notifyTeamsProgress('import_summary', result, getTeamsConfig());

        res.json({
            success: true,
            data: result,
            notifications: { teams }
        });
    } catch (error) {
        console.error('[API /cves/progress/import] Error:', error.message);
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
        const teams = await notifyTeamsProgress('status_changed', {
            cve: progress,
            status: progress.progress_status
        }, getTeamsConfig());

        res.json({
            success: true,
            data: progress,
            notifications: { teams }
        });
    } catch (error) {
        console.error('[API /cves/:id/progress PATCH] Error:', error.message);
        sendError(res, error);
    }
});

router.post('/:id/progress/notes', async (req, res) => {
    try {
        const { id } = req.params;
        const note = req.body?.note;
        const progress = addCveProgressNote(id.toUpperCase(), req.body?.note);
        const teams = await notifyTeamsProgress('note_added', {
            cve: progress,
            note
        }, getTeamsConfig());

        res.status(201).json({
            success: true,
            data: progress,
            notifications: { teams }
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
