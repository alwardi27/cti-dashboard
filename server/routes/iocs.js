import { Router } from 'express';
import { getIocById, getIocs } from '../db/database.js';
import { sendError } from '../utils/http.js';
import { parseIocFilters } from '../utils/validation.js';

const router = Router();

router.get('/', async (req, res) => {
    try {
        const iocs = getIocs(parseIocFilters(req.query));
        res.json({
            success: true,
            count: iocs.length,
            data: iocs
        });
    } catch (error) {
        console.error('[API /iocs] Error:', error.message);
        sendError(res, error);
    }
});

router.get('/:id', async (req, res) => {
    try {
        const ioc = getIocById(req.params.id);
        if (!ioc) {
            return res.status(404).json({ success: false, error: 'IOC not found' });
        }
        res.json({
            success: true,
            data: ioc
        });
    } catch (error) {
        console.error('[API /iocs/:id] Error:', error.message);
        sendError(res, error);
    }
});

export default router;
