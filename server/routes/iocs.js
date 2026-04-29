import { Router } from 'express';
import { getIocs } from '../db/database.js';

const router = Router();

router.get('/', async (req, res) => {
    try {
        const { type, source, threatType, search, fromDate, limit, offset } = req.query;

        const filters = {
            type: type || null,
            source: source || null,
            threatType: threatType || null,
            search: search || null,
            fromDate: fromDate || null,
            limit,
            offset
        };

        const iocs = getIocs(filters);
        res.json({
            success: true,
            count: iocs.length,
            data: iocs
        });
    } catch (error) {
        console.error('[API /iocs] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

export default router;
