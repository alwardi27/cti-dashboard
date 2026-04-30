import { Router } from 'express';
import { searchDocuments } from '../db/database.js';
import { sendError } from '../utils/http.js';
import { parseSearchFilters } from '../utils/validation.js';

const router = Router();

router.get('/', async (req, res) => {
    try {
        const results = searchDocuments(parseSearchFilters(req.query));
        res.json({
            success: true,
            count: results.length,
            data: results
        });
    } catch (error) {
        console.error('[API /search] Error:', error.message);
        sendError(res, error);
    }
});

export default router;

