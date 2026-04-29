import { Router } from 'express';
import { getStats, getDb } from '../db/database.js';
import { searchAll } from '../db/database.js';
import { fetchAllFeeds } from '../workers/scheduler.js';
import { getFeedConfig } from '../config/env.js';

const router = Router();

router.get('/', async (req, res) => {
    try {
        const stats = getStats();
        res.json({
            success: true,
            data: stats
        });
    } catch (error) {
        console.error('[API /stats] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/feeds', async (req, res) => {
    try {
        const db = getDb();
        const stmt = db.prepare('SELECT * FROM feed_status ORDER BY source');
        const feeds = [];
        while (stmt.step()) {
            const feed = stmt.getAsObject();
            if (!shouldHideFeedStatus(feed)) {
                feeds.push(feed);
            }
        }
        stmt.free();

        res.json({
            success: true,
            data: feeds
        });
    } catch (error) {
        console.error('[API /stats/feeds] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/feeds/refresh', async (req, res) => {
    try {
        const results = await fetchAllFeeds(getFeedConfig(req.body || {}));
        res.json({
            success: true,
            data: results
        });
    } catch (error) {
        console.error('[API /stats/feeds/refresh] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.length < 2) {
            return res.json({ success: true, data: [] });
        }
        const results = searchAll(q);
        res.json({
            success: true,
            count: results.length,
            data: results
        });
    } catch (error) {
        console.error('[API /stats/search] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

export default router;

function shouldHideFeedStatus(feed) {
    if (feed?.source === 'urlhaus_hosts') return true;
    if (feed?.status !== 'skipped') return false;

    const message = String(feed.error_message || '').toLowerCase();
    return message.includes('not configured') || message.includes('is required');
}
