import { Router } from 'express';
import { getLastRefreshSummary, getStats, getDb } from '../db/database.js';
import { searchAll } from '../db/database.js';
import { fetchAllFeeds } from '../workers/scheduler.js';
import { getFeedConfig } from '../config/env.js';

const router = Router();

router.get('/', async (req, res) => {
    try {
        const stats = getStats();
        stats.lastRefresh = getLastRefreshSummary();
        stats.latestFeedAt = getLatestFeedTimestamp();
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
        const stmt = db.prepare(`
            SELECT *
            FROM feed_status
            ORDER BY
                CASE status
                    WHEN 'error' THEN 0
                    WHEN 'pending' THEN 1
                    WHEN 'skipped' THEN 2
                    WHEN 'success' THEN 3
                    ELSE 4
                END,
                source
        `);
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

function getLatestFeedTimestamp() {
    const db = getDb();
    const stmt = db.prepare(`
        SELECT MAX(updated_at) AS latest
        FROM feed_status
        WHERE status != 'skipped'
    `);
    const latest = stmt.step() ? stmt.getAsObject().latest : null;
    stmt.free();
    return latest;
}

function shouldHideFeedStatus(feed) {
    if (feed?.source === 'urlhaus_hosts') return true;
    if (feed?.status !== 'skipped') return false;

    const message = String(feed.error_message || '').toLowerCase();
    return message.includes('not configured') || message.includes('is required');
}
