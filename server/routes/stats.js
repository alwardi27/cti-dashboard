import { Router } from 'express';
import { getLastRefreshSummary, getStats, getDb, searchAll } from '../db/database.js';
import { fetchAllFeeds, getManualRefreshStatus, runWithRefreshLock, startManualRefresh } from '../workers/scheduler.js';
import { getFeedConfig } from '../config/env.js';
import { sendError } from '../utils/http.js';
import { validateRefreshOverrides } from '../utils/validation.js';

export default function createStatsRouter(options = {}) {
    const router = Router();
    const refreshFeeds = options.refreshFeeds || fetchAllFeeds;

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
            sendError(res, error);
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
                if (feed?.source !== 'urlhaus_hosts') {
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
            sendError(res, error);
        }
    });

    router.post('/feeds/refresh', async (req, res) => {
        try {
            const overrides = validateRefreshOverrides(req.body || {});
            if (refreshFeeds === fetchAllFeeds) {
                const status = startManualRefresh(getFeedConfig(overrides));
                return res.status(202).json({
                    success: true,
                    data: status
                });
            }

            const results = await runWithRefreshLock(() => refreshFeeds(getFeedConfig(overrides)));
            res.json({
                success: true,
                data: results
            });
        } catch (error) {
            console.error('[API /stats/feeds/refresh] Error:', error.message);
            sendError(res, error);
        }
    });

    router.get('/feeds/refresh/status', async (req, res) => {
        try {
            res.json({
                success: true,
                data: await getManualRefreshStatus()
            });
        } catch (error) {
            console.error('[API /stats/feeds/refresh/status] Error:', error.message);
            sendError(res, error);
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
            sendError(res, error);
        }
    });

    return router;
}

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
