import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { getFeedConfig } from './config/env.js';
import { initializeDb } from './db/database.js';
import { startScheduler, stopScheduler, fetchAllFeeds } from './workers/scheduler.js';
import cvesRouter from './routes/cves.js';
import companyAssetsRouter from './routes/companyAssets.js';
import iocsRouter from './routes/iocs.js';
import searchRouter from './routes/search.js';
import createStatsRouter from './routes/stats.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export function createApp(options = {}) {
    const app = express();

    app.use(cors());
    app.use(express.json());
    app.use(express.static(join(__dirname, '../public')));

    app.use('/api/cves', cvesRouter);
    app.use('/api/company-assets', companyAssetsRouter);
    app.use('/api/iocs', iocsRouter);
    app.use('/api/search', searchRouter);
    app.use('/api/stats', createStatsRouter({
        refreshFeeds: options.refreshFeeds || fetchAllFeeds
    }));

    app.get('/api/health', (req, res) => {
        res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    app.get('*', (req, res) => {
        res.sendFile(join(__dirname, '../public/index.html'));
    });

    return app;
}

export async function startDashboard(options = {}) {
    const port = options.port ?? process.env.PORT ?? 3000;
    const feedConfig = options.feedConfig || getFeedConfig();
    const schedulerEnabled = options.schedulerEnabled ?? process.env.CTI_ENABLE_SCHEDULER === 'true';

    await initializeDb();
    console.log('[DB] Database initialized');

    if (schedulerEnabled) {
        startScheduler(feedConfig);
    } else {
        console.log('[Scheduler] Automatic feed refresh disabled; manual refresh only');
    }

    const app = createApp(options);
    const server = app.listen(port, () => {
        const address = server.address();
        const actualPort = typeof address === 'object' && address ? address.port : port;
        console.log(`[Server] CTI Dashboard running at http://localhost:${actualPort}`);
    });

    server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
            console.error(`[Server] Port ${port} is already in use. Stop the existing dashboard process or set PORT to another value.`);
        } else {
            console.error('[Server] Startup error:', error.message);
        }
        process.exit(1);
    });

    function shutdown(signal) {
        console.log(`[Server] ${signal} received, shutting down...`);
        stopScheduler();
        server.close(() => {
            console.log('[Server] Shutdown complete');
            process.exit(0);
        });
    }

    if (options.installSignalHandlers !== false) {
        process.on('SIGINT', () => shutdown('SIGINT'));
        process.on('SIGTERM', () => shutdown('SIGTERM'));
    }

    return { app, server, shutdown };
}
