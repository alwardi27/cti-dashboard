import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { getFeedConfig } from './config/env.js';
import { initializeDb } from './db/database.js';
import { startScheduler, stopScheduler } from './workers/scheduler.js';
import cvesRouter from './routes/cves.js';
import iocsRouter from './routes/iocs.js';
import statsRouter from './routes/stats.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(join(__dirname, '../public')));

await initializeDb();
console.log('[DB] Database initialized');

startScheduler(getFeedConfig());

app.use('/api/cves', cvesRouter);
app.use('/api/iocs', iocsRouter);
app.use('/api/stats', statsRouter);

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('*', (req, res) => {
    res.sendFile(join(__dirname, '../public/index.html'));
});

const server = app.listen(PORT, () => {
    console.log(`[Server] CTI Dashboard running at http://localhost:${PORT}`);
});

server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`[Server] Port ${PORT} is already in use. Stop the existing dashboard process or set PORT to another value.`);
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

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
