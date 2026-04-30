import { insertIoc, updateFeedStatus } from '../db/database.js';
import { parseCsvRows } from '../utils/csv.js';
import { feedGet } from '../utils/feedHttp.js';

const FEODO_IP_BLOCKLIST_CSV = 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv';

export async function fetchFeodoTracker(url = FEODO_IP_BLOCKLIST_CSV) {
    if (!isEnabled('FEODO_ENABLED')) return skipFeed('feodo', 'Skipped: FEODO_ENABLED is false');

    try {
        const response = await feedGet(url, {
            timeout: Number.parseInt(process.env.FEODO_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.FEODO_RETRIES || '3', 10) });
        const indicators = parseFeodoCsv(response.data);
        let count = 0;

        for (const indicator of indicators) {
            insertIoc({
                type: 'ip',
                value: indicator.ip,
                source: 'feodo',
                threat_type: 'botnet_c2',
                confidence: indicator.status === 'online' ? 85 : 70,
                first_seen: indicator.first_seen,
                last_seen: indicator.last_online || indicator.first_seen,
                metadata: JSON.stringify({
                    port: indicator.port,
                    status: indicator.status,
                    malware: indicator.malware
                }),
                search_text: [indicator.port, indicator.status, indicator.malware].join(' ')
            });
            count++;
        }

        await updateFeedStatus('feodo', 'success', count);
        console.log(`[Feodo] Fetched ${count} botnet C2 IPs`);
        return count;
    } catch (error) {
        const message = error.message;
        await updateFeedStatus('feodo', 'error', 0, message);
        console.error(`[Feodo] Error: ${message}`);
        throw error;
    }
}

export function parseFeodoCsv(csv) {
    return parseCsvRows(csv)
        .map(row => ({
            first_seen: row[0] || null,
            ip: row[1],
            port: row[2] || null,
            status: String(row[3] || '').toLowerCase() || null,
            last_online: row[4] || null,
            malware: row[5] || 'botnet'
        }))
        .filter(row => isIp(row.ip));
}

function isIp(value) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(String(value || ''));
}

function isEnabled(name) {
    return !['0', 'false', 'no', 'off'].includes(String(process.env[name] ?? 'true').trim().toLowerCase());
}

async function skipFeed(source, message) {
    await updateFeedStatus(source, 'skipped', 0, message);
    console.log(`[${source}] ${message}`);
    return 0;
}

export default { fetchFeodoTracker, parseFeodoCsv };
