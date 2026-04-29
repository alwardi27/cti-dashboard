import axios from 'axios';
import { insertIoc, updateFeedStatus } from '../db/database.js';

const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/';

export async function fetchUrlhausUrls(limit = 500, authKey = process.env.URLHAUS_AUTH_KEY || process.env.ABUSECH_AUTH_KEY) {
    if (!authKey) {
        const message = 'Skipped: URLHAUS_AUTH_KEY is required for URLhaus community API access';
        await updateFeedStatus('urlhaus', 'skipped', 0, message);
        throw new Error(message);
    }

    try {
        const boundedLimit = normalizeUrlhausLimit(limit);
        const response = await axios.get(`${URLHAUS_API}urls/recent/limit/${boundedLimit}/`, {
            headers: { 'Auth-Key': authKey },
            timeout: 30000
        });

        const queryStatus = response.data?.query_status;
        if (queryStatus && !['ok', 'no_results'].includes(queryStatus)) {
            throw new Error(`URLhaus query status: ${queryStatus}`);
        }

        const urls = response.data?.urls || [];
        let count = 0;

        for (const url of urls) {
            if (!url.url) continue;

            insertIoc({
                type: 'url',
                value: url.url,
                source: 'urlhaus',
                threat_type: url.threat || 'malware',
                confidence: url.confidence ? parseInt(url.confidence) : 70,
                first_seen: url.date_added,
                last_seen: url.date_updated,
                metadata: JSON.stringify({
                    status: url.url_status,
                    payload: url.payload,
                    tags: url.tags,
                    virus_total: url.virustotal?.result
                })
            });
            count++;

            if (url.host) {
                insertIoc({
                    type: iocTypeForHost(url.host),
                    value: url.host,
                    source: 'urlhaus',
                    threat_type: url.threat || 'malware',
                    confidence: 70,
                    first_seen: url.date_added,
                    last_seen: url.date_added,
                    metadata: JSON.stringify({
                        url_status: url.url_status,
                        tags: url.tags,
                        urlhaus_reference: url.urlhaus_reference
                    })
                });
                count++;
            }
        }

        await updateFeedStatus('urlhaus', 'success', count);
        console.log(`[URLhaus] Fetched ${count} URL and host indicators`);
        return count;
    } catch (error) {
        const message = error.response?.data?.query_status || error.response?.data?.message || error.message || String(error);
        await updateFeedStatus('urlhaus', 'error', 0, message);
        console.error(`[URLhaus] Error: ${message}`);
        throw error;
    }
}

export async function fetchUrlhausHosts(authKey = process.env.URLHAUS_AUTH_KEY || process.env.ABUSECH_AUTH_KEY) {
    if (!authKey) {
        const message = 'Skipped: URLHAUS_AUTH_KEY is required for URLhaus host data access';
        await updateFeedStatus('urlhaus_hosts', 'skipped', 0, message);
        return 0;
    }

    const message = 'Skipped: URLhaus hosts are derived from the recent URL feed';
    await updateFeedStatus('urlhaus_hosts', 'skipped', 0, message);
    return 0;
}

function normalizeUrlhausLimit(limit) {
    const parsed = Number.parseInt(limit, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return 500;
    return Math.min(parsed, 1000);
}

function iocTypeForHost(host) {
    return /^[\d.]+$/.test(host) || /^[a-fA-F0-9:]+$/.test(host) ? 'ip' : 'domain';
}

export default { fetchUrlhausUrls, fetchUrlhausHosts };
