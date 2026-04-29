import axios from 'axios';
import { insertIoc, updateFeedStatus } from '../db/database.js';

const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';

export async function fetchThreatfoxIocs(days = 1, authKey = process.env.THREATFOX_AUTH_KEY || process.env.ABUSECH_AUTH_KEY) {
    if (!authKey) {
        const message = 'Skipped: THREATFOX_AUTH_KEY is required for ThreatFox community API access';
        await updateFeedStatus('threatfox', 'skipped', 0, message);
        throw new Error(message);
    }

    try {
        const response = await axios.post(
            THREATFOX_API,
            {
                query: 'get_iocs',
                days: days
            },
            {
                headers: { 'Auth-Key': authKey },
                timeout: 30000
            }
        );

        const iocs = response.data?.data || [];
        let count = 0;

        for (const ioc of iocs) {
            if (!ioc.ioc) continue;

            const type = mapIocType(ioc.ioc_type, ioc.ioc);
            if (!type) continue;

            insertIoc({
                type: type,
                value: ioc.ioc,
                source: 'threatfox',
                threat_type: ioc.threat_type,
                confidence: ioc.confidence || 75,
                first_seen: ioc.first_seen,
                last_seen: ioc.last_seen,
                metadata: JSON.stringify({
                    malware: ioc.malware,
                    tags: ioc.tags
                })
            });
            count++;
        }

        await updateFeedStatus('threatfox', 'success', count);
        console.log(`[ThreatFox] Fetched ${count} IOCs`);
        return count;
    } catch (error) {
        const message = error.message;
        await updateFeedStatus('threatfox', 'error', 0, message);
        console.error(`[ThreatFox] Error: ${message}`);
        throw error;
    }
}

function mapIocType(iocType, value) {
    const type = iocType?.toLowerCase();

    if (type === 'ip' || type === 'ipaddr') return 'ip';
    if (type === 'domain' || type === 'fqdn') return 'domain';
    if (type === 'url' || type === 'uri') return 'url';
    if (type === 'md5' || type === 'sha1' || type === 'sha256') return 'hash';

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(value)) return 'hash';
    if (/^[a-fA-F0-9]{40}$/.test(value)) return 'hash';
    if (/^[a-fA-F0-9]{64}$/.test(value)) return 'hash';
    if (value.includes('://') || value.startsWith('/')) return 'url';
    if (value.includes('.')) return 'domain';

    return null;
}

export default { fetchThreatfoxIocs };
