import { insertIoc, updateFeedStatus } from '../db/database.js';
import { parseCsvRows } from '../utils/csv.js';
import { feedGet } from '../utils/feedHttp.js';

const SSLBL_IP_CSV = 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv';
const SSLBL_CERT_CSV = 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv';

export async function fetchSslbl(ipUrl = SSLBL_IP_CSV, certUrl = SSLBL_CERT_CSV) {
    if (!isEnabled('SSLBL_ENABLED')) return skipFeed('sslbl', 'Skipped: SSLBL_ENABLED is false');

    try {
        const [ipResponse, certResponse] = await Promise.all([
            feedGet(ipUrl, {
                timeout: Number.parseInt(process.env.SSLBL_TIMEOUT_MS || '90000', 10)
            }, { retries: Number.parseInt(process.env.SSLBL_RETRIES || '3', 10) }),
            feedGet(certUrl, {
                timeout: Number.parseInt(process.env.SSLBL_TIMEOUT_MS || '90000', 10)
            }, { retries: Number.parseInt(process.env.SSLBL_RETRIES || '3', 10) })
        ]);

        const ipCount = saveSslblIps(parseSslblIpCsv(ipResponse.data));
        const certCount = saveSslblCerts(parseSslblCertCsv(certResponse.data));
        const count = ipCount + certCount;

        await updateFeedStatus('sslbl', 'success', count);
        console.log(`[SSLBL] Fetched ${ipCount} C2 IPs and ${certCount} certificate hashes`);
        return count;
    } catch (error) {
        const message = error.message;
        await updateFeedStatus('sslbl', 'error', 0, message);
        console.error(`[SSLBL] Error: ${message}`);
        throw error;
    }
}

export function parseSslblIpCsv(csv) {
    return parseCsvRows(csv)
        .map(row => ({
            first_seen: row[0] || null,
            ip: row[1],
            port: row[2] || null
        }))
        .filter(row => isIp(row.ip));
}

export function parseSslblCertCsv(csv) {
    return parseCsvRows(csv)
        .map(row => ({
            first_seen: row[0] || null,
            sha1: String(row[1] || '').toLowerCase(),
            reason: row[2] || 'malicious ssl certificate'
        }))
        .filter(row => /^[a-f0-9]{40}$/.test(row.sha1));
}

function saveSslblIps(rows) {
    let count = 0;
    for (const row of rows) {
        insertIoc({
            type: 'ip',
            value: row.ip,
            source: 'sslbl',
            threat_type: 'ssl_botnet_c2',
            confidence: 75,
            first_seen: row.first_seen,
            last_seen: row.first_seen,
            metadata: JSON.stringify({ port: row.port }),
            search_text: row.port
        });
        count++;
    }
    return count;
}

function saveSslblCerts(rows) {
    let count = 0;
    for (const row of rows) {
        insertIoc({
            type: 'hash',
            value: row.sha1,
            source: 'sslbl',
            threat_type: 'malicious_ssl_cert',
            confidence: 75,
            first_seen: row.first_seen,
            last_seen: row.first_seen,
            metadata: JSON.stringify({ reason: row.reason }),
            search_text: row.reason
        });
        count++;
    }
    return count;
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

export default { fetchSslbl, parseSslblIpCsv, parseSslblCertCsv };
