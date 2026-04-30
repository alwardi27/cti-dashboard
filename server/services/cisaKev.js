import { insertOrUpdateCve, updateFeedStatus, getSeverity } from '../db/database.js';
import { feedGet } from '../utils/feedHttp.js';

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export async function fetchCisaKev() {
    try {
        const response = await feedGet(CISA_KEV_URL, {
            timeout: Number.parseInt(process.env.CISA_KEV_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.CISA_KEV_RETRIES || '3', 10) });
        const vulnerabilities = response.data?.vulnerabilities || [];
        let count = 0;

        for (const v of vulnerabilities) {
            const cveId = v.cveID;
            if (!cveId) continue;

            insertOrUpdateCve({
                id: cveId,
                source: 'cisa_kev',
                description: v.vulnerabilityName || `CISA KEV: ${cveId}`,
                cvss_score: 9.8,
                cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                severity: 'critical',
                published_at: v.dateAdded || new Date().toISOString()
            });
            count++;
        }

        await updateFeedStatus('cisa_kev', 'success', count);
        console.log(`[CISA KEV] Fetched ${count} known exploited vulnerabilities`);
        return count;
    } catch (error) {
        const message = error.message;
        await updateFeedStatus('cisa_kev', 'error', 0, message);
        console.error(`[CISA KEV] Error: ${message}`);
        throw error;
    }
}

export default { fetchCisaKev };
