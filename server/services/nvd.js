import { insertOrUpdateCve, updateFeedStatus, getSeverity } from '../db/database.js';
import { feedGet } from '../utils/feedHttp.js';

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export async function fetchNvdCves(daysBack = 7, apiKey = process.env.NVD_API_KEY || null) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysBack);
    const endDate = new Date();

    const params = {
        resultsPerPage: 2000,
        pubStartDate: toNvdDate(startDate),
        pubEndDate: toNvdDate(endDate)
    };

    try {
        const response = await feedGet(NVD_API_BASE, {
            params,
            headers: apiKey ? { apiKey } : {},
            timeout: Number.parseInt(process.env.NVD_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.NVD_RETRIES || '3', 10) });
        const vulnerabilities = response.data?.vulnerabilities || [];
        let count = 0;

        for (const v of vulnerabilities) {
            const cve = v.cve;
            const metrics = cve.metrics || {};

            let cvssScore = 0;
            let cvssVector = '';

            if (metrics.cvssMetricV31?.length) {
                cvssScore = metrics.cvssMetricV31[0].cvssData.baseScore;
                cvssVector = metrics.cvssMetricV31[0].cvssData.vectorString;
            } else if (metrics.cvssMetricV30?.length) {
                cvssScore = metrics.cvssMetricV30[0].cvssData.baseScore;
                cvssVector = metrics.cvssMetricV30[0].cvssData.vectorString;
            } else if (metrics.cvssMetricV2?.length) {
                cvssScore = metrics.cvssMetricV2[0].cvssData.baseScore;
            }

            const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
            const vulnerableCpes = extractNvdVulnerableCpes(cve.configurations || v.configurations || []);

            insertOrUpdateCve({
                id: cve.id,
                source: 'nvd',
                description: description.substring(0, 5000),
                cvss_score: cvssScore,
                cvss_vector: cvssVector,
                severity: getSeverity(cvssScore),
                published_at: cve.published,
                search_text: vulnerableCpes.join(' '),
                search_metadata: { vulnerable_cpes: vulnerableCpes }
            });
            count++;
        }

        await updateFeedStatus('nvd', 'success', count);
        console.log(`[NVD] Fetched ${count} CVEs`);
        return count;
    } catch (error) {
        const message = error.response?.data?.message || error.message;
        await updateFeedStatus('nvd', 'error', 0, message);
        console.error(`[NVD] Error: ${message}`);
        throw error;
    }
}

export async function fetchNvdById(cveId, apiKey = process.env.NVD_API_KEY || null) {
    try {
        const response = await feedGet(NVD_API_BASE, {
            params: { cveId },
            headers: apiKey ? { apiKey } : {},
            timeout: Number.parseInt(process.env.NVD_TIMEOUT_MS || '90000', 10)
        }, { retries: Number.parseInt(process.env.NVD_RETRIES || '3', 10) });
        const v = response.data?.vulnerabilities?.[0];
        if (!v) return null;

        const cve = v.cve;
        const metrics = cve.metrics || {};
        let cvssScore = 0;
        let cvssVector = '';

        if (metrics.cvssMetricV31?.length) {
            cvssScore = metrics.cvssMetricV31[0].cvssData.baseScore;
            cvssVector = metrics.cvssMetricV31[0].cvssData.vectorString;
        } else if (metrics.cvssMetricV30?.length) {
            cvssScore = metrics.cvssMetricV30[0].cvssData.baseScore;
            cvssVector = metrics.cvssMetricV30[0].cvssData.vectorString;
        } else if (metrics.cvssMetricV2?.length) {
            cvssScore = metrics.cvssMetricV2[0].cvssData.baseScore;
        }

        const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
        const vulnerableCpes = extractNvdVulnerableCpes(cve.configurations || v.configurations || []);

        return {
            id: cve.id,
            source: 'nvd',
            sources: ['nvd'],
            is_kev: false,
            description: description.substring(0, 5000),
            cvss_score: cvssScore,
            cvss_vector: cvssVector,
            severity: getSeverity(cvssScore),
            published_at: cve.published,
            references: cve.references?.slice(0, 10) || [],
            configurations: cve.configurations || v.configurations || [],
            weaknesses: cve.weaknesses || [],
            search_text: vulnerableCpes.join(' '),
            search_metadata: { vulnerable_cpes: vulnerableCpes }
        };
    } catch (error) {
        console.error(`[NVD] Error fetching ${cveId}:`, error.message);
        return null;
    }
}

function toNvdDate(date) {
    return date.toISOString();
}

export function extractNvdVulnerableCpes(configurations = []) {
    const cpes = new Set();

    function walk(node) {
        if (!node || typeof node !== 'object') return;
        if (Array.isArray(node)) {
            node.forEach(walk);
            return;
        }

        for (const match of node.cpeMatch || node.cpe_match || []) {
            if (match?.vulnerable === false) continue;
            const criteria = match?.criteria || match?.cpe23Uri || match?.cpe_name;
            if (criteria && /^cpe:/i.test(criteria)) cpes.add(String(criteria).trim());
        }

        for (const child of node.nodes || node.children || []) {
            walk(child);
        }
    }

    walk(configurations);
    return [...cpes].slice(0, 100);
}

export default { fetchNvdCves, fetchNvdById };
