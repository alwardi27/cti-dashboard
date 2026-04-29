import cron from 'node-cron';
import { fetchNvdCves } from '../services/nvd.js';
import { fetchCisaKev } from '../services/cisaKev.js';
import { fetchGithubAdvisories } from '../services/githubAdvisories.js';
import { fetchUrlhausUrls, fetchUrlhausHosts } from '../services/urlhaus.js';
import { fetchThreatfoxIocs } from '../services/threatFox.js';
import { fetchMalwareBazaar } from '../services/malwareBazaar.js';
import {
    fetchAbuseIpdbBlacklist,
    fetchCensys,
    fetchGreyNoise,
    fetchOtxPulses,
    fetchShodan,
    fetchVirusTotal,
    fetchVulnCheckCves
} from '../services/keyedFeeds.js';
import { processCveAlerts } from '../services/alerts.js';
import { finishRefreshMetrics, pruneOldData, startRefreshMetrics } from '../db/database.js';
import { getFeedConfig } from '../config/env.js';

const jobs = [];

export function startScheduler(feedConfig = getFeedConfig()) {
    console.log('[Scheduler] Starting CTI feed scheduler...');

    jobs.push(cron.schedule('0 */2 * * *', async () => {
        console.log('[Scheduler] Fetching NVD CVEs...');
        await fetchNvdCves(7, feedConfig.nvdApiKey).catch(console.error);
        await processCveAlerts(feedConfig).catch(console.error);
    }));

    jobs.push(cron.schedule('0 * * * *', async () => {
        console.log('[Scheduler] Fetching CISA KEV...');
        await fetchCisaKev().catch(console.error);
        await processCveAlerts(feedConfig).catch(console.error);
    }));

    jobs.push(cron.schedule('0 */4 * * *', async () => {
        console.log('[Scheduler] Fetching GitHub Advisories...');
        await fetchGithubAdvisories(feedConfig.githubToken).catch(console.error);
        if (feedConfig.vulncheckApiToken) {
            await fetchVulnCheckCves(feedConfig.vulncheckApiToken).catch(console.error);
        }
        await processCveAlerts(feedConfig).catch(console.error);
    }));

    jobs.push(cron.schedule('*/15 * * * *', async () => {
        if (feedConfig.urlhausAuthKey) {
            console.log('[Scheduler] Fetching URLhaus URLs...');
            await fetchUrlhausUrls(500, feedConfig.urlhausAuthKey).catch(console.error);
            await fetchUrlhausHosts(feedConfig.urlhausAuthKey).catch(console.error);
        }
    }));

    jobs.push(cron.schedule('0 * * * *', async () => {
        if (feedConfig.threatfoxAuthKey) {
            console.log('[Scheduler] Fetching ThreatFox IOCs...');
            await fetchThreatfoxIocs(1, feedConfig.threatfoxAuthKey).catch(console.error);
        }
        if (feedConfig.otxApiKey) {
            await fetchOtxPulses(feedConfig.otxApiKey).catch(console.error);
        }
        if (feedConfig.greynoiseApiKey) {
            await fetchGreyNoise(feedConfig.greynoiseApiKey).catch(console.error);
        }
        if (feedConfig.abuseipdbApiKey) {
            await fetchAbuseIpdbBlacklist(feedConfig.abuseipdbApiKey).catch(console.error);
        }
    }));

    jobs.push(cron.schedule('*/15 * * * *', async () => {
        if (feedConfig.malwarebazaarAuthKey) {
            console.log('[Scheduler] Fetching MalwareBazaar...');
            await fetchMalwareBazaar(100, feedConfig.malwarebazaarAuthKey).catch(console.error);
        }
        if (feedConfig.virustotalApiKey && process.env.VIRUSTOTAL_QUERY) {
            await fetchVirusTotal(feedConfig.virustotalApiKey).catch(console.error);
        }
    }));

    jobs.push(cron.schedule('0 */6 * * *', async () => {
        if (feedConfig.shodanApiKey) {
            console.log('[Scheduler] Fetching Shodan exposure feed...');
            await fetchShodan(feedConfig.shodanApiKey).catch(console.error);
        }
        if (feedConfig.censysApiId && feedConfig.censysApiSecret) {
            console.log('[Scheduler] Fetching Censys exposure feed...');
            await fetchCensys(feedConfig.censysApiId, feedConfig.censysApiSecret).catch(console.error);
        }
        await processCveAlerts(feedConfig).catch(console.error);
    }));

    jobs.push(cron.schedule('0 3 * * *', async () => {
        console.log('[Scheduler] Pruning old data (90 days)...');
        pruneOldData(90);
    }));

    console.log('[Scheduler] All jobs scheduled');
}

export function stopScheduler() {
    jobs.forEach(job => job.stop());
    console.log('[Scheduler] All jobs stopped');
}

export async function fetchAllFeeds(feedConfig = getFeedConfig()) {
    console.log('[Scheduler] Manual fetch of all feeds initiated');

    const results = {};

    startRefreshMetrics();

    await runFeed(results, 'nvd', () => fetchNvdCves(7, feedConfig.nvdApiKey));
    await runFeed(results, 'cisa_kev', () => fetchCisaKev());
    await runFeed(results, 'github', () => fetchGithubAdvisories(feedConfig.githubToken));

    if (feedConfig.vulncheckApiToken) {
        await runFeed(results, 'vulncheck', () => fetchVulnCheckCves(feedConfig.vulncheckApiToken));
    }
    if (feedConfig.urlhausAuthKey) {
        await runFeed(results, 'urlhaus', async () => {
            const urlCount = await fetchUrlhausUrls(500, feedConfig.urlhausAuthKey);
            const hostCount = await fetchUrlhausHosts(feedConfig.urlhausAuthKey);
            return urlCount + hostCount;
        });
    }
    if (feedConfig.threatfoxAuthKey) {
        await runFeed(results, 'threatfox', () => fetchThreatfoxIocs(1, feedConfig.threatfoxAuthKey));
    }
    if (feedConfig.malwarebazaarAuthKey) {
        await runFeed(results, 'malwarebazaar', () => fetchMalwareBazaar(100, feedConfig.malwarebazaarAuthKey));
    }
    if (feedConfig.virustotalApiKey && process.env.VIRUSTOTAL_QUERY) {
        await runFeed(results, 'virustotal', () => fetchVirusTotal(feedConfig.virustotalApiKey));
    }
    if (feedConfig.greynoiseApiKey) {
        await runFeed(results, 'greynoise', () => fetchGreyNoise(feedConfig.greynoiseApiKey));
    }
    if (feedConfig.shodanApiKey) {
        await runFeed(results, 'shodan', () => fetchShodan(feedConfig.shodanApiKey));
    }
    if (feedConfig.censysApiId && feedConfig.censysApiSecret) {
        await runFeed(results, 'censys', () => fetchCensys(feedConfig.censysApiId, feedConfig.censysApiSecret));
    }
    if (feedConfig.abuseipdbApiKey) {
        await runFeed(results, 'abuseipdb', () => fetchAbuseIpdbBlacklist(feedConfig.abuseipdbApiKey));
    }
    if (feedConfig.otxApiKey) {
        await runFeed(results, 'otx', () => fetchOtxPulses(feedConfig.otxApiKey));
    }

    const metrics = finishRefreshMetrics();

    try {
        results.alerts = await processCveAlerts(feedConfig);
    } catch (e) {
        results.alerts = { sent: 0, skipped: false, error: e.message };
    }

    results.summary = buildRefreshSummary(results, metrics);
    console.log('[Scheduler] Manual fetch complete:', results);
    return results;
}

async function runFeed(results, key, fetcher) {
    results[key] = { success: false, count: 0 };

    try {
        results[key].count = await fetcher();
        results[key].success = true;
    } catch (error) {
        results[key].success = false;
        results[key].error = error.message;
    }
}

function buildRefreshSummary(results, metrics) {
    const feedEntries = Object.entries(results).filter(([key]) => !['alerts', 'summary'].includes(key));
    const successful = feedEntries.filter(([, result]) => result?.success).length;
    const failed = feedEntries.length - successful;

    return {
        started_at: metrics?.started_at || null,
        finished_at: metrics?.finished_at || new Date().toISOString(),
        feeds: {
            total: feedEntries.length,
            successful,
            failed
        },
        cves: metrics?.cves || { new: 0, updated: 0 },
        iocs: metrics?.iocs || { new: 0, updated: 0 },
        by_source: metrics?.by_source || {},
        processed: feedEntries.reduce((sum, [, result]) => sum + (Number(result?.count) || 0), 0)
    };
}

export default { startScheduler, stopScheduler, fetchAllFeeds };
