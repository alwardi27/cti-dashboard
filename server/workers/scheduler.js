import { fetchNvdCves } from '../services/nvd.js';
import { fetchCisaKev } from '../services/cisaKev.js';
import { fetchGithubAdvisories } from '../services/githubAdvisories.js';
import { fetchUrlhausUrls, fetchUrlhausHosts } from '../services/urlhaus.js';
import { fetchThreatfoxIocs } from '../services/threatFox.js';
import { fetchMalwareBazaar } from '../services/malwareBazaar.js';
import { fetchFeodoTracker } from '../services/feodo.js';
import { fetchSslbl } from '../services/sslbl.js';
import { fetchEpss } from '../services/epss.js';
import { fetchOsvAdvisories } from '../services/osv.js';
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
import { saveLastRefreshSummary, updateFeedStatus, withRefreshMetrics } from '../db/database.js';
import { getFeedConfig } from '../config/env.js';

const jobs = [];
let manualRefreshPromise = null;
const manualRefreshState = {
    running: false,
    started_at: null,
    finished_at: null,
    last_result: null,
    last_error: null
};

export function startScheduler(feedConfig = getFeedConfig()) {
    console.log('[Scheduler] Automatic feed refresh is disabled. Use the dashboard Refresh button to run feeds manually.');
}

export function stopScheduler() {
    jobs.forEach(job => job.stop());
    jobs.length = 0;
    console.log('[Scheduler] All jobs stopped');
}

export async function fetchAllFeeds(feedConfig = getFeedConfig()) {
    console.log('[Scheduler] Manual fetch of all feeds initiated');

    const { result: results, metrics } = await withRefreshMetrics(async () => {
        const results = {};

        await runFeed(results, 'nvd', () => fetchNvdCves(process.env.NVD_DAYS_BACK || 3, feedConfig.nvdApiKey));
        await runFeed(results, 'cisa_kev', () => fetchCisaKev());
        await runFeed(results, 'github', () => fetchGithubAdvisories(feedConfig.githubToken));

        await runFeed(results, 'vulncheck', () => fetchVulnCheckCves(feedConfig.vulncheckApiToken));
        if (feedConfig.urlhausAuthKey) {
            await runFeed(results, 'urlhaus', async () => {
                const urlCount = await fetchUrlhausUrls(process.env.URLHAUS_LIMIT || 200, feedConfig.urlhausAuthKey);
                const hostCount = await fetchUrlhausHosts(feedConfig.urlhausAuthKey);
                return urlCount + hostCount;
            });
        }
        if (feedConfig.threatfoxAuthKey) {
            await runFeed(results, 'threatfox', () => fetchThreatfoxIocs(process.env.THREATFOX_DAYS || 1, feedConfig.threatfoxAuthKey));
        }
        if (feedConfig.malwarebazaarAuthKey) {
            await runFeed(results, 'malwarebazaar', () => fetchMalwareBazaar(process.env.MALWAREBAZAAR_HOURS || 48, feedConfig.malwarebazaarAuthKey));
        }
        await runFeed(results, 'feodo', () => fetchFeodoTracker());
        await runFeed(results, 'sslbl', () => fetchSslbl());
        await runFeed(results, 'epss', () => fetchEpss());
        await runFeed(results, 'osv', () => fetchOsvAdvisories());
        if (feedConfig.virustotalApiKey) {
            await runFeed(results, 'virustotal', () => fetchVirusTotal(feedConfig.virustotalApiKey));
        }
        if (feedConfig.greynoiseApiKey) {
            await runFeed(results, 'greynoise', () => fetchGreyNoise(feedConfig.greynoiseApiKey));
        }
        await runFeed(results, 'shodan', () => fetchShodan(feedConfig.shodanApiKey));
        if (feedConfig.censysApiId && feedConfig.censysApiSecret) {
            await runFeed(results, 'censys', () => fetchCensys(feedConfig.censysApiId, feedConfig.censysApiSecret));
        }
        await runFeed(results, 'abuseipdb', () => fetchAbuseIpdbBlacklist(feedConfig.abuseipdbApiKey));
        await runFeed(results, 'otx', () => fetchOtxPulses(feedConfig.otxApiKey));

        try {
            results.alerts = await processCveAlerts(feedConfig);
        } catch (e) {
            results.alerts = { sent: 0, skipped: false, error: e.message };
        }

        return results;
    });

    results.summary = buildRefreshSummary(results, metrics);
    saveLastRefreshSummary(results.summary);
    console.log('[Scheduler] Manual fetch complete:', results);
    return results;
}

export async function getManualRefreshStatus() {
    return { ...manualRefreshState, running: Boolean(manualRefreshPromise) };
}

export function startManualRefresh(feedConfig = getFeedConfig()) {
    const promise = runWithRefreshLock(() => fetchAllFeeds(feedConfig));
    promise.catch(error => {
        console.error('[Scheduler] Manual refresh failed:', error.message);
    });
    return { ...manualRefreshState, running: true };
}

export async function fetchAllFeedsLocked(feedConfig = getFeedConfig()) {
    return runWithRefreshLock(() => fetchAllFeeds(feedConfig));
}

export async function runWithRefreshLock(refresher) {
    if (manualRefreshPromise) {
        const error = new Error('Refresh already running');
        error.statusCode = 409;
        throw error;
    }

    manualRefreshState.running = true;
    manualRefreshState.started_at = new Date().toISOString();
    manualRefreshState.finished_at = null;
    manualRefreshState.last_error = null;

    manualRefreshPromise = Promise.resolve()
        .then(refresher)
        .then(result => {
            manualRefreshState.last_result = result;
            return result;
        })
        .catch(error => {
            manualRefreshState.last_error = error.message;
            throw error;
        })
        .finally(() => {
            manualRefreshState.running = false;
            manualRefreshState.finished_at = new Date().toISOString();
            manualRefreshPromise = null;
        });

    return manualRefreshPromise;
}

export function isManualRefreshRunning() {
    return Boolean(manualRefreshPromise);
}

async function runFeed(results, key, fetcher) {
    results[key] = { success: false, count: 0 };
    await updateFeedStatus(key, 'running', 0, null);

    try {
        results[key].count = await fetcher();
        results[key].success = true;
    } catch (error) {
        results[key].success = false;
        results[key].error = error.message;
    }
}

export function buildRefreshSummary(results, metrics) {
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

export default { startScheduler, stopScheduler, fetchAllFeeds, fetchAllFeedsLocked, getManualRefreshStatus, runWithRefreshLock, startManualRefresh, isManualRefreshRunning };
