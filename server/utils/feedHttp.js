import http from 'node:http';
import https from 'node:https';
import axios from 'axios';

const httpAgent = new http.Agent({ keepAlive: false, maxSockets: 8 });
const httpsAgent = new https.Agent({ keepAlive: false, maxSockets: 8 });

export async function feedGet(url, config = {}, options = {}) {
    return feedRequest({ ...config, method: 'get', url }, options);
}

export async function feedPost(url, data, config = {}, options = {}) {
    return feedRequest({ ...config, method: 'post', url, data }, options);
}

export async function feedRequest(config, options = {}) {
    const attempts = boundedInt(options.retries ?? process.env.FEED_RETRIES, 1, 5, 3);
    const baseDelayMs = boundedInt(options.retryDelayMs ?? process.env.FEED_RETRY_DELAY_MS, 250, 30000, 1500);
    const timeout = boundedInt(
        config.timeout ?? options.timeoutMs ?? process.env.FEED_TIMEOUT_MS,
        5000,
        300000,
        90000
    );
    let lastError;

    for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
            return await axios.request({
                ...config,
                timeout,
                httpAgent,
                httpsAgent,
                maxContentLength: Infinity,
                maxBodyLength: Infinity,
                decompress: true,
                transitional: {
                    clarifyTimeoutError: true,
                    ...(config.transitional || {})
                },
                headers: {
                    Accept: 'application/json, text/plain, */*',
                    'User-Agent': 'cti-dashboard/1.0',
                    ...(config.headers || {})
                }
            });
        } catch (error) {
            lastError = error;
            if (attempt === attempts || !isRetryableFeedError(error)) break;
            await sleep(baseDelayMs * attempt);
        }
    }

    throw normalizeFeedError(lastError);
}

export function isRetryableFeedError(error) {
    const status = Number(error?.response?.status);
    const message = String(error?.message || '').toLowerCase();
    return [
        'ECONNRESET',
        'ETIMEDOUT',
        'ECONNABORTED',
        'EAI_AGAIN',
        'ENOTFOUND',
        'ERR_BAD_RESPONSE',
        'ERR_NETWORK'
    ].includes(error?.code) ||
        message.includes('aborted') ||
        message.includes('socket hang up') ||
        message.includes('timeout') ||
        [408, 425, 429, 500, 502, 503, 504].includes(status);
}

export function normalizeFeedError(error) {
    if (!error) return new Error('Unknown feed error');
    const status = error.response?.status;
    const apiMessage = error.response?.data?.message ||
        error.response?.data?.error?.message ||
        error.response?.data?.query_status;
    if (apiMessage && !String(error.message || '').includes(apiMessage)) {
        error.message = status ? `HTTP ${status}: ${apiMessage}` : String(apiMessage);
    } else if (status && !String(error.message || '').includes(String(status))) {
        error.message = `HTTP ${status}: ${error.message}`;
    }
    return error;
}

function boundedInt(value, min, max, fallback) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
