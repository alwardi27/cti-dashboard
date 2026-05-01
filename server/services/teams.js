import axios from 'axios';

const MAX_TEAMS_PAYLOAD_BYTES = 28 * 1024;
const SUPPORTED_FORMATS = ['adaptive_card', 'text'];
const EVENT_TITLES = {
    import_summary: 'CVE progress import completed',
    status_changed: 'CVE progress status changed',
    note_added: 'CVE progress note added'
};

export async function notifyTeamsProgress(event, payload = {}, config = {}) {
    const teams = config.teams || config;
    if (!teams?.enabled) {
        return { attempted: false, sent: false, skipped: true, reason: 'Teams alerts are disabled' };
    }

    const validation = validateTeamsConfig(teams);
    if (validation) {
        return { attempted: false, sent: false, skipped: true, reason: validation };
    }

    try {
        const body = buildTeamsWebhookBody(event, payload, teams);
        validatePayloadSize(body);
        const result = await postTeamsWebhook(teams.webhookUrl, body, teams);
        return {
            attempted: true,
            sent: true,
            attempts: result.attempts,
            format: normalizeWebhookFormat(teams.format)
        };
    } catch (error) {
        const message = teamsErrorMessage(error);
        console.error(`[Teams] Failed to send ${event}: ${message}`);
        return {
            attempted: true,
            sent: false,
            attempts: error.attempts || 1,
            format: normalizeWebhookFormat(teams.format),
            error: message
        };
    }
}

export function buildTeamsWebhookBody(event, payload = {}, config = {}) {
    const format = normalizeWebhookFormat(config.format);
    return format === 'text'
        ? buildTeamsTextPayload(event, payload)
        : buildTeamsPayload(event, payload);
}

export function buildTeamsPayload(event, payload = {}) {
    const title = EVENT_TITLES[event] || 'CVE progress update';
    const facts = factsForEvent(event, payload);
    const body = [
        {
            type: 'TextBlock',
            text: title,
            weight: 'Bolder',
            size: 'Medium',
            wrap: true
        },
        {
            type: 'TextBlock',
            text: summaryForEvent(event, payload),
            wrap: true
        }
    ];

    if (facts.length) {
        body.push({
            type: 'FactSet',
            facts
        });
    }

    const actions = actionsForPayload(payload);
    return {
        type: 'message',
        attachments: [
            {
                contentType: 'application/vnd.microsoft.card.adaptive',
                contentUrl: null,
                content: {
                    $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
                    type: 'AdaptiveCard',
                    version: '1.2',
                    body,
                    actions
                }
            }
        ]
    };
}

export function buildTeamsTextPayload(event, payload = {}) {
    const title = EVENT_TITLES[event] || 'CVE progress update';
    const facts = factsForEvent(event, payload)
        .filter(item => item.value !== 'N/A')
        .map(item => `- ${item.title}: ${item.value}`);

    return {
        text: [
            `**${title}**`,
            summaryForEvent(event, payload),
            ...facts
        ].join('\n\n')
    };
}

async function postTeamsWebhook(url, body, teams) {
    const maxAttempts = normalizeInteger(teams.maxAttempts, 2, { min: 1, max: 5 });
    const retryDelayMs = normalizeInteger(teams.retryDelayMs, 500, { min: 0 });
    const timeout = normalizeInteger(teams.timeoutMs, 15000, { min: 1000 });

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            await axios.post(url, body, {
                headers: { 'Content-Type': 'application/json' },
                timeout
            });
            return { attempts: attempt };
        } catch (error) {
            error.attempts = attempt;
            if (attempt >= maxAttempts || !isRetryableTeamsError(error)) {
                throw error;
            }
            await sleep(retryDelay(error, attempt, retryDelayMs));
        }
    }

    return { attempts: maxAttempts };
}

function factsForEvent(event, payload) {
    if (event === 'import_summary') {
        const summary = payload.summary || {};
        return [
            fact('Total', summary.total),
            fact('Imported', summary.imported),
            fact('Updated', summary.updated),
            fact('Placeholders', summary.placeholders),
            fact('Duplicates', summary.duplicates),
            fact('Failed', summary.failed)
        ];
    }

    const cve = payload.cve || payload;
    return [
        fact('CVE', cve.id),
        fact('Status', cve.progress_status || payload.status),
        fact('Severity', cve.severity),
        fact('CVSS', formatScore(cve.cvss_score))
    ];
}

function summaryForEvent(event, payload) {
    if (event === 'import_summary') {
        const summary = payload.summary || {};
        return `Processed ${summary.total || 0} CVE row(s): ${summary.imported || 0} imported, ${summary.updated || 0} updated, ${summary.failed || 0} failed.`;
    }

    if (event === 'note_added') {
        const note = String(payload.note || '').replace(/\s+/g, ' ').trim().slice(0, 500);
        return note ? `New note: ${note}` : 'A note was added to this CVE.';
    }

    const cve = payload.cve || payload;
    return `${cve.id || 'CVE'} is now marked ${cve.progress_status || payload.status || 'updated'}.`;
}

function actionsForPayload(payload) {
    const cve = payload.cve || payload;
    if (!cve?.id || !/^CVE-\d{4}-\d+$/i.test(cve.id)) return [];
    return [{
        type: 'Action.OpenUrl',
        title: 'Open in NVD',
        url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`
    }];
}

function fact(title, value) {
    return {
        title,
        value: value === undefined || value === null || value === '' ? 'N/A' : String(value)
    };
}

function formatScore(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed.toFixed(1) : null;
}

function validateTeamsConfig(teams) {
    if (!teams.webhookUrl) return 'TEAMS_WEBHOOK_URL is not configured';
    if (!SUPPORTED_FORMATS.includes(normalizeWebhookFormat(teams.format))) {
        return `TEAMS_WEBHOOK_FORMAT must be one of: ${SUPPORTED_FORMATS.join(', ')}`;
    }
    try {
        const url = new URL(teams.webhookUrl);
        if (url.protocol !== 'https:') return 'TEAMS_WEBHOOK_URL must use HTTPS';
    } catch {
        return 'TEAMS_WEBHOOK_URL must be a valid URL';
    }
    return null;
}

function validatePayloadSize(body) {
    const size = Buffer.byteLength(JSON.stringify(body), 'utf8');
    if (size > MAX_TEAMS_PAYLOAD_BYTES) {
        throw new Error(`Teams payload is ${size} bytes, above the ${MAX_TEAMS_PAYLOAD_BYTES} byte limit`);
    }
}

function normalizeWebhookFormat(format) {
    const normalized = String(format || 'adaptive_card').trim().toLowerCase().replace(/[\s-]+/g, '_');
    return normalized === 'adaptivecard' ? 'adaptive_card' : normalized;
}

function normalizeInteger(value, fallback, options = {}) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;

    const min = options.min ?? Number.NEGATIVE_INFINITY;
    const max = options.max ?? Number.POSITIVE_INFINITY;
    return Math.trunc(Math.min(max, Math.max(min, parsed)));
}

function teamsErrorMessage(error) {
    if (typeof error.response?.data === 'string' && error.response.data.trim()) {
        return error.response.data.trim();
    }
    return error.response?.data?.message
        || error.response?.data?.error?.message
        || error.message
        || 'Unknown Teams webhook error';
}

function isRetryableTeamsError(error) {
    const status = error.response?.status;
    if (status === 408 || status === 429) return true;
    if (status >= 500 && status <= 599) return true;
    return ['ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED', 'ENOTFOUND', 'EAI_AGAIN'].includes(error.code);
}

function retryDelay(error, attempt, fallbackDelayMs) {
    const retryAfter = error.response?.headers?.['retry-after'];
    const retryAfterSeconds = Number(retryAfter);
    if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds >= 0) {
        return retryAfterSeconds * 1000;
    }
    return fallbackDelayMs * (2 ** (attempt - 1));
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export default { notifyTeamsProgress, buildTeamsPayload, buildTeamsTextPayload, buildTeamsWebhookBody };
