import axios from 'axios';

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
        await axios.post(teams.webhookUrl, buildTeamsPayload(event, payload), {
            headers: { 'Content-Type': 'application/json' },
            timeout: 15000
        });
        return { attempted: true, sent: true };
    } catch (error) {
        const message = error.response?.data?.message || error.response?.data?.error?.message || error.message;
        console.error(`[Teams] Failed to send ${event}: ${message}`);
        return { attempted: true, sent: false, error: message };
    }
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
    try {
        const url = new URL(teams.webhookUrl);
        if (url.protocol !== 'https:') return 'TEAMS_WEBHOOK_URL must use HTTPS';
    } catch {
        return 'TEAMS_WEBHOOK_URL must be a valid URL';
    }
    return null;
}

export default { notifyTeamsProgress, buildTeamsPayload };
