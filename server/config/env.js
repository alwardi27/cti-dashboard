import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

const ENV_PATH = resolve(process.cwd(), '.env');

export function loadEnvFile(path = ENV_PATH) {
    if (!existsSync(path)) return;

    const lines = readFileSync(path, 'utf-8').split(/\r?\n/);
    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;

        const separator = line.indexOf('=');
        if (separator === -1) continue;

        const key = line.slice(0, separator).trim();
        let value = line.slice(separator + 1).trim();
        if (!key || process.env[key] !== undefined) continue;

        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
        }

        process.env[key] = value;
    }
}

export function getFeedConfig(overrides = {}) {
    return {
        nvdApiKey: valueFrom(overrides.nvdApiKey, 'NVD_API_KEY'),
        githubToken: valueFrom(overrides.githubToken, 'GITHUB_TOKEN'),
        vulncheckApiToken: valueFrom(overrides.vulncheckApiToken, 'VULNCHECK_API_TOKEN'),
        threatfoxAuthKey: valueFrom(overrides.threatfoxAuthKey, 'THREATFOX_AUTH_KEY', 'ABUSECH_AUTH_KEY'),
        urlhausAuthKey: valueFrom(overrides.urlhausAuthKey, 'URLHAUS_AUTH_KEY', 'ABUSECH_AUTH_KEY'),
        malwarebazaarAuthKey: valueFrom(overrides.malwarebazaarAuthKey, 'MALWAREBAZAAR_AUTH_KEY', 'ABUSECH_AUTH_KEY'),
        virustotalApiKey: valueFrom(overrides.virustotalApiKey, 'VIRUSTOTAL_API_KEY'),
        greynoiseApiKey: valueFrom(overrides.greynoiseApiKey, 'GREYNOISE_API_KEY'),
        shodanApiKey: valueFrom(overrides.shodanApiKey, 'SHODAN_API_KEY'),
        censysApiId: valueFrom(overrides.censysApiId, 'CENSYS_API_ID'),
        censysApiSecret: valueFrom(overrides.censysApiSecret, 'CENSYS_API_SECRET'),
        abuseipdbApiKey: valueFrom(overrides.abuseipdbApiKey, 'ABUSEIPDB_API_KEY'),
        otxApiKey: valueFrom(overrides.otxApiKey, 'OTX_API_KEY'),
        whatsapp: getWhatsAppConfig(overrides.whatsapp || overrides),
        teams: getTeamsConfig(overrides.teams || overrides)
    };
}

export function getWhatsAppConfig(overrides = {}) {
    return {
        enabled: booleanFrom(valueFrom(overrides.enabled, 'WHATSAPP_ALERTS_ENABLED')),
        provider: valueFrom(overrides.provider, 'WHATSAPP_PROVIDER') || 'twilio',
        minSeverity: (valueFrom(overrides.minSeverity, 'WHATSAPP_MIN_SEVERITY') || 'high').toLowerCase(),
        twilioAccountSid: valueFrom(overrides.twilioAccountSid, 'TWILIO_ACCOUNT_SID'),
        twilioAuthToken: valueFrom(overrides.twilioAuthToken, 'TWILIO_AUTH_TOKEN'),
        twilioFrom: valueFrom(overrides.twilioFrom, 'TWILIO_WHATSAPP_FROM'),
        to: valueFrom(overrides.to, 'WHATSAPP_ALERT_TO')
    };
}

export function getTeamsConfig(overrides = {}) {
    return {
        enabled: booleanFrom(valueFrom(overrides.enabled, 'TEAMS_ALERTS_ENABLED')),
        webhookUrl: valueFrom(overrides.webhookUrl, 'TEAMS_WEBHOOK_URL'),
        format: valueFrom(overrides.format, 'TEAMS_WEBHOOK_FORMAT') || 'adaptive_card',
        timeoutMs: numberFrom(valueFrom(overrides.timeoutMs, 'TEAMS_WEBHOOK_TIMEOUT_MS'), 15000, { min: 1000 }),
        maxAttempts: numberFrom(valueFrom(overrides.maxAttempts, 'TEAMS_WEBHOOK_MAX_ATTEMPTS'), 2, { min: 1, max: 5 }),
        retryDelayMs: numberFrom(valueFrom(overrides.retryDelayMs, 'TEAMS_WEBHOOK_RETRY_DELAY_MS'), 500, { min: 0 })
    };
}

function valueFrom(override, ...envNames) {
    if (override !== undefined && override !== null && override !== '') return override;
    for (const envName of envNames) {
        if (process.env[envName]) return process.env[envName];
    }
    return null;
}

function booleanFrom(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function numberFrom(value, fallback, options = {}) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;

    const min = options.min ?? Number.NEGATIVE_INFINITY;
    const max = options.max ?? Number.POSITIVE_INFINITY;
    return Math.min(max, Math.max(min, parsed));
}

loadEnvFile();
