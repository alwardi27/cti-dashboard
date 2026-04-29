import axios from 'axios';
import { getPendingCveAlerts, markCveAlertError, markCveAlertSent } from '../db/database.js';

const SEVERITY_RANK = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
};

export async function processCveAlerts(config = {}) {
    const whatsapp = config.whatsapp || config;
    if (!whatsapp.enabled) {
        return { sent: 0, skipped: true, reason: 'WhatsApp alerts are disabled' };
    }

    const validation = validateWhatsAppConfig(whatsapp);
    if (validation) {
        console.warn(`[Alerts] ${validation}`);
        return { sent: 0, skipped: true, reason: validation };
    }

    const alerts = getPendingCveAlerts(20)
        .filter(alert => meetsSeverityThreshold(alert.severity, whatsapp.minSeverity));

    let sent = 0;
    for (const alert of alerts) {
        try {
            await sendWhatsAppCveAlert(alert, whatsapp);
            markCveAlertSent(alert.cve_id);
            sent++;
        } catch (error) {
            const message = error.response?.data?.message || error.message;
            markCveAlertError(alert.cve_id, message);
            console.error(`[Alerts] Failed to send ${alert.cve_id}: ${message}`);
        }
    }

    if (sent > 0) {
        console.log(`[Alerts] Sent ${sent} WhatsApp CVE alert(s)`);
    }

    return { sent, skipped: false };
}

async function sendWhatsAppCveAlert(alert, whatsapp) {
    if (whatsapp.provider !== 'twilio') {
        throw new Error(`Unsupported WhatsApp provider: ${whatsapp.provider}`);
    }

    const body = formatCveAlert(alert);
    const url = `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(whatsapp.twilioAccountSid)}/Messages.json`;
    const form = new URLSearchParams({
        From: whatsapp.twilioFrom,
        To: whatsapp.to,
        Body: body
    });

    await axios.post(url, form, {
        auth: {
            username: whatsapp.twilioAccountSid,
            password: whatsapp.twilioAuthToken
        },
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000
    });
}

function formatCveAlert(alert) {
    const description = String(alert.description || 'No description available')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 350);
    const score = Number(alert.cvss_score || 0).toFixed(1);
    const url = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(alert.cve_id)}`;

    return [
        `${String(alert.severity || '').toUpperCase()} CVE alert: ${alert.cve_id}`,
        `CVSS: ${score}`,
        `Source: ${String(alert.source || 'unknown').toUpperCase()}`,
        description,
        url
    ].join('\n');
}

function validateWhatsAppConfig(whatsapp) {
    if (whatsapp.provider !== 'twilio') return `Unsupported WhatsApp provider: ${whatsapp.provider}`;
    if (!whatsapp.twilioAccountSid) return 'TWILIO_ACCOUNT_SID is not configured';
    if (!whatsapp.twilioAuthToken) return 'TWILIO_AUTH_TOKEN is not configured';
    if (!isWhatsAppAddress(whatsapp.twilioFrom)) return 'TWILIO_WHATSAPP_FROM must look like whatsapp:+14155238886';
    if (!isWhatsAppAddress(whatsapp.to)) return 'WHATSAPP_ALERT_TO must look like whatsapp:+971...';
    return null;
}

function isWhatsAppAddress(value) {
    return /^whatsapp:\+\d{8,15}$/.test(String(value || ''));
}

function meetsSeverityThreshold(severity, threshold = 'high') {
    return (SEVERITY_RANK[severity] || 0) >= (SEVERITY_RANK[threshold] || SEVERITY_RANK.high);
}

export default { processCveAlerts };
