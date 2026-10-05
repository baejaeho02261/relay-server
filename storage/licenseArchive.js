'use strict';
// Read-only compatibility for historical snapshots. No activation or issuance path.
const { SafeField, Now } = require('../core/utils');

function NormalizeTags(value) {
    const items = Array.isArray(value) ? value : String(value || '').split(',');
    const out = [];
    for (const raw of items) {
        const tag = SafeField(raw || '').trim().toUpperCase().replace(/[^A-Z0-9_가-힣-]/g, '').slice(0, 24);
        if (tag && !out.includes(tag)) out.push(tag);
        if (out.length >= 10) break;
    }
    return out;
}

function GetLicenseStatus(license) {
    if (!license) return 'UNKNOWN';
    if (license.suspended) return 'SUSPENDED';
    if (license.entryPass !== true && Number(license.expiresAt) <= Now()) return 'EXPIRED';
    if (license.boundClient) return 'BOUND';
    return 'AVAILABLE';
}

module.exports = { NormalizeTags, GetLicenseStatus };
