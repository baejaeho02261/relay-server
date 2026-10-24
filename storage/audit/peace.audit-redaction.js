'use strict';
// Apply only while creating new records. Historical audit bytes and their hash
// chain are deliberately never rewritten by this module.
const crypto = require('node:crypto');
const LICENSE = /\bLICENSE-[a-f0-9]{20}\b/ig;
const COMPLETE_LICENSE = /^LICENSE-[a-f0-9]{20}$/i;
const REF = /^REDACTED_SHA256:[a-f0-9]{64}$/;
const CREDENTIAL_MARKER = '[CREDENTIAL_REDACTED]';
const PRIVATE_FIELD = /^(?:password(?:hash)?|(?:admin|operator|viewer|api|client|shared)?secret|privatekey|licensekey|(?:access|refresh|session|auth|id|api)?token|authorization|cookie|apikey|credentials?)$/i;
const MAX_BYTES = 64 * 1024, MAX_NODES = 4096, MAX_DEPTH = 12;
const digest = value => crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
// Correlation hashes are restricted to generated high-entropy license keys.
// Passwords and other potentially guessable credentials must never have an
// offline hash oracle in an audit row, console output or event broadcast.
function licenseReference(value) {
    return typeof value === 'string' && COMPLETE_LICENSE.test(value)
        ? 'REDACTED_SHA256:' + digest(value.toUpperCase()) : CREDENTIAL_MARKER;
}
function scrubText(value) { return value.replace(LICENSE, licenseReference); }
function Normal(value) { return String(value || '').replace(/[\r\n|]/g, ' ').trim(); }
function licenseEnvelope(value) {
    if (!value || Array.isArray(value) || value.version !== 1 || value.kind !== 'LICENSE_EVENT_REDACTED') return false;
    const fields = Object.keys(value).sort().join(',');
    if (fields === 'kind,version') return true;
    if (fields !== 'kind,references,version' || !Array.isArray(value.references) || value.references.length < 1 ||
        value.references.length > 128 || value.references.some(x => !REF.test(x))) return false;
    return true;
}
function Detail(type, supplied) {
    const text = Normal(supplied), normalizedType = Normal(type);
    if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) {
        return JSON.stringify({ version:1, kind:'AUDIT_DETAIL_REDACTED' });
    }
    let parsed;
    try { parsed = JSON.parse(text); } catch (_) {}
    // Legacy license events previously logged the credential itself, sometimes
    // after removing it from the live map. Only public correlation hashes remain.
    if (/^(?:QR_)?LICENSE_/.test(normalizedType)) {
        if (licenseEnvelope(parsed)) return text;
        const keys = text.match(LICENSE) || [];
        if (!keys.length) return JSON.stringify({ version:1, kind:'LICENSE_EVENT_REDACTED' });
        const references = [...new Set(keys.map(licenseReference))].slice(0, 128);
        return JSON.stringify({ version:1, kind:'LICENSE_EVENT_REDACTED', references });
    }
    if (parsed === undefined) return scrubText(text);
    let nodes = 0, changed = false;
    function walk(value, depth) {
        if (++nodes > MAX_NODES || depth > MAX_DEPTH) throw Error('AUDIT_DETAIL_COMPLEX');
        if (typeof value === 'string') { const next = scrubText(value); if (next !== value) changed = true; return next; }
        if (!value || typeof value !== 'object') return value;
        if (Array.isArray(value)) return value.map(item => walk(item, depth + 1));
        return Object.fromEntries(Object.entries(value).map(([name, item]) => {
            if (PRIVATE_FIELD.test(name.replace(/[_-]/g, ''))) {
                const isLicenseField = name.replace(/[_-]/g, '').toLowerCase() === 'licensekey';
                const next = isLicenseField && typeof item === 'string'
                    ? (REF.test(item) ? item : licenseReference(item)) : CREDENTIAL_MARKER;
                if (next !== item) changed = true;
                return [name, next];
            }
            return [name, walk(item, depth + 1)];
        }));
    }
    try { const safe = walk(parsed, 0); return changed ? JSON.stringify(safe) : text; }
    catch (_) { return JSON.stringify({ version:1, kind:'AUDIT_DETAIL_REDACTED' }); }
}
module.exports = { Detail };
