'use strict';

// This distribution is the Windows license service. Legacy records are kept
// for backup compatibility, but their transport and member workflows are not
// an alternative authentication path into the desktop application.
function Enabled() { return true; }
function LegacyTcpEnabled() { return false; }

function RetiredPath(pathname) {
    const path = String(pathname || '');
    return /^\/(?:member|game-download|pay)(?:\/|$)/i.test(path) ||
        /^\/api\/member/i.test(path) ||
        /^\/api\/(?:licenses|qr-auth|build-sessions|build-bindings|clients|games|support|reinstall-blocks|pairing|failover|load-simulator)(?:\/|$)/i.test(path) ||
        /^\/api\/control\/client(?:\/|$)/i.test(path) ||
        /^\/api\/request-recovery\/clients(?:\/|$)/i.test(path) ||
        /^\/api\/(?:biometric|permissions|client-permissions|access-groups|user-dashboard)(?:\/|$)/i.test(path);
}

function RetiredTarget(pathname, body = {}, params) {
    if (RetiredPath(pathname)) return true;
    if (!String(pathname).startsWith('/api/')) return false;
    // These fields belong to the removed APK identity/pairing protocol. New
    // desktop IDs and administrator sessions use separate fields and stores.
    if (body.clientId || body.targetClientId) return true;
    const type = String(body.type || params?.get('type') || '').toUpperCase();
    if (type === 'CLIENT' && /^\/api\/(?:releases|control|production|security)(?:\/|$)/.test(pathname)) return true;
    if (/^\/api\/enrollment\/(?:decision|reset)$/.test(pathname)) {
        const records = require('../core/state').deviceEnrollments;
        const row = [...records.values()].find(item => item.requestId === body.requestId);
        if (row?.type === 'CLIENT') return true;
    }
    return false;
}

function Reject(res) {
    const body = JSON.stringify({ ok: false, error: 'APK_FEATURE_RETIRED', message: '종료된 APK 기능입니다.' });
    res.writeHead(410, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
    res.end(body);
}

function Cleanup() {
    const state = require('../core/state'), now = Date.now();
    for (const [token, item] of state.confirmTokens) if (now >= item.expiresAt) state.confirmTokens.delete(token);
    const windowMs = require('../config/config').RATE_LIMIT_WINDOW_MS * 5;
    for (const [key, item] of state.rateLimits) if (item.startedAt < now - windowMs) state.rateLimits.delete(key);
}

module.exports = { Enabled, LegacyTcpEnabled, RetiredPath, RetiredTarget, Reject, Cleanup };
