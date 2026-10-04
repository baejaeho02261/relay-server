'use strict';

const crypto = require('crypto');
const net = require('net');
const config = require('../config/config');
const { ConstantTimeEqual, Now } = require('../core/utils');
const { ResolveAdminRole, AdminAllowed } = require('../admin/auth');
const { LogEvent } = require('../storage/audit');

const COOKIE_NAME = 'relay_admin_session';
function BoundedNumber(value, fallback, min, max) {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? Math.min(max, Math.max(min, Math.floor(parsed))) : fallback;
}
const SESSION_MS = BoundedNumber(config.WEB_ADMIN_SESSION_MS, 30 * 60 * 1000, 5 * 60 * 1000, 24 * 60 * 60 * 1000);
const ABSOLUTE_SESSION_MS = BoundedNumber(process.env.WEB_ADMIN_ABSOLUTE_SESSION_MS, 12 * 60 * 60 * 1000, SESSION_MS, 7 * 24 * 60 * 60 * 1000);
const LOGIN_WINDOW_MS = BoundedNumber(process.env.WEB_ADMIN_LOGIN_WINDOW_MS, 15 * 60 * 1000, 1000, 60 * 60 * 1000);
const LOGIN_MAX_ATTEMPTS = BoundedNumber(process.env.WEB_ADMIN_LOGIN_MAX_ATTEMPTS, 10, 2, 100);
const MAX_LOGIN_BUCKETS = 4096;
const MAX_SESSIONS = 1024;
const sessions = new Map();
const loginFailures = new Map();

function RandomToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

function NormalizeAddress(value) {
    const ip = String(value || '').trim().split('%')[0];
    const family = net.isIP(ip);
    if (!family) return '';
    if (family === 4) return ip;
    const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
    const mapped = canonical.match(/^::ffff:([0-9a-f]+):([0-9a-f]+)$/i);
    if (!mapped) return canonical;
    const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
    return [high >>> 8, high & 255, low >>> 8, low & 255].join('.');
}

function TrustedProxy(ip) {
    if (!ip) return false;
    // Exact addresses only: never infer trust from private ranges or a header.
    return String(process.env.WEB_ADMIN_TRUSTED_PROXY_IPS || '').split(',')
        .some(value => NormalizeAddress(value) === ip);
}

function ClientIP(req) {
    const remote = NormalizeAddress(req.socket && req.socket.remoteAddress);
    if (!TrustedProxy(remote)) return remote;
    const chain = String(req.headers['x-forwarded-for'] || '').split(',').map(NormalizeAddress);
    if (chain.some(ip => !ip) || chain.length > 32) return remote;
    let current = remote;
    for (let index = chain.length - 1; index >= 0 && TrustedProxy(current); index--) current = chain[index];
    return current;
}

function ParseCookies(req) {
    const out = Object.create(null);
    const raw = String(req.headers.cookie || '');
    for (const part of raw.split(';')) {
        const p = part.indexOf('=');
        if (p <= 0) continue;
        const key = part.substring(0, p).trim();
        const value = part.substring(p + 1).trim();
        // Ambiguous session cookies must not select an attacker-chosen value.
        if (Object.prototype.hasOwnProperty.call(out, key)) { out[key] = ''; continue; }
        try { out[key] = decodeURIComponent(value); } catch (_) { out[key] = ''; }
    }
    return out;
}

function IsHttps(req) {
    if (req.socket && req.socket.encrypted) return true;
    return TrustedProxy(NormalizeAddress(req.socket && req.socket.remoteAddress)) &&
        String(req.headers['x-forwarded-proto'] || '').trim().toLowerCase() === 'https';
}

function IsSameOrigin(req) {
    if (String(req.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') return false;
    const origin = req.headers.origin;
    if (origin === undefined) return true; // Existing non-browser API clients.
    if (typeof origin !== 'string' || origin === 'null') return false;
    try {
        const expected = new URL(`${IsHttps(req) ? 'https' : 'http'}://${req.headers.host}`);
        const supplied = new URL(origin);
        return supplied.origin === expected.origin && supplied.href === supplied.origin + '/';
    } catch (_) { return false; }
}

function LoginLimit(req) {
    const now = Now();
    const key = ClientIP(req) || 'UNKNOWN';
    for (const [ip, item] of loginFailures) if (item.expiresAt <= now) loginFailures.delete(ip);
    const item = loginFailures.get(key);
    if ((item && item.count >= LOGIN_MAX_ATTEMPTS) || (!item && loginFailures.size >= MAX_LOGIN_BUCKETS)) {
        return { ok: false, status: 429, code: 'AUTH_RATE_LIMITED', retryAfter: Math.max(1, Math.ceil((((item && item.expiresAt) || now + LOGIN_WINDOW_MS) - now) / 1000)) };
    }
    return null;
}

function RecordLoginFailure(req) {
    const key = ClientIP(req) || 'UNKNOWN';
    const item = loginFailures.get(key) || { count: 0, expiresAt: Now() + LOGIN_WINDOW_MS };
    item.count++;
    loginFailures.set(key, item);
}

function IsSessionActive(session) {
    return !!session && sessions.get(session.token) === session &&
        session.expiresAt > Now() && session.absoluteExpiresAt > Now();
}

function SessionCookie(req, token, maxAgeSeconds) {
    const parts = [
        `${COOKIE_NAME}=${encodeURIComponent(token)}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Strict',
        `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`
    ];
    if (IsHttps(req) || String(process.env.WEB_ADMIN_SECURE_COOKIE || '') === '1') parts.push('Secure');
    return parts.join('; ');
}

function GetWebSecret(role) {
    if (role === 'admin') return String(process.env.ADMIN_SECRET || '').trim();
    if (role === 'operator') return String(process.env.OPERATOR_SECRET || '').trim();
    if (role === 'viewer') return String(process.env.VIEWER_SECRET || '').trim();
    return '';
}

function IsWebCredentialConfigured(role) {
    return GetWebSecret(role).length > 0;
}

function CreateSession(req, role) {
    role = ResolveAdminRole(role);
    if (!role) throw new Error('ROLE_NOT_CONFIGURED');
    CleanupSessions();
    Logout(req); // Rotate the browser's prior authenticated session on login.
    while (sessions.size >= MAX_SESSIONS) {
        const oldest = sessions.entries().next().value;
        oldest[1].expiresAt = 0;
        sessions.delete(oldest[0]);
    }
    const token = RandomToken(32);
    const csrf = RandomToken(24);
    const now = Now();
    const session = {
        id: RandomToken(8).toUpperCase(),
        token,
        csrf,
        role,
        ip: ClientIP(req),
        createdAt: now,
        lastSeenAt: now,
        expiresAt: now + Math.min(SESSION_MS, ABSOLUTE_SESSION_MS),
        absoluteExpiresAt: now + ABSOLUTE_SESSION_MS,
        secure: IsHttps(req)
    };
    sessions.set(token, session);
    return session;
}

function Login(req, role, password) {
    const ip = ClientIP(req);
    if (!IsSameOrigin(req)) return { ok: false, status: 403, code: 'ORIGIN_NOT_ALLOWED' };
    const limited = LoginLimit(req);
    if (limited) return limited;
    role = ResolveAdminRole(role);

    if (!role || !IsWebCredentialConfigured(role)) {
        RecordLoginFailure(req);
        return { ok: false, status: 403, code: 'ROLE_NOT_CONFIGURED' };
    }

    const expected = GetWebSecret(role);
    const supplied = typeof password === 'string' && password.length <= 4096 ? password.trim() : '';
    if (!ConstantTimeEqual(expected, supplied)) {
        RecordLoginFailure(req);
        LogEvent('WEB_ADMIN_AUTH_FAILED', `${role} / ${ip}`);
        return { ok: false, status: 401, code: 'AUTH_FAILED' };
    }

    loginFailures.delete(ip || 'UNKNOWN');
    const session = CreateSession(req, role);
    LogEvent('WEB_ADMIN_AUTH', `${role} / ${ip}`);
    return { ok: true, session };
}

function Authenticate(req, refresh = true) {
    const cookies = ParseCookies(req);
    const token = cookies[COOKIE_NAME] || '';
    if (!/^[a-f0-9]{64}$/.test(token)) return null;
    const session = sessions.get(token);
    if (!session) return null;
    const now = Now();
    if (!IsSessionActive(session)) {
        session.expiresAt = 0;
        sessions.delete(token);
        return null;
    }
    if (session.secure && !IsHttps(req)) return null;
    if (refresh) {
        session.lastSeenAt = now;
        session.expiresAt = Math.min(now + SESSION_MS, session.absoluteExpiresAt);
    }
    return session;
}

function Logout(req) {
    const cookies = ParseCookies(req);
    const token = cookies[COOKIE_NAME] || '';
    const session = token ? sessions.get(token) : null;
    if (session) session.expiresAt = 0;
    if (token) sessions.delete(token);
}

function ListSessions(currentSession) {
    const out = [];
    for (const session of sessions.values()) {
        if (!IsSessionActive(session)) continue;
        out.push({
            id: session.id,
            role: session.role,
            ip: session.ip,
            createdAt: session.createdAt,
            lastSeenAt: session.lastSeenAt,
            expiresAt: session.expiresAt,
            current: !!currentSession && session.id === currentSession.id
        });
    }
    return out.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
}

function SessionSummary() {
    const rows = ListSessions(null);
    const roles = { admin: 0, operator: 0, viewer: 0 };
    for (const item of rows) if (Object.prototype.hasOwnProperty.call(roles, item.role)) roles[item.role]++;
    return { total: rows.length, roles };
}

function RevokeSession(sessionId) {
    sessionId = String(sessionId || '').trim().toUpperCase();
    for (const [token, session] of sessions) {
        if (String(session.id || '').toUpperCase() !== sessionId) continue;
        session.expiresAt = 0;
        sessions.delete(token);
        return true;
    }
    return false;
}

function RevokeOtherSessions(currentSession) {
    let count = 0;
    for (const [token, session] of Array.from(sessions)) {
        if (currentSession && session.id === currentSession.id) continue;
        session.expiresAt = 0;
        sessions.delete(token);
        count++;
    }
    return count;
}

function RevokeAllSessions() {
    let count = 0;
    for (const [token, session] of Array.from(sessions)) {
        session.expiresAt = 0;
        sessions.delete(token);
        count++;
    }
    return count;
}

function ValidateCsrf(req, session) {
    if (!IsSessionActive(session) || !IsSameOrigin(req) || (session.secure && !IsHttps(req))) return false;
    const supplied = String(req.headers['x-csrf-token'] || '');
    return ConstantTimeEqual(session.csrf, supplied);
}

function Can(session, operation) {
    return !!session && AdminAllowed(session.role, operation);
}

function IsAdmin(session) {
    return !!session && session.role === 'admin';
}

function CleanupSessions() {
    const now = Now();
    for (const [token, session] of sessions) if (!IsSessionActive(session)) { session.expiresAt = 0; sessions.delete(token); }
    for (const [ip, item] of loginFailures) if (item.expiresAt <= now) loginFailures.delete(ip);
}

setInterval(CleanupSessions, 60 * 1000).unref();

module.exports = {
    COOKIE_NAME,
    SESSION_MS,
    ABSOLUTE_SESSION_MS,
    IsHttps,
    IsSameOrigin,
    IsSessionActive,
    ClientIP,
    SessionCookie,
    Login,
    CreateSession,
    Authenticate,
    Logout,
    ValidateCsrf,
    Can,
    IsAdmin,
    ListSessions,
    SessionSummary,
    RevokeSession,
    RevokeOtherSessions,
    RevokeAllSessions
};
