'use strict';

const crypto = require('crypto');
const net = require('node:net');
const config = require('../config/config');
const { ConstantTimeEqual, Now } = require('../core/utils');
const { ResolveAdminRole, AdminAllowed } = require('../admin/auth');
const { LogEvent } = require('../storage/audit');

const COOKIE_NAME = 'relay_admin_session';
function BoundedSetting(value, fallback, min, max) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}
const SESSION_MS = BoundedSetting(config.WEB_ADMIN_SESSION_MS, 30 * 60 * 1000, 5 * 60 * 1000, 24 * 60 * 60 * 1000);
const ABSOLUTE_SESSION_MS = Math.max(SESSION_MS, BoundedSetting(process.env.WEB_ADMIN_ABSOLUTE_SESSION_MS, 8 * 60 * 60 * 1000, 5 * 60 * 1000, 7 * 24 * 60 * 60 * 1000));
const MAX_SESSIONS = 256;
const LOGIN_WINDOW_MS = 60 * 1000;
const sessions = new Map(), loginAttempts = new Map();
const credentialKey = crypto.randomBytes(32);

function NormalizeIP(value) {
    const text = String(value || '').trim();
    return text.startsWith('::ffff:') && net.isIP(text.slice(7)) === 4 ? text.slice(7) : text;
}
function TrustedIP(peer) {
    if (!net.isIP(peer)) return false;
    return String(process.env.WEB_ADMIN_TRUSTED_PROXIES || '').split(',')
        .some(value => NormalizeIP(value) === peer);
}
function TrustedProxy(req) { return TrustedIP(NormalizeIP(req.socket && req.socket.remoteAddress)); }
function CredentialStamp(role) {
    return crypto.createHmac('sha256', credentialKey).update(role + '\n' + GetWebSecret(role)).digest('hex');
}
function Invalidate(token, session) {
    if (session) { session.expiresAt = 0; session.csrf = ''; }
    sessions.delete(token);
}
function IsSessionActive(session) {
    return !!session && sessions.get(session.token) === session &&
        session.expiresAt > Now() && session.absoluteExpiresAt > Now() &&
        ConstantTimeEqual(session.credentialStamp, CredentialStamp(session.role));
}
// IP/global buckets are bounded. Only explicitly trusted proxies supply client IPs.
function AllowLoginAttempt(req) {
    const now = Now();
    for (const [key, row] of loginAttempts) if (row.until <= now) loginAttempts.delete(key);
    const keys = [['ALL', 600], ['IP:' + ClientIP(req), 20]];
    for (const [key, limit] of keys) {
        let row = loginAttempts.get(key);
        if (!row) {
            if (loginAttempts.size >= 4096) return false;
            row = { count: 0, until: now + LOGIN_WINDOW_MS };
            loginAttempts.set(key, row);
        }
        if (++row.count > limit) return false;
    }
    return true;
}

function RandomToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

function ClientIP(req) {
    let peer = NormalizeIP(req.socket && req.socket.remoteAddress);
    if (!TrustedIP(peer)) return peer;
    const hops = String(req.headers['x-forwarded-for'] || '').split(',').map(NormalizeIP);
    if (hops.length > 32 || hops.some(hop => !net.isIP(hop))) return peer;
    // Walk from the connected proxy back to the first untrusted hop. A proxy
    // may append the real peer after a forged, attacker-provided prefix.
    for (let index = hops.length - 1; index >= 0 && TrustedIP(peer); index--) peer = hops[index];
    return peer;
}

function ParseCookies(req) {
    const out = Object.create(null);
    const raw = String(req.headers.cookie || '');
    for (const part of raw.split(';')) {
        const p = part.indexOf('=');
        if (p <= 0) continue;
        const key = part.substring(0, p).trim();
        const value = part.substring(p + 1).trim();
        // Ambiguous duplicate session cookies must not select an attacker-chosen value.
        if (Object.hasOwn(out, key)) { out[key] = ''; continue; }
        try { out[key] = decodeURIComponent(value); } catch (_) { out[key] = ''; }
    }
    return out;
}

function IsHttps(req) {
    if (req.socket && req.socket.encrypted) return true;
    return TrustedProxy(req) && String(req.headers['x-forwarded-proto'] || '').toLowerCase() === 'https';
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
    const previous = Authenticate(req, false);
    if (sessions.size >= MAX_SESSIONS && !previous) throw new Error('SESSION_CAPACITY');
    // Reauthentication replaces this browser's prior authenticated session.
    Logout(req);
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
        expiresAt: now + SESSION_MS,
        absoluteExpiresAt: now + ABSOLUTE_SESSION_MS,
        credentialStamp: CredentialStamp(role)
    };
    sessions.set(token, session);
    return session;
}

function Login(req, role, password) {
    if (!AllowLoginAttempt(req)) return { ok: false, status: 429, code: 'AUTH_RATE_LIMIT' };
    if (typeof role !== 'string' || typeof password !== 'string' || password.length > 4096)
        return { ok: false, status: 401, code: 'AUTH_FAILED' };
    const ip = ClientIP(req);
    role = ResolveAdminRole(role);

    if (!role || !IsWebCredentialConfigured(role)) {
        return { ok: false, status: 403, code: 'ROLE_NOT_CONFIGURED' };
    }

    const expected = GetWebSecret(role);
    const supplied = String(password || '').trim();
    if (!ConstantTimeEqual(expected, supplied)) {
        LogEvent('WEB_ADMIN_AUTH_FAILED', `${role} / ${ip}`);
        return { ok: false, status: 401, code: 'AUTH_FAILED' };
    }

    let session;
    try { session = CreateSession(req, role); }
    catch (error) { if (error.message === 'SESSION_CAPACITY') return { ok: false, status: 503, code: 'SESSION_CAPACITY' }; throw error; }
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
        Invalidate(token, session);
        return null;
    }
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
    if (token) Invalidate(token, session);
}

function ListSessions(currentSession) {
    const now = Now();
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
        Invalidate(token, session);
        return true;
    }
    return false;
}

function RevokeOtherSessions(currentSession) {
    let count = 0;
    for (const [token, session] of Array.from(sessions)) {
        if (currentSession && session.id === currentSession.id) continue;
        Invalidate(token, session);
        count++;
    }
    return count;
}

function RevokeAllSessions() {
    let count = 0;
    for (const [token, session] of Array.from(sessions)) {
        Invalidate(token, session);
        count++;
    }
    return count;
}

function ValidateCsrf(req, session) {
    if (!IsSessionActive(session)) return false;
    const supplied = String(req.headers['x-csrf-token'] || '');
    return ConstantTimeEqual(session.csrf, supplied);
}

function Can(session, operation) {
    return IsSessionActive(session) && AdminAllowed(session.role, operation);
}

function IsAdmin(session) {
    return IsSessionActive(session) && session.role === 'admin';
}

function CleanupSessions() {
    const now = Now();
    for (const [token, session] of sessions) if (!IsSessionActive(session)) Invalidate(token, session);
}

setInterval(CleanupSessions, 60 * 1000).unref();

module.exports = {
    COOKIE_NAME,
    SESSION_MS,
    ABSOLUTE_SESSION_MS,
    IsHttps,
    IsSessionActive,
    AllowLoginAttempt,
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
