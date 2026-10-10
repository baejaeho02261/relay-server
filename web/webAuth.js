'use strict';

const crypto = require('crypto');
const { performance } = require('node:perf_hooks');
const { ConstantTimeEqual, Now } = require('../core/utils');
const { ResolveAdminRole, AdminAllowed } = require('../admin/auth');
const { LogEvent } = require('../storage/audit');
const policy = require('./webAuthPolicy');

const COOKIE_NAME = 'relay_admin_session';
const SESSION_MS = policy.IntegerSetting('WEB_ADMIN_SESSION_MS', 30 * 60000, 5 * 60000, 24 * 60 * 60000);
const ABSOLUTE_SESSION_MS = policy.IntegerSetting('WEB_ADMIN_ABSOLUTE_SESSION_MS', 12 * 60 * 60000, 5 * 60000, 7 * 24 * 60 * 60000);
const REAUTH_MS = policy.IntegerSetting('DESKTOP_ADMIN_REAUTH_MS', 5 * 60000, 60000, 30 * 60000);
const MAX_SESSIONS = policy.IntegerSetting('WEB_ADMIN_MAX_SESSIONS', 2048, 16, 100000);
const trustedProxies = policy.ParseTrustedProxies(process.env.WEB_ADMIN_TRUSTED_PROXIES || '');
const limiter = new policy.LoginLimiter({
    windowMs: policy.IntegerSetting('WEB_ADMIN_LOGIN_WINDOW_MS', 5 * 60000, 1000, 60 * 60000),
    ipMax: policy.IntegerSetting('WEB_ADMIN_LOGIN_IP_MAX', 20, 1, 10000),
    roleMax: policy.IntegerSetting('WEB_ADMIN_LOGIN_ROLE_MAX', 200, 1, 100000),
    globalMax: policy.IntegerSetting('WEB_ADMIN_LOGIN_GLOBAL_MAX', 1000, 1, 1000000)
});
const sessions = new Map();
const sessionSecurity = new WeakMap();
const managedSessions = new WeakSet();
const stampKey = crypto.randomBytes(32);

function RandomToken(bytes = 32) { return crypto.randomBytes(bytes).toString('hex'); }
function ClientIP(req) { return policy.RequestOrigin(req, trustedProxies).ip; }
function IsHttps(req) { return policy.RequestOrigin(req, trustedProxies).https; }
function ParseCookies(req) {
    const out = Object.create(null);
    const raw = String(req.headers.cookie || '');
    if (raw.length > 16384) return out;
    for (const part of raw.split(';')) {
        const p = part.indexOf('=');
        if (p <= 0) continue;
        const key = part.substring(0, p).trim();
        const value = part.substring(p + 1).trim();
        if (Object.hasOwn(out, key)) { out[key] = ''; continue; }
        try { out[key] = decodeURIComponent(value); } catch (_) { out[key] = ''; }
    }
    return out;
}
function SessionCookie(req, token, maxAgeSeconds) {
    const parts = [
        `${COOKIE_NAME}=${encodeURIComponent(token)}`, 'Path=/', 'HttpOnly', 'SameSite=Strict',
        `Max-Age=${Math.max(0, Math.floor(Math.min(maxAgeSeconds, ABSOLUTE_SESSION_MS / 1000)))}`
    ];
    if (IsHttps(req) || process.env.WEB_ADMIN_SECURE_COOKIE === '1' || process.env.WEB_ADMIN_REQUIRE_HTTPS === '1') parts.push('Secure');
    return parts.join('; ');
}
function GetWebSecret(role) {
    if (role === 'admin') return String(process.env.ADMIN_SECRET || '').trim();
    if (role === 'operator') return String(process.env.OPERATOR_SECRET || '').trim();
    if (role === 'viewer') return String(process.env.VIEWER_SECRET || '').trim();
    return '';
}
function CredentialStamp(role) {
    return crypto.createHmac('sha512', stampKey).update(JSON.stringify([
        role, GetWebSecret(role), process.env.WEB_ADMIN_CREDENTIAL_REVISION || ''
    ])).digest('hex');
}
function DropSession(session) {
    if (!session) return;
    session.expiresAt = 0;
    if (sessions.get(session.token) === session) sessions.delete(session.token);
    sessionSecurity.delete(session);
}
function IsSessionActive(session) {
    const meta = session && sessionSecurity.get(session);
    const now = Now(), tick = performance.now();
    let valid = !!meta && sessions.get(session.token) === session && session.role === meta.role &&
        Number.isSafeInteger(session.expiresAt) && session.expiresAt > now && now >= session.createdAt &&
        now < session.absoluteExpiresAt && tick >= meta.createdTick && tick < meta.absoluteDeadline && tick < meta.idleDeadline &&
        ConstantTimeEqual(meta.credentialStamp, CredentialStamp(session.role));
    if (valid && meta.credentialId) {
        const cred = require('../core/state').production.passkeyCredentials.get(meta.credentialId);
        valid = !!cred && !cred.revokedAt && cred.role === session.role;
    }
    if (!valid && session) DropSession(session);
    return valid;
}
function CleanupSessions() {
    for (const session of Array.from(sessions.values())) IsSessionActive(session);
}
function CreateSession(req, role, options = {}) {
    role = ResolveAdminRole(role);
    if (!role) return null;
    CleanupSessions();
    if (sessions.size >= MAX_SESSIONS) return null;
    const token = RandomToken(32), csrf = RandomToken(24), now = Now(), tick = performance.now();
    const session = {
        id: RandomToken(8).toUpperCase(), token, csrf, role, ip: ClientIP(req),
        createdAt: now, lastSeenAt: now, expiresAt: now + Math.min(SESSION_MS, ABSOLUTE_SESSION_MS),
        absoluteExpiresAt: now + ABSOLUTE_SESSION_MS
    };
    managedSessions.add(session);
    sessionSecurity.set(session, {
        role, createdTick: tick, absoluteDeadline: tick + ABSOLUTE_SESSION_MS,
        idleDeadline: tick + Math.min(SESSION_MS, ABSOLUTE_SESSION_MS), authenticatedTick: tick,
        authenticatedAt: now, credentialStamp: CredentialStamp(role), credentialId: options.credentialId || ''
    });
    sessions.set(token, session);
    return session;
}
function CheckLoginAttempt(req, role) {
    if (process.env.WEB_ADMIN_REQUIRE_HTTPS === '1' && !IsHttps(req))
        return { ok: false, status: 403, code: 'ADMIN_HTTPS_REQUIRED' };
    return limiter.Check(ClientIP(req), ResolveAdminRole(role) || 'unknown');
}
function Login(req, role, password) {
    const limited = CheckLoginAttempt(req, role);
    if (!limited.ok) return limited;
    const ip = ClientIP(req);
    role = ResolveAdminRole(role);
    if (!role || !GetWebSecret(role)) return { ok: false, status: 403, code: 'ROLE_NOT_CONFIGURED' };
    const supplied = typeof password === 'string' && password.length <= 4096 ? password.trim() : '';
    if (!ConstantTimeEqual(GetWebSecret(role), supplied)) {
        LogEvent('WEB_ADMIN_AUTH_FAILED', `${role} / ${ip}`);
        return { ok: false, status: 401, code: 'AUTH_FAILED' };
    }
    const session = CreateSession(req, role);
    if (!session) return { ok: false, status: 503, code: 'ADMIN_SESSION_CAPACITY' };
    LogEvent('WEB_ADMIN_AUTH', `${role} / ${ip}`);
    return { ok: true, session };
}
function Authenticate(req, refresh = true) {
    if (process.env.WEB_ADMIN_REQUIRE_HTTPS === '1' && !IsHttps(req)) return null;
    const token = ParseCookies(req)[COOKIE_NAME] || '';
    if (!/^[a-f0-9]{64}$/.test(token)) return null;
    const session = sessions.get(token);
    if (!IsSessionActive(session)) return null;
    if (refresh) {
        const now = Now(), meta = sessionSecurity.get(session);
        session.lastSeenAt = now;
        session.expiresAt = Math.min(now + SESSION_MS, session.absoluteExpiresAt);
        meta.idleDeadline = Math.min(performance.now() + SESSION_MS, meta.absoluteDeadline);
    }
    return session;
}
function HasRecentAuthentication(session) {
    if (!IsSessionActive(session)) return false;
    const meta = sessionSecurity.get(session), now = Now(), tick = performance.now();
    return now >= meta.authenticatedAt && now - meta.authenticatedAt < REAUTH_MS &&
        tick >= meta.authenticatedTick && tick - meta.authenticatedTick < REAUTH_MS;
}
function MarkReauthenticated(session, credentialId = '') {
    if (!IsSessionActive(session)) return false;
    if (credentialId) {
        const cred = require('../core/state').production.passkeyCredentials.get(credentialId);
        if (!cred || cred.revokedAt || cred.role !== session.role) return false;
    }
    const meta = sessionSecurity.get(session);
    meta.authenticatedAt = Now(); meta.authenticatedTick = performance.now();
    // A session established by a passkey remains tied to that credential even
    // after password reauthentication; revoking it still closes the session.
    if (credentialId) meta.credentialId = credentialId;
    return true;
}
function Reauthenticate(req, session, password) {
    if (!IsSessionActive(session)) return { ok: false, status: 401, code: 'NOT_AUTHORIZED' };
    const limited = CheckLoginAttempt(req, session.role);
    if (!limited.ok) return limited;
    const supplied = typeof password === 'string' && password.length <= 4096 ? password.trim() : '';
    const expected = GetWebSecret(session.role);
    if (!expected || !ConstantTimeEqual(expected, supplied)) {
        LogEvent('WEB_ADMIN_REAUTH_FAILED', `${session.role} / ${ClientIP(req)}`);
        return { ok: false, status: 403, code: 'REAUTH_FAILED' };
    }
    if (!MarkReauthenticated(session)) return { ok: false, status: 401, code: 'NOT_AUTHORIZED' };
    LogEvent('WEB_ADMIN_REAUTH', `${session.role} / ${ClientIP(req)}`);
    return { ok: true, validForMs: REAUTH_MS };
}
function Logout(req) { DropSession(sessions.get(ParseCookies(req)[COOKIE_NAME] || '')); }
function ListSessions(currentSession) {
    CleanupSessions();
    return Array.from(sessions.values(), session => ({
        id: session.id, role: session.role, ip: session.ip, createdAt: session.createdAt,
        lastSeenAt: session.lastSeenAt, expiresAt: session.expiresAt, absoluteExpiresAt: session.absoluteExpiresAt,
        current: !!currentSession && session.id === currentSession.id
    })).sort((a, b) => b.lastSeenAt - a.lastSeenAt);
}
function SessionSummary() {
    const rows = ListSessions(null), roles = { admin: 0, operator: 0, viewer: 0 };
    for (const item of rows) if (Object.hasOwn(roles, item.role)) roles[item.role]++;
    return { total: rows.length, roles };
}
function RevokeSession(sessionId) {
    sessionId = String(sessionId || '').trim().toUpperCase();
    for (const session of sessions.values()) if (session.id === sessionId) { DropSession(session); return true; }
    return false;
}
function RevokeMatching(predicate) {
    let count = 0;
    for (const session of Array.from(sessions.values())) if (predicate(session)) { DropSession(session); count++; }
    return count;
}
function RevokeOtherSessions(currentSession) { return RevokeMatching(s => !currentSession || s.id !== currentSession.id); }
function RevokeAllSessions() { return RevokeMatching(() => true); }
function RevokeRoleSessions(role) { return RevokeMatching(s => s.role === ResolveAdminRole(role)); }
function ValidateCsrf(req, session) {
    return !!session && ConstantTimeEqual(session.csrf, String(req.headers['x-csrf-token'] || ''));
}
function Can(session, operation) { return !!session && AdminAllowed(session.role, operation); }
function IsAdmin(session) { return !!session && session.role === 'admin'; }
setInterval(CleanupSessions, 60 * 1000).unref();
module.exports = {
    COOKIE_NAME, SESSION_MS, ABSOLUTE_SESSION_MS, REAUTH_MS, ClientIP, IsHttps, SessionCookie,
    Login, CreateSession, Authenticate, IsSessionActive, IsManagedSession: session => managedSessions.has(session), Logout, ValidateCsrf, Can, IsAdmin,
    ListSessions, SessionSummary, RevokeSession, RevokeOtherSessions, RevokeAllSessions, RevokeRoleSessions,
    CheckLoginAttempt, HasRecentAuthentication, MarkReauthenticated, Reauthenticate
};
