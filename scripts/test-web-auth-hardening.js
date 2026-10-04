'use strict';
// Behavioral coverage of web/TCP authentication, proxy trust and SSE cleanup.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { execFileSync } = require('node:child_process');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'game-web-auth-'));
Object.assign(process.env, { DATA_DIR: temporary, STORAGE_ENGINE: 'json', HA_ENABLED: '0',
    ADMIN_SECRET: 'fixture-auth-hardening-admin', WEB_ADMIN_TRUSTED_PROXY_IPS: '',
    WEB_ADMIN_PUBLIC_ORIGIN: '', RAILWAY_PUBLIC_DOMAIN: '',
    WEB_ADMIN_LOGIN_MAX_ATTEMPTS: '3', WEB_ADMIN_LOGIN_WINDOW_MS: '1000' });
const utils = require('../core/utils');
utils.EnsureDirs();
const web = require('../web/webAuth');
const tcp = require('../admin/auth');
const streams = require('../web/webEvents');
const state = require('../core/state');
let count = 0;
function test(name, run) { run(); count++; console.log('PASS ' + name); }
function request(ip = '198.51.100.10', headers = {}, encrypted = true) {
    return { headers: { host: 'admin.example', ...headers }, socket: { remoteAddress: ip, encrypted } };
}
function withSession(req, session, extra = {}) {
    return { ...req, headers: { ...req.headers, cookie: web.COOKIE_NAME + '=' + session.token,
        'x-csrf-token': session.csrf, ...extra } };
}
function connection() {
    const lines = [];
    const socket = { remoteAddress: '127.0.0.1', destroyed: false, write: text => { lines.push(text.trim()); return true; } };
    const connection = { socket, lines }; socket.__relayConnection = { type: 'admin' };
    return connection;
}
function authenticate(connection) {
    tcp.HandleAdminHello(connection, 'ADMIN_HELLO|admin');
    const nonce = connection.adminNonce;
    const timestamp = String(Math.floor(Date.now() / 1000));
    const line = ['ADMIN_AUTH', nonce, timestamp, tcp.MakeRoleHmac('admin', nonce, timestamp)].join('|');
    tcp.HandleAdminAuth(connection, line);
    assert.equal(connection.adminAuthenticated, true);
    return line;
}
class Response extends EventEmitter {
    constructor() { super(); this.data = []; this.slow = false; this.writableEnded = false; this.destroyed = false; }
    writeHead(status) { this.status = status; }
    write(value) { this.data.push(value); return !this.slow; }
    end() { this.writableEnded = true; this.emit('close'); }
    destroy() { this.destroyed = true; this.emit('close'); }
}
try {
    test('Untrusted forwarded headers cannot spoof client IP or HTTPS', () => {
        const req = request('198.51.100.10', { 'x-forwarded-for': '127.0.0.1', 'x-forwarded-proto': 'https' }, false);
        assert.equal(web.ClientIP(req), '198.51.100.10'); assert.equal(web.IsHttps(req), false);
        assert.equal(web.ClientIP(request('fe80::1%eth0')), 'fe80::1');
        assert.equal(web.ClientIP(request('::ffff:c000:201')), '192.0.2.1');
        assert.ok(!web.SessionCookie(req, 'x', 60).includes('Secure'));
    });
    test('Trusted proxy resolves the nearest untrusted hop, ignoring injected leftmost IP', () => {
        process.env.WEB_ADMIN_TRUSTED_PROXY_IPS = '127.0.0.1, 10.0.0.2';
        const req = request('::ffff:127.0.0.1', { 'x-forwarded-for': '1.2.3.4, 198.51.100.11, 10.0.0.2', 'x-forwarded-proto': 'https' }, false);
        assert.equal(web.ClientIP(req), '198.51.100.11'); assert.equal(web.IsHttps(req), true);
        assert.equal(web.ClientIP(request('127.0.0.1', { 'x-forwarded-for': 'malformed' })), '127.0.0.1');
        process.env.WEB_ADMIN_TRUSTED_PROXY_IPS = '';
    });
    test('Cross-origin and opaque-origin password login are rejected', () => {
        for (const origin of ['https://evil.example', 'null']) assert.equal(web.Login(request('198.51.100.12', { origin }), 'admin', process.env.ADMIN_SECRET).code, 'ORIGIN_NOT_ALLOWED');
        assert.equal(web.IsSameOrigin(request('198.51.100.12', { origin: 'https://admin.example' })), true);
    });
    test('Failed-password throttle survives spoofed XFF and includes retry delay', () => {
        for (let i = 0; i < 3; i++) assert.equal(web.Login(request('198.51.100.13', { 'x-forwarded-for': `192.0.2.${i}` }), 'admin', 'bad').status, 401);
        const result = web.Login(request('198.51.100.13'), 'admin', process.env.ADMIN_SECRET);
        assert.equal(result.status, 429); assert.equal(result.retryAfter, 1);
        const realNow = Date.now;
        try { Date.now = () => realNow() + 1100; assert.equal(web.Login(request('198.51.100.13'), 'admin', process.env.ADMIN_SECRET).ok, true); }
        finally { Date.now = realNow; }
    });
    test('Successful password login rotates and revokes the prior browser session', () => {
        const req = request(); const first = web.Login(req, 'admin', process.env.ADMIN_SECRET).session;
        const second = web.Login(withSession(req, first), 'admin', process.env.ADMIN_SECRET).session;
        assert.notEqual(first.token, second.token); assert.equal(web.Authenticate(withSession(req, first)), null);
        assert.equal(web.ValidateCsrf(withSession(req, first), first), false);
        assert.equal(web.Authenticate(withSession(req, second)), second);
    });
    test('Cookie parser rejects duplicate, malformed and prototype-name cookies', () => {
        const req = request(); const session = web.CreateSession(req, 'admin');
        for (const cookie of [web.COOKIE_NAME + '=' + session.token + '; ' + web.COOKIE_NAME + '=forged', web.COOKIE_NAME + '=%ZZ', '__proto__=x']) {
            assert.equal(web.Authenticate({ ...req, headers: { ...req.headers, cookie } }), null);
        }
    });
    test('HTTPS-issued sessions reject a plain HTTP downgrade', () => {
        const req = request(); const session = web.CreateSession(req, 'admin');
        const downgraded = withSession(request('198.51.100.10', {}, false), session);
        assert.equal(web.Authenticate(downgraded), null); assert.equal(web.ValidateCsrf(downgraded, session), false);
    });
    test('Idle refresh cannot extend the absolute session lifetime', () => {
        const req = request(); const session = web.CreateSession(req, 'admin');
        session.absoluteExpiresAt = Date.now() + 5000;
        assert.equal(web.Authenticate(withSession(req, session)), session);
        assert.equal(session.expiresAt, session.absoluteExpiresAt);
        session.absoluteExpiresAt = Date.now() - 1;
        assert.equal(web.Authenticate(withSession(req, session)), null);
        assert.equal(web.ValidateCsrf(withSession(req, session), session), false);
    });
    test('Expired, copied and explicitly revoked session objects fail CSRF', () => {
        const req = request(); const session = web.CreateSession(req, 'admin');
        assert.equal(web.ValidateCsrf(withSession(req, session), session), true);
        assert.equal(web.ValidateCsrf(withSession(req, session), { ...session }), false);
        web.RevokeSession(session.id);
        assert.equal(web.ValidateCsrf(withSession(req, session), session), false);
        const expired = web.CreateSession(req, 'admin'); expired.expiresAt = Date.now() - 1;
        assert.equal(web.ValidateCsrf(withSession(req, expired), expired), false);
    });
    test('CSRF rejects a cross-origin request even with a matching token', () => {
        const req = request(); const session = web.CreateSession(req, 'admin');
        assert.equal(web.ValidateCsrf(withSession(req, session, { origin: 'https://evil.example' }), session), false);
    });
    test('Revoking a session closes its stream before another event can be sent', () => {
        const session = web.CreateSession(request(), 'admin'); const req = new EventEmitter(); const res = new Response();
        streams.OpenEventStream(req, res, session); const before = res.data.length;
        web.RevokeSession(session.id); streams.BroadcastEvent({ sentinel: 'must-not-leak' });
        assert.equal(res.writableEnded, true); assert.ok(!res.data.slice(before).join('').includes('must-not-leak'));
    });
    test('Slow stream consumers are disconnected when write backpressure is reached', () => {
        const session = web.CreateSession(request(), 'admin'); const res = new Response();
        streams.OpenEventStream(new EventEmitter(), res, session); res.slow = true;
        streams.BroadcastNotification({ event: 'one' }); assert.equal(res.destroyed, true);
        const before = res.data.length; streams.BroadcastNotification({ event: 'two' }); assert.equal(res.data.length, before);
    });
    test('SSE limits per-session connections and frees slots after response close', () => {
        const session = web.CreateSession(request(), 'admin'); const responses = [];
        for (let i = 0; i < 9; i++) { const res = new Response(); responses.push(res); streams.OpenEventStream(new EventEmitter(), res, session); }
        assert.equal(responses[7].status, 200); assert.equal(responses[8].status, 429);
        responses[0].end(); const replacement = new Response(); streams.OpenEventStream(new EventEmitter(), replacement, session); assert.equal(replacement.status, 200);
        for (const res of responses) res.end(); replacement.end();
    });
    test('TCP authentication consumes a challenge on failure and rejects reuse', () => {
        const peer = connection(); tcp.HandleAdminHello(peer, 'ADMIN_HELLO|admin');
        const nonce = peer.adminNonce; const timestamp = String(Math.floor(Date.now() / 1000));
        tcp.HandleAdminAuth(peer, ['ADMIN_AUTH', nonce, timestamp, '0'.repeat(64)].join('|'));
        tcp.HandleAdminAuth(peer, ['ADMIN_AUTH', nonce, timestamp, tcp.MakeRoleHmac('admin', nonce, timestamp)].join('|'));
        assert.equal(peer.adminAuthenticated, false); assert.equal(peer.lines.at(-1), 'ADMIN_ERROR|AUTH_FAILED');
        authenticate(peer); tcp.HandleAdminHello(peer, 'ADMIN_HELLO|unknown'); assert.equal(peer.adminAuthenticated, false);
    });
    test('TCP confirmation token is bound to its authenticated connection and single use', () => {
        const first = connection(); const second = connection(); authenticate(first); authenticate(second);
        tcp.PrepareConfirm(first, 'WHOAMI'); const token = first.lines.at(-1).split('|')[1];
        tcp.ExecuteConfirmed(second, token); assert.equal(second.lines.at(-1), 'CONFIRM_ERROR|INVALID_OR_EXPIRED');
        assert.equal(state.confirmTokens.has(token), true); tcp.ExecuteConfirmed(first, token);
        assert.equal(state.confirmTokens.has(token), false); tcp.ExecuteConfirmed(first, token);
        assert.equal(first.lines.at(-1), 'CONFIRM_ERROR|INVALID_OR_EXPIRED');
    });
    test('Equivalent IPv6 spellings produce the same /64 network classification', () => {
        const network = require('../services/networkSecurity');
        assert.equal(network.Subnet('2001:db8::1'), network.Subnet('2001:0db8:0000:0000:0:0:0:ffff'));
        assert.notEqual(network.Subnet('2001:db8:0:1::1'), network.Subnet('2001:db8:0:2::1'));
        assert.equal(network.Subnet('not-an-ip'), '');
        assert.equal(network.NormalizeIP('::FFFF:192.0.2.1'), '192.0.2.1');
        assert.equal(network.NormalizeIP('::ffff:c000:201'), '192.0.2.1');
        assert.equal(network.GeoLookup('fe90::1').country, 'LOCAL');
    });
    test('Relay TLS rejects a mismatched key and out-of-validity certificate', () => {
        const cert = path.join(temporary, 'test-cert.pem'); const key = path.join(temporary, 'test-key.pem');
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=test.invalid'], { stdio: 'ignore' });
        Object.assign(process.env, { RELAY_TLS_CERT_FILE: cert, RELAY_TLS_KEY_FILE: key });
        const transport = require('../services/transportSecurity');
        assert.equal(transport.ReadConfiguredTls().configured, true);
        const realNow = Date.now;
        try { Date.now = () => realNow() + 2 * 86400000; assert.equal(transport.ReadConfiguredTls().reason, 'CERTIFICATE_EXPIRED_OR_NOT_YET_VALID'); }
        finally { Date.now = realNow; }
        fs.writeFileSync(key, require('node:crypto').generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }));
        assert.equal(transport.ReadConfiguredTls().reason, 'CERTIFICATE_KEY_MISMATCH');
    });
    console.log(`Web authentication hardening: ${count} behavioral checks passed.`);
} finally {
    web.RevokeAllSessions(); streams.BroadcastEvent({ cleanup: true });
    fs.rmSync(temporary, { recursive: true, force: true });
}
