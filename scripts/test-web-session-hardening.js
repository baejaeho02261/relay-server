'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { PassThrough } = require('node:stream');
const { EventEmitter } = require('node:events');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-web-hardening-'));
Object.assign(process.env, { DATA_DIR: temp, STORAGE_ENGINE: 'json', HA_ENABLED: '0', ADMIN_SECRET: 'study-session-test-secret', WEB_ADMIN_TRUSTED_PROXIES: '' });
require('../core/utils').EnsureDirs();
const auth = require('../web/webAuth'), { ReadJsonBody } = require('../web/requestBody');
const events = require('../web/webEvents');
const req = (ip = '192.0.2.10', headers = {}) => ({ headers, socket: { remoteAddress: ip } });
const cookieReq = session => req('192.0.2.10', { cookie: `${auth.COOKIE_NAME}=${session.token}` });
let count = 0;
function check(name, fn) { fn(); count++; console.log('PASS ' + name); }
async function body(bytes, limit) { const stream = new PassThrough(); stream.headers = {}; const result = ReadJsonBody(stream, limit); stream.end(bytes); return result; }
(async () => {
try {
    check('Forwarded IP and TLS headers are ignored from untrusted peers', () => {
        const forged = req('192.0.2.10', { 'x-forwarded-for': '198.51.100.5', 'x-forwarded-proto': 'https' });
        assert.equal(auth.ClientIP(forged), '192.0.2.10'); assert.equal(auth.IsHttps(forged), false);
        process.env.WEB_ADMIN_TRUSTED_PROXIES = '192.0.2.10';
        assert.equal(auth.ClientIP(forged), '198.51.100.5'); assert.equal(auth.IsHttps(forged), true);
        assert.equal(auth.ClientIP(req('192.0.2.10', { 'x-forwarded-for': '203.0.113.99, 198.51.100.5' })), '198.51.100.5');
        assert.equal(auth.ClientIP(req('192.0.2.10', { 'x-forwarded-for': 'not an IP' })), '192.0.2.10');
        process.env.WEB_ADMIN_TRUSTED_PROXIES = '';
    });
    const session = auth.Login(req(), 'admin', process.env.ADMIN_SECRET).session;
    check('Duplicate cookies and malformed tokens fail closed', () => {
        assert.equal(auth.Authenticate(req('192.0.2.10', { cookie: `${auth.COOKIE_NAME}=${session.token}; ${auth.COOKIE_NAME}=${session.token}` })), null);
        assert.equal(auth.Authenticate(req('192.0.2.10', { cookie: `${auth.COOKIE_NAME}=%ZZ` })), null);
        assert.equal(auth.Authenticate(cookieReq(session), false), session);
    });
    check('Successful reauthentication retires the old cookie and CSRF', () => {
        const next = auth.Login(cookieReq(session), 'admin', process.env.ADMIN_SECRET).session;
        assert.equal(auth.Authenticate(cookieReq(session)), null); assert.equal(session.expiresAt, 0);
        assert.equal(auth.IsAdmin(session), false); assert.equal(auth.Can(session, 'EXTEND'), false);
        assert.equal(auth.ValidateCsrf(req('', { 'x-csrf-token': session.csrf }), session), false);
        assert.equal(auth.Authenticate(cookieReq(next), false), next);
    });
    check('Absolute lifetime caps refresh and cannot be prolonged by requests', () => {
        const current = auth.Login(req(), 'admin', process.env.ADMIN_SECRET).session;
        current.absoluteExpiresAt = Date.now() + 1000;
        assert.equal(auth.Authenticate(cookieReq(current)), current);
        assert.equal(current.expiresAt, current.absoluteExpiresAt);
        current.absoluteExpiresAt = Date.now() - 1;
        assert.equal(auth.Authenticate(cookieReq(current)), null); assert.equal(current.expiresAt, 0);
    });
    check('Credential rotation invalidates previously issued sessions', () => {
        const current = auth.Login(req(), 'admin', process.env.ADMIN_SECRET).session;
        process.env.ADMIN_SECRET += '-rotated';
        assert.equal(auth.Authenticate(cookieReq(current)), null);
    });
    check('Forged forwarded IP cannot evade bounded login attempts', () => {
        for (let i = 0; i < 20; i++) assert.equal(auth.Login(req('198.51.100.9', { 'x-forwarded-for': `203.0.113.${i}` }), 'admin', 'wrong').status, 401);
        assert.equal(auth.Login(req('198.51.100.9', { 'x-forwarded-for': '203.0.113.100' }), 'admin', process.env.ADMIN_SECRET).status, 429);
        assert.equal(auth.Login(req('198.51.100.10'), 'admin', process.env.ADMIN_SECRET).ok, true);
    });
    check('SSE rejects slow consumers and terminates revoked sessions', () => {
        class Response extends EventEmitter {
            constructor(slow = false) { super(); this.slow = slow; this.writes = []; }
            writeHead(status) { this.status = status; }
            write(value) { this.writes.push(value); return !this.slow; }
            destroy() { this.destroyed = true; this.emit('close'); }
            end() { this.writableEnded = true; this.emit('close'); }
        }
        const current = auth.Login(req('198.51.100.11'), 'admin', process.env.ADMIN_SECRET).session;
        const slow = new Response(true); events.OpenEventStream(new EventEmitter(), slow, current); assert.equal(slow.destroyed, true);
        const stream = new Response(); events.OpenEventStream(new EventEmitter(), stream, current); assert.equal(stream.status, 200);
        auth.RevokeSession(current.id); events.BroadcastNotification({ text: 'no revoked session delivery' });
        assert.equal(stream.writableEnded, true); assert.equal(stream.writes.some(x => x.includes('no revoked')), false);
    });
    check('Session capacity remains bounded while reauthentication can replace its own slot', () => {
        auth.RevokeAllSessions();
        let first;
        for (let i = 0; i < 256; i++) { const next = auth.CreateSession(req(), 'admin'); if (!first) first = next; }
        assert.throws(() => auth.CreateSession(req(), 'admin'), /SESSION_CAPACITY/);
        const replacement = auth.CreateSession(cookieReq(first), 'admin');
        assert.equal(auth.Authenticate(cookieReq(replacement), false), replacement);
        assert.equal(auth.Authenticate(cookieReq(first)), null);
        assert.equal(auth.SessionSummary().total, 256);
        auth.RevokeAllSessions();
    });
    assert.deepEqual(await body(Buffer.from('{"text":"공부용"}')), { text: '공부용' }); count++;
    for (const value of ['null', '[]', '42', '"text"', '{bad']) await assert.rejects(body(Buffer.from(value)), /INVALID_JSON/);
    await assert.rejects(body(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])), /INVALID_JSON/); count++;
    await assert.rejects(body(Buffer.from('{"large":"1234567890"}'), 8), /BODY_TOO_LARGE/); count++;
    const aborted = new PassThrough(); aborted.headers = {};
    const pending = ReadJsonBody(aborted); const rejection = assert.rejects(pending, /BODY_ABORTED/);
    aborted.write('{"partial":'); aborted.emit('aborted'); await rejection; assert.equal(aborted.listenerCount('data'), 0); aborted.destroy(); count++;
    console.log(`WEB SESSION / BODY HARDENING PASS: ${count} behavioral groups`);
} finally { auth.RevokeAllSessions(); fs.rmSync(temp, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
