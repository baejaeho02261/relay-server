'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Real HTTP dispatcher and temporary JSON storage; real ES256 signatures from
// a synthetic authenticator. UI functions run in a VM, not a physical browser.
const assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os');
const path = require('node:path'), http = require('node:http'), crypto = require('node:crypto'), vm = require('node:vm');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-admin-choice-http-'));
Object.assign(process.env, { DATA_DIR: tmp, STORAGE_ENGINE: 'json', HA_ENABLED: '0', ADMIN_SECRET: 'test-only-choice-admin-secret',
    VIEWER_SECRET: 'test-only-choice-viewer-secret', WEB_ADMIN_TRANSPORT: 'proxy', WEB_ADMIN_TRUSTED_PROXIES: '127.0.0.1/32,::1/128',
    WEB_ADMIN_REQUIRE_HTTPS: '1', WEB_ADMIN_SECURE_COOKIE: '1', WEBAUTHN_RP_ID: 'localhost', WEBAUTHN_ORIGIN: 'https://localhost',
    WEB_ADMIN_LOGIN_IP_MAX: '500', WEB_ADMIN_LOGIN_ROLE_MAX: '1000', WEB_ADMIN_LOGIN_GLOBAL_MAX: '2000',
    DESKTOP_ADMIN_REAUTH_REQUIRED: '0', DESKTOP_SECURITY_STEP_UP_REQUIRED: '0' });
require("../../core/peace.utilities.js").EnsureDirs();
const web = require("../../web/authentication/peace.web-auth"), state = require("../../core/peace.runtime-state"), wire = require("../fixtures/authentication/peace.passkey-wire-fixture");
const { RequestHandler } = require("../../web/http/peace.web-server");
const beginPath = '/api/production/passkeys/register/begin', finishPath = '/api/production/passkeys/register/finish';
const realNow = Date.now; let now = realNow(), tests = 0, server, passwordSession, keyRecord, pair;
Date.now = () => now;
async function test(name, fn) { await fn(); tests++; console.log('PASS ' + name); }
function call(route, body, actor, extraHeaders = {}) {
    return new Promise((resolve, reject) => {
        const bytes = body === undefined ? null : Buffer.from(JSON.stringify(body));
        const req = http.request({ host: '127.0.0.1', port: server.address().port, path: route, method: bytes ? 'POST' : 'GET',
            headers: { Host: 'localhost', 'X-Forwarded-Proto': 'https',
                ...(bytes ? { 'Content-Type': 'application/json', 'Content-Length': bytes.length } : {}),
                ...(actor ? { Cookie: actor.cookie, 'X-CSRF-Token': actor.csrf } : {}), ...extraHeaders } }, res => {
            let text = ''; res.on('data', b => text += b); res.on('end', () => {
                try { resolve({ status: res.statusCode, data: JSON.parse(text), headers: res.headers }); } catch (e) { reject(e); }
            });
        });
        req.on('error', reject); req.setTimeout(5000, () => req.destroy(Error('TEST_TIMEOUT'))); req.end(bytes);
    });
}
const callApproved=(route,body,actor,headers={})=>require("../fixtures/authentication/peace.action-approval-test-client").Approved(call,route,body,actor,headers);
async function login(role = 'admin') {
    const r = await call('/api/login', { role, password: role === 'admin' ? process.env.ADMIN_SECRET : process.env.VIEWER_SECRET });
    assert.equal(r.status, 200); return { csrf: r.data.csrf, cookie: r.headers['set-cookie'][0].split(';')[0] };
}
function registration(begin) {
    const p = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    return { pair: p, body: { challengeId: begin.data.challengeId, name: 'Synthetic test key',
        ...wire.Registration('localhost', p.publicKey, crypto.randomBytes(32), 0),
        clientDataJSON: wire.b64(JSON.stringify({ type: 'webauthn.create', challenge: begin.data.publicKey.challenge, origin: 'https://localhost' })) } };
}
function assertion(begin, record, p, counter) {
    const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: begin.data.publicKey.challenge, origin: 'https://localhost' }));
    const auth = wire.Auth('localhost', counter);
    return { challengeId: begin.data.challengeId, credentialId: record.credentialId, clientDataJSON: wire.b64(client),
        authenticatorData: wire.b64(auth), signature: wire.b64(crypto.sign('sha256', Buffer.concat([auth, crypto.createHash('sha256').update(client).digest()]), p.privateKey)) };
}
(async () => { try {
    server = http.createServer((req, res) => Promise.resolve(RequestHandler(req, res)).catch(e => {
        res.statusCode = 500; res.end(JSON.stringify({ error: e.message }));
    }));
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    await test('HTTP password login works with zero registered passkeys', async () => {
        assert.equal(state.production.passkeyCredentials.size, 0); passwordSession = await login();
        assert.equal((await call('/api/session', undefined, passwordSession)).status, 200);
    });
    await test('missing passkey is an error, not an automatic password downgrade', async () => {
        const r = await call('/api/passkey/login/begin', { role: 'admin' }); assert.equal(r.data.error, 'PASSKEY_NOT_REGISTERED');
        assert.equal(r.headers['set-cookie'], undefined);
    });
    await test('unauthenticated or missing-CSRF enrollment is denied', async () => {
        assert.equal((await call(beginPath, {})).status, 401);
        assert.equal((await call(beginPath, {}, passwordSession, { 'X-CSRF-Token': '' })).data.error, 'CSRF_FAILED');
    });
    await test('password-authenticated enrollment uses per-action confirmation without SSH or console token', async () => {
        const b = await callApproved(beginPath, {}, passwordSession); assert.equal(b.status, 200, JSON.stringify(b.data));
        const reg = registration(b); pair = reg.pair;
        const r = await callApproved(finishPath, reg.body, passwordSession); assert.equal(r.status, 200, JSON.stringify(r.data));
        keyRecord = state.production.passkeyCredentials.get(r.data.credential.id); assert(keyRecord);
        assert.equal(fs.existsSync(path.join(tmp, '.admin-enrollment')), false);
        const replay = await callApproved(finishPath, reg.body, passwordSession); assert.equal(replay.data.error, 'PASSKEY_CHALLENGE_INVALID');
    });
    await test('password login still works after a passkey has been registered', async () => {
        const another = await login(); assert.equal((await call('/api/session', undefined, another)).status, 200);
    });
    await test('registered passkey independently signs in with a real valid ES256 signature', async () => {
        const b = await call('/api/passkey/login/begin', { role: 'admin' }); assert.equal(b.status, 200);
        const proof = assertion(b, keyRecord, pair, 1); const r = await call('/api/passkey/login/finish', proof);
        assert.equal(r.status, 200, JSON.stringify(r.data)); assert(r.headers['set-cookie'][0].includes('Secure'));
        assert.equal((await call('/api/passkey/login/finish', proof)).status, 401);
    });
    await test('expired recent-auth window returns password-or-passkey prompt on enrollment', async () => {
        now += web.REAUTH_MS + 1;
        assert.equal((await call(beginPath, {}, passwordSession)).data.error, 'ADMIN_ACTION_REQUIRED');
        const bad = await call('/api/session/reauthenticate', { password: 'wrong' }, passwordSession);
        assert.equal(bad.data.error, 'REAUTH_FAILED');
        assert.equal((await call(beginPath, {}, passwordSession)).data.error, 'ADMIN_ACTION_REQUIRED');
    });
    await test('correct password restores enrollment access without an approval token', async () => {
        assert.equal((await call('/api/session/reauthenticate', { password: process.env.ADMIN_SECRET }, passwordSession)).status, 200);
        assert.equal((await callApproved(beginPath, {}, passwordSession)).status, 200);
    });
    await test('registration finish also checks freshness; reauth resumes the same unexpired challenge', async () => {
        now += web.REAUTH_MS - 10000;
        const b = await callApproved(beginPath, {}, passwordSession); assert.equal(b.status, 200); const reg = registration(b);
        now += 10001;
        assert.equal((await call(finishPath, reg.body, passwordSession)).data.error, 'ADMIN_ACTION_REQUIRED');
        assert.equal((await call('/api/session/reauthenticate', { password: process.env.ADMIN_SECRET }, passwordSession)).status, 200);
        assert.equal((await callApproved(finishPath, reg.body, passwordSession)).status, 200);
    });
    await test('enrollment challenge cannot be moved into a different live admin session', async () => {
        const b = await callApproved(beginPath, {}, passwordSession), reg = registration(b), other = await login();
        assert.equal((await callApproved(finishPath, reg.body, other)).data.error, 'PASSKEY_CHALLENGE_INVALID');
    });
    await test('origin and RP checks stay enforced after password authorization', async () => {
        const b = await callApproved(beginPath, {}, passwordSession), reg = registration(b);
        reg.body.clientDataJSON = wire.b64(JSON.stringify({ type: 'webauthn.create', challenge: b.data.publicKey.challenge, origin: 'https://other.invalid' }));
        const r = await callApproved(finishPath, reg.body, passwordSession); assert.equal(r.status, 400); assert.equal(r.data.ok, false);
    });
    await test('viewer cannot enroll and invalid explicit recovery token is not ignored', async () => {
        assert.equal((await call(beginPath, {}, await login('viewer'))).status, 403);
        const r = await call(beginPath, {}, passwordSession, { 'X-Admin-Enrollment-Token': 'a'.repeat(64) });
        assert.equal(r.data.error, 'ADMIN_ENROLLMENT_APPROVAL_REQUIRED');
    });
    await test('passkey reauth remains optional and verifies its actual signature', async () => {
        now += web.REAUTH_MS + 1;
        const b = await call('/api/session/reauthenticate/passkey/begin', {}, passwordSession); assert.equal(b.status, 200);
        const r = await call('/api/session/reauthenticate/passkey/finish', assertion(b, keyRecord, pair, 2), passwordSession);
        assert.equal(r.status, 200, JSON.stringify(r.data)); assert.equal((await callApproved(beginPath, {}, passwordSession)).status, 200);
    });
    await test('revoking the passkey still invalidates its bound session', async () => {
        state.production.passkeyCredentials.get(keyRecord.id).revokedAt = now;
        assert.equal((await call('/api/session', undefined, passwordSession)).status, 401);
        assert.equal((await call('/api/session', undefined, await login())).status, 200); // independent password session
    });
    const src = fs.readFileSync(path.join(MODULE_RESOURCE_ROOT, "../public/scripts/application/peace.admin.js"), 'utf8');
    const section = src.slice(src.indexOf('let adminReauthenticationPending'), src.indexOf('\nfunction showLogin()', src.indexOf('async function api(')));
    function ui(method, { cancel = false, passkeyFailure = false, passwordFailure = false, switchSession = false } = {}) {
        const calls = [], modals = [], values = { method, password: 'test-only-password' }; let passkeyCalls = 0;
        const ctx = { session: { csrf: 'csrf-a' }, dirtyViews: new Set(), currentView: 'test', showLogin() {}, readableApiError: x => x,
            openModal: async options => { modals.push(options); if (switchSession) ctx.session = { csrf: 'csrf-b' }; return cancel ? null : values; },
            reauthenticateWithPasskey: async () => { passkeyCalls++; if (passkeyFailure) throw Error('PASSKEY_CANCELLED'); },
            fetch: async url => { calls.push(url); const firstOperation = url === '/protected' && calls.filter(x => x === url).length === 1;
                const status = firstOperation ? 428 : passwordFailure && url === '/api/session/reauthenticate' ? 403 : 200;
                return { status, ok: status === 200, text: async () => JSON.stringify(status === 428 ? { ok: false, error: 'ADMIN_REAUTH_REQUIRED' } : status === 403 ? { ok: false, error: 'REAUTH_FAILED' } : { ok: true }) };
            } };
        vm.createContext(ctx); vm.runInContext(section + '\nglobalThis.run=api;', ctx);
        return { run: () => ctx.run('/protected', { method: 'POST', body: {} }), calls, modals, values, passkeyCalls: () => passkeyCalls };
    }
    await test('UI offers both methods, defaults to password, retries once and clears the password', async () => {
        const x = ui('password'); await x.run();
        assert.deepEqual(x.calls, ['/protected', '/api/session/reauthenticate', '/protected']);
        assert.equal(x.modals[0].fields[0].value, 'password');
        assert.deepEqual(Array.from(x.modals[0].fields[0].options, o => o.value), ['password', 'passkey']);
        assert.equal(x.values.password, ''); assert.equal(x.passkeyCalls(), 0);
    });
    await test('UI passkey choice sends no password request', async () => {
        const x = ui('passkey'); await x.run(); assert.equal(x.passkeyCalls(), 1);
        assert.deepEqual(x.calls, ['/protected', '/protected']); assert.equal(x.values.password, '');
    });
    await test('UI failed or cancelled passkey never silently retries with password', async () => {
        const x = ui('passkey', { passkeyFailure: true }); await assert.rejects(x.run(), /PASSKEY_CANCELLED/);
        assert.deepEqual(x.calls, ['/protected']); assert.equal(x.values.password, '');
    });
    await test('UI wrong password, modal cancellation and session switch do not apply the operation', async () => {
        const bad = ui('password', { passwordFailure: true }); await assert.rejects(bad.run(), /REAUTH_FAILED/);
        assert.deepEqual(bad.calls, ['/protected', '/api/session/reauthenticate']);
        for (const options of [{ cancel: true }, { switchSession: true }]) {
            const x = ui('password', options); await assert.rejects(x.run()); assert.deepEqual(x.calls, ['/protected']);
        }
    });
    await test('UI invalid method never falls through to a password attempt', async () => {
        const x = ui('invalid'); await assert.rejects(x.run(), /인증 방식/); assert.deepEqual(x.calls, ['/protected']);
    });
    console.log(`ADMIN AUTH CHOICE PASS: ${tests} cases (real HTTP/JSON storage/ES256 fixtures and UI VM; no live Railway or physical WebAuthn run).`);
} finally {
    Date.now = realNow; web.RevokeAllSessions();
    if (server) await new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); });
    fs.rmSync(tmp, { recursive: true, force: true });
} })().catch(e => { console.error(e); process.exitCode = 1; });
