'use strict';
// Real service calls, HTTP dispatcher and UI function execution. No production
// server is started and all storage is redirected before application imports.
const assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const http = require('node:http'), crypto = require('node:crypto'), vm = require('node:vm');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-web-auth-'));
Object.assign(process.env, { DATA_DIR: temp, STORAGE_ENGINE: 'json', HA_ENABLED: '0',
    ADMIN_SECRET: 'test-admin-secret', OPERATOR_SECRET: 'test-operator-secret', VIEWER_SECRET: 'test-viewer-secret',
    WEB_ADMIN_TRUSTED_PROXIES: '127.0.0.1,::1', WEB_ADMIN_SESSION_MS: '1800000', WEB_ADMIN_ABSOLUTE_SESSION_MS: '43200000',
    WEB_ADMIN_LOGIN_IP_MAX: '20', WEB_ADMIN_LOGIN_ROLE_MAX: '200', WEB_ADMIN_LOGIN_GLOBAL_MAX: '1000',
    DESKTOP_ADMIN_REAUTH_REQUIRED: '0', DESKTOP_SECURITY_STEP_UP_REQUIRED: '0', WEB_ADMIN_REQUIRE_HTTPS: '0', WEB_ADMIN_SECURE_COOKIE: '0'
});
require('../core/utils').EnsureDirs();
const policy = require('../web/webAuthPolicy'), web = require('../web/webAuth'), guard = require('../services/desktopAdminGuard');
const state = require('../core/state'), realNow = Date.now;
let now = realNow(), tests = 0, server;
const readWaiters = new Map();
Date.now = () => now;
const req = (ip = '192.0.2.10', headers = {}, encrypted = false) => ({ socket: { remoteAddress: ip, encrypted }, headers });
const cookieReq = session => req('192.0.2.10', { cookie: web.COOKIE_NAME + '=' + session.token });
function test(name, run) { run(); tests++; console.log('PASS ' + name); }
async function atest(name, run) { await run(); tests++; console.log('PASS ' + name); }
function call(url, body, session, headers = {}) {
    return new Promise((resolve, reject) => {
        const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
        const r = http.request({ host: '127.0.0.1', port: server.address().port, path: url, method: data ? 'POST' : 'GET', headers: {
            ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}),
            ...(session ? { Cookie: web.COOKIE_NAME + '=' + session.token, 'X-CSRF-Token': session.csrf } : {}), ...headers
        } }, res => { let text = ''; res.on('data', x => text += x); res.on('end', () => { try { resolve({ status: res.statusCode, data: JSON.parse(text), headers: res.headers }); } catch (e) { reject(e); } }); });
        r.on('error', reject); r.setTimeout(5000, () => r.destroy(Error('TEST_TIMEOUT'))); r.end(data);
    });
}
async function delayedCall(url, body, session, interrupt, raw = false) {
    const barrier = crypto.randomBytes(8).toString('hex'), bytes = Buffer.from(raw ? body : JSON.stringify(body));
    let signalRead;
    const waiting = new Promise(resolve => { signalRead = resolve; });
    readWaiters.set(barrier, signalRead);
    let request;
    const completed = new Promise((resolve, reject) => {
        request = http.request({host:'127.0.0.1',port:server.address().port,path:url,method:'POST',headers:{
            'Content-Type': raw ? 'application/octet-stream' : 'application/json', 'Content-Length':bytes.length,
            'X-Test-Read-Barrier':barrier,Cookie:web.COOKIE_NAME+'='+session.token,'X-CSRF-Token':session.csrf
        }}, response => {let text='';response.on('data', x=>text+=x);response.on('end',()=>{try{resolve({status:response.statusCode,data:JSON.parse(text)});}catch(error){reject(error);}});});
        request.on('error',reject);request.setTimeout(5000,()=>request.destroy(Error('TEST_TIMEOUT')));
    });
    request.write(bytes.subarray(0,1));
    let timer;
    try {
        await Promise.race([waiting,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('BODY_READ_BARRIER_TIMEOUT')),5000);})]);
        interrupt(); request.end(bytes.subarray(1)); return await completed;
    } finally { clearTimeout(timer); readWaiters.delete(barrier); }
}
(async () => {
try {
    test('Untrusted peer cannot spoof client address or HTTPS', () => {
        assert.deepEqual(policy.RequestOrigin(req('192.0.2.1', { 'x-forwarded-for': '1.1.1.1', 'x-forwarded-proto': 'https' }), policy.ParseTrustedProxies('127.0.0.1')), { ip: '192.0.2.1', https: false });
        assert.equal(web.IsHttps(req('192.0.2.1', {}, true)), true);
    });
    test('Trusted CIDR follows chain from peer and stops at first untrusted hop', () => {
        const rules = policy.ParseTrustedProxies('127.0.0.1/32,10.20.0.0/16');
        assert.deepEqual(policy.RequestOrigin(req('127.0.0.1', { 'x-forwarded-for': '9.9.9.9, 192.0.2.8, 10.20.0.2', 'x-forwarded-proto': 'https' }), rules), { ip: '192.0.2.8', https: true });
        assert.equal(policy.RequestOrigin(req('10.21.0.1', { 'x-forwarded-for': '9.9.9.9' }), rules).ip, '10.21.0.1');
    });
    test('IPv6 CIDR and mapped IPv4 normalize equivalent spellings', () => {
        const rules = policy.ParseTrustedProxies('2001:db8::/32,::ffff:127.0.0.0/104');
        assert.equal(policy.RequestOrigin(req('2001:db8::2', { 'x-forwarded-for': '2001:db9::3' }), rules).ip, '2001:db9:0:0:0:0:0:3');
        assert.equal(policy.RequestOrigin(req('::ffff:127.0.0.1', { 'x-forwarded-for': '192.0.2.9' }), rules).ip, '192.0.2.9');
        assert.equal(policy.Address('::FFFF:C000:0209').text, '192.0.2.9');
    });
    test('Malformed CIDRs are rejected and malformed/oversize forwarding falls back to peer', () => {
        for (const text of ['localhost', '*', '1.2.3.4/33', '::/129', '::ffff:127.0.0.1/80', '1.2.3.4,', 'fe80::1%eth0']) assert.throws(() => policy.ParseTrustedProxies(text));
        for (const value of ['192.0.2.1, invalid', '192.0.2.1:80', '1'.repeat(2049), Array(17).fill('1.1.1.1').join(',')])
            assert.equal(policy.RequestOrigin(req('127.0.0.1', { 'x-forwarded-for': value }), policy.ParseTrustedProxies('127.0.0.1')).ip, '127.0.0.1');
    });
    test('IP throttling has finite windows; rejected requests do not extend cooldown', () => {
        let tick = 0; const limiter = new policy.LoginLimiter({ now: () => tick, windowMs: 1000, ipMax: 2 });
        assert.equal(limiter.Check('x', 'admin').ok, true); assert.equal(limiter.Check('x', 'admin').ok, true);
        tick = 999; assert.equal(limiter.Check('x', 'admin').status, 429);
        tick = 1000; assert.equal(limiter.Check('x', 'admin').ok, true);
    });
    test('Role/global limits also cover distributed peers; limiter storage is bounded', () => {
        const role = new policy.LoginLimiter({ roleMax: 1 }); role.Check('a', 'admin'); assert.equal(role.Check('b', 'admin').status, 429);
        assert.equal(role.Check('c', 'viewer').ok, true);
        const global = new policy.LoginLimiter({ globalMax: 1 }); global.Check('a', 'admin'); assert.equal(global.Check('b', 'viewer').status, 429);
        const bounded = new policy.LoginLimiter({ maxEntries: 4 }); bounded.Check('a', 'admin'); bounded.Check('b', 'admin'); assert.equal(bounded.Check('c', 'admin').status, 429); assert.equal(bounded.entries.size, 4);
    });
    test('Idle refresh is capped by absolute expiry, which cannot be renewed by activity', () => {
        const session = web.CreateSession(req(), 'admin'), start = now;
        now += web.SESSION_MS - 1; assert.equal(web.Authenticate(cookieReq(session)), session);
        assert.equal(session.expiresAt, now + web.SESSION_MS);
        now = start + web.ABSOLUTE_SESSION_MS; session.expiresAt = now + web.SESSION_MS;
        assert.equal(web.Authenticate(cookieReq(session)), null); now = start;
    });
    test('Clock rollback rejects a live session instead of lengthening it', () => {
        const session = web.CreateSession(req(), 'admin'); now--; assert.equal(web.Authenticate(cookieReq(session)), null); now++;
    });
    test('Changing password or emergency credential revision revokes active sessions', () => {
        const a = web.CreateSession(req(), 'admin'), viewer = web.CreateSession(req(), 'viewer');
        process.env.ADMIN_SECRET = 'changed'; assert.equal(web.Authenticate(cookieReq(a)), null); assert.equal(web.Authenticate(cookieReq(viewer)), viewer);
        process.env.ADMIN_SECRET = 'test-admin-secret'; process.env.WEB_ADMIN_CREDENTIAL_REVISION = '2'; assert.equal(web.IsSessionActive(viewer), false); delete process.env.WEB_ADMIN_CREDENTIAL_REVISION;
    });
    test('Revoked passkey invalidates its session independently of password', () => {
        state.production.passkeyCredentials.set('testkey', { role: 'admin', revokedAt: 0 });
        const session = web.CreateSession(req(), 'admin', { credentialId: 'testkey' }); assert.equal(web.IsSessionActive(session), true);
        state.production.passkeyCredentials.get('testkey').revokedAt = now; assert.equal(web.IsSessionActive(session), false);
        state.production.passkeyCredentials.delete('testkey');
    });
    test('Credential rotation stops SSE event disclosure for an already-open stream', () => {
        const events = require('../web/webEvents'), { EventEmitter } = require('node:events');
        const session = web.CreateSession(req(), 'admin'), request = new EventEmitter(), writes = [];
        const response = { writeHead() {}, write(text) { writes.push(text); }, end() {} };
        events.OpenEventStream(request, response, session); const initial = writes.length;
        process.env.ADMIN_SECRET = 'rotated-during-sse'; events.BroadcastEvent({ confidential: 'must-not-send' });
        assert.equal(writes.length, initial); assert.equal(session.expiresAt, 0);
        process.env.ADMIN_SECRET = 'test-admin-secret'; request.emit('close');
    });
    test('Duplicate cookies fail closed; role revocation leaves other roles active', () => {
        const admin = web.CreateSession(req(), 'admin'), viewer = web.CreateSession(req(), 'viewer');
        assert.equal(web.Authenticate(req('192.0.2.1', { cookie: `${web.COOKIE_NAME}=${admin.token}; ${web.COOKIE_NAME}=${admin.token}` })), null);
        assert.ok(web.RevokeRoleSessions('admin') >= 1); assert.equal(web.IsSessionActive(admin), false); assert.equal(web.IsSessionActive(viewer), true);
    });
    test('Local HTTP stays compatible; explicit production HTTPS rejects spoofed direct requests', () => {
        assert.ok(!web.SessionCookie(req('127.0.0.1'), 'x', 60).includes('; Secure'));
        process.env.WEB_ADMIN_REQUIRE_HTTPS = '1';
        assert.equal(web.Login(req('192.0.2.1', { 'x-forwarded-proto': 'https' }), 'admin', process.env.ADMIN_SECRET).code, 'ADMIN_HTTPS_REQUIRED');
        assert.equal(web.Login(req('192.0.2.1', {}, true), 'admin', process.env.ADMIN_SECRET).ok, true);
        assert.equal(web.Login(req('127.0.0.1', { 'x-forwarded-proto': 'https' }), 'admin', process.env.ADMIN_SECRET).ok, true);
        assert.ok(web.SessionCookie(req('127.0.0.1'), 'x', 60).includes('; Secure'));
        process.env.WEB_ADMIN_REQUIRE_HTTPS = '0'; process.env.WEB_ADMIN_SECURE_COOKIE = '1';
        assert.ok(web.SessionCookie(req(), 'x', 60).includes('; Secure')); process.env.WEB_ADMIN_SECURE_COOKIE = '0';
    });
    const { RequestHandler } = require('../web/webServer');
    server = http.createServer((request, response) => {
        const signal = readWaiters.get(request.headers['x-test-read-barrier']);
        if (signal) {
            const onListener = event => { if(event === 'data') { request.removeListener('newListener', onListener); queueMicrotask(signal); } };
            request.on('newListener', onListener);
        }
        Promise.resolve(RequestHandler(request, response)).catch(error => { response.statusCode = 500; response.end(JSON.stringify({ error: error.message })); });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let admin;
    await atest('Real HTTP password login, cookie and CSRF routes work', async () => {
        const login = await call('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }); assert.equal(login.status, 200);
        const token = login.headers['set-cookie'][0].split(';')[0].split('=')[1]; admin = web.Authenticate(req('127.0.0.1', { cookie: web.COOKIE_NAME + '=' + token }), false);
        assert.equal((await call('/api/session', undefined, admin)).status, 200);
        assert.equal((await call('/api/session/reauthenticate', { password: process.env.ADMIN_SECRET }, admin, { 'X-CSRF-Token': 'wrong' })).status, 403);
        assert.equal((await call('/api/login', null)).status, 400);
    });
    for (const reason of ['logout', 'expiry', 'password-change']) {
        await atest(`A delayed JSON mutation rechecks session after ${reason} and leaves target untouched`, async () => {
            const actor = web.CreateSession(req(), 'admin'), target = web.CreateSession(req(), 'viewer');
            const result = await delayedCall('/api/sessions/'+target.id+'/revoke', {}, actor, () => {
                if (reason === 'logout') web.RevokeSession(actor.id);
                else if (reason === 'expiry') actor.expiresAt = now;
                else process.env.ADMIN_SECRET = 'changed-while-reading-body';
            });
            assert.equal(result.status, 401); assert.equal(web.IsSessionActive(target), true);
            process.env.ADMIN_SECRET = 'test-admin-secret';
        });
    }
    await atest('A delayed release upload cannot publish after revocation and removes its temporary file', async () => {
        const actor = web.CreateSession(req(), 'admin'), count = state.releaseCatalog.size;
        const result = await delayedCall('/api/releases/upload?type=SERVER&channel=TEST&version=1.0.0&fileName=probe.exe', 'MZfixture', actor, () => web.RevokeSession(actor.id), true);
        assert.equal(result.status, 401); assert.equal(state.releaseCatalog.size, count);
        assert.deepEqual(fs.readdirSync(path.join(temp,'releases','.tmp')), []);
    });
    await atest('A delayed reauthentication request cannot issue a challenge after session revocation', async () => {
        const actor = web.CreateSession(req(), 'admin');
        const result = await delayedCall('/api/session/reauthenticate/passkey/begin', {}, actor, () => web.RevokeSession(actor.id));
        assert.equal(result.status, 401); assert.equal(result.data.error, 'NOT_AUTHORIZED');
    });
    await atest('Viewer/operator direct mutation and raw upload attempts are denied before mutation', async () => {
        for (const role of ['viewer', 'operator']) {
            const session = web.CreateSession(req(), role);
            for (const route of ['/api/desktop/bootstrap/security-authority', '/api/desktop/bootstrap/security-operations/signers', '/api/desktop/bootstrap/security-operations/ci-signers', '/api/desktop/bootstrap/security-operations/plan-release', '/api/desktop/bootstrap/security-operations/recovery/prepare', '/api/desktop/bootstrap/security-operations/recovery/apply', '/api/desktop/bootstrap/artifacts?component=O&version=1.0.0&fileName=O.exe'])
                assert.equal((await call(route, {}, session)).status, 403, route);
        }
    });
    await atest('Optional reauth leaves default unchanged then blocks expired freshness without consuming action', async () => {
        now += web.REAUTH_MS + 1;
        const route = '/api/desktop/bootstrap/security-authority';
        assert.equal(guard.Authorize(admin, 'POST', route, {}).ok, true);
        process.env.DESKTOP_ADMIN_REAUTH_REQUIRED = '1';
        assert.equal((await call(route, {}, admin)).data.error, 'ADMIN_REAUTH_REQUIRED');
        for(const action of ['plan-release','recovery/prepare','recovery/apply'])assert.equal((await call('/api/desktop/bootstrap/security-operations/'+action, {}, admin)).data.error, 'ADMIN_REAUTH_REQUIRED');
        assert.equal((await call('/api/desktop/bootstrap/artifacts?component=O&version=1.0.0&fileName=O.exe', {}, admin)).data.error, 'ADMIN_REAUTH_REQUIRED');
        assert.equal((await call('/api/session/reauthenticate', { password: 'wrong' }, admin)).data.error, 'REAUTH_FAILED');
        assert.equal(guard.Authorize(admin, 'POST', route, {}).reason, 'ADMIN_REAUTH_REQUIRED');
        assert.equal((await call('/api/session/reauthenticate', { password: process.env.ADMIN_SECRET }, admin)).status, 200);
        assert.equal(guard.Authorize(admin, 'POST', route, {}).ok, true);
        // Invalid policy body now reaches validation; the reauth gate has opened.
        const result = await call(route, {}, admin); assert.notEqual(result.status, 428); assert.notEqual(result.status, 500);
    });
    await atest('Passkey reauthentication is bound to the initiating session and verifies a real signature', async () => {
        const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), credentialId = crypto.randomBytes(24).toString('base64url');
        state.production.passkeyCredentials.set('fixture', { id: 'fixture', role: 'admin', credentialId, publicKeySpki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), revokedAt: 0, signCount: 0 });
        const begin = await call('/api/session/reauthenticate/passkey/begin', {}, admin); assert.equal(begin.status, 200);
        const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: begin.data.publicKey.challenge, origin: `http://127.0.0.1:${server.address().port}` }));
        const auth = Buffer.alloc(37); crypto.createHash('sha256').update('127.0.0.1').digest().copy(auth); auth[32] = 5; auth.writeUInt32BE(1, 33);
        const proof = { challengeId: begin.data.challengeId, credentialId, clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: crypto.sign('sha256', Buffer.concat([auth, crypto.createHash('sha256').update(client).digest()]), pair.privateKey).toString('base64url') };
        const other = web.CreateSession(req(), 'admin'); assert.equal((await call('/api/session/reauthenticate/passkey/finish', proof, other)).data.error, 'REAUTH_CHALLENGE_INVALID');
        assert.equal((await call('/api/session/reauthenticate/passkey/finish', proof, admin)).status, 200);
        assert.equal((await call('/api/session/reauthenticate/passkey/finish', proof, admin)).data.error, 'REAUTH_CHALLENGE_INVALID');
        state.production.passkeyCredentials.get('fixture').revokedAt = now;
        assert.equal((await call('/api/session', undefined, admin)).status, 401);
    });
    await atest('Actual login endpoint returns 429 with Retry-After and passkey cannot bypass address budget', async () => {
        const headers = { 'X-Forwarded-For': '192.0.2.200' };
        for (let i = 0; i < 20; i++) assert.equal((await call('/api/login', { role: 'admin', password: 'wrong' }, null, headers)).status, 401);
        const blocked = await call('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, null, headers);
        assert.equal(blocked.status, 429); assert.ok(Number(blocked.headers['retry-after']) > 0);
        assert.equal((await call('/api/passkey/login/begin', { role: 'admin' }, null, headers)).status, 429);
    });
    await atest('UI retries a rejected operation once after successful reauthentication, never after cancel', async () => {
        const source = fs.readFileSync(path.join(__dirname, '../public/admin.js'), 'utf8');
        const section = source.slice(source.indexOf('let adminReauthenticationPending'), source.indexOf('\nfunction showLogin()', source.indexOf('async function api(')));
        let calls = [], prompts = 0, cancel = false;
        const context = { session: { csrf: 'csrf' }, dirtyViews: new Set(), currentView: 'x', showLogin() {}, readableApiError: x => x,
            openModal: async () => { prompts++; return cancel ? null : { method: 'password', password: 'test' }; },
            fetch: async url => { calls.push(url); const reauth = url === '/api/session/reauthenticate', reject = !reauth && calls.filter(x => x === url).length % 2 === 1;
                return { status: reject ? 428 : 200, ok: !reject, text: async () => JSON.stringify(reject ? { ok: false, error: 'ADMIN_REAUTH_REQUIRED' } : { ok: true }) }; }
        };
        vm.createContext(context); vm.runInContext(section + '\nglobalThis.run=api;', context);
        await context.run('/danger', { method: 'POST', body: {} }); assert.deepEqual(calls, ['/danger', '/api/session/reauthenticate', '/danger']); assert.equal(prompts, 1);
        calls = []; cancel = true; await assert.rejects(context.run('/danger', { method: 'POST', body: {} }), /취소/); assert.deepEqual(calls, ['/danger']);
    });
    console.log(`WEB AUTH HARDENING PASS: ${tests} behavioral cases (HTTP, crypto fixture, UI VM; no physical passkey/browser claim)`);
} finally {
    Date.now = realNow; web.RevokeAllSessions();
    if (server) await new Promise(resolve => server.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true });
}
})().catch(error => { console.error(error); process.exitCode = 1; });
