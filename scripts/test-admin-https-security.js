"use strict";
// Real loopback HTTP/TLS sockets, real dispatcher, JSON persistence, synthetic
// ES256 authenticator. Openssl creates a temporary test-only identity.
const assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os');
const path = require('node:path'), http = require('node:http'), https = require('node:https'), crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-admin-https-'));
Object.assign(process.env, { DATA_DIR: tmp, STORAGE_ENGINE: 'json', HA_ENABLED: '0',
    ADMIN_SECRET: 'temporary-test-admin-secret-https-only', WEB_ADMIN_TRANSPORT: 'proxy',
    WEB_ADMIN_TRUSTED_PROXIES: '127.0.0.1/32,::1/128', WEB_ADMIN_REQUIRE_HTTPS: '1', WEB_ADMIN_SECURE_COOKIE: '1',
    WEBAUTHN_RP_ID: 'localhost', WEBAUTHN_ORIGIN: 'https://localhost' });
require('../core/utils').EnsureDirs();
const transport = require('../web/webTransport'), web = require('../web/webAuth');
const { RequestHandler } = require('../web/webServer'), wire = require('./passkey-wire-fixture');
let tests = 0, proxy, direct, cert, auth, keyPair, credentialId;
async function test(name, fn) { await fn(); tests++; console.log('PASS ' + name); }
const handler = (req, res) => Promise.resolve(RequestHandler(req, res)).catch(error => { res.statusCode = 500; res.end(JSON.stringify({ error: error.message })); });
function call(server, { route = '/api/login', body, headers = {}, cookie, csrf, secure = false, localAddress } = {}) {
    return new Promise((resolve, reject) => {
        const bytes = body === undefined ? null : Buffer.from(JSON.stringify(body));
        const client = secure ? https : http;
        const request = client.request({ host: '127.0.0.1', port: server.address().port, path: route,
            method: bytes ? 'POST' : 'GET', ...(localAddress ? { localAddress } : {}),
            ...(secure ? { ca: cert, servername: 'localhost', rejectUnauthorized: true } : {}),
            headers: { Host: secure ? 'localhost:' + server.address().port : 'localhost',
                ...(bytes ? { 'Content-Type': 'application/json', 'Content-Length': bytes.length } : {}),
                ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...headers }
        }, res => { let text = ''; res.on('data', b => text += b); res.on('end', () => {
            let body; try { body = JSON.parse(text); } catch (_) { body = text; }
            resolve({ status: res.statusCode, headers: res.headers, body });
        }); });
        request.setTimeout(5000, () => request.destroy(Error('TEST_TIMEOUT'))); request.on('error', reject); request.end(bytes);
    });
}
const listen = t => new Promise((resolve, reject) => { t.server.once('error', reject); t.server.listen(0, t.host, resolve); });
const close = s => s ? new Promise(resolve => { s.closeAllConnections?.(); s.close(resolve); }) : Promise.resolve();
(async () => { try {
    await test('Safe default binds plaintext only to loopback', async () => {
        assert.deepEqual(transport.Settings({}).host, '127.0.0.1');
        const t = transport.CreateServer(handler, {}); proxy = t.server; await listen(t);
        assert.equal(proxy.address().address, '127.0.0.1');
    });
    await test('Public/private wildcard HTTP binding and old security opt-outs are refused at startup', () => {
        for (const host of ['0.0.0.0', '::', '10.0.0.2', '192.0.2.1', 'localhost'])
            assert.throws(() => transport.Settings({ WEB_ADMIN_HOST: host }));
        for (const name of ['WEB_ADMIN_REQUIRE_HTTPS', 'WEB_ADMIN_SECURE_COOKIE']) assert.throws(() => transport.Settings({ [name]: '0' }));
        for (const rules of ['', '0.0.0.0/0', '::/0', '10.0.0.0/8']) assert.throws(() => transport.Settings({ WEB_ADMIN_TRUSTED_PROXIES: rules }));
        assert.throws(() => transport.Settings({ WEB_ADMIN_TRANSPORT: 'direct', WEB_ADMIN_TRUSTED_PROXIES: '127.0.0.1' }));
    });
    await test('Plain HTTP admin login, passkey, UI, session and event paths all return 403', async () => {
        for (const route of ['/api/login', '/api/passkey/login/begin', '/api/session', '/api/events', '/', '/admin.js']) {
            const out = await call(proxy, { route, ...(/login/.test(route) ? { body: { role: 'admin', password: process.env.ADMIN_SECRET } } : {}) });
            assert.equal(out.status, 403, route); assert.equal(out.body.error, 'ADMIN_HTTPS_REQUIRED');
            assert.equal(out.headers['set-cookie'], undefined); assert.equal(out.headers['strict-transport-security'], undefined);
        }
    });
    await test('No raw HTTP helper can create/authenticate a session; clear cookies stay Secure', () => {
        const req = { socket: { remoteAddress: '192.0.2.1', encrypted: false }, headers: {} };
        assert.equal(web.CreateSession(req, 'admin'), null); assert.equal(web.Authenticate(req), null);
        assert.match(web.SessionCookie(req, '', 0), /; Secure/);
    });
    await test('Spoofed, duplicated or downgraded forwarding does not authenticate HTTPS', async () => {
        const body = { role: 'admin', password: process.env.ADMIN_SECRET };
        for (const proto of ['http', 'https,http', 'https, https']) assert.equal((await call(proxy, { body, headers: { 'X-Forwarded-Proto': proto } })).status, 403);
        const fake = { socket: { remoteAddress: '192.0.2.1' }, headers: { 'x-forwarded-proto': 'https' } };
        assert.equal(web.IsHttps(fake), false);
        fake.socket = { remoteAddress: '127.0.0.1', encrypted: true }; fake.headers['x-forwarded-proto'] = 'http';
        assert.equal(web.IsHttps(fake), false);
    });
    await test('Trusted on-host HTTPS proxy preserves password login and secure cookie behavior', async () => {
        const result = await call(proxy, { body: { role: 'admin', password: process.env.ADMIN_SECRET }, headers: { 'X-Forwarded-Proto': 'https' } });
        assert.equal(result.status, 200); const c = result.headers['set-cookie'][0];
        for (const value of ['Secure', 'HttpOnly', 'SameSite=Strict']) assert.ok(c.includes(value));
        const cookie = c.split(';')[0];
        assert.equal((await call(proxy, { route: '/api/session', cookie })).status, 403);
        assert.equal((await call(proxy, { route: '/api/session', cookie, headers: { 'X-Forwarded-Proto': 'https' } })).status, 200);
        assert.equal(result.headers['strict-transport-security'], 'max-age=31536000');
    });
    await test('Direct TLS requires a complete valid identity and never falls back to HTTP', async () => {
        assert.throws(() => transport.CreateServer(handler, { WEB_ADMIN_TRANSPORT: 'direct' }), /TLS_FILES/);
        const certFile = path.join(tmp, 'test-cert.pem'), keyFile = path.join(tmp, 'test-key.pem');
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', keyFile, '-out', certFile], { stdio: 'ignore', timeout: 10000 });
        cert = fs.readFileSync(certFile);
        const t = transport.CreateServer(handler, { WEB_ADMIN_TRANSPORT: 'direct', WEB_ADMIN_HOST: '127.0.0.1', WEB_ADMIN_TLS_CERT_FILE: certFile, WEB_ADMIN_TLS_KEY_FILE: keyFile });
        direct = t.server; await listen(t);
        process.env.WEBAUTHN_ORIGIN = 'https://localhost:' + direct.address().port;
        fs.writeFileSync(path.join(tmp, 'bad-key.pem'), 'not a private key');
        assert.throws(() => transport.CreateServer(handler, { WEB_ADMIN_TRANSPORT: 'direct', WEB_ADMIN_TLS_CERT_FILE: certFile, WEB_ADMIN_TLS_KEY_FILE: path.join(tmp, 'bad-key.pem') }));
    });
    await test('Actual TLS login works with certificate verification enabled; plaintext on that port fails', async () => {
        const result = await call(direct, { secure: true, body: { role: 'admin', password: process.env.ADMIN_SECRET } });
        assert.equal(result.status, 200); auth = { cookie: result.headers['set-cookie'][0].split(';')[0], csrf: result.body.csrf };
        assert.equal((await call(direct, { secure: true, route: '/api/session', ...auth })).status, 200);
        let rejected = false;
        try { const out = await call(direct, { body: { role: 'admin', password: process.env.ADMIN_SECRET } }); rejected = out.status !== 200; }
        catch (_) { rejected = true; } assert.equal(rejected, true);
    });
    await test('Real TLS registration routes persist the parsed credential with the current UI payload', async () => {
        // Password OR passkey: first enrollment requires recent authentication,
        // but no separate console token. TLS, CSRF and wire parsing stay intact.
        const begin = await call(direct, { secure: true, route: '/api/production/passkeys/register/begin', body: {}, ...auth });
        assert.equal(begin.status, 200, JSON.stringify(begin.body)); keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const value = wire.Registration('localhost', keyPair.publicKey); credentialId = value.credentialId;
        delete value.publicKeySpki; delete value.authenticatorData;
        const body = { ...value, challengeId: begin.body.challengeId, name: 'Synthetic TLS test key',
            clientDataJSON: wire.b64(JSON.stringify({ type: 'webauthn.create', challenge: begin.body.publicKey.challenge, origin: process.env.WEBAUTHN_ORIGIN })) };
        const out = await call(direct, { secure: true, route: '/api/production/passkeys/register/finish', body, ...auth });
        assert.equal(out.status, 200, JSON.stringify(out.body)); assert.equal(out.body.credential.verificationVersion, 2);
    });
    await test('Real TLS passkey login verifies a fresh ES256 assertion and issues a server session', async () => {
        const begin = await call(direct, { secure: true, route: '/api/passkey/login/begin', body: { role: 'admin' } }); assert.equal(begin.status, 200);
        const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: begin.body.publicKey.challenge, origin: process.env.WEBAUTHN_ORIGIN }));
        const data = wire.Auth('localhost');
        const body = { challengeId: begin.body.challengeId, credentialId, authenticatorData: wire.b64(data), clientDataJSON: wire.b64(client),
            signature: wire.b64(crypto.sign('sha256', Buffer.concat([data, crypto.createHash('sha256').update(client).digest()]), keyPair.privateKey)) };
        const out = await call(direct, { secure: true, route: '/api/passkey/login/finish', body }); assert.equal(out.status, 200, JSON.stringify(out.body));
        assert.match(out.headers['set-cookie'][0], /; Secure/);
        assert.equal((await call(direct, { secure: true, route: '/api/passkey/login/finish', body })).status, 401);
    });
    console.log(`ADMIN HTTPS SECURITY PASS: ${tests} cases; real HTTP/TLS + JSON persistence; no physical passkey/browser/WAN claim`);
} catch (error) { console.error(error); process.exitCode = 1; }
finally { web.RevokeAllSessions(); await close(proxy); await close(direct); fs.rmSync(tmp, { recursive: true, force: true }); }
})();
