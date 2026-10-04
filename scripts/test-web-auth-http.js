'use strict';
// Real HTTP coverage; no dependency on the native license/TLS listener.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'game-web-auth-http-'));
Object.assign(process.env, { DATA_DIR: temporary, STORAGE_ENGINE: 'json', HOST: '127.0.0.1',
    ADMIN_SECRET: 'fixture-http-auth-admin', WEB_ADMIN_TRUSTED_PROXY_IPS: '',
    WEB_ADMIN_PUBLIC_ORIGIN: '', RAILWAY_PUBLIC_DOMAIN: '',
    WEB_ADMIN_LOGIN_MAX_ATTEMPTS: '3', WEB_ADMIN_LOGIN_WINDOW_MS: '900000', HA_ENABLED: '0' });
let server;
let count = 0;
async function test(name, run) { await run(); count++; console.log('PASS ' + name); }
(async () => {
    const temporaryListener = net.createServer();
    await new Promise(resolve => temporaryListener.listen(0, '127.0.0.1', resolve));
    const port = temporaryListener.address().port;
    await new Promise(resolve => temporaryListener.close(resolve));
    const config = require('../config/config'); config.WEB_ADMIN_PORT = port;
    require('../core/utils').EnsureDirs();
    const web = require('../web/webAuth');
    server = require('../web/webServer').StartWebAdmin();
    await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
    const base = 'http://127.0.0.1:' + port;
    async function request(route, body, headers = {}) {
        const response = await fetch(base + route, { method: body === undefined ? 'GET' : 'POST',
            headers: { ...headers, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000) });
        const json = await response.json(); return { status: response.status, headers: response.headers, json };
    }
    let cookie, csrf;
    await test('HTTP login rejects cross-origin and non-object JSON requests', async () => {
        const rejected = await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, { Origin: 'https://evil.invalid' });
        assert.equal(rejected.status, 403); assert.equal(rejected.json.error, 'ORIGIN_NOT_ALLOWED');
        assert.match(rejected.json.problem.title, /ORIGIN_NOT_ALLOWED/); assert.match(rejected.json.problem.next, /WEB_ADMIN_PUBLIC_ORIGIN/);
        assert.equal((await request('/api/login', null)).status, 400);
    });
    await test('HTTP password login preserves the existing cookie and CSRF contract', async () => {
        const response = await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, { 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '1.2.3.4' });
        assert.equal(response.status, 200); assert.equal(response.json.role, 'admin');
        const setCookie = response.headers.get('set-cookie'); assert.match(setCookie, /HttpOnly/); assert.match(setCookie, /SameSite=Strict/); assert.ok(!setCookie.includes('Secure'));
        assert.equal(response.headers.get('strict-transport-security'), null);
        cookie = setCookie.split(';')[0]; csrf = response.json.csrf;
        assert.equal((await request('/api/session', undefined, { Cookie: cookie })).status, 200);
    });
    await test('HTTP logout enforces CSRF and revokes the real session', async () => {
        assert.equal((await request('/api/logout', {}, { Cookie: cookie })).status, 403);
        assert.equal((await request('/api/logout', {}, { Cookie: cookie, 'X-CSRF-Token': csrf, Origin: base })).status, 200);
        assert.equal((await request('/api/session', undefined, { Cookie: cookie })).status, 401);
    });
    await test('HTTP SSE stream closes on revocation without disclosing a later event', async () => {
        const login = await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET });
        cookie = login.headers.get('set-cookie').split(';')[0];
        const response = await fetch(base + '/api/events', { headers: { Cookie: cookie }, signal: AbortSignal.timeout(5000) });
        assert.equal(response.status, 200);
        web.RevokeAllSessions(); require('../web/webEvents').BroadcastEvent({ sentinel: 'SECRET_AFTER_REVOKE' });
        const body = await response.text(); assert.match(body, /event: ready/); assert.match(body, /"expired":true/); assert.ok(!body.includes('SECRET_AFTER_REVOKE'));
    });
    await test('Railway HTTPS proxy login preserves cookie, session GET, CSRF and SSE without trusted proxy headers', async () => {
        process.env.RAILWAY_PUBLIC_DOMAIN = 'game-admin.up.railway.app';
        const headers = { Host: 'game-admin.up.railway.app', Origin: 'https://game-admin.up.railway.app',
            'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '198.51.100.20', 'Sec-Fetch-Site': 'same-origin' };
        try {
            const login = await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, headers);
            assert.equal(login.status, 200); assert.match(login.headers.get('set-cookie'), /; Secure(?:;|$)/);
            assert.equal(login.headers.get('strict-transport-security'), 'max-age=31536000');
            const auth = { Cookie: login.headers.get('set-cookie').split(';')[0] };
            // GET has no Origin, and some proxies rewrite Host to the internal listener.
            assert.equal((await request('/api/session', undefined, { ...auth, Host: 'backend.internal:8080' })).status, 200);
            const eventResponse = await fetch(base + '/api/events', { headers: { ...auth, Host: 'backend.internal:8080' }, signal: AbortSignal.timeout(5000) });
            assert.equal(eventResponse.status, 200);
            const logout = await request('/api/logout', {}, { ...headers, ...auth, Host: 'backend.internal:8080', 'X-CSRF-Token': login.json.csrf });
            assert.equal(logout.status, 200);
            require('../web/webEvents').BroadcastEvent({ sentinel: 'SECRET_AFTER_REVOKE' });
            const events = await eventResponse.text(); assert.match(events, /event: ready/); assert.match(events, /"expired":true/); assert.ok(!events.includes('SECRET_AFTER_REVOKE'));
            assert.equal((await request('/api/session', undefined, { ...auth, Host: headers.Host })).status, 401);
        } finally { process.env.RAILWAY_PUBLIC_DOMAIN = ''; }
    });
    await test('Explicit custom HTTPS origin overrides Railway and permits rewritten Host only for that exact origin', async () => {
        process.env.RAILWAY_PUBLIC_DOMAIN = 'game-admin.up.railway.app';
        process.env.WEB_ADMIN_PUBLIC_ORIGIN = 'https://admin.example:8443';
        const headers = { Host: 'backend.internal:8080', Origin: 'https://admin.example:8443' };
        try {
            for (const origin of ['https://game-admin.up.railway.app', 'https://evil.invalid', 'https://admin.example', 'http://admin.example:8443']) {
                assert.equal((await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, { ...headers, Origin: origin, 'X-Forwarded-Host': 'admin.example:8443', 'X-Forwarded-Proto': 'https' })).status, 403);
            }
            const login = await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, headers);
            assert.equal(login.status, 200); assert.match(login.headers.get('set-cookie'), /; Secure(?:;|$)/);
            const auth = { Cookie: login.headers.get('set-cookie').split(';')[0], 'X-CSRF-Token': login.json.csrf };
            assert.equal((await request('/api/session', undefined, { ...auth, Host: headers.Host })).status, 200);
            assert.equal((await request('/api/logout', {}, { ...headers, ...auth })).status, 200);
            process.env.WEB_ADMIN_PUBLIC_ORIGIN = 'https://admin.example:8443/unexpected/path';
            assert.equal((await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, headers)).status, 403);
        } finally { process.env.RAILWAY_PUBLIC_DOMAIN = ''; process.env.WEB_ADMIN_PUBLIC_ORIGIN = ''; }
    });
    await test('Unconfigured HTTPS custom domains still require explicit origin or proxy trust', async () => {
        const headers = { Host: 'admin.example', Origin: 'https://admin.example', 'X-Forwarded-Host': 'admin.example', 'X-Forwarded-Proto': 'https' };
        const rejected = await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET }, headers);
        assert.equal(rejected.status, 403); assert.equal(rejected.json.error, 'ORIGIN_NOT_ALLOWED');
        assert.match(rejected.json.problem.next, /WEB_ADMIN_PUBLIC_ORIGIN/);
    });
    await test('HTTP failed-password throttle ignores forged proxy IPs and sends Retry-After', async () => {
        for (let i = 0; i < 3; i++) {
            const failed = await request('/api/login', { role: 'admin', password: 'bad' }, { 'X-Forwarded-For': `192.0.2.${i}` });
            assert.equal(failed.status, 401); assert.equal(failed.json.error, 'AUTH_FAILED');
            assert.match(failed.json.problem.title, /로그인/); assert.match(failed.json.problem.next, /비밀번호/);
        }
        const response = await request('/api/login', { role: 'admin', password: process.env.ADMIN_SECRET });
        assert.equal(response.status, 429); assert.equal(response.json.error, 'AUTH_RATE_LIMITED'); assert.ok(Number(response.headers.get('retry-after')) > 0);
        assert.match(response.json.problem.title, /로그인 시도/); assert.ok(response.json.problem.next);
    });
    await test('HTTP listener applies finite header, request and keepalive limits', async () => {
        assert.equal(server.headersTimeout, 15000); assert.equal(server.requestTimeout, 120000);
        assert.equal(server.keepAliveTimeout, 5000); assert.equal(server.maxRequestsPerSocket, 1000);
    });
    console.log(`Web authentication HTTP: ${count} integration checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
    if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    fs.rmSync(temporary, { recursive: true, force: true });
});
