'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), net = require('node:net');
const {spawn, spawnSync} = require('node:child_process');
const endpoint = require('../services/connectEndpoint');
const root = path.resolve(__dirname, '..');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'moaplay-connect-deploy-'));
const adminSecret = 'isolated-deployment-test-admin';
let child, output = '', base, cookie, csrf;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function port() {
    const s = net.createServer(); await new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
    const value = s.address().port; await new Promise(resolve => s.close(resolve)); return value;
}
async function stop() {
    if (!child || child.exitCode !== null) return;
    const done = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM');
    const kill = setTimeout(() => child.kill('SIGKILL'), 3000); await done; clearTimeout(kill);
}
async function request(route, body, authenticated = false) {
    const headers = {};
    if (authenticated) { headers.Cookie = cookie; headers['X-CSRF-Token'] = csrf; }
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(base + route, {method: body === undefined ? 'GET' : 'POST', headers,
        ...(body === undefined ? {} : {body: JSON.stringify(body)}), signal: AbortSignal.timeout(3000)});
    return {status: response.status, body: await response.json(), cookie: response.headers.get('set-cookie')};
}
async function start(httpPort, tcpPort, extra = {}) {
    output = ''; base = 'http://127.0.0.1:' + httpPort;
    child = spawn(process.execPath, ['server.js'], {cwd: root, env: {...process.env,
        DATA_DIR: dataDir, STORAGE_ENGINE: 'json', PORT: String(httpPort), WEB_ADMIN_PORT: String(httpPort),
        CONNECT_TCP_PORT: String(tcpPort), HEALTH_PORT: '0', HA_ENABLED: '0', ADMIN_SECRET: adminSecret,
        DESKTOP_PUBLIC_HOST: '', DESKTOP_PUBLIC_PORT: '', RAILWAY_TCP_PROXY_DOMAIN: 'proxy.example.test',
        RAILWAY_TCP_PROXY_PORT: '17959', RAILWAY_SERVICE_ID: 'DEPLOYMENT-TEST',
        VAPID_PUBLIC_KEY: '', VAPID_PRIVATE_KEY: '', ...extra}, stdio: ['ignore', 'pipe', 'pipe']});
    child.stdout.on('data', chunk => {output += chunk;}); child.stderr.on('data', chunk => {output += chunk;});
    for (let i = 0; i < 80; i++) {
        if (child.exitCode !== null) throw Error('Deployment fixture exited: ' + output);
        try {if ((await request('/readyz')).status === 200) return;} catch (_) {}
        await delay(75);
    }
    throw Error('HTTP readiness never became available: ' + output);
}
async function login() {
    const response = await request('/api/login', {role: 'admin', password: adminSecret});
    assert.equal(response.status, 200); cookie = response.cookie.split(';')[0]; csrf = response.body.csrf;
}
(async () => {
    try {
        assert.equal(endpoint.Resolve({}).ready, false);
        const auto = {RAILWAY_TCP_PROXY_DOMAIN: 'proxy.example.test', RAILWAY_TCP_PROXY_PORT: '17959'};
        assert.equal(endpoint.Resolve(auto).ready, true);
        assert.equal(endpoint.Resolve(auto).source, 'railway');
        const manual = {...auto, DESKTOP_PUBLIC_HOST: '  "Manual.Example.Test"  ', DESKTOP_PUBLIC_PORT: "'12345'"};
        assert.equal(endpoint.Resolve(manual).host, 'manual.example.test');
        assert.equal(endpoint.Resolve(manual).port, 12345);
        assert.equal(endpoint.Resolve(manual).source, 'manual');
        for (const host of ['https://bad.example', 'host.example:17959', 'bad.example/path', '::1', '999.999.999.999', '<script>']) {
            const result = endpoint.Resolve({...manual, DESKTOP_PUBLIC_HOST: host});
            assert.equal(result.ready, false, host); assert.equal(result.source, 'manual');
        }
        for (const value of ['', 'NaN', '0', '65536', '8080.0', '-1', '${{MISSING}}']) {
            assert.equal(endpoint.Resolve({...manual, DESKTOP_PUBLIC_PORT: value}).ready, false, value);
        }
        assert.equal(endpoint.Resolve({DESKTOP_PUBLIC_HOST: 'host.example', PORT: '3000'}).ready, false,
            'An internal listener port must never silently become the exported public port');
        console.log('PASS public endpoint auto detection, explicit precedence, missing/invalid values and no internal-port fallback');

        const legacy = spawnSync(process.execPath, ['-e', "const c=require(require('node:path').resolve('config/config'));console.log(c.CONNECT_TCP_PORT,c.WEB_ADMIN_PORT)"],
            {cwd: root, env: {...process.env, PORT: '31001', WEB_ADMIN_PORT: '31002', CONNECT_TCP_PORT: '', RAILWAY_TCP_APPLICATION_PORT: ''}, encoding: 'utf8'});
        assert.equal(legacy.status, 0); assert.equal(legacy.stdout.trim(), '31001 31002');
        let httpPort = await port(), tcpPort = await port(); while (tcpPort === httpPort) tcpPort = await port();
        await start(httpPort, tcpPort);
        assert.equal((await request('/readyz')).body.revision, 'windows-console-80');
        const head = await fetch(base + '/readyz', {method: 'HEAD', signal: AbortSignal.timeout(3000)});
        assert.equal(head.status, 200); assert.equal(await head.text(), '');
        assert.equal((await request('/api/desktop/connect-profile')).status, 401);
        await login();
        let response = await request('/api/desktop/connect-profile', undefined, true);
        assert.equal(response.status, 200); const pin = response.body.profile.serverKeyId;
        assert.equal(response.body.profile.host, 'proxy.example.test'); assert.equal(response.body.profile.port, 17959);
        assert.equal(response.body.connection.source, 'railway'); assert.equal(response.body.connection.probePortMatches, true);
        assert.equal(response.body.connection.tcpPort, tcpPort); assert.equal(response.body.connection.httpPort, httpPort);
        assert.deepEqual(Object.keys(response.body.profile).sort(), ['host','port','protocol','serverKeyId','serverPublicKey','version']);
        assert.ok(!JSON.stringify(response.body).includes(adminSecret));
        assert.match(output, /Connect public endpoint: proxy\.example\.test:17959 \(railway\)/);
        assert.ok(!output.includes('RAILWAY_HEALTHCHECK_PORT_MISMATCH'));
        console.log('PASS actual separate TCP/HTTP listeners, Railway PORT readiness, authenticated automatic profile export');

        response = await request('/api/system/service/stop', {}, true); assert.equal(response.status, 200);
        assert.equal((await request('/health')).status, 503);
        assert.equal((await request('/readyz')).status, 200, 'Admin service must remain deployable while licenses are disabled');
        assert.equal((await request('/api/desktop/connect-profile', undefined, true)).status, 200);
        await stop();
        await start(httpPort, tcpPort); await login();
        assert.equal((await request('/readyz')).status, 200);
        assert.equal((await request('/health')).status, 503, 'Business stop must stay persisted; readiness does not enable it');
        assert.equal((await request('/api/desktop/connect-profile', undefined, true)).body.profile.serverKeyId, pin);
        console.log('PASS deployment readiness survives business stop and restart without regenerating the server key');

        await stop();
        await start(httpPort, tcpPort, {DESKTOP_PUBLIC_HOST: 'https://wrong.example', DESKTOP_PUBLIC_PORT: '17959'});
        await login(); response = await request('/api/desktop/connect-profile', undefined, true);
        assert.equal(response.status, 503); assert.equal(response.body.error, 'CONNECT_PUBLIC_ENDPOINT_REQUIRED');
        assert.equal(response.body.connection.hostVariable, 'DESKTOP_PUBLIC_HOST');
        assert.equal(response.body.connection.host, 'https://wrong.example');
        assert.match(response.body.message, /호스트 이름만/);
        assert.ok(!JSON.stringify(response.body).includes(adminSecret));
        assert.equal((await request('/readyz')).status, 200, 'Missing export settings must not prevent the admin from deploying');
        console.log('PASS diagnostics show the running values and revision to administrators without leaking other environment variables');
        console.log('CONNECT DEPLOYMENT PASS');
    } finally { await stop(); fs.rmSync(dataDir, {recursive: true, force: true}); }
})().catch(error => {console.error(error); process.exitCode = 1;});
