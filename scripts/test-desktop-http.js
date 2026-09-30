'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const net = require('node:net'), crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'moaplay-desktop-http-'));
const adminPassword = 'desktop-http-regression-admin-secret';
let child, base, output = '', sequence = 0;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

async function freePort() {
    const server = net.createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
async function stop() {
    if (!child || child.exitCode !== null) return;
    const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000); await exited; clearTimeout(timer);
}
async function call(url, body, auth, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (auth) { headers.Cookie = auth.cookie; if (options.csrf !== false) headers['X-CSRF-Token'] = auth.csrf; }
    const response = await fetch(base + url, { method: body === undefined ? 'GET' : 'POST', headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'manual', signal: AbortSignal.timeout(5000) });
    const json = await response.json(); return { status: response.status, json, cookie: response.headers.get('set-cookie') };
}
async function start() {
    const port = await freePort(); base = 'http://127.0.0.1:' + port;
    let tcpPort = await freePort();
    while (tcpPort === port) tcpPort = await freePort();
    child = spawn(process.execPath, ['server.js'], { cwd: root, env: { ...process.env, DATA_DIR: dataDir,
        STORAGE_ENGINE: 'json', PORT: String(tcpPort), CONNECT_TCP_PORT: String(tcpPort), WEB_ADMIN_PORT: String(port), HEALTH_PORT: '0', HA_ENABLED: '0',
        ADMIN_SECRET: adminPassword, DESKTOP_ALLOW_HTTP_LOOPBACK: '1', DESKTOP_TRUST_PROXY: '0',
        VAPID_PUBLIC_KEY: '', VAPID_PRIVATE_KEY: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { output += data; });
    for (let attempt = 0; attempt < 70; attempt++) {
        if (child.exitCode !== null) throw Error('HTTP server exited: ' + output);
        try { const response = await call('/health'); if (response.status === 200) return; } catch (_) {}
        await delay(70);
    }
    throw Error('HTTP server did not start: ' + output);
}
async function login() {
    const response = await call('/api/login', { role: 'admin', password: adminPassword });
    assert.equal(response.status, 200); return { cookie: response.cookie.split(';')[0], csrf: response.json.csrf };
}
function device(name) {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const exponent = Buffer.from(jwk.e, 'base64url'), modulus = Buffer.from(jwk.n, 'base64url');
    const header = Buffer.alloc(24);
    [0x31415352, 2048, exponent.length, modulus.length, 0, 0].forEach((value, index) => header.writeUInt32LE(value, index * 4));
    const blob = Buffer.concat([header, exponent, modulus]);
    return { name, privateKey: pair.privateKey, publicKey: blob.toString('base64'), deviceId: digest(blob).toUpperCase() };
}
async function signed(device, action, payload) {
    const payloadJSON = JSON.stringify(payload), payloadHash = digest(Buffer.from(payloadJSON));
    const requestId = 'HTTP-REQUEST-' + (++sequence);
    const body = { action, requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash };
    const response = await call('/api/desktop/challenge', body); assert.equal(response.status, 200);
    const challenge = response.json.data;
    const canonical = ['MOAPLAY-DESKTOP-V1', action, challenge.challengeId, challenge.nonce, requestId,
        device.deviceId, payloadHash, String(challenge.expiresAt)].join('\n');
    assert.equal(challenge.canonical, canonical, 'The actual native wire canonical must match the client construction');
    const signature = crypto.sign('sha256', Buffer.from(canonical), { key: device.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }).toString('base64');
    return { ...body, challengeId: challenge.challengeId, payloadJSON, signature };
}
async function execute(device, action, payload) { return call('/api/desktop/execute', await signed(device, action, payload)); }

(async () => {
    try {
        await start();
        assert.equal((await call('/api/desktop/licenses')).status, 401);
        assert.equal((await call('/api/desktop/licenses', { label: '미인증 요청' })).status, 401);
        let auth = await login();
        assert.equal((await call('/api/desktop/licenses', { label: 'CSRF 없는 요청' }, auth, { csrf: false })).status, 403);
        const empty = await call('/api/desktop/licenses', undefined, auth); assert.equal(empty.status, 200); assert.equal(empty.json.items.length, 0);
        const system = await call('/api/system', undefined, auth); assert.equal(system.status, 200);
        const savedClientVersion = system.json.system.minClientVersion;
        const update = await call('/api/system/version', { protocol: system.json.system.currentProtocolVersion, serverVersion: system.json.system.minServerVersion }, auth);
        assert.equal(update.status, 200, 'Windows version policy must accept an omitted APK field');
        assert.equal(update.json.clientVersion, savedClientVersion);
        assert.equal((await call('/api/system', undefined, auth)).json.system.minClientVersion, savedClientVersion);

        const created = await call('/api/desktop/licenses', { label: 'HTTP 동시 등록 검사', validDays: 7, requestId: 'HTTP-ADMIN-CREATE-01' }, auth);
        assert.equal(created.status, 200);
        const id = created.json.license.id, key = created.json.licenseKey;
        const devices = [device('Windows A'), device('Windows B')];
        const packets = await Promise.all(devices.map(item => signed(item, 'redeem', { licenseKey: key, deviceName: item.name, appVersion: '1.0.0' })));
        const race = await Promise.all(packets.map(packet => call('/api/desktop/execute', packet)));
        assert.equal(race.filter(result => result.status === 200).length, 1, 'Only one Windows device can consume one registration key');
        const winnerIndex = race.findIndex(result => result.status === 200), loserIndex = 1 - winnerIndex;
        assert.equal(race[loserIndex].status, 409); assert.equal(race[loserIndex].json.error, 'DESKTOP_KEY_USED');
        const winner = devices[winnerIndex], token = race[winnerIndex].json.data.activationToken;
        const replay = await call('/api/desktop/execute', packets[winnerIndex]);
        assert.equal(replay.status, 200); assert.equal(replay.json.data.activationToken, token, 'Exact wire retry returns the same committed result');
        let list = await call('/api/desktop/licenses', undefined, auth); assert.equal(list.status, 200); assert.equal(list.json.items.length, 1);
        assert.equal(list.json.items[0].deviceId, winner.deviceId);
        const active = await call('/api/desktop/licenses?status=ACTIVE', undefined, auth); assert.equal(active.status, 200); assert.equal(active.json.items.length, 1);
        assert.ok(!JSON.stringify(list.json).includes(key), 'List must not expose the issued key');
        assert.ok(!JSON.stringify(list.json).includes(token), 'List must not expose the activation token');
        const verify = await execute(winner, 'verify', { activationToken: token, appVersion: '1.0.0' });
        assert.equal(verify.status, 200); assert.ok(verify.json.data.leaseExpiresAt > verify.json.data.serverTime);
        const stolen = await execute(devices[loserIndex], 'verify', { activationToken: token });
        assert.equal(stolen.status, 403); assert.equal(stolen.json.error, 'DESKTOP_DEVICE_MISMATCH');
        assert.equal((await call('/api/desktop/licenses/' + id + '/revoke', { reason: 'HTTP 검사 해지' }, auth, { csrf: false })).status, 403);
        const revoked = await call('/api/desktop/licenses/' + id + '/revoke', { reason: 'HTTP 검사 해지' }, auth);
        assert.equal(revoked.status, 200); assert.equal(revoked.json.license.status, 'REVOKED');
        const denied = await execute(winner, 'verify', { activationToken: token });
        assert.equal(denied.status, 403); assert.equal(denied.json.error, 'DESKTOP_REVOKED');
        const revokedReplay = await call('/api/desktop/execute', packets[winnerIndex]);
        assert.equal(revokedReplay.status, 403); assert.equal(revokedReplay.json.error, 'DESKTOP_REVOKED');

        await stop(); await start(); auth = await login();
        list = await call('/api/desktop/licenses', undefined, auth);
        assert.equal(list.status, 200); assert.equal(list.json.items.length, 1); assert.equal(list.json.items[0].status, 'REVOKED');
        assert.equal((await call('/api/desktop/licenses?status=ACTIVE', undefined, auth)).json.items.length, 0);
        const restartDenied = await execute(winner, 'verify', { activationToken: token });
        assert.equal(restartDenied.status, 403); assert.equal(restartDenied.json.error, 'DESKTOP_REVOKED');
        const retryKey = await execute(devices[loserIndex], 'redeem', { licenseKey: key });
        assert.equal(retryKey.status, 403); assert.equal(retryKey.json.error, 'DESKTOP_REVOKED');
        console.log('DESKTOP HTTP PASS: admin auth + CSRF, omitted APK policy field, native RSA canonical, two-device redemption race, token binding, replay, revocation and restart durability.');
    } finally { await stop(); fs.rmSync(dataDir, { recursive: true, force: true }); }
})().catch(error => { console.error(error); if (output) console.error(output.slice(-5000)); process.exitCode = 1; });
