'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const net = require('node:net'), crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'game-desktop-http-'));
const adminPassword = 'desktop-http-regression-admin-secret';
const viewerPassword = 'desktop-http-regression-viewer-secret';
const bootstrapFixture = require('./desktop-bootstrap-fixture');
let child, base, nativeProfile, output = '', sequence = 0;
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
    // Admin calls use real HTTP. Native authorization uses pinned TLS only.
    if (['/api/desktop/challenge','/api/desktop/execute'].includes(url)) {
        const json=await require('./tls-request-fixture').Request(nativeProfile,url.endsWith('challenge')?'challenge':'execute',body);
        return {status:json.ok?200:0,json};
    }
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
        VIEWER_SECRET: viewerPassword, DESKTOP_PUBLIC_HOST: '127.0.0.1', DESKTOP_PUBLIC_PORT: String(tcpPort),
        VAPID_PUBLIC_KEY: '', VAPID_PRIVATE_KEY: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { output += data; });
    for (let attempt = 0; attempt < 70; attempt++) {
        if (child.exitCode !== null) throw Error('HTTP server exited: ' + output);
        try { const response = await call('/health'); if (response.status === 200) return; } catch (_) {}
        await delay(70);
    }
    throw Error('HTTP server did not start: ' + output);
}
async function login(role = 'admin') {
    const response = await call('/api/login', { role, password: role === 'admin' ? adminPassword : viewerPassword });
    assert.equal(response.status, 200); return { cookie: response.cookie.split(';')[0], csrf: response.json.csrf };
}
function device(name) {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const exponent = Buffer.from(jwk.e, 'base64url'), modulus = Buffer.from(jwk.n, 'base64url');
    const header = Buffer.alloc(24);
    [0x31415352, 2048, exponent.length, modulus.length, 0, 0].forEach((value, index) => header.writeUInt32LE(value, index * 4));
    const blob = Buffer.concat([header, exponent, modulus]);
    return { name, privateKey: pair.privateKey, publicKey: blob.toString('base64'), deviceId: digest(blob).toUpperCase(), machineId:crypto.randomBytes(32).toString('hex').toUpperCase() };
}
async function signed(device, action, payload) {
    if (device.bootstrap) payload = { ...payload, ...bootstrapFixture.Evidence(device,device.bootstrap), bootstrapSessionId: device.bootstrap.sessionId, bootstrapSessionToken: device.bootstrap.sessionToken };
    const payloadJSON = JSON.stringify(payload), payloadHash = digest(Buffer.from(payloadJSON));
    const requestId = 'HTTP-REQUEST-' + (++sequence);
    const body = { action, requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash };
    const response = await call('/api/desktop/challenge', body); assert.equal(response.status, 200);
    const challenge = response.json.data;
    const canonical = ['GAME-DESKTOP-V1', action, challenge.challengeId, challenge.nonce, requestId,
        device.deviceId, payloadHash, String(challenge.expiresAt)].join('\n');
    assert.equal(challenge.canonical, canonical, 'The actual native wire canonical must match the client construction');
    const signature = crypto.sign('sha256', Buffer.from(canonical), { key: device.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }).toString('base64');
    return { ...body, challengeId: challenge.challengeId, payloadJSON, signature };
}
async function execute(device, action, payload) { return call('/api/desktop/execute', await signed(device, action, payload)); }
async function upload(component, bytes, auth, csrf = true) {
    const headers = { 'Content-Type': 'application/octet-stream' };
    if (auth) { headers.Cookie = auth.cookie; if (csrf) headers['X-CSRF-Token'] = auth.csrf; }
    const response = await fetch(base + '/api/desktop/bootstrap/artifacts?component=' + component + '&version=80.0.0&fileName=Game' + component + '.exe', { method: 'POST', headers, body: bytes, signal: AbortSignal.timeout(5000) });
    return { status: response.status, json: await response.json() };
}
async function uploadBaseline(bytes, auth, csrf = true, fileName = 'ntdll.dll') {
    const headers = { 'Content-Type': 'application/octet-stream' };
    if (auth) { headers.Cookie = auth.cookie; if (csrf) headers['X-CSRF-Token'] = auth.csrf; }
    const response = await fetch(base + '/api/desktop/bootstrap/module-baselines?fileName=' + encodeURIComponent(fileName) + '&label=HTTP-test', { method: 'POST', headers, body: bytes, signal: AbortSignal.timeout(5000) });
    return { status: response.status, json: await response.json() };
}
async function bootstrapDevice(device, auth) {
    const issue = await call('/api/desktop/bootstrap/launchers', { requestId: crypto.randomUUID(), label: device.name }, auth); assert.equal(issue.status, 200);
    const response = await fetch(base + issue.json.downloadUrl, { headers: { Cookie: auth.cookie }, signal: AbortSignal.timeout(5000) }); assert.equal(response.status, 200);
    assert.match(issue.json.downloadName,/^[a-f0-9]{32}\.exe$/);assert.equal(response.headers.get('content-disposition'),'attachment; filename="'+issue.json.downloadName+'"');assert.match(response.headers.get('content-type'), /application\/octet-stream/); assert.match(response.headers.get('cache-control'), /no-store/);
    const launcher = Buffer.from(await response.arrayBuffer()); assert.equal(bootstrapFixture.Config(launcher).launcherId, issue.json.launcherId);
    device.bootstrap = await bootstrapFixture.RemoteSession(device, launcher);
}

(async () => {
    try {
        await start();
        assert.equal((await call('/api/desktop/licenses')).status, 401);
        assert.equal((await call('/api/desktop/licenses', { label: '미인증 요청' })).status, 401);
        for(const route of ['/api/desktop/challenge','/api/desktop/execute']) {
            const retired=await fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
            assert.equal(retired.status,410);
        }
        let auth = await login();
        nativeProfile=(await call('/api/desktop/connect-profile',undefined,auth)).json.profile;
        const viewer = await login('viewer');
        for (const route of ['/api/desktop/bootstrap', '/api/desktop/bootstrap/integrity-reports', '/api/desktop/bootstrap/module-baselines', '/api/desktop/bootstrap/launchers/LA-' + 'A'.repeat(24) + '/download']) {
            assert.equal((await call(route)).status, 401); assert.equal((await call(route, undefined, viewer)).status, 403);
        }
        assert.equal((await upload('A', bootstrapFixture.PE('A'))).status, 401);
        assert.equal((await upload('A', bootstrapFixture.PE('A'), viewer)).status, 403);
        assert.equal((await upload('A', bootstrapFixture.PE('A'), auth, false)).status, 403);
        const invalidPE = await upload('A', Buffer.from('MZ not an executable'), auth); assert.equal(invalidPE.status, 400); assert.equal(invalidPE.json.error, 'BOOTSTRAP_PE_INVALID');
        for (const component of ['A', 'B']) { const bytes = bootstrapFixture.PE(component), published = await upload(component, bytes, auth); assert.equal(published.status, 200); assert.equal(published.json.artifact.sha256, digest(bytes)); }
        const dll = bootstrapFixture.PE('B'), peOffset = dll.readUInt32LE(0x3c);
        dll.writeUInt16LE(dll.readUInt16LE(peOffset + 22) | 0x2000, peOffset + 22);
        assert.equal((await uploadBaseline(dll)).status,401);
        assert.equal((await uploadBaseline(dll,viewer)).status,403);
        assert.equal((await uploadBaseline(dll,auth,false)).status,403);
        assert.equal((await uploadBaseline(bootstrapFixture.PE('B'),auth)).status,400,'EXE renamed DLL must not become trusted module baseline');
        assert.equal((await uploadBaseline(dll,auth,true,'../ntdll.dll')).status,400);
        const baseline=await uploadBaseline(dll,auth);assert.equal(baseline.status,200,JSON.stringify(baseline.json));assert.equal(baseline.json.baseline.fileSha256,digest(dll));
        const baselineList=await call('/api/desktop/bootstrap/module-baselines',undefined,auth);assert.equal(baselineList.status,200);assert.equal(baselineList.json.items.length,1);
        assert.equal((await call('/api/desktop/bootstrap/integrity-reports',undefined,auth)).status,200);
        assert.equal((await call('/api/desktop/bootstrap/launchers', { requestId: crypto.randomUUID() }, auth, { csrf: false })).status, 403);
        assert.equal((await call('/api/desktop/licenses', { label: 'CSRF 없는 요청' }, auth, { csrf: false })).status, 403);
        const empty = await call('/api/desktop/licenses', undefined, auth); assert.equal(empty.status, 200); assert.equal(empty.json.items.length, 0);
        const system = await call('/api/system', undefined, auth); assert.equal(system.status, 200);
        const savedClientVersion = system.json.system.minClientVersion;
        const update = await call('/api/system/version', { protocol: system.json.system.currentProtocolVersion, serverVersion: system.json.system.minServerVersion }, auth);
        assert.equal(update.status, 200, 'Windows version policy must accept an omitted APK field');
        assert.equal(update.json.clientVersion, savedClientVersion);
        assert.equal((await call('/api/system', undefined, auth)).json.system.minClientVersion, savedClientVersion);

        const period = await call('/api/desktop/licenses', {label:'Period rejected',validDays:7},auth);assert.equal(period.status,400);assert.equal(period.json.error,'DESKTOP_SINGLE_USE_ONLY');
        const created = await call('/api/desktop/licenses', { label: 'HTTP 동시 등록 검사', requestId: 'HTTP-ADMIN-CREATE-01' }, auth);
        assert.equal(created.status, 200);
        const id = created.json.license.id, key = created.json.licenseKey;
        assert.match(id,/^[A-F0-9]{24}$/);assert.match(key,/^[A-F0-9]{64}$/);
        assert.equal((await call('/api/desktop/licenses/'+id)).status,401);
        assert.equal((await call('/api/desktop/licenses/'+id,undefined,viewer)).status,403);
        assert.equal((await call('/api/desktop/licenses/'+id,undefined,auth)).json.licenseKey,undefined);
        const devices = [device('Windows A'), device('Windows B')];
        await Promise.all(devices.map(item => bootstrapDevice(item, auth)));
        const packets = await Promise.all(devices.map(item => signed(item, 'redeem', { licenseKey: key, deviceName: item.name, appVersion: '1.0.0' })));
        const race = await Promise.all(packets.map(packet => call('/api/desktop/execute', packet)));
        assert.equal(race.filter(result => result.status === 200).length, 1, 'Only one Windows device can consume one registration key');
        const winnerIndex = race.findIndex(result => result.status === 200), loserIndex = 1 - winnerIndex;
        assert.equal(race[loserIndex].json.ok, false); assert.equal(race[loserIndex].json.error, 'DESKTOP_KEY_USED');
        const winner = devices[winnerIndex], token = race[winnerIndex].json.data.activationToken;
        const replay = await call('/api/desktop/execute', packets[winnerIndex]);
        assert.equal(replay.status, 200); assert.equal(replay.json.data.activationToken, token, 'Exact wire retry returns the same committed result');
        let list = await call('/api/desktop/licenses', undefined, auth); assert.equal(list.status, 200); assert.equal(list.json.items.length, 1);
        assert.equal(list.json.items[0].deviceId, winner.deviceId);
        const detail=await call('/api/desktop/licenses/'+id,undefined,auth);assert.equal(detail.status,200);assert.equal(detail.json.licenseKey,undefined);assert.equal(detail.json.license.status,'USED');
        const active = await call('/api/desktop/licenses?status=USED', undefined, auth); assert.equal(active.status, 200); assert.equal(active.json.items.length, 1);
        const unused = await call('/api/desktop/licenses', { label: 'Global status count', requestId: crypto.randomUUID() }, auth); assert.equal(unused.status, 200);
        const filtered = await call('/api/desktop/licenses?status=USED', undefined, auth); assert.equal(filtered.json.items.length, 1); assert.equal(filtered.json.counts.AVAILABLE, 1); assert.equal(filtered.json.counts.USED, 1);
        const overview = await call('/api/desktop/bootstrap', undefined, auth); assert.equal(overview.status, 200); assert.ok(overview.json.bootstrap.artifacts.A && overview.json.bootstrap.artifacts.B);
        const linked = overview.json.bootstrap.sessions.find(row => row.id === winner.bootstrap.sessionId); assert.equal(linked.licenseId, id); assert.equal(linked.licenseStatus, 'USED'); assert.equal(linked.deviceId, winner.deviceId);
        assert.ok(!JSON.stringify(overview.json).includes(winner.bootstrap.sessionToken));
        assert.ok(!JSON.stringify(list.json).includes(key), 'List must not expose the issued key');
        assert.ok(!JSON.stringify(list.json).includes(token), 'List must not expose the activation token');
        const verify = await execute(winner, 'verify', { activationToken: token, appVersion: '1.0.0' });
        assert.equal(verify.status, 200); assert.ok(verify.json.data.leaseExpiresAt > verify.json.data.serverTime);
        const stolen = await execute(devices[loserIndex], 'verify', { activationToken: token });
        assert.equal(stolen.json.ok, false); assert.equal(stolen.json.error, 'DESKTOP_DEVICE_MISMATCH');
        assert.equal((await call('/api/desktop/licenses/' + id + '/revoke', { reason: 'HTTP 검사 해지' }, auth, { csrf: false })).status, 403);
        const revoked = await call('/api/desktop/licenses/' + id + '/revoke', { reason: 'HTTP 검사 해지' }, auth);
        assert.equal(revoked.status, 200); assert.equal(revoked.json.license.status, 'REVOKED');
        const denied = await execute(winner, 'verify', { activationToken: token });
        assert.equal(denied.json.ok, false); assert.equal(denied.json.error, 'DESKTOP_REVOKED');
        const revokedReplay = await call('/api/desktop/execute', packets[winnerIndex]);
        assert.equal(revokedReplay.json.ok, false); assert.equal(revokedReplay.json.error, 'DESKTOP_REVOKED');

        // PC policy is admin-only and cannot be changed without CSRF.
        const policyKey=(await call('/api/desktop/licenses',{label:'PC policy'},auth)).json.licenseKey;
        const policyDevice=device('Policy Windows');await bootstrapDevice(policyDevice,auth);
        const registered=await execute(policyDevice,'redeem',{licenseKey:policyKey});assert.equal(registered.json.ok,true);
        const policyRoute='/api/desktop/machines/'+policyDevice.machineId;
        const policyBody={requestId:crypto.randomUUID(),reason:'Integration policy check'};
        assert.equal((await call('/api/desktop/machines')).status,401);
        assert.equal((await call('/api/desktop/machines',undefined,viewer)).status,403);
        assert.equal((await call(policyRoute+'/block',policyBody)).status,401);
        assert.equal((await call(policyRoute+'/block',policyBody,viewer)).status,403);
        assert.equal((await call(policyRoute+'/block',policyBody,auth,{csrf:false})).status,403);
        assert.equal((await call(policyRoute+'/block',policyBody,auth)).status,410);
        assert.equal((await call('/api/desktop/machines',undefined,auth)).json.items.find(x=>x.machineId===policyDevice.machineId).source,'SINGLE_USE');
        assert.equal((await execute(policyDevice,'verify',{activationToken:registered.json.data.activationToken})).json.ok,true,'Original one-use owner must remain authorized');
        assert.equal((await call(policyRoute+'/unblock',{...policyBody,requestId:crypto.randomUUID()},auth)).json.machine.blocked,false);
        assert.equal((await execute(policyDevice,'verify',{activationToken:registered.json.data.activationToken})).json.error,'DESKTOP_MACHINE_SESSION_REVOKED');

        await stop(); await start(); auth = await login();
        nativeProfile=(await call('/api/desktop/connect-profile',undefined,auth)).json.profile;
        list = await call('/api/desktop/licenses', undefined, auth);
        assert.equal(list.status, 200); assert.equal(list.json.items.length, 3); assert.equal(list.json.items.find(item => item.id === id).status, 'REVOKED');
        assert.equal((await call('/api/desktop/licenses?status=USED', undefined, auth)).json.items.length, 1);
        assert.equal((await call('/api/desktop/licenses/'+id,undefined,auth)).json.licenseKey,undefined);
        assert.ok(!output.includes(key)&&!output.includes(token),'Issued key and session credentials must not appear in server logs');
        const restartDenied = await execute(winner, 'verify', { activationToken: token });
        assert.equal(restartDenied.json.ok, false); assert.equal(restartDenied.json.error, 'DESKTOP_REVOKED');
        const retryKey = await execute(devices[loserIndex], 'redeem', { licenseKey: key });
        assert.equal(retryKey.json.ok, false); assert.equal(retryKey.json.error, 'DESKTOP_REVOKED');
        console.log('DESKTOP ADMIN HTTP + NATIVE TLS PASS: executable provisioning admin/viewer auth + CSRF, PE validation and pinned launcher download, real encrypted bootstrap, global status totals, session/license linkage, native RSA canonical, redemption race, token binding, replay, revocation and restart durability.');
    } finally { await stop(); fs.rmSync(dataDir, { recursive: true, force: true }); }
})().catch(error => { console.error(error); if (output) console.error(output.slice(-5000)); process.exitCode = 1; });
