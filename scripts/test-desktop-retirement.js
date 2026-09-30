'use strict';
// Real HTTP boundary regression: retired mobile workflows cannot be revived by
// an old callback, an administrator cookie, or a stale native TCP connection.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'moaplay-desktop-retirement-'));
process.env.DATA_DIR = temp;
process.env.STORAGE_ENGINE = 'json';
process.env.HA_ENABLED = '0';
const mode = require('../services/desktopMode');
const secret = 'retirement-regression-admin-secret';
let child, output = '';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function port() {
    const server = net.createServer();
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const value = server.address().port;
    await new Promise(resolve => server.close(resolve));
    return value;
}
async function stop() {
    if (!child || child.exitCode !== null) return;
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    await exited; clearTimeout(timer);
}
async function request(base, url, method = 'GET', body, auth) {
    const headers = {};
    if (auth) { headers.Cookie = auth.cookie; headers['X-CSRF-Token'] = auth.csrf; }
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return fetch(base + url, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000), redirect: 'manual' });
}

(async () => {
    try {
        assert.equal(mode.Enabled(), true);
        assert.equal(mode.LegacyTcpEnabled(), false);
        // An old launcher must fail closed even if it manually imports the TCP factory.
        let rejected = '', registered = false;
        require('../core/connection').CreateConnection({ end: text => { rejected = text; }, destroySoon() {}, on() { registered = true; } });
        assert.equal(rejected, 'ERROR|APK_FEATURE_RETIRED\n');
        assert.equal(registered, false);

        require('../core/utils').EnsureDirs();
        const state = require('../core/state');
        const archive = require('../services/member/store').Empty();
        archive.profiles['ARCHIVED-SUBJECT'] = { id: 'USR-AAAAAAAAAAAAAAAAAAAAAAAA', subject: 'ARCHIVED-SUBJECT', nickname: '보관 회원', balance: 13579, points: 2468, recentServices: Array.from({ length: 25 }, (_, i) => ({ id: 'legacy-' + i, at: i + 1 })) };
        archive.settings.retirementProbe = 'preserve-exactly';
        state.memberHub = structuredClone(archive);
        const db = require('../storage/database');
        const seed = db.BuildDatabaseObject();
        fs.writeFileSync(path.join(temp, 'relay-identities.json'), JSON.stringify(seed));
        const webPort = await port(), relayPort = await port();
        child = spawn(process.execPath, ['server.js'], { cwd: root, env: { ...process.env, PORT: String(relayPort), CONNECT_TCP_PORT: String(relayPort), WEB_ADMIN_PORT: String(webPort), HEALTH_PORT: '0', ADMIN_SECRET: secret, ENABLE_LEGACY_TCP_ADMIN: '1', DESKTOP_ALLOW_HTTP_LOOPBACK: '1', VAPID_PUBLIC_KEY: '', VAPID_PRIVATE_KEY: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
        child.stdout.on('data', data => { output += data; });
        child.stderr.on('data', data => { output += data; });
        const base = 'http://127.0.0.1:' + webPort;
        let ready = false;
        for (let attempt = 0; attempt < 60; attempt++) {
            if (child.exitCode !== null) throw Error('Server exited: ' + output);
            try { const response = await request(base, '/health'); ready = [200, 503].includes(response.status); if (ready) break; } catch (_) {}
            await delay(80);
        }
        assert.ok(ready, output);
        await new Promise((resolve, reject) => {
            const socket = net.connect(relayPort, '127.0.0.1');let reply='';
            socket.setTimeout(3000,()=>{socket.destroy();reject(Error('Legacy plaintext must be rejected'));});
            socket.once('connect', () => socket.write('HELLO|CLIENT|old-apk\n'));
            socket.on('data',data=>{reply+=data.toString();});socket.once('error',error=>{if(error.code!=='ECONNRESET')reject(error);});
            socket.once('close',()=>{try{assert.equal(reply,'','The new encrypted listener never authorizes a legacy frame');resolve();}catch(error){reject(error);}});
        });

        const retired = [
            '/member/oauth/open/old', '/member/oauth/callback/google?code=old', '/member/oauth/unlink/kakao',
            '/game-download/old-token', '/pay/return/old', '/api/member', '/api/member/action',
            '/api/licenses', '/api/licenses/OLD/qr', '/api/qr-auth', '/api/qr-auth/approve',
            '/api/clients', '/api/clients/1234567890123456/biometric/reset', '/api/build-sessions',
            '/api/build-bindings/1234567890123456/rebind', '/api/games/upload', '/api/support',
            '/api/reinstall-blocks', '/api/pairing/repair', '/api/failover', '/api/user-dashboard',
            '/api/control/client/1234567890123456/command', '/api/request-recovery/clients/1234567890123456'
        ];
        for (const url of retired) for (const method of ['GET', 'POST']) {
            const response = await request(base, url, method, method === 'POST' ? { action: 'identity.start', provider: 'google' } : undefined);
            assert.equal(response.status, 410, method + ' ' + url);
            assert.equal((await response.json()).error, 'APK_FEATURE_RETIRED');
        }
        assert.equal((await request(base, '/api/dashboard')).status, 401);
        assert.equal((await request(base, '/api/desktop/licenses')).status, 401, 'Desktop license administration is not a public member API');

        const login = await request(base, '/api/login', 'POST', { role: 'admin', password: secret });
        assert.equal(login.status, 200);
        const auth = { cookie: login.headers.get('set-cookie').split(';')[0], csrf: (await login.json()).csrf };
        for (const url of ['/api/dashboard', '/api/system', '/api/ha/status', '/api/backups', '/api/security/dashboard', '/api/reports/daily']) {
            assert.equal((await request(base, url, 'GET', undefined, auth)).status, 200, url);
        }
        for (const url of ['/api/releases/rollout', '/api/control/security/challenge', '/api/control/features/device', '/api/production/diagnostics']) {
            assert.equal((await request(base, url, 'POST', { type: 'CLIENT', id: '1234567890123456' }, auth)).status, 410, url);
        }
        assert.equal((await request(base, '/api/releases/upload?type=CLIENT&fileName=old.apk', 'POST', {}, auth)).status, 410);
        // A correctly-shaped challenge plus an administrator cookie still
        // needs proof from the Windows device's private RSA key.
        const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const jwk = pair.publicKey.export({ format: 'jwk' });
        const exponent = Buffer.from(jwk.e, 'base64url'), modulus = Buffer.from(jwk.n, 'base64url');
        const header = Buffer.alloc(24); [0x31415352, 2048, exponent.length, modulus.length, 0, 0].forEach((value, i) => header.writeUInt32LE(value, i * 4));
        const blob = Buffer.concat([header, exponent, modulus]);
        const payloadJSON = JSON.stringify({ activationToken: 'DLA-' + 'a'.repeat(43) });
        const proof = { action: 'verify', requestId: 'retirement-proof-check', deviceId: crypto.createHash('sha256').update(blob).digest('hex').toUpperCase(), publicKey: blob.toString('base64'), payloadHash: crypto.createHash('sha256').update(payloadJSON).digest('hex') };
        const challengeResponse = await request(base, '/api/desktop/challenge', 'POST', proof, auth);
        assert.equal(challengeResponse.status, 200, 'Native challenge is separate from admin-cookie authentication');
        const challenge = (await challengeResponse.json()).data;
        const forged = await request(base, '/api/desktop/execute', 'POST', { ...proof, challengeId: challenge.challengeId, payloadJSON, signature: Buffer.alloc(256).toString('base64') }, auth);
        assert.equal(forged.status, 401);
        assert.equal((await forged.json()).error, 'DESKTOP_PROOF_INVALID', 'Administrator cookie cannot replace Windows private-key proof');


        // Give the scheduler an opportunity to run: no old QR, pairing or member
        // migration may edit the archived APK data on startup or maintenance ticks.
        await delay(1100);
        await stop();
        const saved = JSON.parse(fs.readFileSync(path.join(temp, 'relay-identities.json'), 'utf8'));
        assert.deepEqual(saved.memberHub, archive, 'Archived member data must survive startup, scheduler and shutdown without a member migration');
        console.log('DESKTOP RETIREMENT PASS: real HTTP 410 boundaries, authenticated admin preserved, desktop auth separation, no legacy TCP listener, unchanged member archive.');
    } finally {
        await stop();
        fs.rmSync(temp, { recursive: true, force: true });
    }
})().catch(error => { console.error(error); if (output) console.error(output.slice(-6000)); process.exitCode = 1; });
