'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const net = require('node:net'), crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'game-workspace-http-'));
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


let passed=0;
async function test(name,fn){await fn();passed++;console.log('PASS '+name);}
async function until(fn){for(let i=0;i<100;i++){const r=await fn();if(r)return r;await delay(100);}throw Error('TEST_WAIT_TIMEOUT');}
(async()=>{try{
 await start();let auth=await login(),viewer=await login('viewer');
 const w='/api/desktop/workspace';let job,licenseIds=[];
 await test('New workspace routes require administrator authentication',async()=>{for(const p of ['/licenses','/summary','/jobs','/storage']){assert.equal((await call(w+p)).status,401);assert.equal((await call(w+p,undefined,viewer)).status,403);assert.equal((await call(w+p,undefined,auth)).status,200);}});
 await test('Workspace mutation rejects missing CSRF and unknown fields',async()=>{assert.equal((await call(w+'/jobs/preview',{kind:'CREATE',count:1,prefix:'HTTP'},auth,{csrf:false})).status,403);const bad=await call(w+'/jobs/preview',{kind:'CREATE',count:1,permit:true},auth);assert.equal(bad.status,400);assert.ok(bad.json.problem?.next);});
 await test('HTTP preview causes no creation; commit is receipt-idempotent',async()=>{const p=await call(w+'/jobs/preview',{kind:'CREATE',count:3,prefix:'HTTP'},auth);assert.equal(p.status,200);assert.equal((await call(w+'/licenses',undefined,auth)).json.items.length,0);const body={planId:p.json.planId,requestId:crypto.randomUUID()},c=await call(w+'/jobs',body,auth);assert.equal(c.status,200);job=c.json;assert.equal((await call(w+'/jobs',body,auth)).json.id,job.id);});
 await test('Committed jobs finish on the server after browser logout',async()=>{assert.equal((await call('/api/logout',{},auth)).status,200);await delay(1200);auth=await login();const j=await until(async()=>{const v=(await call(w+'/jobs',undefined,auth)).json.items.find(x=>x.id===job.id);return v?.status==='DONE'&&v;});assert.equal(j.done,3);licenseIds=j.items.map(x=>x.result.license.id);assert.equal(new Set(licenseIds).size,3);});
 await test('Metadata saves, server search and export do not expose credentials',async()=>{const id=licenseIds[0],r=await call(w+'/licenses/'+id+'/metadata',{expectedRevision:0,note:'웹 작업 메모',tags:['HTTP']},auth);assert.equal(r.status,200);assert.equal((await call(w+'/licenses?q=HTTP&pageSize=2',undefined,auth)).json.items.length,2);const bad=await call(w+'/licenses/'+id+'/metadata',{expectedRevision:0,note:'stale',tags:[]},auth);assert.equal(bad.status,409);const p=await call(w+'/jobs/preview',{kind:'EXPORT',ids:licenseIds},auth),j=await call(w+'/jobs',{planId:p.json.planId,requestId:crypto.randomUUID()},auth);await until(async()=>((await call(w+'/jobs',undefined,auth)).json.items.find(x=>x.id===j.json.id).status==='DONE'));const out=await call(w+'/jobs/'+j.json.id+'/export',undefined,auth);assert.equal(out.json.items.length,3);for(const secret of ['licenseKey','activationToken','sessionToken','keyHash'])assert.ok(!JSON.stringify(out.json).includes(secret));assert.equal((await call(w+'/jobs/'+j.json.id+'/export',undefined,viewer)).status,403);});
 let resumable;
 await test('An interrupted job resumes after a real server process restart',async()=>{const p=await call(w+'/jobs/preview',{kind:'CREATE',count:12,prefix:'RESTART'},auth);resumable=(await call(w+'/jobs',{planId:p.json.planId,requestId:crypto.randomUUID()},auth)).json.id;await delay(120);await stop();await start();auth=await login();const done=await until(async()=>{const x=(await call(w+'/jobs',undefined,auth)).json.items.find(x=>x.id===resumable);return x?.status==='DONE'&&x;});assert.equal(done.done,12);assert.equal(new Set(done.items.map(x=>x.result.license.id)).size,12);assert.equal((await call(w+'/licenses?q=RESTART',undefined,auth)).json.filteredCount,12);});
 nativeProfile=(await call('/api/desktop/connect-profile',undefined,auth)).json.profile;
 let candidates={};
 await test('Duplicate candidate upload reuses the same verified bytes instead of creating a second artifact',async()=>{for(const c of ['A','B']){const bytes=bootstrapFixture.PE(c,c==='B'?'manual key console':'user launcher');const one=await upload(c,bytes,auth),two=await upload(c,bytes,auth);assert.equal(one.status,200);assert.equal(two.status,200);assert.equal(two.json.artifact.id,one.json.artifact.id);candidates[c]=one.json.artifact;}});
 await test('New candidates are inactive until explicit validated pair publication',async()=>{const op='/api/desktop/bootstrap/security-operations';const p=await call(op+'/preview-pair',{aId:candidates.A.id,bId:candidates.B.id},auth);assert.equal(p.json.preview.eligible,true);const r=await call(op+'/activate',{aId:candidates.A.id,bId:candidates.B.id,expectedRevision:p.json.preview.operationsRevision,expectedPolicyRevision:p.json.preview.policyRevision},auth);assert.equal(r.status,200);});
 let issued,dev,manualKey;
 await test('A issuance needs no selected license and does not consume a key',async()=>{const before=(await call(w+'/licenses',undefined,auth)).json.filteredCount;const result=await call('/api/desktop/bootstrap/launchers',{requestId:crypto.randomUUID(),label:'User console'},auth);assert.equal(result.status,200,JSON.stringify(result.json));issued=result.json;assert.ok(issued.launcherId);assert.equal((await call(w+'/licenses',undefined,auth)).json.filteredCount,before);const key=await call('/api/desktop/licenses',{requestId:crypto.randomUUID(),label:'Manual key after A issuance'},auth);assert.equal(key.status,200,JSON.stringify(key.json));manualKey=key.json.licenseKey;licenseIds[0]=key.json.license.id;});
 await test('Real encrypted TLS bootstrap and signed redeem accept the entered KEY, not the old automatic marker',async()=>{const response=await fetch(base+issued.downloadUrl,{headers:{Cookie:auth.cookie}}),bytes=Buffer.from(await response.arrayBuffer());assert.equal(response.status,200);assert.ok(!JSON.stringify(bootstrapFixture.Config(bytes)).includes(licenseIds[0]));dev=device('Workspace user');dev.bootstrap=await bootstrapFixture.RemoteSession(dev,bytes);const marker=await execute(dev,'redeem',{licenseKey:'SERVER_ASSIGNED_V1',appVersion:'92.0'});assert.equal(marker.json.ok,false);assert.equal(marker.json.error,'DESKTOP_KEY_INVALID');const p=await signed(dev,'redeem',{licenseKey:manualKey,appVersion:'92.0'}),invalid={...p,signature:'A'.repeat(342)+'=='};const bad=await call('/api/desktop/execute',invalid);assert.equal(bad.json.ok,false);const result=await execute(dev,'redeem',{licenseKey:manualKey,appVersion:'92.0'});assert.equal(result.json.ok,true,JSON.stringify(result));assert.equal(result.json.data.licenseId,licenseIds[0]);dev.activationToken=result.json.data.activationToken;});
 await test('Native request diagnostics arrive in admin detail without raw tokens or payloads',async()=>{const r=(await call(w+'/licenses/'+licenseIds[0],undefined,auth)).json;assert.ok(r.timeline.some(x=>x.type==='DESKTOP_RUNTIME_REQUEST_FAILED'),JSON.stringify(r.timeline));assert.ok(r.timeline.some(x=>x.type==='B_CLAIMED'));assert.ok(!JSON.stringify(r).includes(dev.bootstrap.sessionToken));assert.ok(!JSON.stringify(r).includes(dev.activationToken));});
 await test('Original verification and release remain authenticated and functional',async()=>{assert.equal((await execute(dev,'verify',{activationToken:dev.activationToken,appVersion:'91.0'})).json.ok,true);assert.equal((await execute(dev,'release',{activationToken:dev.activationToken})).json.data.released,true);});
 console.log(`Workspace HTTP/TLS: ${passed} scenarios passed. Real HTTP/auth/CSRF + encrypted TLS and RSA; synthetic PE, not a Windows EXE test.`);
}catch(e){console.error(e);console.error(output.slice(-5000));process.exitCode=1;}finally{await stop();fs.rmSync(dataDir,{recursive:true,force:true});}})();
