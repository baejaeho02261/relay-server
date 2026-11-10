'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const net = require('node:net'), crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const root = path.resolve(MODULE_RESOURCE_ROOT, '..');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'game-workspace-http-'));
const adminPassword = 'desktop-http-regression-admin-secret';
const viewerPassword = 'desktop-http-regression-viewer-secret';
const bootstrapFixture = require("../fixtures/runtime/peace.modern-http-fixture");
const releaseSigner=bootstrapFixture.CreateSyntheticApprovalSigner();
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
    // Admin calls simulate the on-host hop of a trusted HTTPS proxy. Native authorization uses pinned TLS only.
    if (['/api/desktop/challenge','/api/desktop/execute'].includes(url)) {
        const json=await require("../fixtures/network/peace.tls-request-fixture").Request(nativeProfile,url.endsWith('challenge')?'challenge':'execute',body);
        return {status:json.ok?200:0,json};
    }
    const headers = { 'X-Forwarded-Proto': 'https', ...(options.headers || {}) };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (auth) { headers.Cookie = auth.cookie; if (options.csrf !== false) headers['X-CSRF-Token'] = auth.csrf; }
    const response = await fetch(base + url, { method: body === undefined ? 'GET' : 'POST', headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'manual', signal: AbortSignal.timeout(5000) });
    const json = await response.json();
    if(response.status===428&&json.error==='ADMIN_ACTION_REQUIRED'&&auth&&!options.actionApproved){
        const approval=await call('/api/session/reauthenticate',{password:adminPassword,actionId:json.action.id},auth);
        assert.equal(approval.status,200,JSON.stringify(approval.json));
        return call(url,body,auth,{...options,actionApproved:true,headers:{...options.headers,'X-Admin-Action':json.action.id}});
    }
    return { status: response.status, json, cookie: response.headers.get('set-cookie') };
}
async function start() {
    const port = await freePort(); base = 'http://127.0.0.1:' + port;
    let tcpPort = await freePort();
    while (tcpPort === port) tcpPort = await freePort();
    child = spawn(process.execPath, ['peace.relay-server.js'], { cwd: root, env: { ...process.env, ...releaseSigner.environment, DATA_DIR: dataDir,
        STORAGE_ENGINE: 'json', PORT: String(tcpPort), CONNECT_TCP_PORT: String(tcpPort), WEB_ADMIN_PORT: String(port), HEALTH_PORT: '0', HA_ENABLED: '0',
        WEB_ADMIN_TRANSPORT: 'proxy', WEB_ADMIN_HOST: '127.0.0.1', WEB_ADMIN_TRUSTED_PROXIES: '127.0.0.1/32', WEB_ADMIN_REQUIRE_HTTPS: '1', WEB_ADMIN_SECURE_COOKIE: '1',
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
    const payloadJSON = JSON.stringify(payload), payloadHash = sha512(Buffer.from(payloadJSON));
    const requestId = 'HTTP-REQUEST-' + (++sequence);
    if (device.bootstrap) {
        try { await bootstrapFixture.RemoteObserveLicense(nativeProfile, device, device.bootstrap, action, requestId, payloadHash); }
        catch (error) {
            // A revoked machine capability must also be rejected by the license
            // endpoint under test; it cannot obtain a new authority observation.
            if (!String(error.message).includes('DESKTOP_MACHINE_SESSION_REVOKED')) throw error;
        }
    }
    const body = { action, requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash };
    const response = await call('/api/desktop/challenge', body); assert.equal(response.status, 200);
    const challenge = response.json.data;
    const canonical = ['GAME-DESKTOP-V2', action, challenge.challengeId, challenge.nonce, requestId,
        device.deviceId, payloadHash, String(challenge.expiresAt)].join('\n');
    assert.equal(challenge.canonical, canonical, 'The actual native wire canonical must match the client construction');
    const signature = crypto.sign('sha256', Buffer.from(canonical), { key: device.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }).toString('base64');
    return { ...body, challengeId: challenge.challengeId, payloadJSON, signature };
}
async function execute(device, action, payload) { return call('/api/desktop/execute', await signed(device, action, payload)); }
async function upload(component, bytes, auth, csrf = true) {
    const headers = { 'X-Forwarded-Proto': 'https', 'Content-Type': 'application/octet-stream' };
    const approval=releaseSigner.Approval(component,'80.0.0',bytes);
    headers['x-game-release-key-id']=approval.keyId;headers['x-game-release-signature']=approval.signature;
    if (auth) { headers.Cookie = auth.cookie; if (csrf) headers['X-CSRF-Token'] = auth.csrf; }
    const response = await fetch(base + '/api/desktop/bootstrap/artifacts?component=' + component + '&version=80.0.0&fileName=Game' + component + '.exe', { method: 'POST', headers, body: bytes, signal: AbortSignal.timeout(5000) });
    return { status: response.status, json: await response.json() };
}
async function download(url, auth) {
    const response=await fetch(base+url,{headers:{'X-Forwarded-Proto':'https',Cookie:auth.cookie},signal:AbortSignal.timeout(5000)});
    assert.equal(response.status,200);return Buffer.from(await response.arrayBuffer());
}
async function uploadBaseline(bytes, auth, csrf = true, fileName = 'ntdll.dll') {
    const headers = { 'X-Forwarded-Proto': 'https', 'Content-Type': 'application/octet-stream' };
    if (auth) { headers.Cookie = auth.cookie; if (csrf) headers['X-CSRF-Token'] = auth.csrf; }
    const response = await fetch(base + '/api/desktop/bootstrap/module-baselines?fileName=' + encodeURIComponent(fileName) + '&label=HTTP-test', { method: 'POST', headers, body: bytes, signal: AbortSignal.timeout(5000) });
    return { status: response.status, json: await response.json() };
}
async function bootstrapDevice(device, auth) {
    const issue = await call('/api/desktop/bootstrap/launchers', { requestId: crypto.randomUUID(), label: device.name }, auth); assert.equal(issue.status, 200);
    const response = await fetch(base + issue.json.downloadUrl, { headers: { 'X-Forwarded-Proto': 'https', Cookie: auth.cookie }, signal: AbortSignal.timeout(5000) }); assert.equal(response.status, 200);
    assert.match(issue.json.downloadName,/^[a-f0-9]{32}\.exe$/);assert.equal(response.headers.get('content-disposition'),'attachment; filename="'+issue.json.downloadName+'"');assert.match(response.headers.get('content-type'), /application\/octet-stream/); assert.match(response.headers.get('cache-control'), /no-store/);
    const launcher = Buffer.from(await response.arrayBuffer()); assert.equal(bootstrapFixture.Config(launcher).launcherId, issue.json.launcherId);
    device.bootstrap = await bootstrapFixture.RemoteSession(device, launcher, {call,auth});
}


let passed=0;
async function test(name,fn){await fn();passed++;console.log('PASS '+name);}
async function until(fn){for(let i=0;i<100;i++){const r=await fn();if(r)return r;await delay(100);}throw Error('TEST_WAIT_TIMEOUT');}
(async()=>{try{
 await start();let auth=await login(),viewer=await login('viewer');
 await test('Production HTTP shell serves the current detection UI and matching script bundle',async()=>{
  const expectedRevision='cozy-peace-v20-nhw-detections';
  const headers={'X-Forwarded-Proto':'https',Cookie:auth.cookie};
  async function asset(url,type){const r=await fetch(base+url,{headers,signal:AbortSignal.timeout(5000)});assert.equal(r.status,200,url);assert.match(r.headers.get('content-type')||'',type,url);assert.match(r.headers.get('cache-control')||'',/no-store/,url);return r.text();}
  const html=await asset('/',/text\/html/);
  const scripts=[...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map(x=>x[1]);
  assert.ok(scripts.length>20,'The complete production shell must be served');
  assert.ok(scripts.every(url=>url.endsWith('?v=5.0.2-'+expectedRevision)),'Mixed old/new script query versions');
  const memberUrl=scripts.find(url=>url.startsWith('/scripts/desktop/peace.admin-desktop-members.js?'));
  const workflowUrl=scripts.find(url=>url.startsWith('/scripts/desktop/peace.admin-desktop-workflow.js?'));
  assert.ok(memberUrl&&workflowUrl);assert.ok(scripts.indexOf(memberUrl)<scripts.indexOf(workflowUrl));
  const sources=await Promise.all(scripts.map(url=>asset(url,/(?:application|text)\/javascript/)));
  for(let i=0;i<sources.length;i++)assert.equal(sources[i],fs.readFileSync(path.join(root,'public',scripts[i].split('?')[0]),'utf8'),scripts[i]);
  const members=sources[scripts.indexOf(memberUrl)];
  assert.match(members,/desktopMemberCategory\s*=\s*'detections'/);
  assert.ok(members.includes('보안 감지 · 대응 경로'));
  assert.ok(!members.includes('보안 사건 · 서버 기록'));
  const sw=await asset('/peace.service-worker.js',/(?:application|text)\/javascript/);
  assert.ok(sw.includes('relay-admin-shell-v5.0.2-'+expectedRevision));
  const version=await call('/ui-version.json');
  assert.equal(version.status,200);assert.equal(version.json.ready,true,JSON.stringify(version.json.issues));assert.equal(version.json.uiRevision,expectedRevision);
 });
 const w='/api/desktop/workspace';let job,licenseIds=[];
 await test('New workspace routes require administrator authentication',async()=>{for(const p of ['/licenses','/summary','/jobs','/storage']){assert.equal((await call(w+p)).status,401);assert.equal((await call(w+p,undefined,viewer)).status,403);assert.equal((await call(w+p,undefined,auth)).status,200);}});
 await test('Product catalog is admin-only, read-only and has six explicit products per category',async()=>{const path='/api/desktop/products';assert.equal((await call(path)).status,401);assert.equal((await call(path,undefined,viewer)).status,403);const r=await call(path,undefined,auth);assert.equal(r.status,200);assert.equal(r.json.version,1);assert.equal(r.json.products.length,18);assert.equal(new Set(r.json.products.map(x=>x.id)).size,18);for(const category of ['cleaner','mobile','spoofer'])assert.equal(r.json.products.filter(x=>x.category===category).length,6);assert.equal((await call(path,{},auth)).status,405);});
 await test('Missing, wildcard and multiple product grants are rejected over HTTP',async()=>{for(const productId of [undefined,'','all','cleaner.*',['mobile.roblox','cleaner.pubg']]){const r=await call(w+'/jobs/preview',{kind:'CREATE',count:1,prefix:'Denied',...(productId===undefined?{}:{productId})},auth);assert.equal(r.status,400);assert.match(r.json.error,/DESKTOP_PRODUCT_(REQUIRED|INVALID)/);}assert.equal((await call(w+'/licenses',undefined,auth)).json.filteredCount,0);});
 await test('Workspace mutation rejects missing CSRF and unknown fields',async()=>{assert.equal((await call(w+'/jobs/preview',{kind:'CREATE',productId:'mobile.brawl-stars',count:1,prefix:'HTTP'},auth,{csrf:false})).status,403);const bad=await call(w+'/jobs/preview',{kind:'CREATE',productId:'mobile.brawl-stars',count:1,permit:true},auth);assert.equal(bad.status,400);assert.ok(bad.json.problem?.next);});
 await test('HTTP preview causes no creation; commit is receipt-idempotent',async()=>{const p=await call(w+'/jobs/preview',{kind:'CREATE',productId:'mobile.brawl-stars',count:3,prefix:'HTTP'},auth);assert.equal(p.status,200);assert.ok(p.json.items.every(x=>x.productId==='mobile.brawl-stars'));assert.equal((await call(w+'/licenses',undefined,auth)).json.items.length,0);const body={planId:p.json.planId,requestId:crypto.randomUUID()},c=await call(w+'/jobs',body,auth);assert.equal(c.status,200);job=c.json;assert.equal((await call(w+'/jobs',body,auth)).json.id,job.id);});
 await test('Committed jobs finish on the server after browser logout',async()=>{assert.equal((await call('/api/logout',{},auth)).status,200);await delay(1200);auth=await login();const j=await until(async()=>{const v=(await call(w+'/jobs',undefined,auth)).json.items.find(x=>x.id===job.id);return v?.status==='DONE'&&v;});assert.equal(j.done,3);assert.ok(j.items.every(x=>x.result.license.productId==='mobile.brawl-stars'&&x.result.license.productAssigned===true));licenseIds=j.items.map(x=>x.result.license.id);assert.equal(new Set(licenseIds).size,3);});
 await test('Metadata saves, server search and export do not expose credentials',async()=>{const id=licenseIds[0],r=await call(w+'/licenses/'+id+'/metadata',{expectedRevision:0,note:'웹 작업 메모',tags:['HTTP']},auth);assert.equal(r.status,200);assert.equal((await call(w+'/licenses?q=HTTP&pageSize=2',undefined,auth)).json.items.length,2);const bad=await call(w+'/licenses/'+id+'/metadata',{expectedRevision:0,note:'stale',tags:[]},auth);assert.equal(bad.status,409);const p=await call(w+'/jobs/preview',{kind:'EXPORT',ids:licenseIds},auth),j=await call(w+'/jobs',{planId:p.json.planId,requestId:crypto.randomUUID()},auth);await until(async()=>((await call(w+'/jobs',undefined,auth)).json.items.find(x=>x.id===j.json.id).status==='DONE'));const out=await call(w+'/jobs/'+j.json.id+'/export',undefined,auth);assert.equal(out.json.items.length,3);for(const secret of ['licenseKey','activationToken','sessionToken','keyHash'])assert.ok(!JSON.stringify(out.json).includes(secret));assert.equal((await call(w+'/jobs/'+j.json.id+'/export',undefined,viewer)).status,403);});
 let resumable;
 await test('An interrupted job resumes after a real server process restart',async()=>{const p=await call(w+'/jobs/preview',{kind:'CREATE',productId:'mobile.brawl-stars',count:12,prefix:'RESTART'},auth);resumable=(await call(w+'/jobs',{planId:p.json.planId,requestId:crypto.randomUUID()},auth)).json.id;await delay(120);await stop();await start();auth=await login();const done=await until(async()=>{const x=(await call(w+'/jobs',undefined,auth)).json.items.find(x=>x.id===resumable);return x?.status==='DONE'&&x;});assert.equal(done.done,12);assert.ok(done.items.every(x=>x.result.license.productId==='mobile.brawl-stars'));assert.equal(new Set(done.items.map(x=>x.result.license.id)).size,12);assert.equal((await call(w+'/licenses?q=RESTART',undefined,auth)).json.filteredCount,12);});
 nativeProfile=(await call('/api/desktop/connect-profile',undefined,auth)).json.profile;
 const security='/api/desktop/bootstrap/security-authority',settings=(await call(security,undefined,auth)).json;
 const trust=await call(security,{expectedRevision:settings.policy.revision,expectedOperationsRevision:settings.operations.operations.revision,requireReleaseSignature:true,trustedReleaseKeys:[releaseSigner.trustedKey]},auth);
 assert.equal(trust.status,200,JSON.stringify(trust.json));
 let candidates={};
 await test('Duplicate unsealed source upload reuses candidate bytes while runtime publication stays blocked',async()=>{
  const before=(await call(security,undefined,auth)).json.operations.active;
  for(const c of ['A','B','O']){
   const bytes=bootstrapFixture.PE(c,c==='B'?'manual key console':'user launcher'),one=await upload(c,bytes,auth),two=await upload(c,bytes,auth);
   assert.equal(one.status,200,JSON.stringify(one.json));assert.equal(two.status,200,JSON.stringify(two.json));
   assert.equal(two.json.artifact.id,one.json.artifact.id);assert.equal(two.json.artifact.ownProtection.state,'UNSEALED');
   assert.equal(two.json.activeUnchanged,true);candidates[c]=one.json.artifact;
  }
  assert.deepEqual((await call(security,undefined,auth)).json.operations.active,before);
  const preview=await call('/api/desktop/bootstrap/security-operations/preview-pair',{aId:candidates.A.id,bId:candidates.B.id,oId:candidates.O.id},auth);
  assert.equal(preview.status,200,JSON.stringify(preview.json));assert.equal(preview.json.preview.eligible,false);
  assert.ok(preview.json.preview.reasons.includes('COZY_PROTECTION_COHORT_INCOMPLETE'));
  const issue=await call('/api/desktop/bootstrap/launchers',{requestId:crypto.randomUUID(),label:'Unbound source must not run'},auth);
  assert.equal(issue.status,409);assert.equal(issue.json.error,'BOOTSTRAP_NOT_READY');
 });
 await bootstrapFixture.BindSyntheticCohort({call,auth,candidates,download,upload});
 await test('Manual publication requires signed A/B/O and a complete manifest with unchanged release security checks',async()=>{
  const op='/api/desktop/bootstrap/security-operations',cohort={aId:candidates.A.id,bId:candidates.B.id,oId:candidates.O.id};
  const before=await call(op+'/preview-pair',cohort,auth);assert.equal(before.json.preview.eligible,false);assert(before.json.preview.reasons.includes('SECURITY_RELEASE_MANIFEST_REQUIRED'));
  await bootstrapFixture.RegisterSyntheticRelease({call,auth,candidates,label:'SYNTHETIC WORKSPACE HTTP CONTRACT ONLY',afterManifest:async()=>assert.equal((await call(op+'/preview-pair',cohort,auth)).json.preview.eligible,true)});
  assert.equal((await call(op+'/preview-pair',{aId:candidates.A.id,bId:candidates.B.id},auth)).json.preview.eligible,false);
  const p=await call(op+'/preview-pair',cohort,auth);assert.equal(p.json.preview.eligible,true,JSON.stringify(p.json));
  assert.equal(p.json.preview.hardwareAttested,false);
  const beforeActivation=(await call(security,undefined,auth)).json.operations.operations.releaseGovernance;
  assert.equal(beforeActivation.minimumSecurityVersion>=0,true);
  const r=await call(op+'/activate',{...cohort,expectedRevision:p.json.preview.operationsRevision,expectedPolicyRevision:p.json.preview.policyRevision},auth);assert.equal(r.status,200,JSON.stringify(r.json));
 });
 let issued,dev,manualKey;
 await test('A issuance needs no selected license and does not consume a key',async()=>{const before=(await call(w+'/licenses',undefined,auth)).json.filteredCount;const result=await call('/api/desktop/bootstrap/launchers',{requestId:crypto.randomUUID(),label:'User license window'},auth);assert.equal(result.status,200,JSON.stringify(result.json));issued=result.json;assert.ok(issued.launcherId);assert.equal((await call(w+'/licenses',undefined,auth)).json.filteredCount,before);const key=await call('/api/desktop/licenses',{requestId:crypto.randomUUID(),label:'Manual key after A issuance',productId:'cleaner.pubg'},auth);assert.equal(key.status,200,JSON.stringify(key.json));manualKey=key.json.licenseKey;licenseIds[0]=key.json.license.id;});
 await test('Real encrypted TLS bootstrap and signed redeem accept the entered KEY, not the old automatic marker',async()=>{const response=await fetch(base+issued.downloadUrl,{headers:{'X-Forwarded-Proto':'https',Cookie:auth.cookie}}),bytes=Buffer.from(await response.arrayBuffer());assert.equal(response.status,200);assert.ok(!JSON.stringify(bootstrapFixture.Config(bytes)).includes(licenseIds[0]));dev=device('Workspace user');dev.bootstrap=await bootstrapFixture.RemoteSession(dev,bytes,{call,auth});const marker=await execute(dev,'redeem',{licenseKey:'SERVER_ASSIGNED_V1',appVersion:'92.0'});assert.equal(marker.json.ok,false);assert.equal(marker.json.error,'DESKTOP_KEY_INVALID');const p=await signed(dev,'redeem',{licenseKey:manualKey,appVersion:'92.0'}),invalid={...p,signature:'A'.repeat(342)+'=='};const bad=await call('/api/desktop/execute',invalid);assert.equal(bad.json.ok,false);const result=await execute(dev,'redeem',{licenseKey:manualKey,appVersion:'92.0'});assert.equal(result.json.ok,true,JSON.stringify(result));assert.equal(result.json.data.licenseId,licenseIds[0]);dev.activationToken=result.json.data.activationToken;});
 await test('Native request diagnostics arrive in admin detail without raw tokens or payloads',async()=>{const r=(await call(w+'/licenses/'+licenseIds[0],undefined,auth)).json;assert.ok(r.timeline.some(x=>x.type==='DESKTOP_RUNTIME_REQUEST_FAILED'),JSON.stringify(r.timeline));assert.ok(r.timeline.some(x=>x.type==='B_CLAIMED'));assert.ok(!JSON.stringify(r).includes(dev.bootstrap.sessionToken));assert.ok(!JSON.stringify(r).includes(dev.activationToken));});
 await test('Original verification and release remain authenticated and functional',async()=>{assert.equal((await execute(dev,'verify',{activationToken:dev.activationToken,appVersion:'91.0'})).json.ok,true);assert.equal((await execute(dev,'release',{activationToken:dev.activationToken})).json.data.released,true);});
 console.log(`Workspace HTTP/TLS: ${passed} scenarios passed. Real HTTP/auth/CSRF + encrypted TLS and RSA; synthetic PE, not a Windows EXE test.`);
}catch(e){console.error(e);console.error(output.slice(-5000));process.exitCode=1;}finally{await stop();fs.rmSync(dataDir,{recursive:true,force:true});}})();
