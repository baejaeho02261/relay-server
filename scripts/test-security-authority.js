'use strict';
const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
// Production services + synthetic PE files; never a production bypass.
const assert = require('node:assert/strict'), crypto = require('node:crypto');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const child = require('node:child_process');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-authority-test-'));
process.env.DATA_DIR = temp; process.env.STORAGE_ENGINE = 'json'; process.env.HA_ENABLED = '0';
process.env.DESKTOP_PUBLIC_HOST = '127.0.0.1'; process.env.DESKTOP_PUBLIC_PORT = '29131';
require('../core/utils').EnsureDirs();
const boot = require('../services/desktopBootstrap'), auth = require('../services/desktopSecurityAuthority');
const licenses = require('../services/desktopLicenses'), fixture = require('./desktop-bootstrap-fixture');
const { PE, Device, Sign, Begin, Download, Finish, Claim, sha256 } = fixture;
let checks = 0;
function Check(label, run) { run(); ++checks; console.log('PASS ' + label); }
function Reject(run, code) { assert.throws(run, error => error.message === code, code); }
function Context(device, stage, session, intent, binding) {
  return { action: 'challenge', stage, sessionId: stage === 'A' ? session.flowId : session.sessionId,
    sessionToken: stage === 'A' ? session.downloadTicket : session.sessionToken,
    machineId: device.machineId, intent, binding };
}
function Evidence(context, patch = {}) {
  const b = boot.AuthenticateIntegrityReport(context).integrityArtifact;
  return { version: 1, hashVersion:3, measurement: 'MEASURED', fileSha512: b.sha512, fileCrc64: b.crc64,
    codeSha512: b.codeSha512, codeCrc64: b.codeCrc64, codeXxh3_128:b.codeXxh3_128,codeBlake3:b.codeBlake3,crcLayers:b.crcLayers,apiSealed: true, apiSlots: 60,
    dynamicCode: 'ALLOWED', cfg: 'DISABLED', ...patch };
}
function Signed(context, challenge, device, patch) {
  const payload = JSON.stringify(Evidence(context, patch));
  return { ...context, action: 'submit', challengeId: challenge.challengeId, payload,
    signature: Sign(device, auth.Canonical(context, challenge, payload)) };
}
function Observe(context, device, patch) {
  const challenge = auth.Execute(context);
  return auth.Execute(Signed(context, challenge, device, patch));
}
function Row(session) { return Object.values(boot.Initialize().flows).find(x => x.sessionId === session.sessionId); }
function Fresh(session, intent, binding) { auth.RequireFresh(Row(session), 'B', intent, binding); }
function NewSession(device) {
  const started = Begin(device); Download(started.begin);
  return Claim(device, started.begin, Finish(device, started.begin));
}
function LeaseProof(device, session, action, requestId, extra) {
  const payloadJSON = JSON.stringify({ ...fixture.Evidence(device, session), ...extra,
    bootstrapSessionId: session.sessionId, bootstrapSessionToken: session.sessionToken });
  const base = { action, requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash:sha512(payloadJSON) };
  const challenge = licenses.Challenge(base);
  return { ...base, challengeId: challenge.challengeId, payloadJSON, signature: Sign(device, challenge.canonical) };
}
let dev, start, session, verifyContext;
Check('Defaults preserve legacy builds, exact policy is bounded and immutable to caller', () => {
  assert.equal(auth.Policy().mode, 'enforce'); assert.equal(auth.Policy().enforceLegacy, false);
  const p = auth.Policy(); p.freshnessMs = 1; assert.equal(auth.Policy().freshnessMs, 45000);
  for (const patch of [{freshnessMs:1},{challengeMs:999999},{unexpected:true},{minVersionB:'abc'}, {trustedReleaseKeys:[{}]}]) {
    assert.throws(() => auth.ValidatePolicy({...auth.Defaults(), ...patch}));
  }
  Reject(() => auth.SetPolicy({ expectedRevision: 1 }, 'test'), 'SECURITY_POLICY_CONFLICT');
});
Check('Capability comes from administrator-published bytes, not a client flag', () => {
  boot.Publish('A', '87.1.0', PE('A', auth.DOMAIN)); boot.Publish('B', '87.1.0', PE('B', auth.DOMAIN));
  for (const component of ['A','B']) assert.equal(boot.Initialize().artifacts[boot.Initialize().active[component]].authorityVersion, 1);
  assert.equal(auth.PeCapabilities(PE('B')).authorityVersion, 1);const old=PE('B');const marker=old.indexOf(Buffer.from(auth.DOMAIN));old.fill(0,marker,marker+auth.DOMAIN.length);assert.equal(auth.PeCapabilities(old).authorityVersion,0);Reject(()=>boot.Publish('B','87.1.0',old),'SECURITY_CLIENT_UPGRADE_REQUIRED');
  assert.deepEqual(auth.PeCapabilities(Buffer.from('bad')), {authorityVersion:0,compiledCfg:false});
  dev = Device(); start = Begin(dev); Download(start.begin);
});
Check('Stage A cannot finish without a current A/finish decision', () => {
  Reject(() => Finish(dev, start.begin,false), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
  const ctx = Context(dev, 'A', start.begin, 'finish', auth.Binding(start.begin.flowId, start.begin.release.sha512));
  const out = Observe(ctx, dev); assert.equal(out.status, 'PASS'); assert.equal(out.attested, false);
  const finish = Finish(dev, start.begin,false); session = Claim(dev, start.begin, finish);
  assert.equal(Object.keys(session.release).length, 13, 'Exact release schema matches integrity v3');
});
Check('One-use challenge, context binding and signature verification are enforced', () => {
  const ctx = Context(dev, 'B', session, 'verify', sha512('request-test'));
  const c = auth.Execute(ctx); assert.equal(Object.keys(c).length, 8);
  const signed = Signed(ctx, c, dev);
  Reject(() => auth.Execute({...signed,binding:sha512('other')}), 'SECURITY_CHALLENGE_INVALID');
  Reject(() => auth.Execute({...signed,intent:'redeem'}), 'SECURITY_CHALLENGE_INVALID');
  Reject(() => auth.Execute(Signed(ctx,c,Device())), 'SECURITY_SIGNATURE_INVALID');
  const out = auth.Execute(signed); assert.equal(Object.keys(out).length, 8); assert.equal(out.status,'PASS');
  assert.deepEqual(auth.Execute(signed), out, 'lost response recovers exact bounded receipt');
  Reject(() => auth.Execute({...signed,payload:signed.payload+' '}), 'SECURITY_REQUEST_REUSED');
  Fresh(session,'verify',ctx.binding);
  Reject(() => Fresh(session,'redeem',ctx.binding), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
  Reject(() => auth.Execute({...ctx,authorityVersion:0}), 'SECURITY_INPUT_INVALID');
});
Check('Newer result cannot be overwritten by an older in-flight result', () => {
  const ctx = Context(dev,'B',session,'verify',sha512('order'));
  const c1 = auth.Execute(ctx), c2 = auth.Execute(ctx);
  auth.Execute(Signed(ctx,c2,dev));
  Reject(() => auth.Execute(Signed(ctx,c1,dev,{apiSealed:false})), 'SECURITY_OBSERVATION_REPLAY');
  Fresh(session,'verify',ctx.binding);
});
Check('READ_ERROR and unsealed storage hold work without revoking the session', () => {
  const ctx = Context(dev,'B',session,'verify',sha512('indeterminate'));
  const result = Observe(ctx,dev,{measurement:'READ_ERROR',codeSha512:'',codeCrc64:''});
  assert.equal(result.status,'INDETERMINATE'); assert.equal(result.proceed,false);
  Reject(() => Fresh(session,'verify',ctx.binding), 'SECURITY_OBSERVATION_INDETERMINATE');
  assert.equal(Row(session).status,'CLAIMED');
  assert.equal(Observe(ctx,dev,{apiSealed:false}).status,'INDETERMINATE');
  Observe(ctx,dev); Fresh(session,'verify',ctx.binding);
});
Check('Measured mismatch is distinct, does not permanently ban an account', () => {
  const ctx = Context(dev,'B',session,'verify',sha512('mismatch'));
  const out = Observe(ctx,dev,{codeSha512:'0'.repeat(128)}); assert.equal(out.status,'MISMATCH');
  Reject(() => Fresh(session,'verify',ctx.binding), 'SECURITY_OBSERVATION_MISMATCH');
  assert.equal(Row(session).status,'CLAIMED');
});
Check('Expired challenges and decisions require new measurements', () => {
  const ctx=Context(dev,'B',session,'verify',sha512('expired')), c=auth.Execute(ctx), submit=Signed(ctx,c,dev);
  const real=Date.now; Date.now=()=>real()+auth.Policy().challengeMs+10;
  try { Reject(()=>auth.Execute(submit),'SECURITY_CHALLENGE_INVALID'); } finally { Date.now=real; }
  Observe(ctx,dev); Date.now=()=>real()+auth.Policy().freshnessMs+10;
  try { Reject(()=>Fresh(session,'verify',ctx.binding),'SECURITY_FRESH_OBSERVATION_REQUIRED'); } finally { Date.now=real; }
});
Check('Captured responses cannot transfer to another session even with the same device key', () => {
  const device = Device(), first = NewSession(device), second = NewSession(device), binding = sha512('same-operation');
  const ctx1 = Context(device,'B',first,'verify',binding), ctx2 = Context(device,'B',second,'verify',binding);
  const c1 = auth.Execute(ctx1), captured = Signed(ctx1,c1,device), c2 = auth.Execute(ctx2);
  Reject(() => auth.Execute({...captured,sessionId:second.sessionId,sessionToken:second.sessionToken}), 'SECURITY_CHALLENGE_INVALID');
  Reject(() => auth.Execute({...captured,sessionId:second.sessionId,sessionToken:second.sessionToken,challengeId:c2.challengeId}), 'SECURITY_SIGNATURE_INVALID');
  Reject(() => Fresh(second,'verify',binding), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
  assert.equal(auth.Execute(captured).status,'PASS');
  assert.equal(auth.Execute(Signed(ctx2,c2,device)).status,'PASS');
});
Check('Every challenge field and the exact payload bytes are covered by the response signature', () => {
  const device = Device(), s = NewSession(device), ctx = Context(device,'B',s,'verify',sha512('canonical-boundaries'));
  const c = auth.Execute(ctx), signed = Signed(ctx,c,device);
  const patches = [{nonce:'0'.repeat(48)},{epoch:'0'.repeat(48)},{sequence:c.sequence+1},
    {revision:c.revision+1},{expiresAt:c.expiresAt+1},{challengeId:'0'.repeat(48)}];
  for (const patch of patches) Reject(() => auth.Execute({...signed,
    signature:Sign(device,auth.Canonical(ctx,{...c,...patch},signed.payload))}), 'SECURITY_SIGNATURE_INVALID');
  Reject(() => auth.Execute({...signed,signature:Sign(device,auth.Canonical({...ctx,stage:'O'},c,signed.payload))}), 'SECURITY_SIGNATURE_INVALID');
  Reject(() => auth.Execute({...signed,payload:JSON.stringify({...JSON.parse(signed.payload),apiSlots:61})}), 'SECURITY_SIGNATURE_INVALID');
  Reject(() => auth.Execute({...signed,payload:JSON.stringify(JSON.parse(signed.payload),null,1)}), 'SECURITY_SIGNATURE_INVALID');
  for (const patch of [{version:2},{hashVersion:2}]) Reject(() => auth.Execute(Signed(ctx,c,device,patch)), 'SECURITY_INPUT_INVALID');
  Reject(() => Fresh(s,'verify',ctx.binding), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
  assert.equal(auth.Execute(signed).status,'PASS');
});
Check('Noncanonical base64 aliases cannot represent a second signature encoding', () => {
  const device = Device(), s = NewSession(device), ctx = Context(device,'B',s,'verify',sha512('signature-encoding'));
  const c = auth.Execute(ctx), signed = Signed(ctx,c,device), alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const at = signed.signature.length-3, alias = signed.signature.slice(0,at)+alphabet[alphabet.indexOf(signed.signature[at])+1]+'==';
  assert.deepEqual(Buffer.from(alias,'base64'),Buffer.from(signed.signature,'base64'));
  Reject(() => auth.Execute({...signed,signature:alias}), 'SECURITY_SIGNATURE_INVALID');
  assert.equal(auth.Execute(signed).status,'PASS');
});
Check('A challenge that expires during RSA verification cannot create a decision', () => {
  const device = Device(), s = NewSession(device), ctx = Context(device,'B',s,'verify',sha512('verification-deadline'));
  const c = auth.Execute(ctx), signed = Signed(ctx,c,device), realNow = Date.now, realVerify = crypto.verify;
  try {
    crypto.verify = function(...args) {
      const verified = Reflect.apply(realVerify,this,args); Date.now = () => c.expiresAt; return verified;
    };
    Reject(() => auth.Execute(signed), 'SECURITY_CHALLENGE_INVALID');
  } finally { crypto.verify = realVerify; Date.now = realNow; }
  Reject(() => Fresh(s,'verify',ctx.binding), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
  Reject(() => auth.Execute(signed), 'SECURITY_CHALLENGE_INVALID');
});
Check('A backward wall clock cannot extend a monotonic challenge deadline', () => {
  const device = Device(), s = NewSession(device), ctx = Context(device,'B',s,'verify',sha512('monotonic-deadline'));
  const c = auth.Execute(ctx), signed = Signed(ctx,c,device), realNow = Date.now, realVerify = crypto.verify;
  const clock = require('node:perf_hooks').performance, priorNow = Object.getOwnPropertyDescriptor(clock,'now');
  const expiredTick = clock.now()+auth.Policy().challengeMs+1, pastWall = realNow()-1000;
  try {
    crypto.verify = function(...args) {
      const verified = Reflect.apply(realVerify,this,args);
      Date.now = () => pastWall; Object.defineProperty(clock,'now',{configurable:true,value:() => expiredTick});
      return verified;
    };
    Reject(() => auth.Execute(signed), 'SECURITY_CHALLENGE_INVALID');
  } finally {
    crypto.verify = realVerify; Date.now = realNow;
    if (priorNow) Object.defineProperty(clock,'now',priorNow); else delete clock.now;
  }
  Reject(() => Fresh(s,'verify',ctx.binding), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
});
Check('Pruning a newer decision never revives an older in-flight observation', () => {
  const policy = auth.Policy(), realNow = Date.now;
  try {
    auth.SetPolicy({expectedRevision:policy.revision,freshnessMs:5000,challengeMs:30000},'TEST');
    const device = Device(), s = NewSession(device), ctx = Context(device,'B',s,'verify',sha512('expired-ordering'));
    const older = auth.Execute(ctx), captured = Signed(ctx,older,device), newer = auth.Execute(ctx);
    assert.equal(auth.Execute(Signed(ctx,newer,device,{codeSha512:'0'.repeat(128)})).status,'MISMATCH');
    const future = realNow()+6000; Date.now = () => future;
    Reject(() => Fresh(s,'verify',ctx.binding), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
    Reject(() => auth.Execute(captured), 'SECURITY_OBSERVATION_REPLAY');
    Reject(() => Fresh(s,'verify',ctx.binding), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
    assert.equal(Observe(ctx,device).status,'PASS');
    Fresh(s,'verify',ctx.binding);
  } finally {
    Date.now = realNow;
    auth.SetPolicy({expectedRevision:auth.Policy().revision,freshnessMs:policy.freshnessMs,challengeMs:policy.challengeMs},'TEST');
  }
});
Check('License redeem and renew are bound to exact request ID and payload', () => {
  const key=licenses.Create({label:'server-authority-test'},'TEST');
  const requestId=crypto.randomUUID(); let proof=LeaseProof(dev,session,'redeem',requestId,{licenseKey:key.licenseKey});
  Reject(()=>licenses.Execute(proof),'SECURITY_FRESH_OBSERVATION_REQUIRED');
  const ctx=Context(dev,'B',session,'redeem',auth.Binding(requestId,proof.payloadHash)); Observe(ctx,dev);
  proof=LeaseProof(dev,session,'redeem',requestId,{licenseKey:key.licenseKey});
  const result=licenses.Execute(proof); assert.ok(result.activationToken);
  const id=crypto.randomUUID(); let renew=LeaseProof(dev,session,'verify',id,{activationToken:result.activationToken});
  Reject(()=>licenses.Execute(renew),'SECURITY_FRESH_OBSERVATION_REQUIRED');
  verifyContext=Context(dev,'B',session,'verify',auth.Binding(id,renew.payloadHash)); Observe(verifyContext,dev);
  renew=LeaseProof(dev,session,'verify',id,{activationToken:result.activationToken}); assert.equal(licenses.Execute(renew).status,'USED');
  session.testActivationToken=result.activationToken;
});
Check('Periodic read error invalidates new-client grants, does not revoke', () => {
  const reports=require('../services/desktopIntegrityReports');
  const ctx={action:'challenge',stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:dev.machineId};
  const c=reports.Execute(ctx);
  const payload=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'READ_ERROR',codeSha512:'',codeCrc64:''}});
  const out=reports.Execute({...ctx,action:'submit',reportId:c.reportId,payload,signature:Sign(dev,reports.Canonical(session.sessionId,c,payload))});
  assert.equal(out.terminate,false); assert.equal(out.status,'CLIENT_DIAGNOSTIC'); assert.equal(Row(session).status,'CLAIMED');
  Reject(()=>Fresh(session,'verify',verifyContext.binding),'SECURITY_FRESH_OBSERVATION_REQUIRED');
});
Check('Policy revision invalidates all outstanding grants and pending signatures', () => {
  const ctx=Context(dev,'B',session,'verify',sha512('policy')), c=auth.Execute(ctx); const signed=Signed(ctx,c,dev);
  Observe(verifyContext,dev);
  const p=auth.Policy(); auth.SetPolicy({expectedRevision:p.revision,freshnessMs:30000},'TEST');
  Reject(()=>auth.Execute(signed),'SECURITY_CHALLENGE_INVALID');
  Reject(()=>Fresh(session,'verify',verifyContext.binding),'SECURITY_FRESH_OBSERVATION_REQUIRED');
});
Check('Observe-only and opt-in mitigations have explicit distinct outcomes', () => {
  let p=auth.Policy(); auth.SetPolicy({expectedRevision:p.revision,mode:'observe',dynamicCode:'prohibit'},'TEST');
  const ctx=Context(dev,'B',session,'verify',sha512('observe')); let out=Observe(ctx,dev);
  assert.equal(out.status,'INDETERMINATE'); assert.equal(out.proceed,true); Fresh(session,'verify',ctx.binding);
  p=auth.Policy(); auth.SetPolicy({expectedRevision:p.revision,mode:'enforce'},'TEST');
  out=Observe(ctx,dev,{dynamicCode:'PROHIBITED'}); assert.equal(out.status,'PASS');
  p=auth.Policy(); auth.SetPolicy({expectedRevision:p.revision,dynamicCode:'observe'},'TEST');
});
Check('Client-reported app version does not bypass server-approved minimum version', () => {
  assert.equal(auth.VersionAtLeast('87.1.0','87.0.9'),true); assert.equal(auth.VersionAtLeast('9.0','10'),false);
  Reject(()=>auth.SetPolicy({expectedRevision:auth.Policy().revision,minVersionB:'999'},'TEST'),'SECURITY_RELEASE_VERSION');
  Reject(()=>auth.SetPolicy({expectedRevision:auth.Policy().revision,requireCfg:true},'TEST'),'SECURITY_CFG_BUILD_REQUIRED');
  const b=boot.Initialize().artifacts[boot.Initialize().active.B];
  Reject(()=>auth.SetPolicy({expectedRevision:auth.Policy().revision,revokedSha512:[b.sha512]},'TEST'),'SECURITY_RELEASE_REVOKED');
});
Check('Audits contain outcomes but never tokens, payloads or signatures', () => {
  const text=JSON.stringify(auth.List().events);
  for(const value of [session.sessionToken,session.testActivationToken,dev.publicKey,start.begin.downloadTicket]) assert.ok(!text.includes(value));
  assert.ok(auth.List().events.every(x=>x.attested===false));
});
Check('Restart preserves policy and sessions but never reuses RAM decisions', () => {
  Observe(verifyContext,dev);
  const script=`const b=require(process.cwd()+'/services/desktopBootstrap'),a=require(process.cwd()+'/services/desktopSecurityAuthority');const s=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const row=Object.values(b.Initialize().flows).find(x=>x.sessionId===s.sessionId);let error='';try{a.RequireFresh(row,'B','verify',s.binding);}catch(e){error=e.message;}console.log('RESULT:'+JSON.stringify({revision:a.Policy().revision,error,status:row.status}));`;
  const run=child.spawnSync(process.execPath,['-e',script],{cwd:path.resolve(__dirname,'..'),env:process.env,input:JSON.stringify({sessionId:session.sessionId,binding:verifyContext.binding}),encoding:'utf8',timeout:15000});
  assert.equal(run.status,0,run.stderr); const out=JSON.parse(run.stdout.split('RESULT:').at(-1));
  assert.equal(out.revision,auth.Policy().revision); assert.equal(out.error,'SECURITY_FRESH_OBSERVATION_REQUIRED'); assert.equal(out.status,'CLAIMED');
});
Check('Authorized release and cleanup remain possible without a fresh observation', () => {
  auth.Invalidate(Row(session),'B','TEST_RESET');
  const proof=LeaseProof(dev,session,'release',crypto.randomUUID(),{activationToken:session.testActivationToken});
  assert.equal(licenses.Execute(proof).released,true);
});
Check('Publisher supports detached approval bound to component/version/bytes', () => {
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ed25519');
  const pem=publicKey.export({type:'spki',format:'pem'}).toString(), keyId=sha256(publicKey.export({type:'spki',format:'der'}));
  auth.SetPolicy({expectedRevision:auth.Policy().revision,trustedReleaseKeys:[{keyId,publicKey:pem}]},'TEST');
  const bytes=PE('B',auth.DOMAIN+' signed'),version='88.0.0';
  const approval={keyId,signature:crypto.sign(null,Buffer.from(auth.ReleaseCanonical('B',version,sha512(bytes))),privateKey).toString('base64')};
  boot.Publish('B',version,bytes,approval);
  Reject(()=>boot.Publish('B','88.0.1',bytes,approval),'SECURITY_RELEASE_SIGNATURE');
  const a=PE('A',auth.DOMAIN+' signed');boot.Publish('A',version,a,{keyId,signature:crypto.sign(null,Buffer.from(auth.ReleaseCanonical('A',version,sha512(a))),privateKey).toString('base64')});
  auth.SetPolicy({expectedRevision:auth.Policy().revision,requireReleaseSignature:true},'TEST');
  Reject(()=>boot.Publish('B',version,bytes),'SECURITY_RELEASE_SIGNATURE');
});
console.log(`Server authority regression: ${checks} passed (real services; synthetic PE; JSON storage)`);
