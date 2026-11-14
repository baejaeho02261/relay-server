'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
// Production services + synthetic PE files; never a production bypass.
const assert = require('node:assert/strict'), crypto = require('node:crypto');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const child = require('node:child_process');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-authority-test-'));
process.once('exit',()=>{try{fs.rmSync(temp,{recursive:true,force:true});}catch(_){console.error('TEST_SCRATCH_CLEANUP_FAILED');process.exitCode=1;}});
process.env.DATA_DIR = temp; process.env.STORAGE_ENGINE = 'json'; process.env.HA_ENABLED = '0';
process.env.DESKTOP_PUBLIC_HOST = '127.0.0.1'; process.env.DESKTOP_PUBLIC_PORT = '29131';
require("../../core/peace.utilities.js").EnsureDirs();
const boot = require("../../services/bootstrap/peace.desktop-bootstrap"), auth = require("../../services/security/peace.desktop-security-authority");
const licenses = require("../../services/licensing/peace.desktop-licenses"), fixture = require("../fixtures/bootstrap/peace.desktop-bootstrap-fixture");
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
  const parent=fixture.Child(device),started=Begin(parent);Download(started.begin);
  return Claim(parent,started.begin,Finish(parent,started.begin),device);
}
function LeaseProof(device, session, action, requestId, extra) {
  const payloadJSON = JSON.stringify({ ...fixture.Evidence(device, session), ...extra,
    bootstrapSessionId: session.sessionId, bootstrapSessionToken: session.sessionToken });
  const base = { action, requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash:sha512(payloadJSON) };
  const challenge = licenses.Challenge(base);
  return { ...base, challengeId: challenge.challengeId, payloadJSON, signature: Sign(device, challenge.canonical) };
}
function NhwEvidence(challenge, { trust = 0, mask = 0, invalidated = false, measuredBoot = false } = {}) {
  const frame = Buffer.alloc(179);
  frame.write('NHWA');
  frame.writeUInt16LE(1,4);
  frame[6] = 2;
  frame.writeUInt32LE(167,8);
  Buffer.from(challenge.nhwChallenge,'base64').copy(frame,12,12);
  frame.writeBigUInt64LE(19n,60);
  frame[76] = trust;
  frame[77] = mask;
  if (measuredBoot) {
    frame[78] = 1;
    frame.writeUInt32LE(2,103);
    frame.writeUInt32LE(65536,107);
    crypto.createHash('sha256').update('test boot log digest').digest().copy(frame,111);
  }
  const nhwResponses = {};
  for (const [index,path] of ['trust','driver','integrity'].entries()) {
    if (!(mask & (1 << index))) continue;
    const value = BigInt(index+1);
    frame.writeBigUInt64LE(value,79+8*index);
    nhwResponses[path] = { sequence: '0000000000000001', tick: '0000000000001000', digest: value.toString(16).padStart(16,'0') };
  }
  crypto.createHash('sha256').update(frame.subarray(12,78)).update(frame.subarray(79,103))
    .update(frame.subarray(78,79)).update(frame.subarray(103,143)).digest().copy(frame,143);
  return { nhwEvidence: frame.toString('base64'), nhwResponses, ...(invalidated ? {nhwInvalidated:true} : {}) };
}
let dev, parent, start, session, verifyContext;
Check('Defaults preserve legacy builds, exact policy is bounded and immutable to caller', () => {
  assert.equal(auth.Policy().deviceSignalsRequested,false);
  const legacyPolicy=auth.Defaults();delete legacyPolicy.deviceSignalsRequested;assert.equal(auth.ValidatePolicy(legacyPolicy).deviceSignalsRequested,false);assert(!Object.hasOwn(legacyPolicy,'deviceSignalsRequested'));
  for(const v of [0,1,'true',null])assert.throws(()=>auth.ValidatePolicy({...auth.Defaults(),deviceSignalsRequested:v}));
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
  fixture.CurrentCohort({version:'87.1.0',marker:auth.DOMAIN});dev=Device();parent=fixture.Child(dev);start=Begin(parent);Download(start.begin);
});
Check('Stage A cannot finish without a current A/finish decision', () => {
  Reject(() => Finish(parent, start.begin,false), 'SECURITY_FRESH_OBSERVATION_REQUIRED');
  const ctx = Context(parent, 'A', start.begin, 'finish', auth.Binding(start.begin.flowId, start.begin.release.sha512));
  const out = Observe(ctx, parent); assert.equal(out.status, 'PASS'); assert.equal(out.attested, false);
  const finish = Finish(parent, start.begin,false); session = Claim(parent, start.begin, finish,dev);
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
Check('NHW challenge, compact evidence and verdict are bound to exact signed authority', () => {
  const ctx = Context(dev,'B',session,'verify',sha512('NHW binding'));
  const c = auth.Execute({...ctx,nhwVersion:1});
  const raw = Buffer.from(c.nhwChallenge,'base64');
  assert.equal(raw.length,60);
  assert.equal(raw.readBigUInt64LE(12),BigInt(Row(session).createdAt));
  const evidence = NhwEvidence(c,{trust:1,mask:1,measuredBoot:true});
  const signed = Signed(ctx,c,dev,evidence);
  Reject(() => auth.Execute({...signed,payload:JSON.stringify(Evidence(ctx,NhwEvidence(c,{trust:2,mask:1})))}),'SECURITY_SIGNATURE_INVALID');
  const out = auth.Execute(signed);
  const verdict = Buffer.from(out.nhwVerdict,'base64');
  assert.equal(verdict.length,93);
  assert.deepEqual(verdict.subarray(12,60),raw.subarray(12,60));
  assert.deepEqual(verdict.subarray(60,92),Buffer.from(evidence.nhwEvidence,'base64').subarray(143,175));
  assert.equal(verdict[92],1);
  assert.equal(out.attested,false);
  const acceptedAttestation=Row(session).nhwAttestations.B.find(item=>item.sequence===raw.readBigUInt64LE(20).toString(16).padStart(16,'0'));
  assert.equal(acceptedAttestation.status,'VERIFIED_BINDING');
  assert.equal(acceptedAttestation.hardwareAttested,false);
  assert.deepEqual(auth.Execute(signed),out);
  const next = auth.Execute({...ctx,nhwVersion:1});
  assert.ok(Buffer.from(next.nhwChallenge,'base64').readBigUInt64LE(20)>raw.readBigUInt64LE(20));
  Reject(() => auth.Execute(Signed(ctx,next,dev,evidence)),'SECURITY_NHW_EVIDENCE_INVALID');
  assert.equal(Row(session).status,'CLAIMED');
  const rejectedEvidence=require('../../services/security/peace.security-detections').ForFlow(Row(session).id).find(item=>item.detectionId==='SECURITY_NHW_EVIDENCE_INVALID');
  assert.equal(rejectedEvidence.attestation.status,'REJECTED');
  assert.equal(rejectedEvidence.invalidated,false);
  assert.equal(rejectedEvidence.localOnly,true);
  const unavailable = auth.Execute({...ctx,nhwVersion:1});
  assert.equal(auth.Execute(Signed(ctx,unavailable,dev)).nhwVerdict,undefined);
  assert.equal(Row(session).status,'CLAIMED');
});
Check('NHW validates compact claims without treating a signed client verdict as a session stop', () => {
  const device = Device(), isolated = NewSession(device);
  const ctx = Context(device,'B',isolated,'verify',sha512('NHW revoke'));
  let c = auth.Execute({...ctx,nhwVersion:1});
  Reject(() => auth.Execute(Signed(ctx,c,device,NhwEvidence(c,{trust:3,mask:1,invalidated:true}))),'SECURITY_NHW_EVIDENCE_INVALID');
  c = auth.Execute({...ctx,nhwVersion:1});
  const wrong = NhwEvidence(c,{trust:3,mask:3,invalidated:true});
  delete wrong.nhwResponses.driver;
  Reject(() => auth.Execute(Signed(ctx,c,device,wrong)),'SECURITY_NHW_EVIDENCE_INVALID');
  assert.equal(Row(isolated).status,'CLAIMED');
  c = auth.Execute({...ctx,nhwVersion:1});
  const signed = Signed(ctx,c,device,NhwEvidence(c,{trust:3,mask:3,invalidated:true}));
  const result = auth.Execute(signed);
  assert.equal(result.proceed,true);
  assert.equal(result.status,'PASS');
  assert.equal(Buffer.from(result.nhwVerdict,'base64')[92],1);
  assert.equal(Row(isolated).status,'CLAIMED');
  assert.equal(Row(session).status,'CLAIMED');
  assert.deepEqual(auth.Execute(signed),result);
  c = auth.Execute({...ctx,nhwVersion:1});
  const mismatch = auth.Execute(Signed(ctx,c,device,{
    ...NhwEvidence(c,{trust:3,mask:3,invalidated:true}), codeSha512:'0'.repeat(128)
  }));
  assert.equal(mismatch.proceed,false);
  assert.equal(mismatch.status,'MISMATCH');
  assert.equal(mismatch.reason,'IMAGE_DIGEST_MISMATCH');
  assert.equal(Buffer.from(mismatch.nhwVerdict,'base64')[92],0);
  assert.equal(Row(isolated).status,'REVOKED');
  assert.equal(Row(session).status,'CLAIMED');
});
Check('NHW sequence advances across a later server restart without resetting the session epoch', () => {
  const codecPath = require.resolve('../../services/security/peace.nhw-attestation');
  const row = Row(session);
  const before = require(codecPath).Issue(row);
  const afterTime = Number(before.readBigUInt64LE(20) >> 20n) + 1;
  const script = 'const [file,createdAt,now]=process.argv.slice(1);Date.now=()=>Number(now);' +
    "process.stdout.write(require(file).Issue({createdAt:Number(createdAt)}).toString('base64'));";
  const restarted = child.spawnSync(process.execPath,['-e',script,codecPath,String(row.createdAt),String(afterTime)],{encoding:'utf8'});
  assert.equal(restarted.status,0,restarted.stderr);
  const after = Buffer.from(restarted.stdout,'base64');
  assert.equal(after.readBigUInt64LE(12),before.readBigUInt64LE(12));
  assert.ok(after.readBigUInt64LE(20)>before.readBigUInt64LE(20));
  assert.notDeepEqual(after.subarray(28,60),before.subarray(28,60));
});
Check('Device signals require explicit policy opt-in and negotiated client support',()=>{
 const ctx=Context(dev,'B',session,'verify',sha512('optional-device-signals'));
 assert.equal(require("../../services/authentication/peace.desktop-admin-guard").Summary('/api/desktop/bootstrap/security-authority',{deviceSignalsRequested:true}).deviceSignalsRequested,true);
 const revision=auth.Policy().revision,preview=auth.PreviewPolicy({expectedRevision:revision,deviceSignalsRequested:true});assert.equal(preview.policy.deviceSignalsRequested,true);assert.equal(auth.Policy().revision,revision);assert.equal(auth.Policy().deviceSignalsRequested,false);
 let c=auth.Execute({...ctx,deviceSignalsVersion:1});assert(!Object.hasOwn(c,'deviceSignalsRequested'));auth.Execute(Signed(ctx,c,dev));
 auth.SetPolicy({expectedRevision:auth.Policy().revision,deviceSignalsRequested:true},'TEST');
 c=auth.Execute(ctx);assert(!Object.hasOwn(c,'deviceSignalsRequested'));assert.equal(Object.keys(c).length,8);auth.Execute(Signed(ctx,c,dev));
 for(const v of [null,0,2,'1',true])Reject(()=>auth.Execute({...ctx,deviceSignalsVersion:v}),'SECURITY_INPUT_INVALID');
 c=auth.Execute({...ctx,deviceSignalsVersion:1});assert.equal(c.deviceSignalsRequested,true);assert.equal(Object.keys(c).length,9);assert.equal(auth.Execute(Signed(ctx,c,dev)).proceed,true);
 auth.SetPolicy({expectedRevision:auth.Policy().revision,deviceSignalsRequested:false},'TEST');
 c=auth.Execute({...ctx,deviceSignalsVersion:1});assert(!Object.hasOwn(c,'deviceSignalsRequested'));auth.Execute(Signed(ctx,c,dev));
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
  // A read failure is rejected by the measurement-completeness gate first.
  Reject(() => Fresh(session,'verify',ctx.binding), 'SECURITY_MEASUREMENT_INCOMPLETE');
  assert.equal(Row(session).status,'CLAIMED');
  assert.equal(Observe(ctx,dev,{apiSealed:false}).status,'INDETERMINATE');
  Reject(() => Fresh(session,'verify',ctx.binding), 'SECURITY_OBSERVATION_INDETERMINATE');
  Observe(ctx,dev); Fresh(session,'verify',ctx.binding);
});
Check('Enforce mode revokes the exact measured image mismatch without compact evidence', () => {
  const device = Device(), isolated = NewSession(device), unrelated = NewSession(device);
  const ctx = Context(device,'B',isolated,'verify',sha512('mismatch'));
  const challenge = auth.Execute({...ctx,nhwVersion:1});
  assert.ok(challenge.nhwChallenge);
  const signed = Signed(ctx,challenge,device,{codeSha512:'0'.repeat(128)});
  const out = auth.Execute(signed);
  assert.deepEqual(out,{version:1,accepted:true,status:'MISMATCH',reason:'IMAGE_DIGEST_MISMATCH',
    proceed:false,sequence:challenge.sequence,expiresAt:challenge.expiresAt,attested:false});
  const row = Row(isolated);
  assert.equal(row.status,'REVOKED');
  assert.equal(row.reason,out.reason);
  assert.equal(row.sessionNonce,undefined);
  assert.equal(Row(unrelated).status,'CLAIMED');
  assert.equal(Row(session).status,'CLAIMED');

  const detections = require('../../services/security/peace.security-detections');
  const finding = detections.ForFlow(row.id).find(item=>item.detectionId===out.reason);
  assert.equal(finding.sensor,'peace.desktop-security-authority');
  assert.equal(finding.sessionId,isolated.sessionId);
  assert.equal(finding.invalidated,true);
  assert.equal(finding.authorityAction,'DETECTION_REVOKE');
  assert.equal(finding.attestation.status,'NOT_BOUND');
  assert.equal(detections.ListRecent().items.find(item=>item.id===finding.recordId).verdict,'confirmed');
  Reject(() => auth.Execute(signed),'BOOTSTRAP_REVOKED');
  assert.equal(Row(isolated).status,'REVOKED');
  assert.equal(detections.ForFlow(row.id).find(item=>item.recordId===finding.recordId).count,1);
});
Check('Image mismatch stops the authenticated A download and O cohort without compact evidence', () => {
  const aDevice = Device(), a = Begin(aDevice).begin;
  const aCtx = Context(aDevice,'A',a,'observe',sha512('A image mismatch'));
  const aResult = Observe(aCtx,aDevice,{codeSha512:'0'.repeat(128)});
  assert.equal(aResult.reason,'IMAGE_DIGEST_MISMATCH');
  assert.equal(aResult.proceed,false);
  assert.equal(boot.Initialize().flows[a.flowId].status,'REVOKED');
  assert.equal(boot.Initialize().flows[a.flowId].downloadNonce,undefined);

  const bDevice = Device(), b = NewSession(bDevice), oDevice = fixture.Child(bDevice);
  const issue = licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID(),label:'Authority integrity'},'TEST');
  function LicenseOperation(action, extra) {
    const proof = LeaseProof(bDevice,b,action,crypto.randomUUID(),extra);
    fixture.ObserveLicense(bDevice,action,proof.requestId,proof.payloadHash,JSON.parse(proof.payloadJSON));
    return licenses.Execute(proof);
  }
  const activation = LicenseOperation('redeem',{licenseKey:issue.licenseKey,deviceName:'Authority test'});
  const prepared = LicenseOperation('overlay',{activationToken:activation.activationToken});
  const ticket = {overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket};
  for (let offset = 0; offset < prepared.release.size; offset += prepared.chunkSize) boot.Execute({action:'overlayChunk',...ticket,offset});
  const finished = boot.Execute({action:'overlayFinish',...ticket,signature:Sign(bDevice,prepared.finishCanonical)});
  const o = boot.Execute({action:'overlayClaim',...ticket,...fixture.Delegated(bDevice,oDevice,'O',finished.claimCanonical),
    binarySha512:prepared.release.sha512,crc64:prepared.release.crc64,oCodeSha512:prepared.release.codeSha512,oCodeCrc64:prepared.release.codeCrc64});
  const oCtx = Context(oDevice,'O',o,'observe',sha512('O image mismatch'));
  fixture.Enroll(oDevice,{stage:oCtx.stage,sessionId:oCtx.sessionId,sessionToken:oCtx.sessionToken,machineId:oCtx.machineId});
  const oResult = Observe(oCtx,oDevice,{codeSha512:'0'.repeat(128)});
  assert.equal(oResult.reason,'IMAGE_DIGEST_MISMATCH');
  assert.equal(oResult.proceed,false);
  const overlay = boot.Initialize().overlays[prepared.overlayId];
  assert.equal(overlay.status,'REVOKED');
  assert.equal(overlay.sessionNonce,undefined);
  assert.equal(Row(b).status,'REVOKED');
  assert.equal(Row(session).status,'CLAIMED');

  const detections = require('../../services/security/peace.security-detections');
  const aFinding = detections.ForFlow(a.flowId).find(item=>item.detectionId===aResult.reason);
  const oFinding = detections.ForFlow(Row(b).id).find(item=>item.detectionId===oResult.reason);
  assert.equal(aFinding.sessionId,a.flowId);
  assert.equal(oFinding.sessionId,o.sessionId);
  assert.equal(aFinding.authorityAction,'DETECTION_REVOKE');
  assert.equal(oFinding.authorityAction,'DETECTION_REVOKE');
});
Check('Failed measurement coverage cannot cause an image-mismatch stop without compact evidence', () => {
  const ctx = Context(dev,'B',session,'verify',sha512('incomplete-mismatch'));
  const crcLayers = structuredClone(Evidence(ctx).crcLayers);
  const {algorithm,role} = crcLayers.ecma182;
  crcLayers.ecma182 = {algorithm,role,status:'failed',reason:'READ_ERROR'};
  const out = Observe(ctx,dev,{crcLayers,codeSha512:'0'.repeat(128)});
  assert.equal(out.status,'MISMATCH');
  assert.equal(out.proceed,false);
  assert.equal(Row(session).status,'CLAIMED');
  Reject(() => Fresh(session,'verify',ctx.binding),'SECURITY_MEASUREMENT_INCOMPLETE');
  const crcOnly = Observe(ctx,dev,{crcLayers});
  assert.equal(crcOnly.reason,'CRC_ROLE_MISMATCH');
  assert.equal(crcOnly.proceed,false);
  assert.equal(Row(session).status,'CLAIMED');
  const findings = require('../../services/security/peace.security-detections').ForFlow(Row(session).id);
  assert.equal(findings.find(item=>item.detectionId===out.reason).causedAuthorityChange,false);
  assert.equal(findings.find(item=>item.detectionId===crcOnly.reason).causedAuthorityChange,false);
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
    assert.equal(auth.Execute(Signed(ctx,newer,device,{apiSealed:false})).status,'INDETERMINATE');
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
  const key=licenses.Create({productId:'cleaner.pubg',requestId:require('node:crypto').randomUUID(),label:'server-authority-test'},'TEST');
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
  const reports=require("../../services/integrity/peace.desktop-integrity-reports");
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
Check('Observe-only diagnostics do not authorize a bound server-policy cohort', () => {
  let p=auth.Policy(); auth.SetPolicy({expectedRevision:p.revision,mode:'observe',dynamicCode:'prohibit'},'TEST');
  const ctx=Context(dev,'B',session,'verify',sha512('observe')); let out=Observe(ctx,dev);
  assert.equal(out.status,'INDETERMINATE');assert.equal(out.proceed,true);Reject(()=>Fresh(session,'verify',ctx.binding),'COZY_SERVER_POLICY_AUTHORITY_REQUIRED');
  const mismatch=Observe(ctx,dev,{codeSha512:'0'.repeat(128)});
  assert.equal(mismatch.reason,'IMAGE_DIGEST_MISMATCH');assert.equal(mismatch.proceed,true);
  assert.equal(Row(session).status,'CLAIMED');
  p=auth.Policy(); auth.SetPolicy({expectedRevision:p.revision,mode:'enforce'},'TEST');
  out=Observe(ctx,dev,{dynamicCode:'PROHIBITED'});assert.equal(out.status,'PASS');Fresh(session,'verify',ctx.binding);
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
  const script=`const b=require(process.cwd()+'/services/bootstrap/peace.desktop-bootstrap.js'),a=require(process.cwd()+'/services/security/peace.desktop-security-authority.js');const s=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const row=Object.values(b.Initialize().flows).find(x=>x.sessionId===s.sessionId);let error='';try{a.RequireFresh(row,'B','verify',s.binding);}catch(e){error=e.message;}console.log('RESULT:'+JSON.stringify({revision:a.Policy().revision,error,status:row.status}));`;
  const run=child.spawnSync(process.execPath,['-e',script],{cwd:path.resolve(MODULE_RESOURCE_ROOT,'..'),env:process.env,input:JSON.stringify({sessionId:session.sessionId,binding:verifyContext.binding}),encoding:'utf8',timeout:15000});
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
  const o=PE('O',auth.DOMAIN+' signed');boot.Publish('O',version,o,{keyId,signature:crypto.sign(null,Buffer.from(auth.ReleaseCanonical('O',version,sha512(o))),privateKey).toString('base64')});
  auth.SetPolicy({expectedRevision:auth.Policy().revision,requireReleaseSignature:true},'TEST');
  Reject(()=>boot.Publish('B',version,bytes),'SECURITY_RELEASE_SIGNATURE');
});
console.log(`Server authority regression: ${checks} passed (real services; synthetic PE; JSON storage)`);
