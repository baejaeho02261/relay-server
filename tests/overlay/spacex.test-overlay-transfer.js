'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Real production stores, RSA proofs, CRC/hash reports and authority checks.
// The clock is controlled only in this isolated synthetic-artifact regression.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-transfer-'));
process.env.OVERLAY_CAPTURE_PRIVACY='0';
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require("../../core/spacex.utilities.js").EnsureDirs();
const fixture=require("../fixtures/bootstrap/spacex.desktop-bootstrap-fixture"),bootstrap=require("../../services/bootstrap/spacex.desktop-bootstrap"),licenses=require("../../services/licensing/spacex.desktop-licenses"),overlay=require("../../services/overlay/spacex.desktop-overlay"),reports=require("../../services/integrity/spacex.desktop-integrity-reports"),authority=require("../../services/security/spacex.desktop-security-authority");
let checks=0,clock;
const realNow=Date.now;
process.once('exit',()=>{Date.now=realNow;try{fs.rmSync(temp,{recursive:true,force:true});}catch(_){console.error('TEST_SCRATCH_CLEANUP_FAILED');process.exitCode=1;}});
const sha512=v=>crypto.createHash('sha512').update(v).digest('hex');
function check(label,fn){fn();checks++;console.log('PASS '+label);}
function reject(fn,code){assert.throws(fn,e=>code?e.message===code:/^(BOOTSTRAP|DESKTOP|SECURITY|INTEGRITY)_/.test(e.message));}
// Model a new committed generation rather than changing expiry at one frozen issue time.
function proof(d,action,payload){clock++;const body={action,requestId:crypto.randomUUID(),deviceId:d.deviceId,publicKey:d.publicKey,payloadHash:sha512(JSON.stringify(payload))},c=licenses.Challenge(body);fixture.ObserveLicense(d,action,body.requestId,body.payloadHash,payload);return licenses.Execute({...body,challengeId:c.challengeId,payloadJSON:JSON.stringify(payload),signature:fixture.Sign(d,c.canonical)});}
function setup(){
 const parent=fixture.Device(),d=fixture.Child(parent),overlayDevice=fixture.Child(d),begin=fixture.Begin(parent).begin;fixture.Download(begin);const b=fixture.Claim(parent,begin,fixture.Finish(parent,begin),d);
 const common={...fixture.Evidence(d,b),bootstrapSessionId:b.sessionId,bootstrapSessionToken:b.sessionToken,appVersion:'89.0.0'},issue=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID(),label:'overlay transfer'},'TEST');
 const activation=proof(d,'redeem',{...common,licenseKey:issue.licenseKey,deviceName:'Transfer test'}),prepared=proof(d,'overlay',{...common,activationToken:activation.activationToken});
 for(let offset=0;offset<prepared.release.size;offset+=prepared.chunkSize)bootstrap.Execute({action:'overlayChunk',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,offset});
 const finished=bootstrap.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(d,prepared.finishCanonical)});
 const claim={action:'overlayClaim',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,...fixture.Delegated(d,overlayDevice,'O',finished.claimCanonical),binarySha512:prepared.release.sha512,crc64:prepared.release.crc64,oCodeSha512:prepared.release.codeSha512,oCodeCrc64:prepared.release.codeCrc64};
 const o=bootstrap.Execute(claim);
 const context={stage:'O',sessionId:o.sessionId,sessionToken:o.sessionToken,machineId:d.machineId};
 fixture.Enroll(overlayDevice,context);
 const commit={action:'overlayCommit',handoffVersion:1,sessionId:b.sessionId,sessionToken:b.sessionToken,overlayId:prepared.overlayId,signature:fixture.Sign(d,['GAME-OVERLAY-TRANSFER-V1',b.sessionId,prepared.overlayId].join('\n'))};
 return {d,overlayDevice,b,o,prepared,context,commit,common,activation,claim,licenseKey:issue.licenseKey};
}
function observe(s){
 clock++;
 const base=overlay.AuthenticateIntegrityReport(s.context).integrityArtifact;
 const payload=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:base.codeSha512,codeCrc64:base.codeCrc64,fileXxh3_128:base.fileXxh3_128,fileBlake3:base.fileBlake3,codeXxh3_128:base.codeXxh3_128,codeBlake3:base.codeBlake3},crcLayers:base.crcLayers});
 const challenge=reports.Execute({...s.context,action:'challenge'});
 assert.equal(reports.Execute({...s.context,action:'submit',reportId:challenge.reportId,payload,signature:fixture.Sign(s.overlayDevice,reports.Canonical(s.o.sessionId,challenge,payload))}).status,'VERIFIED');
 fixture.Observe(s.overlayDevice,{...s.context,intent:'verify',binding:authority.Binding(s.o.sessionId,base.sha512)});
}
function verificationBody(s){return {action:'overlayVerify',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,...fixture.Evidence(s.overlayDevice,s.o)};}
function verify(s,extra={}){observe(s);return bootstrap.Execute({...verificationBody(s),...extra});}
function parent(s){return Object.values(bootstrap.Initialize().flows).find(r=>r.sessionId===s.b.sessionId);}
function child(s){return bootstrap.Initialize().overlays[s.prepared.overlayId];}
fixture.CurrentCohort({version:'89.0.0'});
require("../../services/network/spacex.connect-transport-key").Profile();clock=Date.now();Date.now=()=>clock;
const s=setup();let receipt;
check('Claim alone cannot retire B; a successful O authority verification is required',()=>{reject(()=>bootstrap.Execute(s.commit),'BOOTSTRAP_OVERLAY_NOT_READY');assert.equal(parent(s).status,'CLAIMED');const state=verify(s);assert.equal(state.transferConfirmed,false);assert.equal(state.handoffVersion,1);assert.equal(state.parentSessionId,s.b.sessionId);assert.equal(Object.keys(state).length,7);});
check('Capture privacy is optional, negotiated and default off without changing legacy replies',()=>{
 const config=require("../../config/spacex.runtime-configuration");assert.equal(config.OVERLAY_CAPTURE_PRIVACY,false);
 observe(s);const body={action:'overlayVerify',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,...fixture.Evidence(s.overlayDevice,s.o),capturePrivacyVersion:1};
 const first=bootstrap.Execute(body);assert.equal(first.capturePrivacy,false);assert.equal(Object.keys(first).length,8);
 config.OVERLAY_CAPTURE_PRIVACY=true;
 assert.deepEqual(bootstrap.Execute(body),first,'a policy change cannot rewrite an existing retry receipt');
 reject(()=>bootstrap.Execute({...body,capturePrivacyVersion:2}),'BOOTSTRAP_INPUT_INVALID');
 reject(()=>bootstrap.Execute({...body,capturePrivacyVersion:null}),'BOOTSTRAP_INPUT_INVALID');
 reject(()=>bootstrap.Execute({...body,capturePrivacyVersion:'1'}),'BOOTSTRAP_INPUT_INVALID');
 const legacy={...body};delete legacy.capturePrivacyVersion;
 reject(()=>bootstrap.Execute(legacy),'BOOTSTRAP_REQUEST_REUSED');
 observe(s);const active=bootstrap.Execute(body);assert.equal(active.capturePrivacy,true);
 const db=structuredClone(bootstrap.Initialize());overlay.ValidateTransferRows(db);
 db.overlays[s.prepared.overlayId].verifyReceipt.response.capturePrivacy='true';
 assert.throws(()=>overlay.ValidateTransferRows(db),/OVERLAY_STORE_INVALID/);
 config.OVERLAY_CAPTURE_PRIVACY=false;observe(s);assert.equal(bootstrap.Execute(body).capturePrivacy,false);
});
check('A prepared O can refresh past the first click cutoff without transferring or starting another child',()=>{
 const firstAuthorizedAt=child(s).authorizedAt, parentId=parent(s).id, parentSessionHash=parent(s).sessionHash;
 let previous=firstAuthorizedAt;
 for(let renewal=0;renewal<4;renewal++){
  clock+=10500;
  const verified=verify(s), row=child(s), launcher=parent(s);
  assert.equal(verified.status,'ACTIVE');
  assert.equal(verified.transferConfirmed,false);
  assert.equal(row.sessionId,s.o.sessionId);
  assert.equal(row.parentSessionId,s.b.sessionId);
  assert.ok(row.authorizedAt>previous);
  assert.equal(row.transferVersion,undefined);
  assert.equal(launcher.status,'CLAIMED');
  assert.equal(launcher.overlayTransferVersion,undefined);
  assert.notEqual(launcher.closedByOverlay,true);
  assert.equal(launcher.sessionHash,parentSessionHash);
  assert.equal(Object.values(bootstrap.Initialize().overlays).filter(o=>o.parentFlowId===parentId).length,1);
  previous=row.authorizedAt;
 }
 assert.ok(clock-firstAuthorizedAt>30000);
});
check('Transfer requires exact version, parent token and B RSA proof',()=>{reject(()=>bootstrap.Execute({...s.commit,handoffVersion:2}),'BOOTSTRAP_INPUT_INVALID');reject(()=>bootstrap.Execute({...s.commit,sessionToken:'invalid'}),'BOOTSTRAP_SESSION_INVALID');reject(()=>bootstrap.Execute({...s.commit,signature:fixture.Sign(fixture.Device(),'invalid')}),'BOOTSTRAP_PROOF_INVALID');assert.equal(parent(s).status,'CLAIMED');});
check('Commit atomically transfers O and destroys the B session capability',()=>{receipt=bootstrap.Execute(s.commit);assert.deepEqual(receipt,{handoffVersion:1,status:'TRANSFERRED',parentSessionId:s.b.sessionId,overlayId:s.prepared.overlayId,overlaySessionId:s.o.sessionId});const row=parent(s);assert.equal(row.status,'CLOSED');assert.equal(row.sessionHash,undefined);assert.equal(row.sessionNonce,undefined);assert.equal(row.downloadNonce,undefined);assert.equal(row.handoffNonce,undefined);assert.equal(row.licenseLeaseExpiresAt,0);assert.match(row.transferReceiptHash,/^[a-f0-9]{128}$/);assert.equal(child(s).transferVersion,1);});
check('Exact lost-response recovery is idempotent and cannot extend the lease',()=>{const revision=bootstrap.Initialize().revision,expiry=child(s).sessionExpiresAt;assert.deepEqual(bootstrap.Execute(s.commit),receipt);assert.equal(bootstrap.Initialize().revision,revision);assert.equal(child(s).sessionExpiresAt,expiry);reject(()=>bootstrap.Execute({...s.commit,signature:fixture.Sign(s.d,'different transcript')}),'BOOTSTRAP_REQUEST_REUSED');});
check('Retired B cannot report, challenge security, verify its license or query session status',()=>{const context={stage:'B',sessionId:s.b.sessionId,sessionToken:s.b.sessionToken,machineId:s.d.machineId};reject(()=>bootstrap.SessionAuthenticated(s.b.sessionId,s.b.sessionToken),'BOOTSTRAP_SESSION_INVALID');reject(()=>reports.Execute({...context,action:'challenge'}),'BOOTSTRAP_SESSION_INVALID');reject(()=>authority.Execute({...context,intent:'verify',binding:authority.Binding(s.b.sessionId,s.b.release.sha512),action:'challenge'}),'BOOTSTRAP_SESSION_INVALID');reject(()=>proof(s.d,'verify',{...s.common,activationToken:s.activation.activationToken}),'BOOTSTRAP_SESSION_INVALID');reject(()=>bootstrap.Execute({action:'status',sessionId:s.b.sessionId,sessionToken:s.b.sessionToken}),'BOOTSTRAP_SESSION_INVALID');});
check('Best-effort B close acknowledges retirement without closing O',()=>{assert.equal(bootstrap.Execute({action:'close',sessionId:s.b.sessionId,sessionToken:s.b.sessionToken}).status,'CLOSED');assert.equal(child(s).status,'CLAIMED');assert.equal(verify(s).transferConfirmed,true);});
check('Server restart validates the transfer and keeps O authenticated',()=>{const script="const fs=require('node:fs');const x=JSON.parse(fs.readFileSync(0,'utf8'));Date.now=()=>x.clock;const b=require(\"../services/bootstrap/spacex.desktop-bootstrap.js\");const o=require(\"../services/overlay/spacex.desktop-overlay.js\");b.Initialize();const r=o.AuthenticateIntegrityReport(x.context);if(r.transferVersion!==1)throw Error('TRANSFER_LOST');console.log('RELOAD_OK');";const r=cp.spawnSync(process.execPath,['-e',script],{cwd:MODULE_RESOURCE_ROOT,env:process.env,input:JSON.stringify({clock,context:s.context}),encoding:'utf8'});assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/RELOAD_OK/);});
check('Recovery expires and O renews beyond the former B lease',()=>{const oldExpiry=parent(s).sessionExpiresAt;for(let n=0;n<2;n++){clock+=20000;assert.equal(verify(s).transferConfirmed,true);}assert.equal(parent(s).transferReceiptHash,undefined);assert.equal(parent(s).transferRecoveryUntil,undefined);reject(()=>bootstrap.Execute(s.commit),'BOOTSTRAP_SESSION_INVALID');while(clock+20000<oldExpiry){clock+=20000;verify(s);}clock=oldExpiry+1;assert.ok(child(s).sessionExpiresAt>clock);assert.equal(verify(s).status,'ACTIVE');assert.ok(child(s).sessionExpiresAt>oldExpiry);});
check('Administrator revocation of the retired parent still terminates O authority',()=>{bootstrap.Revoke(s.b.sessionId,{reason:'TEST_TRANSFER_PARENT_REVOKE'},'TEST');reject(()=>overlay.AuthenticateIntegrityReport(s.context),'BOOTSTRAP_REVOKED');assert.equal(child(s).status,'REVOKED');assert.equal(child(s).sessionNonce,undefined);});
const ordinary=setup();verify(ordinary);
check('Ordinary B close without committed handoff never leaves independent O access',()=>{bootstrap.Execute({action:'close',sessionId:ordinary.b.sessionId,sessionToken:ordinary.b.sessionToken});reject(()=>overlay.AuthenticateIntegrityReport(ordinary.context),'BOOTSTRAP_SESSION_CLOSED');assert.equal(child(ordinary).status,'CLOSED');assert.equal(child(ordinary).sessionNonce,undefined);reject(()=>bootstrap.Execute(ordinary.commit),'BOOTSTRAP_SESSION_CLOSED');});
const revoked=setup();verify(revoked);
check('An old O authorization is rejected until O measures and verifies again',()=>{clock+=30001;reject(()=>bootstrap.Execute(revoked.commit),'BOOTSTRAP_OVERLAY_NOT_READY');verify(revoked);bootstrap.Execute(revoked.commit);});
check('License revocation remains authoritative after B is fully retired',()=>{licenses.Revoke(revoked.activation.licenseId,{requestId:require('node:crypto').randomUUID(),reason:'TEST_TRANSFER_LICENSE_REVOKE'},'TEST');reject(()=>overlay.AuthenticateIntegrityReport(revoked.context),'DESKTOP_ACTIVATION_INVALID');});
check('Durable validators reject one-sided or resurrected transfer records',()=>{const db=structuredClone(bootstrap.Initialize()),row=db.flows[parent(s).id];overlay.ValidateStore(db);overlay.ValidateTransferRows(db);overlay.ValidateParentTransfer(db,row);row.sessionHash='a'.repeat(64);assert.throws(()=>overlay.ValidateParentTransfer(db,row),/OVERLAY_STORE_INVALID/);delete row.sessionHash;delete db.overlays[s.prepared.overlayId].transferVersion;assert.throws(()=>overlay.ValidateParentTransfer(db,row),/OVERLAY_STORE_INVALID/);});

function usageRequest(s,operation,sequence){
 const body={action:'overlayUsage',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,operation,requestId:crypto.randomUUID(),sequence};
 body.signature=fixture.Sign(s.overlayDevice,['SPACEX-OVERLAY-USAGE-V1',body.sessionId,operation,body.requestId,String(sequence)].join('\n'));
 return body;
}
function protectedCall(body){
 const envelope={operation:'bootstrap',body};
 const dispatch=require('../../services/authentication/spacex.desktop-protected-dispatch');
 require('../../services/protocol/spacex.packet-schema').ValidateEnvelope(envelope);
 return dispatch.Execute(dispatch.Prepare(envelope),envelope,{bootstrap:bootstrap.Execute});
}
function usagePreference(s,appearance,sequence){
 const body={action:'overlayTheme',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,
  requestId:crypto.randomUUID(),sequence,theme:0x1000000,font:1,appearance};
 body.signature=fixture.Sign(s.overlayDevice,['COZY-OVERLAY-THEME-V3',body.sessionId,body.requestId,String(sequence),
  String(body.theme),String(body.font),String(body.appearance)].join('\n'));
 return body;
}
const metered=setup();
check('Workspace state is negotiated and requires complete O transfer',()=>{
 const pre=verify(metered,{workspaceStateVersion:1});
 assert.equal(pre.transferConfirmed,false);
 assert.equal(pre.workspaceState,undefined);
 assert.equal(Object.keys(pre).length,7);
 reject(()=>bootstrap.Execute({...verificationBody(metered),workspaceStateVersion:2}),'BOOTSTRAP_INPUT_INVALID');
 reject(()=>bootstrap.Execute({...verificationBody(metered),workspaceStateVersion:1,sessionToken:'invalid'}),'BOOTSTRAP_SESSION_INVALID');
});
check('Usage requires the exact O device, a committed transfer, and current signed evidence',()=>{
 const read=usageRequest(metered,'read',0);
 reject(()=>bootstrap.Execute(read),'BOOTSTRAP_OVERLAY_NOT_READY');
 bootstrap.Execute(metered.commit);
 reject(()=>bootstrap.Execute({...read,sessionToken:'wrong'}),'BOOTSTRAP_SESSION_INVALID');
 reject(()=>bootstrap.Execute({...read,signature:fixture.Sign(metered.d,'different purpose')}),'BOOTSTRAP_PROOF_INVALID');
 reject(()=>bootstrap.Execute(usageRequest(metered,'read',1)),'BOOTSTRAP_INPUT_INVALID');
 reject(()=>bootstrap.Execute(usageRequest(metered,'consume',2)),'BOOTSTRAP_REQUEST_REUSED');
 const revision=bootstrap.Initialize().revision,expiry=child(metered).sessionExpiresAt;
 assert.equal(bootstrap.ProofTasks(read).length,1);
 const balance=protectedCall(read);
 assert.equal(balance.licenseReference,metered.activation.licenseId.replace(/^DL-/,''));
 assert.equal(balance.remaining,100);assert.equal(balance.sequence,0);
 assert.equal(bootstrap.Initialize().revision,revision);assert.equal(child(metered).sessionExpiresAt,expiry);
});
check('Authenticated workspace has its starting balance and masked key suffix before any usage read',()=>{
 assert.equal(verify(metered).workspaceState,undefined);
 observe(metered);
 const body={...verificationBody(metered),workspaceStateVersion:1};
 const first=protectedCall(body);
 assert.deepEqual(first.workspaceState,{version:1,limit:100,remaining:100,sequence:0,licenseKeySuffix:metered.licenseKey.slice(-6)});
 assert.equal(JSON.stringify(first).includes(metered.licenseKey),false);
 assert.deepEqual(bootstrap.Execute(body),first);
 const db=structuredClone(bootstrap.Initialize());
 overlay.ValidateTransferRows(db);
 db.overlays[metered.prepared.overlayId].verifyReceipt.response.workspaceState.licenseKeySuffix=metered.licenseKey;
 assert.throws(()=>overlay.ValidateTransferRows(db),/OVERLAY_STORE_INVALID/);
});
check('Usage debit can be retried exactly without spending or renewing the lease twice',()=>{
 const debit=usageRequest(metered,'consume',1),expiry=child(metered).sessionExpiresAt;
 const result=bootstrap.Execute(debit);assert.equal(result.remaining,99);assert.equal(result.sequence,1);
 const revision=bootstrap.Initialize().revision;
 assert.deepEqual(bootstrap.Execute(debit),result);
 assert.equal(bootstrap.Initialize().revision,revision);assert.equal(child(metered).sessionExpiresAt,expiry);
 reject(()=>bootstrap.Execute(usageRequest(metered,'consume',1)),'BOOTSTRAP_REQUEST_REUSED');
 const read=bootstrap.Execute(usageRequest(metered,'read',0));assert.equal(read.remaining,99);assert.equal(read.sequence,1);
});
check('Fresh workspace state reflects the exact completed debit sequence',()=>{
 const ws=verify(metered,{workspaceStateVersion:1}).workspaceState;
 assert.equal(ws.remaining,99);
 assert.equal(ws.sequence,1);
});

check('New appearance saves charge a changed setting once and do not charge a no-op',()=>{
 const first=usagePreference(metered,1,1),result=protectedCall(first);
 assert.deepEqual(protectedCall(first),result);
 protectedCall(usagePreference(metered,1,2));
 const read=protectedCall(usageRequest(metered,'read',0));assert.equal(read.remaining,98);assert.equal(read.sequence,1);
});
const unrelated=setup();verify(unrelated);bootstrap.Execute(unrelated.commit);
check('Final usage debit retires just the bound execution and license and cannot grant replay authority',()=>{
 let final;
 for(let sequence=2;sequence<=99;sequence++){
  const request=usageRequest(metered,'consume',sequence),balance=protectedCall(request);
  assert.equal(balance.remaining,99-sequence);
  assert.equal(balance.status,sequence===99?'EXHAUSTED':'ACTIVE');
  if(sequence===99)final={request,balance};
 }
 assert.deepEqual(protectedCall(final.request),final.balance);
 reject(()=>protectedCall(usageRequest(metered,'consume',100)),'BOOTSTRAP_REVOKED');
 const terminal=protectedCall(usageRequest(metered,'read',0));assert.equal(terminal.status,'EXHAUSTED');assert.equal(terminal.remaining,0);
 assert.equal(child(metered).sessionNonce,undefined);assert.equal(parent(metered).transferRecoveryUntil,undefined);
 assert.equal(child(metered).reason,'USAGE_EXHAUSTED');
 const license=licenses.Detail(metered.activation.licenseId).license;
 assert.equal(license.status,'REVOKED');assert.equal(license.reason,'USAGE_EXHAUSTED');assert.equal(license.revokedAt,clock);
 assert.equal(licenses.Detail(unrelated.activation.licenseId).license.status,'USED');
 assert.equal(bootstrap.Execute(usageRequest(unrelated,'read',0)).remaining,100);
 const cleanup={action:'overlayClose',sessionId:metered.o.sessionId,sessionToken:metered.o.sessionToken};
 assert.equal(bootstrap.Execute(cleanup).status,'REVOKED');
 const script="const x=JSON.parse(require('node:fs').readFileSync(0,'utf8'));Date.now=()=>x.clock;const b=require(process.argv[1]);b.Initialize();const result=b.Execute(x.request);if(result.status!=='EXHAUSTED'||result.remaining!==0)throw Error('USAGE_REPLAY_MISMATCH');";
 const restart=cp.spawnSync(process.execPath,['-e',script,require.resolve('../../services/bootstrap/spacex.desktop-bootstrap')],{env:process.env,input:JSON.stringify({clock,request:final.request}),encoding:'utf8',timeout:10000});
 assert.equal(restart.status,0,restart.stderr);
 clock+=30001;
 reject(()=>bootstrap.Execute(final.request),'BOOTSTRAP_EXPIRED');
 reject(()=>protectedCall(usageRequest(metered,'read',0)),'BOOTSTRAP_EXPIRED');
});
check('Final appearance debit exposes a signed zero balance for the exact retired O',()=>{
 verify(unrelated);
 const store=require('../../services/bootstrap/spacex.desktop-bootstrap-store');
 store.Atomic(next=>{next.licenseUsage[unrelated.activation.licenseId]={limit:100,remaining:1,exhaustedAt:0};});
 const completed=protectedCall(usagePreference(unrelated,2,1));assert.equal(completed.appearance,2);
 const result=protectedCall(usageRequest(unrelated,'read',0));assert.equal(result.status,'EXHAUSTED');assert.equal(result.remaining,0);
 assert.equal(child(unrelated).reason,'USAGE_EXHAUSTED');assert.equal(child(unrelated).appearanceV3Receipt,undefined);
 reject(()=>protectedCall(usagePreference(unrelated,1,2)),'BOOTSTRAP_REVOKED');
});

const generation=setup();verify(generation);bootstrap.Execute(generation.commit);
check('Issuer retirement keeps transferred O, issuer revocation closes O after B has retired',()=>{
 const ring=require('../../services/bootstrap/spacex.issued-a-keyring'),signing=require('../../services/bootstrap/spacex.issued-a-signing');
 const keyId=signing.ConfiguredPublic().find(k=>k.legacy).keyId;
 ring.Mutate({action:'initialize',expectedRevision:0},'TEST');
 assert.ok(ring.Status().keys.find(k=>k.keyId===keyId).liveOverlays>0);
 ring.Mutate({action:'state',expectedRevision:1,keyId,state:'RETIRING'},'TEST');assert.equal(verify(generation).status,'ACTIVE');
 // Isolate the live authorization fence from eager cleanup: a stale active O
 // projection must still honor the original key's durable revocation state.
 const store=require('../../services/bootstrap/spacex.desktop-bootstrap-store'),load=store.Load,stale=structuredClone(load());stale.issuedAKeyring.keys[keyId].state='REVOKED';
 store.Load=()=>stale;try{reject(()=>overlay.AuthenticateIntegrityReport(generation.context),'ISSUED_A_SIGNING_KEY_REVOKED');}finally{store.Load=load;}
 ring.Mutate({action:'state',expectedRevision:2,keyId,state:'REVOKED'},'TEST');
 assert.equal(parent(generation).status,'REVOKED');assert.equal(child(generation).status,'REVOKED');assert.equal(child(generation).sessionNonce,undefined);
 reject(()=>overlay.AuthenticateIntegrityReport(generation.context),'BOOTSTRAP_REVOKED');
 reject(()=>bootstrap.Execute({action:'overlayChunk',overlayId:generation.prepared.overlayId,overlayTicket:generation.prepared.overlayTicket,offset:0}),'BOOTSTRAP_REVOKED');
 reject(()=>bootstrap.Execute(generation.claim),'BOOTSTRAP_REVOKED');
 const db=structuredClone(bootstrap.Initialize());overlay.ValidateStore(db);overlay.ValidateTransferRows(db);overlay.ValidateParentTransfer(db,parent(generation));
});
check('Revoked transferred O stays revoked across a fresh authority-store load',()=>{
 const script="const x=JSON.parse(require('node:fs').readFileSync(0,'utf8'));Date.now=()=>x.clock;const b=require(process.argv[1]),o=require(process.argv[2]);b.Initialize();try{o.AuthenticateIntegrityReport(x.context);throw Error('UNSAFE_O');}catch(e){if(e.message!=='BOOTSTRAP_REVOKED')throw e;}if(b.Initialize().overlays[x.id].status!=='REVOKED')throw Error('LOST_REVOCATION');console.log('REVOKED_O_RELOAD_OK');";
 const out=cp.spawnSync(process.execPath,['-e',script,require.resolve('../../services/bootstrap/spacex.desktop-bootstrap'),require.resolve('../../services/overlay/spacex.desktop-overlay')],{env:process.env,input:JSON.stringify({clock,context:generation.context,id:generation.prepared.overlayId}),encoding:'utf8',timeout:10000});
 assert.equal(out.status,0,out.stderr);assert.match(out.stdout,/REVOKED_O_RELOAD_OK/);
});
console.log(`Overlay transfer lifecycle: ${checks} checks passed`);
