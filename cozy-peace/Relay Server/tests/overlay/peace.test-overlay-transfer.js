'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Real production stores, RSA proofs, CRC/hash reports and authority checks.
// The clock is controlled only in this isolated synthetic-artifact regression.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-transfer-'));
process.env.OVERLAY_CAPTURE_PRIVACY='0';
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require("../../core/peace.utilities.js").EnsureDirs();
const fixture=require("../fixtures/bootstrap/peace.desktop-bootstrap-fixture"),bootstrap=require("../../services/bootstrap/peace.desktop-bootstrap"),licenses=require("../../services/licensing/peace.desktop-licenses"),overlay=require("../../services/overlay/peace.desktop-overlay"),reports=require("../../services/integrity/peace.desktop-integrity-reports"),authority=require("../../services/security/peace.desktop-security-authority");
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
 return {d,overlayDevice,b,o,prepared,context,commit,common,activation,claim};
}
function observe(s){
 clock++;
 const base=overlay.AuthenticateIntegrityReport(s.context).integrityArtifact;
 const payload=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:base.codeSha512,codeCrc64:base.codeCrc64,fileXxh3_128:base.fileXxh3_128,fileBlake3:base.fileBlake3,codeXxh3_128:base.codeXxh3_128,codeBlake3:base.codeBlake3},crcLayers:base.crcLayers});
 const challenge=reports.Execute({...s.context,action:'challenge'});
 assert.equal(reports.Execute({...s.context,action:'submit',reportId:challenge.reportId,payload,signature:fixture.Sign(s.overlayDevice,reports.Canonical(s.o.sessionId,challenge,payload))}).status,'VERIFIED');
 fixture.Observe(s.overlayDevice,{...s.context,intent:'verify',binding:authority.Binding(s.o.sessionId,base.sha512)});
}
function verify(s){observe(s);return bootstrap.Execute({action:'overlayVerify',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,...fixture.Evidence(s.overlayDevice,s.o)});}
function parent(s){return Object.values(bootstrap.Initialize().flows).find(r=>r.sessionId===s.b.sessionId);}
function child(s){return bootstrap.Initialize().overlays[s.prepared.overlayId];}
fixture.CurrentCohort({version:'89.0.0'});
require("../../services/network/peace.connect-transport-key").Profile();clock=Date.now();Date.now=()=>clock;
const s=setup();let receipt;
check('Claim alone cannot retire B; a successful O authority verification is required',()=>{reject(()=>bootstrap.Execute(s.commit),'BOOTSTRAP_OVERLAY_NOT_READY');assert.equal(parent(s).status,'CLAIMED');const state=verify(s);assert.equal(state.transferConfirmed,false);assert.equal(state.handoffVersion,1);assert.equal(state.parentSessionId,s.b.sessionId);assert.equal(Object.keys(state).length,7);});
check('Capture privacy is optional, negotiated and default off without changing legacy replies',()=>{
 const config=require("../../config/peace.runtime-configuration");assert.equal(config.OVERLAY_CAPTURE_PRIVACY,false);
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
check('Transfer requires exact version, parent token and B RSA proof',()=>{reject(()=>bootstrap.Execute({...s.commit,handoffVersion:2}),'BOOTSTRAP_INPUT_INVALID');reject(()=>bootstrap.Execute({...s.commit,sessionToken:'invalid'}),'BOOTSTRAP_SESSION_INVALID');reject(()=>bootstrap.Execute({...s.commit,signature:fixture.Sign(fixture.Device(),'invalid')}),'BOOTSTRAP_PROOF_INVALID');assert.equal(parent(s).status,'CLAIMED');});
check('Commit atomically transfers O and destroys the B session capability',()=>{receipt=bootstrap.Execute(s.commit);assert.deepEqual(receipt,{handoffVersion:1,status:'TRANSFERRED',parentSessionId:s.b.sessionId,overlayId:s.prepared.overlayId,overlaySessionId:s.o.sessionId});const row=parent(s);assert.equal(row.status,'CLOSED');assert.equal(row.sessionHash,undefined);assert.equal(row.sessionNonce,undefined);assert.equal(row.downloadNonce,undefined);assert.equal(row.handoffNonce,undefined);assert.equal(row.licenseLeaseExpiresAt,0);assert.match(row.transferReceiptHash,/^[a-f0-9]{128}$/);assert.equal(child(s).transferVersion,1);});
check('Exact lost-response recovery is idempotent and cannot extend the lease',()=>{const revision=bootstrap.Initialize().revision,expiry=child(s).sessionExpiresAt;assert.deepEqual(bootstrap.Execute(s.commit),receipt);assert.equal(bootstrap.Initialize().revision,revision);assert.equal(child(s).sessionExpiresAt,expiry);reject(()=>bootstrap.Execute({...s.commit,signature:fixture.Sign(s.d,'different transcript')}),'BOOTSTRAP_REQUEST_REUSED');});
check('Retired B cannot report, challenge security, verify its license or query session status',()=>{const context={stage:'B',sessionId:s.b.sessionId,sessionToken:s.b.sessionToken,machineId:s.d.machineId};reject(()=>bootstrap.SessionAuthenticated(s.b.sessionId,s.b.sessionToken),'BOOTSTRAP_SESSION_INVALID');reject(()=>reports.Execute({...context,action:'challenge'}),'BOOTSTRAP_SESSION_INVALID');reject(()=>authority.Execute({...context,intent:'verify',binding:authority.Binding(s.b.sessionId,s.b.release.sha512),action:'challenge'}),'BOOTSTRAP_SESSION_INVALID');reject(()=>proof(s.d,'verify',{...s.common,activationToken:s.activation.activationToken}),'BOOTSTRAP_SESSION_INVALID');reject(()=>bootstrap.Execute({action:'status',sessionId:s.b.sessionId,sessionToken:s.b.sessionToken}),'BOOTSTRAP_SESSION_INVALID');});
check('Best-effort B close acknowledges retirement without closing O',()=>{assert.equal(bootstrap.Execute({action:'close',sessionId:s.b.sessionId,sessionToken:s.b.sessionToken}).status,'CLOSED');assert.equal(child(s).status,'CLAIMED');assert.equal(verify(s).transferConfirmed,true);});
check('Server restart validates the transfer and keeps O authenticated',()=>{const script="const fs=require('node:fs');const x=JSON.parse(fs.readFileSync(0,'utf8'));Date.now=()=>x.clock;const b=require(\"../services/bootstrap/peace.desktop-bootstrap.js\");const o=require(\"../services/overlay/peace.desktop-overlay.js\");b.Initialize();const r=o.AuthenticateIntegrityReport(x.context);if(r.transferVersion!==1)throw Error('TRANSFER_LOST');console.log('RELOAD_OK');";const r=cp.spawnSync(process.execPath,['-e',script],{cwd:MODULE_RESOURCE_ROOT,env:process.env,input:JSON.stringify({clock,context:s.context}),encoding:'utf8'});assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/RELOAD_OK/);});
check('Recovery expires and O renews beyond the former B lease',()=>{const oldExpiry=parent(s).sessionExpiresAt;for(let n=0;n<2;n++){clock+=20000;assert.equal(verify(s).transferConfirmed,true);}assert.equal(parent(s).transferReceiptHash,undefined);assert.equal(parent(s).transferRecoveryUntil,undefined);reject(()=>bootstrap.Execute(s.commit),'BOOTSTRAP_SESSION_INVALID');while(clock+20000<oldExpiry){clock+=20000;verify(s);}clock=oldExpiry+1;assert.ok(child(s).sessionExpiresAt>clock);assert.equal(verify(s).status,'ACTIVE');assert.ok(child(s).sessionExpiresAt>oldExpiry);});
check('Administrator revocation of the retired parent still terminates O authority',()=>{bootstrap.Revoke(s.b.sessionId,{reason:'TEST_TRANSFER_PARENT_REVOKE'},'TEST');reject(()=>overlay.AuthenticateIntegrityReport(s.context),'BOOTSTRAP_REVOKED');assert.equal(child(s).status,'REVOKED');assert.equal(child(s).sessionNonce,undefined);});
const ordinary=setup();verify(ordinary);
check('Ordinary B close without committed handoff never leaves independent O access',()=>{bootstrap.Execute({action:'close',sessionId:ordinary.b.sessionId,sessionToken:ordinary.b.sessionToken});reject(()=>overlay.AuthenticateIntegrityReport(ordinary.context),'BOOTSTRAP_SESSION_CLOSED');assert.equal(child(ordinary).status,'CLOSED');assert.equal(child(ordinary).sessionNonce,undefined);reject(()=>bootstrap.Execute(ordinary.commit),'BOOTSTRAP_SESSION_CLOSED');});
const revoked=setup();verify(revoked);
check('An old O authorization is rejected until O measures and verifies again',()=>{clock+=30001;reject(()=>bootstrap.Execute(revoked.commit),'BOOTSTRAP_OVERLAY_NOT_READY');verify(revoked);bootstrap.Execute(revoked.commit);});
check('License revocation remains authoritative after B is fully retired',()=>{licenses.Revoke(revoked.activation.licenseId,{requestId:require('node:crypto').randomUUID(),reason:'TEST_TRANSFER_LICENSE_REVOKE'},'TEST');reject(()=>overlay.AuthenticateIntegrityReport(revoked.context),'DESKTOP_ACTIVATION_INVALID');});
check('Durable validators reject one-sided or resurrected transfer records',()=>{const db=structuredClone(bootstrap.Initialize()),row=db.flows[parent(s).id];overlay.ValidateStore(db);overlay.ValidateTransferRows(db);overlay.ValidateParentTransfer(db,row);row.sessionHash='a'.repeat(64);assert.throws(()=>overlay.ValidateParentTransfer(db,row),/OVERLAY_STORE_INVALID/);delete row.sessionHash;delete db.overlays[s.prepared.overlayId].transferVersion;assert.throws(()=>overlay.ValidateParentTransfer(db,row),/OVERLAY_STORE_INVALID/);});
function securityStop(s, overlayId=s.prepared.overlayId, scope='COHORT') {
 return {action:'overlayAbort',handoffVersion:3,parentSessionId:s.b.sessionId,parentSessionToken:s.b.sessionToken,overlayId,securityStop:true,
   signature:fixture.Sign(s.d,['GAME-OVERLAY-ABORT-V3',s.b.sessionId,scope,overlayId].join('\n'))};
}
check('Confirmed security stop before transfer retires the exact live cohort',()=>{
 const stopped=setup();verify(stopped);
 const body=securityStop(stopped);
 assert.equal(overlay.ProofTasks(body)[0].message.toString(),['GAME-OVERLAY-ABORT-V3',stopped.b.sessionId,'COHORT',stopped.prepared.overlayId].join('\n'));
 reject(()=>bootstrap.Execute(securityStop(stopped,revoked.prepared.overlayId)),'BOOTSTRAP_FLOW_INVALID');
 reject(()=>bootstrap.Execute(securityStop(stopped,stopped.prepared.overlayId,'OVERLAY')),'BOOTSTRAP_PROOF_INVALID');
 assert.equal(bootstrap.Execute(body).status,'REVOKED');
 assert.equal(parent(stopped).status,'REVOKED');assert.equal(child(stopped).status,'REVOKED');
 assert.equal(child(stopped).sessionNonce,undefined);
 reject(()=>bootstrap.Execute(stopped.commit));
});
check('Confirmed security stop after transfer uses only the exact retired-parent receipt',()=>{
 const stopped=setup(),unrelated=setup();verify(stopped);verify(unrelated);bootstrap.Execute(stopped.commit);
 const body=securityStop(stopped);
 reject(()=>bootstrap.Execute({...body,parentSessionToken:unrelated.b.sessionToken}),'BOOTSTRAP_SESSION_INVALID');
 reject(()=>bootstrap.Execute(securityStop(stopped,unrelated.prepared.overlayId)),'BOOTSTRAP_FLOW_INVALID');
 assert.equal(bootstrap.Execute(body).status,'REVOKED');
 assert.equal(parent(stopped).status,'CLOSED');assert.equal(child(stopped).status,'REVOKED');
 assert.equal(child(stopped).sessionNonce,undefined);assert.equal(child(unrelated).status,'CLAIMED');
 const revision=bootstrap.Initialize().revision;
 assert.equal(bootstrap.Execute(body).status,'REVOKED');assert.equal(bootstrap.Initialize().revision,revision);
 clock+=30001;
 reject(()=>bootstrap.Execute(body),'BOOTSTRAP_SESSION_INVALID');
});
const generation=setup();verify(generation);bootstrap.Execute(generation.commit);
check('Issuer retirement keeps transferred O, issuer revocation closes O after B has retired',()=>{
 const ring=require('../../services/bootstrap/peace.issued-a-keyring'),signing=require('../../services/bootstrap/peace.issued-a-signing');
 const keyId=signing.ConfiguredPublic().find(k=>k.legacy).keyId;
 ring.Mutate({action:'initialize',expectedRevision:0},'TEST');
 assert.ok(ring.Status().keys.find(k=>k.keyId===keyId).liveOverlays>0);
 ring.Mutate({action:'state',expectedRevision:1,keyId,state:'RETIRING'},'TEST');assert.equal(verify(generation).status,'ACTIVE');
 // Isolate the live authorization fence from eager cleanup: a stale active O
 // projection must still honor the original key's durable revocation state.
 const store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),load=store.Load,stale=structuredClone(load());stale.issuedAKeyring.keys[keyId].state='REVOKED';
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
 const out=cp.spawnSync(process.execPath,['-e',script,require.resolve('../../services/bootstrap/peace.desktop-bootstrap'),require.resolve('../../services/overlay/peace.desktop-overlay')],{env:process.env,input:JSON.stringify({clock,context:generation.context,id:generation.prepared.overlayId}),encoding:'utf8',timeout:10000});
 assert.equal(out.status,0,out.stderr);assert.match(out.stdout,/REVOKED_O_RELOAD_OK/);
});
console.log(`Overlay transfer lifecycle: ${checks} checks passed`);
