'use strict';
// Real production stores, RSA delegation and lease handlers over synthetic
// executable fixtures. Wall time is controlled; this is not Windows evidence.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-overlay-download-lifetime-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../../core/peace.utilities.js').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap'),licenses=require('../../services/licensing/peace.desktop-licenses'),overlay=require('../../services/overlay/peace.desktop-overlay');
const realNow=Date.now;let clock,checks=0;
process.once('exit',()=>{Date.now=realNow;try{fs.rmSync(temp,{recursive:true,force:true});}catch(_){console.error('TEST_SCRATCH_CLEANUP_FAILED');process.exitCode=1;}});
const sha512=value=>crypto.createHash('sha512').update(value).digest('hex');
function check(label,fn){fn();checks++;console.log('PASS '+label);}
function reject(fn){assert.throws(fn,error=>/^(BOOTSTRAP|DESKTOP|SECURITY)_/.test(error.message));}
function advance(ms){assert.ok(Number.isSafeInteger(ms)&&ms>=0);clock+=ms;}
function parent(s){return Object.values(bootstrap.Initialize().flows).find(row=>row.sessionId===s.session.sessionId);}
function child(s){return bootstrap.Initialize().overlays[s.prepared.overlayId];}
function proof(s,action,payload){
 clock++;
 const body={action,requestId:crypto.randomUUID(),deviceId:s.device.deviceId,publicKey:s.device.publicKey,payloadHash:sha512(JSON.stringify(payload))},challenge=licenses.Challenge(body);
 fixture.ObserveLicense(s.device,action,body.requestId,body.payloadHash,payload);
 return licenses.Execute({...body,challengeId:challenge.challengeId,payloadJSON:JSON.stringify(payload),signature:fixture.Sign(s.device,challenge.canonical)});
}
function renew(s){return proof(s,'verify',{...s.common,activationToken:s.activation.activationToken});}
function setup(){
 clock++;
 const launcher=fixture.Device(),device=fixture.Child(launcher),overlayDevice=fixture.Child(device),begin=fixture.Begin(launcher).begin;
 fixture.Download(begin);const session=fixture.Claim(launcher,begin,fixture.Finish(launcher,begin),device),s={device,overlayDevice,session};
 s.common={...fixture.Evidence(device,session),bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken,appVersion:'88.0.0'};
 const issued=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID(),label:'Overlay lifetime regression'},'TEST');
 s.activation=proof(s,'redeem',{...s.common,licenseKey:issued.licenseKey,deviceName:'Synthetic lifetime fixture'});
 s.prepared=proof(s,'overlay',{...s.common,activationToken:s.activation.activationToken});
 return s;
}
function chunk(s){return bootstrap.Execute({action:'overlayChunk',overlayId:s.prepared.overlayId,overlayTicket:s.prepared.overlayTicket,offset:0});}
function finish(s){return bootstrap.Execute({action:'overlayFinish',overlayId:s.prepared.overlayId,overlayTicket:s.prepared.overlayTicket,signature:fixture.Sign(s.device,s.prepared.finishCanonical)});}
function claim(s,finished){return bootstrap.Execute({action:'overlayClaim',overlayId:s.prepared.overlayId,overlayTicket:s.prepared.overlayTicket,...fixture.Delegated(s.device,s.overlayDevice,'O',finished.claimCanonical),binarySha512:s.prepared.release.sha512,crc64:s.prepared.release.crc64,oCodeSha512:s.prepared.release.codeSha512,oCodeCrc64:s.prepared.release.codeCrc64});}
function maintainUntil(s,at){while(clock+20000<at){advance(20000);renew(s);}advance(at-clock);}
fixture.CurrentCohort({version:'88.0.0'});require('../../services/network/peace.connect-transport-key').Profile();
clock=Date.now();Date.now=()=>clock;
const slow=setup(),createdAt=child(slow).createdAt,originalParentExpiry=parent(slow).sessionExpiresAt,signedExpiry=slow.prepared.expiresAt;
let finished;
check('110s download leaves its fixed startup budget while B renews beyond its captured lease ceiling',()=>{
 maintainUntil(slow,createdAt+110000);
 assert.ok(originalParentExpiry-clock<10000);assert.ok(parent(slow).sessionExpiresAt>originalParentExpiry);
 chunk(slow);finished=finish(slow);
 assert.equal(child(slow).status,'READY');assert.equal(parent(slow).status,'CLAIMED');
 assert.equal(finished.expiresAt,signedExpiry);assert.equal(finished.claimCanonical,slow.prepared.claimCanonical);
});
check('later child Claim works with a fresh current parent and keeps the ordinary O session bound',()=>{
 maintainUntil(slow,createdAt+150000);renew(slow);
 assert.ok(clock>originalParentExpiry);
 const reply=claim(slow,finished);
 assert.equal(child(slow).status,'CLAIMED');assert.equal(parent(slow).status,'CLAIMED');
 assert.ok(reply.expiresAt>clock);assert.ok(reply.expiresAt<=clock+120000);
 assert.ok(reply.expiresAt<=parent(slow).sessionExpiresAt);
 assert.equal(child(slow).expiresAt,signedExpiry);
});
check('new O download capability has one 410s budget independent of the captured renewable B lease',()=>{
 assert.equal(signedExpiry,createdAt+410000);
 assert.ok(signedExpiry>originalParentExpiry);
 assert.equal(slow.prepared.finishCanonical.split('\n').at(-1),String(signedExpiry));
 assert.equal(slow.prepared.claimCanonical.split('\n').at(-1),String(signedExpiry));
});
check('a longer download ticket cannot authorize any chunk after its current parent lease expires',()=>{
 const s=setup(),ticketExpiry=s.prepared.expiresAt,parentExpiry=parent(s).sessionExpiresAt;
 assert.ok(ticketExpiry>parentExpiry);advance(parentExpiry-clock);
 reject(()=>chunk(s));assert.equal(child(s).status,'EXPIRED');
});
check('Finish and exact retries preserve the immutable ticket deadline and cannot revive it',()=>{
 const s=setup(),expiry=s.prepared.expiresAt;chunk(s);const first=finish(s);
 maintainUntil(s,expiry-1000);renew(s);
 assert.deepEqual(finish(s),first);assert.equal(child(s).expiresAt,expiry);
 advance(expiry-clock);assert.ok(parent(s).sessionExpiresAt>clock);
 reject(()=>finish(s));reject(()=>claim(s,first));
 assert.equal(child(s).status,'EXPIRED');assert.equal(child(s).expiresAt,expiry);
});
check('parent revocation still ends a prepared O immediately despite its remaining download budget',()=>{
 const s=setup();bootstrap.Revoke(s.session.sessionId,{reason:'TEST_CURRENT_PARENT_REVOKED'},'TEST');
 reject(()=>chunk(s));reject(()=>finish(s));assert.equal(child(s).status,'REVOKED');
});
console.log(`Overlay download lifetime: ${checks} checks passed`);
