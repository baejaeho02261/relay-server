'use strict';
// Real authenticated session and persistent store; synthetic PE fixtures only.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-outcome-routing-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../../core/peace.utilities').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=require('../../services/bootstrap/peace.desktop-bootstrap'),reports=require('../../services/security/peace.security-detections'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
process.once('exit',()=>{boot.Stop();fs.rmSync(temp,{recursive:true,force:true});});
fixture.CurrentCohort({version:'90.0.1'});
function subject(){const a=fixture.Device(),start=fixture.Begin(a),b=fixture.Child(a);fixture.Download(start.begin);const session=fixture.Claim(a,start.begin,fixture.Finish(a,start.begin),b);return {b,session,flow:start.begin.flowId,evidence:fixture.Evidence(b,session)};}
const s=subject(),other=subject(),wrongMachine=crypto.randomBytes(32).toString('hex').toUpperCase();
assert.throws(()=>boot.Gate(s.session.sessionId,'incorrect',s.b.deviceId,{...s.evidence,machineId:wrongMachine}),/BOOTSTRAP_SESSION_INVALID/);
assert.equal(reports.ForFlow(s.flow).length,0,'unverified session cannot attach an incident');
assert.throws(()=>boot.Gate(s.session.sessionId,s.session.sessionToken,s.b.deviceId,{...s.evidence,machineId:wrongMachine}),/BOOTSTRAP_HASH_MISMATCH/);
let event=reports.ForFlow(s.flow).find(x=>x.detectionId==='BOOTSTRAP_MACHINE_BINDING_MISMATCH');
assert.ok(event);assert.equal(event.correlation,false);assert.equal(event.invalidated,false);assert.equal(event.role,'B');assert.equal(event.sessionId,s.session.sessionId);
assert.throws(()=>boot.Gate(s.session.sessionId,s.session.sessionToken,s.b.deviceId,{...s.evidence,binarySha512:'1'.repeat(128)}),/BOOTSTRAP_HASH_MISMATCH/);
event=reports.ForFlow(s.flow).find(x=>x.detectionId==='FILE_DIGEST_MISMATCH');assert.ok(event);assert.equal(event.correlation,true);assert.equal(event.invalidated,false);
assert.throws(()=>boot.Gate(s.session.sessionId,s.session.sessionToken,s.b.deviceId,{...s.evidence,codeSha512:'2'.repeat(128)}),/BOOTSTRAP_CODE_MISMATCH/);
event=reports.ForFlow(s.flow).find(x=>x.detectionId==='CODE_DIGEST_MISMATCH');assert.ok(event);assert.equal(event.invalidated,true);assert.equal(store.Load().flows[s.flow].status,'REVOKED');assert.equal(store.Load().flows[other.flow].status,'CLAIMED');assert.equal(reports.ForFlow(other.flow).length,0);
for(const event of reports.ForFlow(s.flow))for(const field of ['machineId','deviceId','pid','path','rawEvidence'])assert.equal(Object.hasOwn(event,field),false);
reports.Validate(store.Load().securityDetections,store.Load());
const licensed=subject(),licenses=require('../../services/licensing/peace.desktop-licenses');
function license(action,payload){const body={action,requestId:crypto.randomUUID(),deviceId:licensed.b.deviceId,publicKey:licensed.b.publicKey,payloadHash:crypto.createHash('sha512').update(JSON.stringify(payload)).digest('hex')},c=licenses.Challenge(body);fixture.ObserveLicense(licensed.b,action,body.requestId,body.payloadHash,payload);return licenses.Execute({...body,challengeId:c.challengeId,payloadJSON:JSON.stringify(payload),signature:fixture.Sign(licensed.b,c.canonical)});}
const common={...licensed.evidence,bootstrapSessionId:licensed.session.sessionId,bootstrapSessionToken:licensed.session.sessionToken,appVersion:'90.0.1'},issued=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID()},'TEST');
const activation=license('redeem',{...common,licenseKey:issued.licenseKey}),prepared=license('overlay',{...common,activationToken:activation.activationToken});
for(let offset=0;offset<prepared.release.size;offset+=prepared.chunkSize)boot.Execute({action:'overlayChunk',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,offset});
const finished=boot.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(licensed.b,prepared.finishCanonical)}),o=fixture.Child(licensed.b);
assert.throws(()=>boot.Execute({action:'overlayClaim',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,...fixture.Delegated(licensed.b,o,'O',finished.claimCanonical),binarySha512:prepared.release.sha512,crc64:prepared.release.crc64,oCodeSha512:'3'.repeat(128),oCodeCrc64:prepared.release.codeCrc64}),/BOOTSTRAP_CODE_MISMATCH/);
const overlayEvent=reports.ForFlow(licensed.flow).find(e=>e.role==='O'&&e.detectionId==='CODE_DIGEST_MISMATCH');assert.ok(overlayEvent);assert.equal(overlayEvent.invalidated,true);assert.equal(overlayEvent.sensor,'peace.desktop-overlay');assert.equal(reports.ForFlow(other.flow).length,0);
reports.Validate(store.Load().securityDetections,store.Load());
console.log('Security outcome routing: authenticated binding, exact B/O file/code causes, unrelated-session isolation PASS');
