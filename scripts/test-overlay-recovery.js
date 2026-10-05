'use strict';
// Persistence failure and restart checks using synthetic desktop executables.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs');
const os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-recovery-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../core/utils').EnsureDirs();
const boot=require('../services/desktopBootstrap'),store=require('../services/desktopBootstrapStore');
const licenses=require('../services/desktopLicenses'),fixture=require('./desktop-bootstrap-fixture');
let count=0;
function test(name,fn){fn();console.log('PASS '+name);count++;}
function proof(device,session,action,payload){
 const payloadJSON=JSON.stringify({...fixture.Evidence(device,session),...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken});
 const base={action,requestId:crypto.randomUUID(),deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:fixture.sha256(payloadJSON)};
 const challenge=licenses.Challenge(base);
 return {...base,challengeId:challenge.challengeId,payloadJSON,signature:fixture.Sign(device,challenge.canonical)};
}
function failSave(run){
 const target=path.join(temp,'desktop-bootstrap','authority.json'),before=fs.readFileSync(target),rename=fs.renameSync;
 fs.renameSync=(from,to)=>{if(to===target)throw Error('TEST_AUTHORITY_SAVE_FAILED');return rename(from,to);};
 try{assert.throws(run,/TEST_AUTHORITY_SAVE_FAILED/);}finally{fs.renameSync=rename;}
 assert.deepEqual(fs.readFileSync(target),before);
}
function reload(){
 require('../storage/database').SaveDatabase();
 const code="const service=n=>require(require('node:path').resolve('services',n));require(require('node:path').resolve('storage','database')).LoadDatabase();const db=service('desktopBootstrapStore').Load();process.stdout.write('RESULT:'+JSON.stringify({parent:Object.values(db.flows)[0].status,overlay:Object.values(db.overlays)[0].status,parentRetired:!!Object.values(db.flows)[0].retiredAt,hasTicket:!!Object.values(db.overlays)[0].ticketNonce,hasSession:!!Object.values(db.overlays)[0].sessionNonce}));";
 const run=child.spawnSync(process.execPath,['-e',code],{cwd:path.resolve(__dirname,'..'),env:process.env,encoding:'utf8'});
 assert.equal(run.status,0,run.stderr);return JSON.parse(run.stdout.split('RESULT:').at(-1));
}
try {
 fixture.Publish();boot.Publish('O','1.0',fixture.PE('O','GAME-AUTHORITY-V1'));
 const device=fixture.Device(),session=fixture.Session(device),key=licenses.Create({label:'Synthetic recovery test'},'TEST');
 const licensed=licenses.Execute(proof(device,session,'redeem',{licenseKey:key.licenseKey}));
 const prepared=licenses.Execute(proof(device,session,'overlay',{activationToken:licensed.activationToken}));
 for(let offset=0;offset<prepared.release.size;offset+=prepared.chunkSize)boot.Execute({action:'overlayChunk',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,offset});
 const finish={action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(device,prepared.finishCanonical)};
 test('Failed finish write keeps both the B session and PREPARED handoff intact',()=>{
  failSave(()=>boot.Execute(finish));
  const db=store.Load(),parent=Object.values(db.flows)[0];assert.equal(parent.status,'CLAIMED');assert.ok(parent.sessionNonce);
  assert.equal(db.overlays[prepared.overlayId].status,'PREPARED');
  assert.equal(boot.Gate(session.sessionId,session.sessionToken,device.deviceId,fixture.Evidence(device,session)).sessionId,session.sessionId);
 });
 test('PREPARED handoff and unretired B validate after a separate-process restart',()=>{
  assert.deepEqual(reload(),{parent:'CLAIMED',overlay:'PREPARED',parentRetired:false,hasTicket:true,hasSession:false});
 });
 test('Successful finish is retry-safe while READY and retires B in the same durable write',()=>{
  const first=boot.Execute(finish);assert.deepEqual(boot.Execute(finish),first);
  assert.deepEqual(reload(),{parent:'CLOSED',overlay:'READY',parentRetired:true,hasTicket:true,hasSession:false});
  assert.throws(()=>boot.Gate(session.sessionId,session.sessionToken,device.deviceId,fixture.Evidence(device,session)),/BOOTSTRAP_SESSION_CLOSED/);
 });
 const claim={action:'overlayClaim',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(device,prepared.claimCanonical),binarySha256:prepared.release.sha256,crc64:prepared.release.crc64,oCodeSha256:prepared.release.codeSha256,oCodeCrc64:prepared.release.codeCrc64};
 let o;
 test('Failed claim write preserves READY capability without persisting an O session',()=>{
  failSave(()=>boot.Execute(claim));assert.equal(store.Load().overlays[prepared.overlayId].status,'READY');
  assert.equal(store.Load().overlays[prepared.overlayId].sessionNonce,undefined);
  assert.deepEqual(reload(),{parent:'CLOSED',overlay:'READY',parentRetired:true,hasTicket:true,hasSession:false});
  o=boot.Execute(claim);assert.notEqual(o.sessionId,session.sessionId);
 });
 test('CLAIMED O and retired parent validate together after restart',()=>{
  assert.deepEqual(reload(),{parent:'CLOSED',overlay:'CLAIMED',parentRetired:true,hasTicket:false,hasSession:true});
  assert.equal(boot.AuthenticateIntegrityReport({stage:'O',sessionId:o.sessionId,sessionToken:o.sessionToken,machineId:device.machineId}).releaseId,prepared.release.id);
 });
 test('Lost claim responses recover the same session after restart without another O row',()=>{
  const before=store.Load().revision;
  assert.deepEqual(boot.Execute(claim),o);assert.equal(store.Load().revision,before);
  require('../storage/database').SaveDatabase();
  const code="const load=n=>require(require('node:path').resolve(n));load('storage/database').LoadDatabase();const body=JSON.parse(require('node:fs').readFileSync(0,'utf8')),result=load('services/desktopBootstrap').Execute(body);process.stdout.write('RESULT:'+JSON.stringify({result,count:Object.keys(load('services/desktopBootstrapStore').Load().overlays).length}));";
  const run=child.spawnSync(process.execPath,['-e',code],{cwd:path.resolve(__dirname,'..'),env:process.env,input:JSON.stringify(claim),encoding:'utf8'});
  assert.equal(run.status,0,run.stderr);assert.deepEqual(JSON.parse(run.stdout.split('RESULT:').at(-1)),{result:o,count:1});
  assert.throws(()=>boot.Execute({...claim,oCodeSha256:'0'.repeat(64)}),/BOOTSTRAP_LAUNCHER_USED/);
 });
 test('Recovery ends at its 30-second boundary and cannot renew the session',()=>{
  const clock=Date.now,until=store.Load().overlays[prepared.overlayId].claimRecoveryUntil,revision=store.Load().revision;
  Date.now=()=>until;
  try{assert.throws(()=>boot.Execute(claim),/BOOTSTRAP_LAUNCHER_USED/);assert.equal(store.Load().revision,revision);}
  finally{Date.now=clock;}
 });
 test('Restart validation rejects extended, partial or backward recovery records',()=>{
  const overlay=require('../services/desktopOverlay'),valid=structuredClone(store.Load());
  overlay.ValidateStore(valid);
  for(const mutate of [
   row=>{row.claimRecoveryUntil=row.claimedAt+30001;},
   row=>{row.claimRecoveryUntil=row.claimedAt-1;},
   row=>{delete row.claimRecoveryUntil;},
   row=>{delete row.claimFingerprint;}
  ]){const db=structuredClone(valid);mutate(db.overlays[prepared.overlayId]);assert.throws(()=>overlay.ValidateStore(db),/OVERLAY_STORE_INVALID/);}
 });
 test('The first successful O verification permanently disables signed claim recovery',()=>{
  const auth=require('../services/desktopSecurityAuthority');
  const context={action:'challenge',stage:'O',sessionId:o.sessionId,sessionToken:o.sessionToken,machineId:device.machineId,intent:'verify',binding:auth.Binding(o.sessionId,o.release.sha256)};
  const baseline=boot.AuthenticateIntegrityReport(context).integrityArtifact,challenge=auth.Execute(context);
  const payload=JSON.stringify({version:1,measurement:'MEASURED',fileSha256:baseline.sha256,fileCrc64:baseline.crc64,codeSha256:baseline.codeSha256,codeCrc64:baseline.codeCrc64,apiSealed:true,apiSlots:60,dynamicCode:'ALLOWED',cfg:'DISABLED'});
  assert.equal(auth.Execute({...context,action:'submit',challengeId:challenge.challengeId,payload,signature:fixture.Sign(device,auth.Canonical(context,challenge,payload))}).status,'PASS');
  assert.equal(boot.Execute({action:'overlayVerify',sessionId:o.sessionId,sessionToken:o.sessionToken,...fixture.Evidence(device,o)}).status,'ACTIVE');
  assert.equal(store.Load().overlays[prepared.overlayId].claimRecoveryUntil,undefined);
  assert.equal(store.Load().overlays[prepared.overlayId].claimFingerprint,undefined);
  assert.throws(()=>boot.Execute(claim),/BOOTSTRAP_LAUNCHER_USED/);
 });
 test('Failed close remains authenticated; successful retry durably retires O capability',()=>{
  const close={action:'overlayClose',sessionId:o.sessionId,sessionToken:o.sessionToken};
  failSave(()=>boot.Execute(close));assert.equal(store.Load().overlays[prepared.overlayId].status,'CLAIMED');
  assert.equal(boot.Execute(close).status,'CLOSED');
  assert.deepEqual(reload(),{parent:'CLOSED',overlay:'CLOSED',parentRetired:true,hasTicket:false,hasSession:false});
 });
 console.log(`Overlay recovery: ${count} passed (synthetic PE, injected write failures, real process restarts).`);
} finally {fs.rmSync(temp,{recursive:true,force:true});}
