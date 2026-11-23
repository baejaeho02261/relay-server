'use strict';

const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs');
const os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
const test=require('node:test');

test('a confirmed O persists a signed theme for later B/O launches on the same installation',()=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-native-ui-theme-'));
 Object.assign(process.env,{
  DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',
  DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'
 });
 require('../../core/peace.utilities').EnsureDirs();
 const bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap');
 const store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
 const schema=require('../../services/protocol/peace.packet-schema');
 const dispatch=require('../../services/authentication/peace.desktop-protected-dispatch');
 const registry=require('../../services/devices/peace.desktop-device-registry');
 const authority=require('../../services/security/peace.desktop-security-authority');
 const work=require('../../services/integrity/peace.desktop-proof-work');
 const licenses=require('../../services/licensing/peace.desktop-licenses');
 const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');

 function Call(body){
  const packet={operation:'bootstrap',body};
  schema.ValidateEnvelope(packet);
  return dispatch.Execute(dispatch.Prepare(packet),packet,{bootstrap:bootstrap.Execute});
 }
 function StartB(device,withTheme=true){
  const child=fixture.Child(device),{begin}=fixture.Begin(device);
  fixture.Download(begin);
  const body=fixture.ClaimBody(device,begin,fixture.Finish(device,begin),child);
  const session=Call(withTheme?{...body,themeVersion:1}:body);
  fixture.Enroll(child,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:child.machineId});
  return {child,session};
 }
 function License(action,client,session,payload){
  const full={...fixture.Evidence(client,session),bootstrapSessionId:session.sessionId,
   bootstrapSessionToken:session.sessionToken,appVersion:'88.0.0',...payload};
  const payloadJSON=JSON.stringify(full);
  const request={action,requestId:crypto.randomUUID(),deviceId:client.deviceId,
   publicKey:client.publicKey,payloadHash:fixture.sha512(payloadJSON)};
  const challenge=licenses.Challenge(request);
  fixture.ObserveLicense(client,action,request.requestId,request.payloadHash,full);
  return licenses.Execute({...request,challengeId:challenge.challengeId,payloadJSON,
   signature:fixture.Sign(client,challenge.canonical)});
 }
 function ClaimO({child,session}){
  const license=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID(),label:'UI theme test'},'TEST');
  const activation=License('redeem',child,session,{licenseKey:license.licenseKey,deviceName:'Test B'});
  const {overlayId,overlayTicket,chunkSize,release,finishCanonical,claimCanonical}=
   License('overlay',child,session,{activationToken:activation.activationToken});
  assert.ok(chunkSize>0);
  for(let offset=0;offset<release.size;offset+=chunkSize)Call({action:'overlayChunk',overlayId,overlayTicket,offset});
  Call({action:'overlayFinish',overlayId,overlayTicket,signature:fixture.Sign(child,finishCanonical)});
  const device=fixture.Child(child);
  const body={action:'overlayClaim',overlayId,overlayTicket,productScopeVersion:1,themeVersion:1,
   binarySha512:release.sha512,crc64:release.crc64,oCodeSha512:release.codeSha512,oCodeCrc64:release.codeCrc64,
   ...fixture.Delegated(child,device,'O',claimCanonical)};
  const live=Call(body);
  assert.deepEqual(Call(body),live);
  assert.equal(live.productId,'cleaner.pubg');
  fixture.Enroll(device,{stage:'O',sessionId:live.sessionId,sessionToken:live.sessionToken,machineId:device.machineId});
  return {device,live,overlayId};
 }
 function Transfer({child,session},{device,live,overlayId}){
  const context={sessionId:live.sessionId,sessionToken:live.sessionToken,machineId:device.machineId};
  fixture.Observe(device,{...context,stage:'O',intent:'verify',binding:authority.Binding(live.sessionId,live.release.sha512)});
  const verified=Call({action:'overlayVerify',...context,...fixture.Evidence(device,live),productScopeVersion:1});
  assert.equal(verified.transferConfirmed,false);
  const signature=fixture.Sign(child,['GAME-OVERLAY-TRANSFER-V1',session.sessionId,overlayId].join('\n'));
  assert.equal(Call({action:'overlayCommit',handoffVersion:1,sessionId:session.sessionId,
   sessionToken:session.sessionToken,overlayId,signature}).status,'TRANSFERRED');
 }
 function SignedTheme({device,live},theme,sequence){
  const requestId=crypto.randomUUID();
  const canonical=['COZY-OVERLAY-THEME-V1',live.sessionId,requestId,String(sequence),String(theme)].join('\n');
  return {action:'overlayTheme',sessionId:live.sessionId,sessionToken:live.sessionToken,
   requestId,theme,sequence,signature:fixture.Sign(device,canonical)};
 }
 const first=fixture.Device();
 try{
  fixture.CurrentCohort({version:'88.0.0'});
  const initial=StartB(first),overlay=ClaimO(initial),blue=SignedTheme(overlay,0,1);
  assert.equal(initial.session.theme,0);
  assert.equal(overlay.live.theme,0);
  assert.throws(()=>Call(blue),/BOOTSTRAP_OVERLAY_NOT_READY/);
  assert.throws(()=>Call({...blue,sessionId:initial.session.sessionId,sessionToken:initial.session.sessionToken}),/BOOTSTRAP_SESSION_INVALID/);
  Transfer(initial,overlay);
  const violet=SignedTheme(overlay,2,1),previousExpiry=store.Load().overlays[overlay.overlayId].sessionExpiresAt;
  assert.equal(bootstrap.ProofTasks(violet).length,1);
  const proof=bootstrap.ProofTasks(violet)[0];
  assert.ok(work.Verify(overlay.device.publicKey,proof.message.toString(),violet.signature));
  assert.throws(()=>Call({...violet,sessionToken:'a'.repeat(43)}),/BOOTSTRAP_SESSION_INVALID/);
  assert.throws(()=>Call({...violet,theme:4}),/PROTOCOL_SCHEMA_INVALID/);
  assert.throws(()=>Call({...violet,theme:3}),/BOOTSTRAP_PROOF_INVALID/);
  const saved=Call(violet),saveRevision=store.Load().revision;
  assert.deepEqual(saved,{version:1,sessionId:violet.sessionId,requestId:violet.requestId,sequence:1,theme:2});
  assert.deepEqual(Call(violet),saved);
  assert.equal(store.Load().revision,saveRevision);
  assert.equal(store.Load().overlays[overlay.overlayId].sessionExpiresAt,previousExpiry);
  assert.throws(()=>Call(blue),/BOOTSTRAP_REQUEST_REUSED/);
  const amber=SignedTheme(overlay,3,2);
  assert.equal(Call(amber).theme,3);
  assert.throws(()=>Call(violet),/BOOTSTRAP_REQUEST_REUSED/);
  assert.equal(Call({action:'overlayClose',sessionId:overlay.live.sessionId,sessionToken:overlay.live.sessionToken}).status,'CLOSED');
  assert.throws(()=>Call(amber),/BOOTSTRAP_SESSION_CLOSED/);

  // Fresh A/B/O still requires the existing single-use machine unlock and a
  // fresh license. Saving a color never changes its authorization.
  const machinePolicy=require('../../services/devices/peace.desktop-machine-policy');
  assert.equal(machinePolicy.Public(first.machineId).source,'SINGLE_USE');
  machinePolicy.Set(first.machineId,false,{requestId:crypto.randomUUID(),reason:'Approve a fresh test run'},'TEST');
  const next=StartB(fixture.Child(first));
  assert.equal(next.session.theme,3);
  assert.equal(ClaimO(next).live.theme,3);
  assert.equal(StartB(fixture.Device()).session.theme,0);
  machinePolicy.Set(first.machineId,false,{requestId:crypto.randomUUID(),reason:'Approve a legacy test run'},'TEST');
  assert.equal(Object.hasOwn(StartB(fixture.Child(first),false).session,'theme'),false);

  const binding=registry.BindingId(first.machineId,store.Load());
  assert.equal(registry.State().bindings[binding].uiTheme,3);
  const check=spawnSync(process.execPath,['-e',`
   const assert=require('node:assert/strict');
   const registry=require('./services/devices/peace.desktop-device-registry');
   const persistence=require('./services/devices/peace.desktop-ui-theme');
   assert.equal(registry.State().bindings[process.argv[1]].uiTheme,3);
   assert.deepEqual(persistence.Projection({machineId:process.argv[2]},1),{theme:3});
  `,binding,first.machineId],{cwd:path.resolve(__dirname,'../..'),encoding:'utf8'});
  assert.equal(check.status,0,check.stderr);
  const invalid=structuredClone(registry.State());
  invalid.bindings[binding].uiTheme=4;
  assert.throws(()=>registry.Validate(invalid),/DEVICE_REGISTRY_INVALID/);
 }finally{
  bootstrap.Stop();
  fs.rmSync(temp,{recursive:true,force:true});
 }
});
