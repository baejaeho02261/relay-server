'use strict';

const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs');
const os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
const test=require('node:test');

const engine=process.argv.includes('--sqlite')?'sqlite':'json';
const black=0x1000000,white=0x1ffffff;
const curated=[0x1131520,0x110211e,0x119152b,0x1091523,0x124131b];
const finalPreset=curated.at(-1);

test(`authenticated B/O claims share signed appearance and published layouts on ${engine}`,async()=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-native-ui-theme-'));
 Object.assign(process.env,{
  DATA_DIR:temp,STORAGE_ENGINE:engine,HA_ENABLED:'0',
  DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'
 });
 require('../../core/spacex.utilities').EnsureDirs();
 const bootstrap=require('../../services/bootstrap/spacex.desktop-bootstrap');
 const store=require('../../services/bootstrap/spacex.desktop-bootstrap-store');
 const schema=require('../../services/protocol/spacex.packet-schema');
 const dispatch=require('../../services/authentication/spacex.desktop-protected-dispatch');
 const registry=require('../../services/devices/spacex.desktop-device-registry');
 const authority=require('../../services/security/spacex.desktop-security-authority');
 const work=require('../../services/integrity/spacex.desktop-proof-work');
 const licenses=require('../../services/licensing/spacex.desktop-licenses');
 const fixture=require('../fixtures/bootstrap/spacex.desktop-bootstrap-fixture');

 function Call(body){
  const packet={operation:'bootstrap',body};
  schema.ValidateEnvelope(packet);
  return dispatch.Execute(dispatch.Prepare(packet),packet,{bootstrap:bootstrap.Execute});
 }
 function StartB(device,themeVersion=1){
  const child=fixture.Child(device),{begin}=fixture.Begin(device);
  fixture.Download(begin);
  const body=fixture.ClaimBody(device,begin,fixture.Finish(device,begin),child);
  const session=Call(themeVersion===null?body:{...body,themeVersion});
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
 function ClaimO({child,session},themeVersion=1){
  const license=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID(),label:'UI theme test'},'TEST');
  const activation=License('redeem',child,session,{licenseKey:license.licenseKey,deviceName:'Test B'});
  const {overlayId,overlayTicket,chunkSize,release,finishCanonical,claimCanonical}=
   License('overlay',child,session,{activationToken:activation.activationToken});
  assert.ok(chunkSize>0);
  for(let offset=0;offset<release.size;offset+=chunkSize)Call({action:'overlayChunk',overlayId,overlayTicket,offset});
  Call({action:'overlayFinish',overlayId,overlayTicket,signature:fixture.Sign(child,finishCanonical)});
  const device=fixture.Child(child);
  const body={action:'overlayClaim',overlayId,overlayTicket,productScopeVersion:1,
   ...(themeVersion===null?{}:{themeVersion}),
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
 function SignedTheme({device,live},theme,sequence,font){
  const requestId=crypto.randomUUID();
  const canonical=[font===undefined?'COZY-OVERLAY-THEME-V1':'COZY-OVERLAY-THEME-V2',
   live.sessionId,requestId,String(sequence),String(theme),...(font===undefined?[]:[String(font)])].join('\n');
  return {action:'overlayTheme',sessionId:live.sessionId,sessionToken:live.sessionToken,
   requestId,theme,sequence,...(font===undefined?{}:{font}),signature:fixture.Sign(device,canonical)};
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
  for(const invalid of [-1,4,0xffffff,black+0.5,white+1,String(black)]){
   assert.throws(()=>Call({...violet,theme:invalid}),/PROTOCOL_SCHEMA_INVALID/);
  }
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
  const binding=registry.BindingId(first.machineId,store.Load());
  assert.equal(registry.State().bindings[binding].uiTheme,3);
  const persistence=require('../../services/devices/spacex.desktop-ui-theme');
  assert.deepEqual(persistence.Projection(first,1),{theme:3});
  assert.deepEqual(persistence.Projection(first,2),{theme:3});
  const whiteRequest=SignedTheme(overlay,white,3);
  assert.equal(Call(whiteRequest).theme,white);
  const blackRequest=SignedTheme(overlay,black,4);
  assert.throws(()=>Call({...blackRequest,theme:black+1}),/BOOTSTRAP_PROOF_INVALID/);
  const blackReceipt=Call(blackRequest);
  const rgbRevision=store.Load().revision;
  assert.deepEqual(blackReceipt,{version:1,sessionId:blackRequest.sessionId,
   requestId:blackRequest.requestId,sequence:4,theme:black});
  assert.deepEqual(Call(blackRequest),blackReceipt);
  assert.equal(store.Load().revision,rgbRevision);
  assert.equal(store.Load().overlays[overlay.overlayId].themeReceipt.sequence,2);
  assert.equal(store.Load().overlays[overlay.overlayId].themeRgbReceipt.sequence,4);
  assert.throws(()=>Call(amber),/BOOTSTRAP_REQUEST_REUSED/);
  assert.throws(()=>Call(whiteRequest),/BOOTSTRAP_REQUEST_REUSED/);
  assert.equal(Call(SignedTheme(overlay,0,5)).theme,0);
  assert.equal(registry.State().bindings[binding].uiTheme,0);
  assert.equal(Object.hasOwn(registry.State().bindings[binding],'uiThemeRgb'),false);
  assert.equal(Object.hasOwn(store.Load().overlays[overlay.overlayId],'themeRgbReceipt'),false);
  assert.throws(()=>Call(blackRequest),/BOOTSTRAP_REQUEST_REUSED/);
  assert.equal(Call(SignedTheme(overlay,black,6)).theme,black);
  if(process.env.COZY_LEGACY_RELAY_ROOT){
   const legacyCheck=spawnSync(process.execPath,['-e',`
    const assert=require('node:assert/strict');
    const store=require('./services/bootstrap/spacex.desktop-bootstrap-store');
    const persistence=require('./services/devices/spacex.desktop-ui-theme');
    const row=store.Load().overlays[process.argv[2]];
    assert.equal(row.themeReceipt.theme,0);
    assert.equal(row.themeRgbReceipt.sequence,6);
    assert.deepEqual(persistence.Projection({machineId:process.argv[1]},1),{theme:0});
   `,first.machineId,overlay.overlayId],{cwd:process.env.COZY_LEGACY_RELAY_ROOT,encoding:'utf8'});
   assert.equal(legacyCheck.status,0,legacyCheck.stderr);
  }
  const legacyColor=SignedTheme(overlay,0x1f4ff91,7);
  assert.equal(Call(legacyColor).theme,legacyColor.theme);
  let nextSequence=8;
  for(const theme of curated){
   const choice=SignedTheme(overlay,theme,nextSequence++);
   const receipt=Call(choice),revision=store.Load().revision;
   assert.equal(receipt.theme,theme);
   assert.deepEqual(Call(choice),receipt);
   assert.equal(store.Load().revision,revision);
   assert.deepEqual(persistence.Projection(first,2),{theme});
   assert.deepEqual(persistence.Projection(first,1),{theme:0});
  }
  assert.throws(()=>Call(legacyColor),/BOOTSTRAP_REQUEST_REUSED/);
  const orbit=SignedTheme(overlay,1,nextSequence++);
  assert.equal(Call(orbit).theme,1);
  assert.deepEqual(persistence.Projection(first,1),{theme:1});
  assert.equal(Object.hasOwn(registry.State().bindings[binding],'uiThemeRgb'),false);
  const fontRequest=SignedTheme(overlay,finalPreset,nextSequence++,2);
  assert.throws(()=>Call({...fontRequest,font:5}),/PROTOCOL_SCHEMA_INVALID/);
  assert.throws(()=>Call({...fontRequest,font:3}),/BOOTSTRAP_PROOF_INVALID/);
  const fontReceipt=Call(fontRequest), fontRevision=store.Load().revision;
  assert.equal(fontReceipt.font,2);
  assert.deepEqual(Call(fontRequest),fontReceipt);
  assert.equal(store.Load().revision,fontRevision);
  assert.equal(registry.State().bindings[binding].uiFont,2);
  assert.equal(Call(SignedTheme(overlay,finalPreset,nextSequence)).theme,finalPreset);
  assert.equal(registry.State().bindings[binding].uiFont,2);
  assert.throws(()=>Call(fontRequest),/BOOTSTRAP_REQUEST_REUSED/);
  assert.equal(store.Load().overlays[overlay.overlayId].sessionExpiresAt,previousExpiry);
  assert.equal(Call({action:'overlayClose',sessionId:overlay.live.sessionId,sessionToken:overlay.live.sessionToken}).status,'CLOSED');
  assert.equal(Object.hasOwn(store.Load().overlays[overlay.overlayId],'themeRgbReceipt'),false);
  assert.throws(()=>Call(amber),/BOOTSTRAP_SESSION_CLOSED/);

  // Fresh A/B/O still requires the existing single-use machine unlock and a
  // fresh license. Saving a color never changes its authorization.
  const machinePolicy=require('../../services/devices/spacex.desktop-machine-policy');
  assert.equal(machinePolicy.Public(first.machineId).source,'SINGLE_USE');
  machinePolicy.Set(first.machineId,false,{requestId:crypto.randomUUID(),reason:'Approve a fresh test run'},'TEST');
  const design=require('../../services/devices/spacex.desktop-ui-design');
  const route=require('../../web/routes/web/spacex.desktop-workspace-routes');
  const guard=require('../../services/authentication/spacex.desktop-admin-guard');
  const pathname='/api/desktop/workspace/ui-design', admin={role:'admin',id:'DESIGN_TEST',csrf:'DESIGN_TEST_CSRF'};
  assert.equal(guard.IsMutation(pathname),true);
  async function DesignRequest(method,session,body,csrf=''){
   let status,response;
   const res={writeHead(value){status=value;},end(value){response=JSON.parse(value);}};
   assert.equal(await route.Handle({method,pathname,body,session,req:{headers:{'x-csrf-token':csrf}},res}),true);
   return {status,response};
  }
  assert.equal((await DesignRequest('GET',{role:'viewer',id:'VIEWER'})).status,403);
  const initialDesign=await DesignRequest('GET',admin);
  assert.equal(initialDesign.status,200);
  const baseline=initialDesign.response.design;
  assert.equal(baseline.revision,0);
  assert.equal(baseline.b.stars,100);
  const draft=structuredClone(baseline);
  Object.assign(draft.b,{x:15,labelY:22,stars:33});
  Object.assign(draft.o,{scale:109,labelX:-21,labelScale:115});
  for(const patch of [{x:33},{labelScale:80.5},{stars:-1},{style:'arbitrary CSS'}]){
   assert.throws(()=>design.Publish({...draft,b:{...draft.b,...patch}},'TEST'),/DESKTOP_DESIGN_INVALID/);
  }
  assert.equal((await DesignRequest('POST',admin,draft)).status,403);
  const savedDesign=await DesignRequest('POST',admin,draft,admin.csrf);
  assert.equal(savedDesign.status,200);
  const published=savedDesign.response.design;
  assert.equal(published.revision,1);
  const staleDesign=await DesignRequest('POST',admin,draft,admin.csrf);
  assert.equal(staleDesign.status,409);
  assert.equal(staleDesign.response.error,'DESKTOP_DESIGN_CONFLICT');
  draft.b.x=0;
  assert.equal(design.Read().b.x,15);
  const next=StartB(fixture.Child(first),3);
  assert.equal(next.session.theme,finalPreset);
  assert.equal(next.session.font,2);
  assert.deepEqual(next.session.desktopDesign,published);
  const nextO=ClaimO(next,3).live;
  assert.equal(nextO.theme,finalPreset);
  assert.equal(nextO.font,2);
  assert.deepEqual(nextO.desktopDesign,published);
  assert.equal(StartB(fixture.Device(),2).session.theme,0);
  const previewFresh=StartB(fixture.Device(),3);
  assert.equal(previewFresh.session.theme,black);
  assert.equal(previewFresh.session.font,0);
  machinePolicy.Set(first.machineId,false,{requestId:crypto.randomUUID(),reason:'Approve a legacy test run'},'TEST');
  const legacy=StartB(fixture.Child(first));
  assert.equal(legacy.session.theme,0);
  assert.equal(ClaimO(legacy).live.theme,0);
  machinePolicy.Set(first.machineId,false,{requestId:crypto.randomUUID(),reason:'Approve a theme-free test run'},'TEST');
  const withoutTheme=StartB(fixture.Child(first),null);
  assert.equal(Object.hasOwn(withoutTheme.session,'theme'),false);
  assert.equal(Object.hasOwn(ClaimO(withoutTheme,null).live,'theme'),false);

  assert.equal(Object.hasOwn(registry.State().bindings[binding],'uiTheme'),false);
  assert.equal(registry.State().bindings[binding].uiThemeRgb,finalPreset);
  const check=spawnSync(process.execPath,['-e',`
   const assert=require('node:assert/strict');
   const registry=require('./services/devices/spacex.desktop-device-registry');
   const persistence=require('./services/devices/spacex.desktop-ui-theme');
   const expected=Number(process.argv[3]),row={machineId:process.argv[2]};
   assert.equal(registry.State().bindings[process.argv[1]].uiThemeRgb,expected);
   assert.deepEqual(persistence.Projection(row,1),{theme:0});
   assert.deepEqual(persistence.Projection(row,2),{theme:expected});
   const v3=persistence.Projection(row,3);
   assert.equal(v3.font,2);
   assert.equal(v3.desktopDesign.revision,1);
   assert.equal(v3.desktopDesign.o.labelX,-21);
  `,binding,first.machineId,String(finalPreset)],{cwd:path.resolve(__dirname,'../..'),encoding:'utf8'});
  assert.equal(check.status,0,check.stderr);
  const invalid=structuredClone(registry.State());
  invalid.bindings[binding].uiTheme=4;
  assert.throws(()=>registry.Validate(invalid),/DEVICE_REGISTRY_INVALID/);
  delete invalid.bindings[binding].uiTheme;
  invalid.bindings[binding].uiThemeRgb=3;
  assert.throws(()=>registry.Validate(invalid),/DEVICE_REGISTRY_INVALID/);

  // An older server's write recreates the preset slot; the v2 reader must
  // respect it even when its value matches the older server's default.
  store.Atomic(db=>{registry.State(db).bindings[binding].uiTheme=0;});
  assert.deepEqual(persistence.Projection(first,2),{theme:0});
 }finally{
  bootstrap.Stop();
  fs.rmSync(temp,{recursive:true,force:true});
 }
});
