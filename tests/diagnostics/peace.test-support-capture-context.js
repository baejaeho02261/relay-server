'use strict';
// Actual services, synthetic executables/PNG; no native execution or capture.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),zlib=require('node:zlib');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-capture-context-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-CAPTURE-CONTEXT',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../../core/peace.utilities').EnsureDirs();
const captures=require('../../services/diagnostics/peace.support-captures'),members=require('../../services/members/peace.desktop-members'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap'),licenses=require('../../services/licensing/peace.desktop-licenses'),fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),png=require('../../services/diagnostics/peace.strict-png');
const actor='ADMIN:synthetic-context',rid=()=>crypto.randomUUID(),body=()=>({requestId:rid(),expectedRevision:captures.State().revision}),memberBody=x=>({requestId:rid(),expectedRevision:members.State().revision,...x});
const fail=(code,fn)=>assert.throws(fn,e=>e.message===code,code);
let checks=0;async function check(name,fn){await fn();checks++;console.log('PASS '+name);}
function chunk(name,data){const t=Buffer.from(name),b=Buffer.alloc(data.length+12);b.writeUInt32BE(data.length);t.copy(b,4);data.copy(b,8);b.writeUInt32BE(png.Crc(Buffer.concat([t,data])),b.length-4);return b;}
const header=Buffer.alloc(13);header.writeUInt32BE(1,0);header.writeUInt32BE(1,4);header[8]=8;header[9]=6;
const image=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',zlib.deflateSync(Buffer.from([0,30,80,150,255]))),chunk('IEND',Buffer.alloc(0))]);
function proof(device,action,payload){const text=JSON.stringify(payload),request={action,requestId:rid(),deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:fixture.sha512(text)},challenge=licenses.Challenge(request);fixture.ObserveLicense(device,action,request.requestId,request.payloadHash,payload);return licenses.Execute({...request,challengeId:challenge.challengeId,payloadJSON:text,signature:fixture.Sign(device,challenge.canonical)});}
async function run(){
 for(const role of ['A','B','O'])bootstrap.Publish(role,'88.0.0',fixture.PE(role));
 const device=fixture.Device(),session=fixture.Session(device),flow=Object.values(store.Load().flows).find(r=>r.sessionId===session.sessionId);
 const us=fixture.Session(fixture.Device()),uf=Object.values(store.Load().flows).find(r=>r.sessionId===us.sessionId);
 const member=members.Create(memberBody({displayName:'지원 회원',note:''}),actor).member,other=members.Create(memberBody({displayName:'다른 회원',note:''}),actor).member;
 const assign=(memberId,expectedMemberId)=>members.Assign(memberBody({kind:'FLOW',targetId:flow.id,memberId,expectedMemberId}),actor);
 assign(member.id,'');
 const make=role=>captures.Create(member.id,{...body(),context:{flowId:flow.id,role}},actor);let a,b,o,legacy,prepared;
 await check('Choices require owned real execution records and do not invent O',async()=>{
  const expected=[{flowId:flow.id,role:'A'},{flowId:flow.id,role:'B'}];assert.deepEqual(captures.EligibleContexts(member.id,flow.id),expected);assert.deepEqual(members.Detail(member.id,{category:'flows'}).categories.flows.items[0].supportContexts,expected);assert.deepEqual(captures.EligibleContexts(other.id,flow.id),[]);assert.deepEqual(captures.EligibleContexts('',uf.id),[]);fail('CAPTURE_CONTEXT_INVALID',()=>make('O'));
 });
 await check('Malformed schemas and unassigned/cross-member targets fail before mutation',async()=>{
  const rev=captures.State().revision;
  for(const context of [null,[],{}, {flowId:flow.id,role:'o'}, {flowId:flow.id+'\n',role:'A'}, {flowId:[flow.id],role:'A'}, {flowId:flow.id,role:'A',sessionId:flow.sessionId}, {flowId:uf.id,role:'B'}, {flowId:'0'.repeat(24),role:'A'}])fail('CAPTURE_CONTEXT_INVALID',()=>captures.Create(member.id,{...body(),context},actor));
  fail('CAPTURE_CONTEXT_INVALID',()=>captures.Create(other.id,{...body(),context:{flowId:flow.id,role:'B'}},actor));assert.equal(captures.State().revision,rev);
 });
 await check('Context binds retry identity; public consent exposes role/flow only; legacy fingerprint unchanged',async()=>{
  const request={...body(),context:{flowId:flow.id,role:'A'}};a=captures.Create(member.id,request,actor);assert.equal(captures.Create(member.id,request,actor).token,a.token);
  fail('CAPTURE_REQUEST_REUSED',()=>captures.Create(member.id,{...request,context:{flowId:flow.id,role:'B'}},actor));fail('CAPTURE_REQUEST_REUSED',()=>captures.Create(member.id,{expectedRevision:request.expectedRevision,requestId:request.requestId},actor));b=make('B');
  for(const x of [a,b]){assert.deepEqual(captures.Status(x.token).context,x.capture.context);assert.deepEqual(Object.keys(x.capture.context).sort(),['flowId','role']);for(const k of ['memberId','sessionId','artifactId','deviceId'])assert.equal(captures.Status(x.token)[k],undefined);}
  assert.equal(captures.State().items[a.capture.id].context.sessionId,flow.id);assert.equal(captures.State().items[b.capture.id].context.sessionId,flow.sessionId);
  fail('CAPTURE_INPUT_INVALID',()=>captures.Close(member.id,a.capture.id,{...body(),context:{flowId:flow.id,role:'A'}},actor,'REVOKE'));
  const old=body();legacy=captures.Create(member.id,old,actor);const key=crypto.createHash('sha256').update('COZY-CAPTURE-ADMIN-V1\n'+actor+'\n'+old.requestId).digest('hex'),fingerprint=crypto.createHash('sha256').update(JSON.stringify(['CREATE',member.id,'',old.expectedRevision])).digest('hex');assert.equal(captures.State().receipts[key].fingerprint,fingerprint);assert.equal(legacy.capture.context,undefined);assert.equal(captures.Status(legacy.token).context,undefined);
 });
 await check('Real prepared O becomes a support subject; terminal execution remains diagnosable',async()=>{
  const issued=licenses.Create({requestId:rid(),label:'Support O context'},actor),common={...fixture.Evidence(device,session),bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken,appVersion:'88.0.0'},activation=proof(device,'redeem',{...common,licenseKey:issued.licenseKey,deviceName:'Synthetic context'});prepared=proof(device,'overlay',{...common,activationToken:activation.activationToken});o=make('O');assert.deepEqual(o.capture.context,{flowId:flow.id,role:'O'});assert.equal(captures.State().items[o.capture.id].context.overlayId,prepared.overlayId);assert.deepEqual(captures.EligibleContexts(member.id,flow.id).map(x=>x.role),['A','B','O']);bootstrap.Revoke(session.sessionId,{reason:'SYNTHETIC_SUPPORT_FAILURE'},actor);assert.equal(store.Load().flows[flow.id].status,'REVOKED');assert.equal(store.Load().overlays[prepared.overlayId].status,'REVOKED');assert.deepEqual(make('O').capture.context,o.capture.context);assert.equal(captures.Status(o.token).status,'AVAILABLE');
 });
 await check('Stored types, changed bindings and ambiguous O records fail closed',async()=>{
  const state=structuredClone(captures.State());captures.Validate(state);
  for(const change of [c=>c.sessionId=[flow.sessionId],c=>c.artifactId=[c.artifactId],c=>c.overlayId=[c.overlayId],c=>c.flowId+='\n',c=>c.role='X',c=>c.extra=true,c=>c.sessionId=7]){const bad=structuredClone(state);change(bad.items[o.capture.id].context);fail('CAPTURE_STORAGE_INVALID',()=>captures.Validate(bad));}
  const child=store.Load().overlays[prepared.overlayId],old=child.parentSessionId;child.parentSessionId='0'.repeat(24);try{fail('CAPTURE_NOT_AVAILABLE',()=>captures.Status(o.token));fail('CAPTURE_CONTEXT_INVALID',()=>make('O'));}finally{child.parentSessionId=old;}
  const twin=crypto.randomBytes(12).toString('hex').toUpperCase();store.Load().overlays[twin]={...child,id:twin};try{fail('CAPTURE_CONTEXT_INVALID',()=>make('O'));}finally{delete store.Load().overlays[twin];}
 });
 await check('AAD binds new context and cannot relabel existing or legacy encrypted images',async()=>{
  await captures.Upload(captures.BeginUpload(o.token,rid()),image);await captures.Upload(captures.BeginUpload(legacy.token,rid()),image);
  for(const x of [o,legacy]){const r=captures.Image(member.id,x.capture.id);assert.deepEqual(r.bytes,image);r.bytes.fill(0);}
  const row=captures.State().items[o.capture.id],context=structuredClone(row.context),replacement=structuredClone(captures.State().items[b.capture.id].context);
  try{row.context=replacement;assert.throws(()=>captures.Image(member.id,row.id));delete row.context;assert.throws(()=>captures.Image(member.id,row.id));}finally{row.context=context;}
  const old=captures.State().items[legacy.capture.id];try{old.context=replacement;assert.throws(()=>captures.Image(member.id,old.id));}finally{delete old.context;}
  const verified=captures.Image(member.id,row.id);assert.deepEqual(verified.bytes,image);verified.bytes.fill(0);
 });
 await check('Reassignment during decode cancels upload and removes old associated media',async()=>{
  const fresh=make('B'),pending=captures.Upload(captures.BeginUpload(fresh.token,rid()),image);assign(other.id,member.id);await assert.rejects(pending,e=>e.message==='CAPTURE_NOT_AVAILABLE');fail('CAPTURE_NOT_AVAILABLE',()=>captures.Status(a.token));fail('CAPTURE_NOT_AVAILABLE',()=>captures.Image(member.id,o.capture.id));fail('CAPTURE_NOT_FOUND',()=>captures.Image(other.id,o.capture.id));captures.Maintain(true);assert.equal(captures.State().items[o.capture.id].status,'DELETED');assert.ok(!fs.existsSync(path.join(captures.DIR,o.capture.id+'.enc')));assert.equal(captures.State().items[fresh.capture.id].status,'REVOKED');assign(member.id,other.id);fail('CAPTURE_NOT_AVAILABLE',()=>captures.Status(fresh.token));const old=captures.Image(member.id,legacy.capture.id);assert.deepEqual(old.bytes,image);old.bytes.fill(0);
 });
 console.log('SUPPORT_CAPTURE_CONTEXT_PASS '+checks+' checks; native/browser execution NOT_RUN');
}
run().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>{captures.Stop();bootstrap.Stop();fs.rmSync(temp,{recursive:true,force:true});});
