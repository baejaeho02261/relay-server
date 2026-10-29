'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),zlib=require('node:zlib'),cp=require('node:child_process');
const {Readable}=require('node:stream'),{EventEmitter}=require('node:events');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-support-captures-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-SUPPORT-TEST'});
require('../../core/peace.utilities').EnsureDirs();
const captures=require('../../services/diagnostics/peace.support-captures'),png=require('../../services/diagnostics/peace.strict-png'),members=require('../../services/members/peace.desktop-members'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
const actor='ADMIN:synthetic-support',rid=()=>crypto.randomUUID(),body=()=>({requestId:rid(),expectedRevision:captures.State().revision});
const captureModulePath=require.resolve('../../services/diagnostics/peace.support-captures');
function childEnvironment(dataDir){
 const env={DATA_DIR:dataDir,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-SUPPORT-TEST',TMPDIR:dataDir,TMP:dataDir,TEMP:dataDir};
 // Keep dependency lookup, but never inherit operator endpoints, keys, witness
 // locations or Node preload options into the isolated restart probes.
 for(const name of ['PATH','Path','SystemRoot','SYSTEMROOT','WINDIR','PATHEXT','COMSPEC','LANG','LC_ALL','TZ','NODE_PATH'])if(typeof process.env[name]==='string')env[name]=process.env[name];
 return env;
}
const sig=Buffer.from([137,80,78,71,13,10,26,10]);
function Chunk(name,data){const t=Buffer.from(name,'latin1'),out=Buffer.alloc(data.length+12);out.writeUInt32BE(data.length);t.copy(out,4);data.copy(out,8);out.writeUInt32BE(png.Crc(Buffer.concat([t,data])),out.length-4);return out;}
function IHDR(w=2,h=2,color=6){const b=Buffer.alloc(13);b.writeUInt32BE(w);b.writeUInt32BE(h,4);b[8]=8;b[9]=color;return b;}
function Image({header=IHDR(),raw=Buffer.from([0,255,0,0,255,0,255,0,255,0,0,0,255,255,255,255,255,255]),before=[],after=[],compressed}={}){return Buffer.concat([sig,Chunk('IHDR',header),...before,Chunk('IDAT',compressed||zlib.deflateSync(raw)),...after,Chunk('IEND',Buffer.alloc(0))]);}
const valid=Image(),withMeta=Image({before:[Chunk('pHYs',Buffer.from([0,0,0,1,0,0,0,1,0]))]});
let checks=0;async function check(name,fn){await fn();checks++;console.log('PASS '+name);}
const rejects=(code,fn)=>assert.rejects(fn,e=>e.message===code,code),throws=(code,fn)=>assert.throws(fn,e=>e.message===code,code);
class Response extends EventEmitter{constructor(){super();this.headers={};this.statusCode=0;this.headersSent=false;}setHeader(k,v){this.headers[k.toLowerCase()]=v;}writeHead(code,headers={}){this.statusCode=code;this.headersSent=true;for(const [k,v]of Object.entries(headers))this.setHeader(k,v);}end(value,callback){this.bytes=Buffer.isBuffer(value)?Buffer.from(value):Buffer.from(value||'');this.emit('finish');callback?.();}get json(){return JSON.parse(this.bytes.toString());}}
async function run(){
 await check('Strict PNG accepts supported still canvas bytes and strips density metadata',async()=>{const out=await png.Normalize(withMeta);assert.deepEqual(out.bytes,valid);assert.equal(out.width,2);assert.equal(out.height,2);out.bytes.fill(0);});
 await check('Malformed chunks, high-bit aliases, animations, metadata and trailing streams fail closed',async()=>{
  const crc=Buffer.from(valid);crc[20]^=1;const badFilter=Buffer.alloc(18);badFilter[0]=5;
  const header=IHDR();header[12]=1;
  const cases=[Buffer.from('<svg/>'),valid.subarray(0,-1),crc,Buffer.concat([valid,Buffer.from([0])]),Image({before:[Chunk('IHDR',IHDR())]}),Image({before:[Chunk('acTL',Buffer.alloc(8))]}),Image({before:[Chunk('tEXt',Buffer.from('private'))]}),Image({before:[Chunk('iCCP',Buffer.alloc(4))]}),Image({header}),Image({header:IHDR(4097,1)}),Image({header:IHDR(4096,4096)}),Image({header:IHDR(2,2,3)}),Image({raw:badFilter}),Image({compressed:Buffer.concat([zlib.deflateSync(Buffer.alloc(18)),Buffer.from([0])])}),Image({header:IHDR(1,1),raw:Buffer.alloc(1024*1024)}),Buffer.concat([sig,Chunk('\xc9HDR',IHDR()),Chunk('IDAT',zlib.deflateSync(Buffer.alloc(18))),Chunk('IEND',Buffer.alloc(0))]),Buffer.concat([sig,Chunk('IHDR',IHDR()),Chunk('\xc9DAT',zlib.deflateSync(Buffer.alloc(18))),Chunk('IEND',Buffer.alloc(0))])];
  for(const bytes of cases)await rejects('CAPTURE_PNG_INVALID',()=>png.Normalize(bytes));
  const tiny=zlib.deflateSync(Buffer.alloc(18));const pieces=Array.from({length:128},()=>Chunk('IDAT',Buffer.from([0])));await rejects('CAPTURE_PNG_INVALID',()=>png.Normalize(Buffer.concat([sig,Chunk('IHDR',IHDR()),...pieces,Chunk('IEND',Buffer.alloc(0))])));
 });
 const member=members.Create({displayName:'Synthetic support',note:'',expectedRevision:0,requestId:rid()},actor).member;
 const other=members.Create({displayName:'Other',note:'',expectedRevision:members.State().revision,requestId:rid()},actor).member;
 const create=()=>captures.Create(member.id,body(),actor);
 let invitation,uploadedId,request;
 await check('One-use invitation has no public member data and stores no raw bearer',async()=>{
  const b=body();invitation=captures.Create(member.id,b,actor);assert.match(invitation.token,/^[A-F0-9]{24}\.[a-f0-9]{64}$/);
  assert.equal(captures.Create(member.id,b,actor).token,invitation.token);assert.equal(captures.State().revision,1);
  assert.ok(!JSON.stringify(store.Load()).includes(invitation.token));
  const status=captures.Status(invitation.token);assert.equal(status.status,'AVAILABLE');assert.equal(status.expiresAt-invitation.capture.createdAt,600000);assert.equal(status.retentionHours,24);assert.equal(status.maxPixels,4194304);assert.ok(Number.isSafeInteger(status.serverTime));assert.equal(status.memberId,undefined);assert.equal(status.displayName,undefined);
  throws('CAPTURE_REQUEST_REUSED',()=>captures.Create(member.id,{...b,expectedRevision:b.expectedRevision+1},actor));
 });
 await check('Reservation prevents concurrent bodies and incomplete body can retry only the same request',async()=>{
  const first=create(),second=create(),third=create(),id=rid(),t=captures.BeginUpload(first.token,id),u=captures.BeginUpload(second.token,rid());
  throws('CAPTURE_BUSY',()=>captures.BeginUpload(first.token,id));throws('CAPTURE_BUSY',()=>captures.BeginUpload(third.token,rid()));
  captures.EndUpload(t);assert.equal(captures.Status(first.token).status,'AVAILABLE');throws('CAPTURE_REQUEST_REUSED',()=>captures.BeginUpload(first.token,rid()));
  const retry=captures.BeginUpload(first.token,id);captures.EndUpload(retry);captures.EndUpload(u);
 });
 await check('Validated upload is encrypted on disk, one-use, exact-retry only and admin member-bound',async()=>{
  request=rid();const result=await captures.Upload(captures.BeginUpload(invitation.token,request),withMeta);assert.equal(result.status,'UPLOADED');uploadedId=invitation.capture.id;
  const disk=fs.readFileSync(path.join(captures.DIR,uploadedId+'.enc'));assert.ok(!disk.includes(valid));assert.ok(!disk.subarray(0,8).equals(sig));
  const image=captures.Image(member.id,uploadedId);assert.deepEqual(image.bytes,valid);image.bytes.fill(0);
  assert.equal((await captures.Upload(captures.BeginUpload(invitation.token,request),withMeta)).duplicate,true);
  throws('CAPTURE_REQUEST_REUSED',()=>captures.BeginUpload(invitation.token,rid()));await rejects('CAPTURE_REQUEST_REUSED',()=>captures.Upload(captures.BeginUpload(invitation.token,request),valid));
  throws('CAPTURE_NOT_FOUND',()=>captures.Image(other.id,uploadedId));assert.equal(captures.Status(invitation.token).status,'UPLOADED');
 });
 await check('Malformed PNG consumes no image capacity and permanently closes that grant',async()=>{const x=create();await rejects('CAPTURE_PNG_INVALID',()=>captures.Upload(captures.BeginUpload(x.token,rid()),Buffer.from('bad')));throws('CAPTURE_NOT_AVAILABLE',()=>captures.Status(x.token));assert.ok(!fs.existsSync(path.join(captures.DIR,x.capture.id+'.enc')));});
 await check('Archive during async decode aborts upload and unarchive cannot revive invitation',async()=>{
  const x=create(),pending=captures.Upload(captures.BeginUpload(x.token,rid()),valid);
  members.Archive(member.id,{archived:true,expectedRevision:members.State().revision,requestId:rid()},actor);
  await rejects('CAPTURE_NOT_AVAILABLE',()=>pending);throws('CAPTURE_NOT_AVAILABLE',()=>captures.Image(member.id,uploadedId));
  members.Archive(member.id,{archived:false,expectedRevision:members.State().revision,requestId:rid()},actor);
  throws('CAPTURE_NOT_AVAILABLE',()=>captures.Status(x.token));captures.Maintain(true);assert.ok(!fs.existsSync(path.join(captures.DIR,uploadedId+'.enc')));
 });
 await check('Revocation and reset drain are rechecked after asynchronous decoding',async()=>{
  const x=create(),pending=captures.Upload(captures.BeginUpload(x.token,rid()),valid);captures.Close(member.id,x.capture.id,body(),actor,'REVOKE');await rejects('CAPTURE_NOT_AVAILABLE',()=>pending);
  const y=create(),reset=require('../../services/operations/peace.registration-reset'),original=reset.AssertAvailable,pending2=captures.Upload(captures.BeginUpload(y.token,rid()),valid);
  reset.AssertAvailable=()=>{throw Object.assign(Error('REGISTRATION_RESET_IN_PROGRESS'),{desktopError:true,status:503});};try{await rejects('REGISTRATION_RESET_IN_PROGRESS',()=>pending2);}finally{reset.AssertAvailable=original;}
  assert.ok(!fs.existsSync(path.join(captures.DIR,y.capture.id+'.enc')));
 });
 await check('Deadline and backwards wall time cannot grant a new upload',async()=>{
  const x=create(),real=Date.now,now=real();try{Date.now=()=>x.capture.createdAt-1;throws('CAPTURE_NOT_AVAILABLE',()=>captures.Status(x.token));Date.now=()=>now+captures.TTL+1;throws('CAPTURE_NOT_AVAILABLE',()=>captures.Status(x.token));}finally{Date.now=real;}
  throws('CAPTURE_NOT_AVAILABLE',()=>captures.Status(x.token),'observed expiry is terminal in the monotonic bound');
 });
 await check('Image write failure removes the active reservation and retries preserve request identity',async()=>{
  const x=create(),id=rid(),durable=require('../../services/storage/peace.durable-file'),original=durable.Atomic;
  durable.Atomic=(file,...rest)=>{if(file===path.join(captures.DIR,x.capture.id+'.enc'))throw Error('SYNTHETIC_DISK_FULL');return original(file,...rest);};
  try{await assert.rejects(()=>captures.Upload(captures.BeginUpload(x.token,id),valid),/SYNTHETIC_DISK_FULL/);}finally{durable.Atomic=original;}
  assert.equal(captures.Status(x.token).status,'AVAILABLE');assert.equal((await captures.Upload(captures.BeginUpload(x.token,id),valid)).status,'UPLOADED');
 });
 const auth=require('../../web/authentication/peace.web-auth'),adminRoute=require('../../web/routes/licensing/peace.desktop-capture-routes'),publicRoute=require('../../web/http/peace.diagnostic-capture-public');
 const req={headers:{host:'support.example',origin:'https://support.example'},socket:{remoteAddress:'127.0.0.1',encrypted:true}},admin=auth.CreateSession(req,'admin');
 async function adminCall(suffix='',method='GET',payload={},session=admin,csrf=true,memberId=member.id){const url=new URL('https://support.example/api/desktop/members/'+memberId+'/captures'+suffix),res=new Response();assert.equal(await adminRoute.Handle({method,pathname:url.pathname,url,req:{...req,headers:{...req.headers,...(csrf?{'x-csrf-token':session?.csrf||''}:{})}},res,session,body:payload}),true);return res;}
 async function publicCall(suffix,token,data=Buffer.from('{}'),headers={}){const stream=Readable.from([Buffer.from(data)]);stream.method='POST';stream.socket=req.socket;stream.headers={...req.headers,authorization:'Bearer '+token,'content-type':'application/json',...headers};stream.complete=true;const res=new Response();assert.equal(await publicRoute.Handle(stream,res,new URL('https://support.example/api/diagnostic-capture/'+suffix)),true);return res;}
 await check('Public endpoints require HTTPS same-origin header capability and explicit still-image consent',async()=>{
  const x=create();assert.equal((await publicCall('status',x.token)).statusCode,200);assert.equal((await publicCall('status',x.token,Buffer.from('{}'),{origin:'https://elsewhere.example'})).statusCode,403);
  assert.equal((await publicCall('status?token='+x.token,x.token)).statusCode,400);assert.equal((await publicCall('status',x.token,Buffer.from('{"x":1}'))).statusCode,400);
  assert.equal((await publicCall('upload',x.token,valid,{'content-type':'image/png'})).statusCode,400);
  const up=await publicCall('upload',x.token,valid,{'content-type':'image/png','x-diagnostic-consent':'1','x-diagnostic-request':rid()});assert.equal(up.statusCode,200);assert.equal(up.json.status,'UPLOADED');
  assert.equal((await publicCall('image',x.token)).statusCode,404);assert.match(up.headers['cache-control'],/no-store/);
 });
 await check('Image/list/create routes enforce live admin, CSRF, recent auth and mutation guard path',async()=>{
  assert.equal((await adminCall('','GET',{},null)).statusCode,403);assert.equal((await adminCall()).statusCode,200);
  assert.equal((await adminCall('','POST',body(),admin,false)).statusCode,403);
  const guard=require('../../services/authentication/peace.desktop-admin-guard'),original=guard.CheckSession;let seen='';guard.CheckSession=(session,pathname,method)=>{if(method==='POST')seen=pathname;return original(session,pathname,method);};
  let made;try{made=await adminCall('','POST',body());}finally{guard.CheckSession=original;}assert.equal(made.statusCode,200);assert.match(seen,/\/members\/[A-F0-9]{24}\/captures$/);
  const x=made.json;await captures.Upload(captures.BeginUpload(x.token,rid()),valid);const image=await adminCall('/'+x.capture.id+'/image');assert.equal(image.statusCode,200);assert.equal(image.headers['content-type'],'image/png');assert.deepEqual(image.bytes,valid);assert.match(image.headers['cache-control'],/no-store/);
  const real=Date.now,now=real();try{Date.now=()=>now+auth.REAUTH_MS+1;assert.equal((await adminCall('/'+x.capture.id+'/image')).statusCode,428);assert.equal((await adminCall('','POST',body())).statusCode,428);}finally{Date.now=real;}
  auth.RevokeAllSessions();assert.equal((await adminCall()).statusCode,401);
 });
 await check('Fresh process decrypts committed media and permanently revokes crash-left reservation',async()=>{
  const x=create();await captures.Upload(captures.BeginUpload(x.token,rid()),valid);
  const copied=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-capture-restart-'));fs.cpSync(temp,copied,{recursive:true});
  try{const code=`const assert=require('node:assert/strict'),c=require(process.argv[1]);const img=c.Image(${JSON.stringify(member.id)},${JSON.stringify(x.capture.id)});assert.equal(img.bytes.toString('hex'),${JSON.stringify(valid.toString('hex'))});img.bytes.fill(0);console.log('RESTART_CAPTURE_PASS');`;const child=cp.spawnSync(process.execPath,['-e',code,captureModulePath],{cwd:path.resolve(__dirname,'../..'),env:childEnvironment(copied),encoding:'utf8',timeout:15000});assert.equal(child.status,0,child.stderr);assert.match(child.stdout,/RESTART_CAPTURE_PASS/);}finally{fs.rmSync(copied,{recursive:true,force:true});}
  const y=create(),ticket=captures.BeginUpload(y.token,rid()),copy=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-capture-crash-'));fs.cpSync(temp,copy,{recursive:true});captures.EndUpload(ticket);
  try{const file=path.join(copy,'support-captures',y.capture.id+'.enc');fs.writeFileSync(file,Buffer.from('orphan'));const code=`const assert=require('node:assert/strict'),c=require(process.argv[1]),fs=require('node:fs');assert.throws(()=>c.Status(${JSON.stringify(y.token)}),/CAPTURE_NOT_AVAILABLE/);assert.equal(c.State().items[${JSON.stringify(y.capture.id)}].status,'REVOKED');assert.equal(fs.existsSync(${JSON.stringify(file)}),false);console.log('CRASH_CAPTURE_PASS');`;const child=cp.spawnSync(process.execPath,['-e',code,captureModulePath],{cwd:path.resolve(__dirname,'../..'),env:childEnvironment(copy),encoding:'utf8',timeout:15000});assert.equal(child.status,0,child.stderr);assert.match(child.stdout,/CRASH_CAPTURE_PASS/);}finally{fs.rmSync(copy,{recursive:true,force:true});}
 });
 await check('Undeletable media/orphans still consume disk capacity and deletion is authenticated state',async()=>{
  captures.Maintain(true);
  while(new Set([...Object.values(captures.State().items).filter(r=>['UPLOADED','RECEIVING','DELETE_PENDING'].includes(r.status)).map(r=>r.id),...fs.readdirSync(captures.DIR).map(n=>n.slice(0,24))]).size<32){const x=create();await captures.Upload(captures.BeginUpload(x.token,rid()),valid);}
  const row=Object.values(captures.State().items).find(r=>r.status==='UPLOADED'),target=path.join(captures.DIR,row.id+'.enc'),unlink=fs.unlinkSync;fs.unlinkSync=file=>{if(file===target)throw Error('SYNTHETIC_UNLINK_FAILURE');return unlink(file);};
  try{captures.Close(member.id,row.id,body(),actor,'DELETE');assert.equal(captures.State().items[row.id].status,'DELETE_PENDING');const x=create();throws('CAPTURE_CAPACITY',()=>captures.BeginUpload(x.token,rid()));}finally{fs.unlinkSync=unlink;}
  captures.Maintain(true);assert.equal(captures.State().items[row.id].status,'DELETED');assert.ok(!fs.existsSync(target));
 });
 await check('Retention expires images without requests and ciphertext authentication fails closed',async()=>{
  const row=Object.values(captures.State().items).find(r=>r.status==='UPLOADED'),file=path.join(captures.DIR,row.id+'.enc'),before=fs.readFileSync(file),changed=Buffer.from(before);changed[changed.length-1]^=1;fs.writeFileSync(file,changed);
  assert.throws(()=>captures.Image(member.id,row.id));fs.writeFileSync(file,before);
  const real=Date.now,at=real();try{Date.now=()=>at+captures.RETENTION+1;captures.Maintain(true);assert.equal(Object.values(captures.State().items).filter(r=>r.status==='UPLOADED').length,0);assert.equal(fs.readdirSync(captures.DIR).length,0);}finally{Date.now=real;}
 });
 await check('Every physical orphan consumes capacity including multiple temp files for one grant',async()=>{
  const x=create(),same=crypto.randomBytes(12).toString('hex').toUpperCase();
  for(let i=0;i<2;i++)fs.writeFileSync(path.join(captures.DIR,same+'.enc.'+crypto.randomBytes(16).toString('hex')+'.tmp'),Buffer.from([0]));
  for(let i=0;i<30;i++)fs.writeFileSync(path.join(captures.DIR,crypto.randomBytes(12).toString('hex').toUpperCase()+'.enc'),Buffer.from([0]));
  assert.equal(fs.readdirSync(captures.DIR).length,32);assert.equal(new Set(fs.readdirSync(captures.DIR).map(n=>n.slice(0,24))).size,31);
  throws('CAPTURE_CAPACITY',()=>captures.BeginUpload(x.token,rid()));assert.equal(captures.Status(x.token).status,'AVAILABLE');
  captures.Maintain(true);assert.equal(fs.readdirSync(captures.DIR).length,0);
 });
 await check('Lifecycle stop closes access and startup recovers interrupted reservations before serving',async()=>{
  const x=create(),ticket=captures.BeginUpload(x.token,rid());captures.Stop();throws('CAPTURE_NOT_AVAILABLE',()=>captures.Status(x.token));
  captures.Start();captures.EndUpload(ticket);assert.equal(captures.State().items[x.capture.id].status,'REVOKED');throws('CAPTURE_NOT_AVAILABLE',()=>captures.Status(x.token));
  const y=create();captures.Start();assert.equal(captures.Status(y.token).status,'AVAILABLE');assert.equal((await captures.Upload(captures.BeginUpload(y.token,rid()),valid)).status,'UPLOADED');
 });
 console.log('SUPPORT_CAPTURE_BACKEND_PASS '+checks+' checks; visible consent workflow; no native capture; browser/Windows NOT_RUN');
}
run().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>{captures.Stop();require('../../services/bootstrap/peace.desktop-bootstrap').Stop();require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(temp,{recursive:true,force:true});});
