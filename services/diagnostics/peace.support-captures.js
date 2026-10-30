'use strict';
// Explicit customer-selected still images only. No native screen capture,
// automatic collection, keyboard data, or public image-reading capability.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const store=require('../bootstrap/peace.desktop-bootstrap-store'),png=require('./peace.strict-png');
const config=require('../../config/peace.runtime-configuration'),durable=require('../storage/peace.durable-file');
const DIR=path.join(config.DATA_DIR,'support-captures');
const TTL=10*60000,RETENTION=24*60*60000,MAX_IMAGES=32,MAX_INVITES=256,MAX_ROWS=2048,MAX_ACTIVE=2;
const ID=/^[A-F0-9]{24}$/,HEX=/^[a-f0-9]{64}$/,STRONG=/^[a-f0-9]{128}$/;
const MAGIC=Buffer.from('COZY-DIAGNOSTIC-GCM1\0');
const bounds=require('../runtime/peace.desktop-deadline').CreatePersistentBounds({max:4096});
const active=new Map(),tickets=new WeakMap();let recovered=false,lastMaintenance=-Infinity,started=false,stopped=false;
const plain=v=>!!v&&Object.getPrototypeOf(v)===Object.prototype;
const sha=v=>crypto.createHash('sha256').update(v).digest('hex'),digest=v=>crypto.createHash('sha512').update(v).digest('hex');
function Fail(code,status=400){throw Object.assign(Error(code),{desktopError:true,status});}
function Empty(){return {version:1,revision:0,items:{},receipts:{}};}
function State(db=store.Load()){return db.supportCaptures||Empty();}
function Epoch(db){return require('../recovery/peace.desktop-recovery').Epoch(db);}
function Member(db,id,activeOnly=false){const row=db.members?.items[id];if(!ID.test(id)||!row)Fail('MEMBER_NOT_FOUND',404);if(activeOnly&&row.status!=='ACTIVE')Fail('CAPTURE_NOT_AVAILABLE',403);return row;}
// A context is a support subject, never proof that the process ran or consented.
// All role/session/artifact bindings come from the authority store, not the link.
function ContextId(v){return typeof v==='string'&&v.length===24&&ID.test(v);}
function InputContext(v){return plain(v)&&Object.keys(v).sort().join(',')==='flowId,role'&&ContextId(v.flowId)&&['A','B','O'].includes(v.role);}
function StoredContext(v){return plain(v)&&Object.keys(v).sort().join(',')==='artifactId,flowId,overlayId,role,sessionId'&&InputContext({flowId:v.flowId,role:v.role})&&ContextId(v.sessionId)&&ContextId(v.artifactId)&&(v.role==='O'?ContextId(v.overlayId):v.overlayId==='')&&(v.role!=='A'||v.sessionId===v.flowId);}
function ResolveContext(db,memberId,input){
 if(!InputContext(input)||!memberId||require('../members/peace.desktop-members').FlowMembership(input.flowId,db).memberId!==memberId)return null;
 const flow=db.flows?.[input.flowId],launcher=db.launchers?.[flow?.launcherId];
 if(!flow||flow.id!==input.flowId||!launcher||launcher.id!==flow.launcherId||launcher.flowId!==flow.id)return null;
 let sessionId,artifactId,overlayId='';
 if(input.role==='A'){sessionId=flow.id;artifactId=launcher.artifactId;}
 else if(input.role==='B'){sessionId=flow.sessionId;artifactId=flow.releaseId;}
 else{
  const children=Object.values(db.overlays||{}).filter(r=>r.parentFlowId===flow.id);
  if(children.length!==1)return null;
  const child=children[0];
  if(db.overlays[child.id]!==child||child.parentSessionId!==flow.sessionId||child.launcherId!==flow.launcherId||child.releaseId!==flow.overlayReleaseId||child.licenseId!==flow.licenseId)return null;
  sessionId=child.sessionId;artifactId=child.releaseId;overlayId=child.id;
 }
 const context={flowId:flow.id,role:input.role,sessionId,artifactId,overlayId},artifact=db.artifacts?.[artifactId];
 return StoredContext(context)&&artifact?.id===artifactId&&artifact.component===input.role?context:null;
}
function ContextPublic(r){return r.context?{context:{flowId:r.context.flowId,role:r.context.role}}:{};}
function SameContext(a,b){return !!a&&!!b&&['flowId','role','sessionId','artifactId','overlayId'].every(k=>a[k]===b[k]);}
function ContextAvailable(db,r){return r.context===undefined||StoredContext(r.context)&&SameContext(r.context,ResolveContext(db,r.memberId,{flowId:r.context.flowId,role:r.context.role}));}
function EligibleContexts(memberId,flowId,db=store.Load()){
 if(db.members?.items[memberId]?.status!=='ACTIVE')return [];
 return ['A','B','O'].filter(role=>ResolveContext(db,memberId,{flowId,role})).map(role=>({flowId,role}));
}
function Validate(s){
 const bad=()=>{throw Error('CAPTURE_STORAGE_INVALID');};
 if(!plain(s)||Object.keys(s).sort().join(',')!=='items,receipts,revision,version'||s.version!==1||!Number.isSafeInteger(s.revision)||s.revision<0||!plain(s.items)||!plain(s.receipts)||Object.keys(s.items).length>MAX_ROWS||Object.keys(s.receipts).length>4096)bad();
 const required=['id','memberId','status','createdAt','expiresAt','epoch','tokenHash','issuerHash'],optional=['tokenSeed','requestHash','uploadedAt','retainedUntil','width','height','bytes','inputSha512','imageSha512','consentVersion','closedAt','context'];
 for(const [id,r]of Object.entries(s.items)){
  if(!ID.test(id)||!plain(r)||r.id!==id||required.some(k=>!Object.hasOwn(r,k))||Object.keys(r).some(k=>!required.includes(k)&&!optional.includes(k))||!ID.test(r.memberId)||!['AVAILABLE','RECEIVING','UPLOADED','REVOKED','EXPIRED','DELETE_PENDING','DELETED'].includes(r.status)||!Number.isSafeInteger(r.createdAt)||r.createdAt<1||r.expiresAt!==r.createdAt+TTL||!Number.isSafeInteger(r.epoch)||r.epoch<0||!HEX.test(r.tokenHash)||!HEX.test(r.issuerHash))bad();
  if(r.context!==undefined&&!StoredContext(r.context))bad();
  if(['AVAILABLE','RECEIVING'].includes(r.status)?!HEX.test(r.tokenSeed||''):r.tokenSeed!==undefined)bad();
  if(r.requestHash!==undefined&&!HEX.test(r.requestHash)||r.status==='RECEIVING'&&!r.requestHash)bad();
  if(r.closedAt!==undefined&&(!Number.isSafeInteger(r.closedAt)||r.closedAt<r.createdAt))bad();
  if(r.uploadedAt!==undefined){if(!Number.isSafeInteger(r.uploadedAt)||r.uploadedAt<r.createdAt||r.uploadedAt>=r.expiresAt||r.retainedUntil!==r.uploadedAt+RETENTION||!Number.isSafeInteger(r.width)||r.width<1||r.width>png.LIMITS.maxWidth||!Number.isSafeInteger(r.height)||r.height<1||r.height>png.LIMITS.maxHeight||r.width*r.height>png.LIMITS.maxPixels||!Number.isSafeInteger(r.bytes)||r.bytes<57||r.bytes>png.LIMITS.maxPngBytes||!STRONG.test(r.inputSha512)||!STRONG.test(r.imageSha512)||!r.requestHash||r.consentVersion!==1)bad();}
  else if(['UPLOADED','DELETE_PENDING'].includes(r.status)||['retainedUntil','width','height','bytes','inputSha512','imageSha512','consentVersion'].some(k=>r[k]!==undefined))bad();
 }
 for(const [key,r]of Object.entries(s.receipts))if(!HEX.test(key)||!plain(r)||Object.keys(r).sort().join(',')!=='captureId,fingerprint,revision'||!ID.test(r.captureId)||!HEX.test(r.fingerprint)||!Number.isSafeInteger(r.revision)||r.revision<1||r.revision>s.revision)bad();
}
function Directory(){fs.mkdirSync(DIR,{recursive:true,mode:0o700});const st=fs.lstatSync(DIR);if(!st.isDirectory()||st.isSymbolicLink()||fs.realpathSync(DIR)!==path.join(fs.realpathSync(config.DATA_DIR),'support-captures'))Fail('CAPTURE_STORAGE_UNAVAILABLE',503);}
function File(id){if(!ID.test(id))Fail('CAPTURE_INPUT_INVALID');return path.join(DIR,id+'.enc');}
function DiskSlots(){
 const ids=new Set(),dir=fs.opendirSync(DIR);let entries=0,count=0,entry;
 try{while((entry=dir.readSync())){if(++entries>4096)Fail('CAPTURE_STORAGE_UNAVAILABLE',503);const match=/^([A-F0-9]{24})\.enc(?:\.[a-f0-9]{32}\.tmp)?$/.exec(entry.name);if(!match)continue;const st=fs.lstatSync(path.join(DIR,entry.name));if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)Fail('CAPTURE_STORAGE_UNAVAILABLE',503);ids.add(match[1]);count++;}}finally{dir.closeSync();}
 return {ids,count};
}
function DeleteFile(id){const file=File(id);if(!fs.existsSync(file))return;const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)Fail('CAPTURE_STORAGE_UNAVAILABLE',503);fs.unlinkSync(file);durable.SyncDirectory(DIR);}
function Sweep(){
 const live=State().items,dir=fs.opendirSync(DIR);let count=0,entry;
 try{while((entry=dir.readSync())){if(++count>4096)Fail('CAPTURE_STORAGE_UNAVAILABLE',503);const match=/^([A-F0-9]{24})\.enc(\.[a-f0-9]{32}\.tmp)?$/.exec(entry.name);if(!match)continue;if(!match[2]&&['UPLOADED','RECEIVING'].includes(live[match[1]]?.status))continue;const file=path.join(DIR,entry.name),st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)Fail('CAPTURE_STORAGE_UNAVAILABLE',503);fs.unlinkSync(file);}}finally{dir.closeSync();}durable.SyncDirectory(DIR);
}
function Ready(){
 if(stopped)Fail('CAPTURE_NOT_AVAILABLE',503);
 Directory();if(recovered)return;
 const stale=Object.values(State().items).filter(r=>r.status==='RECEIVING');
 if(stale.length)store.Atomic(db=>{for(const old of stale){const r=db.supportCaptures.items[old.id];r.status='REVOKED';r.closedAt=Math.max(r.createdAt,Date.now());delete r.tokenSeed;}db.supportCaptures.revision++;});
 recovered=true;try{Sweep();}catch(error){recovered=false;throw error;}
}
function Public(r){return {id:r.id,memberId:r.memberId,status:r.status,createdAt:r.createdAt,expiresAt:r.expiresAt,uploadedAt:r.uploadedAt||0,retainedUntil:r.retainedUntil||0,width:r.width||0,height:r.height||0,bytes:r.bytes||0,consentVersion:r.consentVersion||0,...ContextPublic(r)};}
function SeedToken(db,r){if(!r.tokenSeed)Fail('CAPTURE_NOT_AVAILABLE',410);return r.id+'.'+crypto.createHmac('sha256',Buffer.from(db.secret,'hex')).update('COZY-DIAGNOSTIC-CAPABILITY-V1\n'+r.id+'\n'+r.tokenSeed).digest('hex');}
function Expired(r){return bounds.expired(r.id,r.createdAt,r.expiresAt);}
function Available(r,db,allowUploaded=false){return !!r&&db.members?.items[r.memberId]?.status==='ACTIVE'&&r.epoch===Epoch(db)&&ContextAvailable(db,r)&&!Expired(r)&&(['AVAILABLE','RECEIVING'].includes(r.status)||allowUploaded&&r.status==='UPLOADED');}
function Mutation(action,memberId,id,body,actor,fn){
 require('../operations/peace.registration-reset').AssertAvailable();
 Ready();if(!plain(body)||Object.keys(body).some(k=>!['expectedRevision','requestId',...(action==='CREATE'?['context']:[])].includes(k))||!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||typeof body.requestId!=='string'||!/^[-A-Za-z0-9_]{16,80}$/.test(body.requestId))Fail('CAPTURE_INPUT_INVALID');
 const hasContext=Object.hasOwn(body,'context');if(hasContext&&!InputContext(body.context))Fail('CAPTURE_CONTEXT_INVALID');
 Member(store.Load(),memberId);
 // Preserve exact legacy receipt fingerprints when no context was supplied.
 const fields=[action,memberId,id,body.expectedRevision];if(hasContext)fields.push(['CONTEXT_V1',body.context.flowId,body.context.role]);
 const key=sha('COZY-CAPTURE-ADMIN-V1\n'+actor+'\n'+body.requestId),fingerprint=sha(JSON.stringify(fields));
 const previous=State().receipts[key];
 if(previous){if(previous.fingerprint!==fingerprint)Fail('CAPTURE_REQUEST_REUSED',409);const row=State().items[previous.captureId];if(!row)Fail('CAPTURE_NOT_AVAILABLE',410);return {version:1,revision:previous.revision,capture:Public(row),duplicate:true,...(action==='CREATE'&&row.status==='AVAILABLE'&&Available(row,store.Load())?Link(store.Load(),row):{})};}
 if(State().revision!==body.expectedRevision)Fail('CAPTURE_REVISION_CONFLICT',409);
 let result=require('../storage/peace.desktop-operation-audit').Run('CAPTURE_'+action,actor,{subject:sha(id||memberId),fingerprint},db=>{
  const s=db.supportCaptures||(db.supportCaptures=Empty());if(s.revision!==body.expectedRevision)Fail('CAPTURE_REVISION_CONFLICT',409);
  const row=fn(db,s),revision=++s.revision;s.receipts[key]={fingerprint,captureId:row.id,revision};
  const receipts=Object.entries(s.receipts).sort((a,b)=>a[1].revision-b[1].revision);for(const [old]of receipts.slice(0,Math.max(0,receipts.length-4096)))delete s.receipts[old];
  Validate(s);return {version:1,revision,capture:Public(row)};
 });
 const row=State().items[result.capture.id];if(action==='CREATE'&&row.status==='AVAILABLE')result={...result,...Link(store.Load(),row)};
 return result;
}
function Link(db,row){const token=SeedToken(db,row);return {token,fragmentPath:'/diagnostics.html#token='+encodeURIComponent(token)};}
function Create(memberId,body,actor){return Mutation('CREATE',memberId,'',body,actor,(db,s)=>{
 Member(db,memberId,true);const rows=Object.values(s.items);if(rows.length>=MAX_ROWS||rows.filter(r=>['AVAILABLE','RECEIVING'].includes(r.status)).length>=MAX_INVITES)Fail('CAPTURE_CAPACITY',429);
 const id=crypto.randomBytes(12).toString('hex').toUpperCase(),at=Date.now();if(s.items[id])Fail('CAPTURE_STORAGE_UNAVAILABLE',503);
 const context=body.context===undefined?null:ResolveContext(db,memberId,body.context);if(body.context!==undefined&&!context)Fail('CAPTURE_CONTEXT_INVALID');
 const r={id,memberId,status:'AVAILABLE',createdAt:at,expiresAt:at+TTL,epoch:Epoch(db),tokenSeed:crypto.randomBytes(32).toString('hex'),issuerHash:sha(actor),...(context?{context}:{})};r.tokenHash=sha(SeedToken(db,r));s.items[id]=r;store.AfterCommit(()=>bounds.expired(id,r.createdAt,r.expiresAt));return r;
});}
function AdminRow(db,memberId,id){Member(db,memberId);if(!ID.test(id)||db.supportCaptures?.items[id]?.memberId!==memberId)Fail('CAPTURE_NOT_FOUND',404);return db.supportCaptures.items[id];}
function Close(memberId,id,body,actor,action){if(!['REVOKE','DELETE'].includes(action))Fail('CAPTURE_INPUT_INVALID');const result=Mutation(action,memberId,id,body,actor,(db)=>{const r=AdminRow(db,memberId,id);r.status=r.uploadedAt?'DELETE_PENDING':action==='DELETE'?'DELETED':'REVOKED';r.closedAt=Math.max(r.createdAt,Date.now());delete r.tokenSeed;return r;});try{Maintain(true);}catch(_){}return {...result,capture:Public(State().items[id])};}
function ArchiveMemberInState(db,memberId){
 const s=db.supportCaptures;if(!s)return;let changed=false;
 for(const r of Object.values(s.items))if(r.memberId===memberId&&['AVAILABLE','RECEIVING','UPLOADED'].includes(r.status)){r.status=r.uploadedAt?'DELETE_PENDING':'REVOKED';r.closedAt=Math.max(r.createdAt,Date.now());delete r.tokenSeed;changed=true;}
 if(changed)s.revision++;
}
function List(memberId,query={}){
 Ready();Maintain();Member(store.Load(),memberId);if(!plain(query)||Object.keys(query).some(k=>!['page','pageSize'].includes(k)))Fail('CAPTURE_INPUT_INVALID');
 const number=(k,def,max)=>{if(query[k]===undefined)return def;if(typeof query[k]!=='string'||!/^[1-9][0-9]{0,4}$/.test(query[k])||Number(query[k])>max)Fail('CAPTURE_INPUT_INVALID');return Number(query[k]);};
 const page=number('page',1,10000),pageSize=number('pageSize',20,100),s=State(),rows=Object.values(s.items).filter(r=>r.memberId===memberId).sort((a,b)=>b.createdAt-a.createdAt||a.id.localeCompare(b.id));
 return {version:1,revision:s.revision,items:rows.slice((page-1)*pageSize,page*pageSize).map(Public),totalCount:rows.length,page,pageSize,retentionHours:24,invitationLifetimeMs:TTL,...png.LIMITS};
}
function Authenticate(token,allowUploaded=true){
 require('../operations/peace.registration-reset').AssertAvailable();
 if(typeof token!=='string'||!/^[A-F0-9]{24}\.[a-f0-9]{64}$/.test(token))Fail('CAPTURE_NOT_AVAILABLE',403);
 Ready();const db=store.Load(),r=State(db).items[token.slice(0,24)];
 if(!r||!durable.SecretEqual(r.tokenHash,sha(token))||!Available(r,db,allowUploaded))Fail('CAPTURE_NOT_AVAILABLE',403);return r;
}
function Status(token){const r=Authenticate(token);return {version:1,status:r.status,serverTime:Date.now(),expiresAt:r.expiresAt,receivedAt:r.uploadedAt||0,retentionHours:24,consentVersion:1,...ContextPublic(r),...png.LIMITS};}
function BeginUpload(token,requestId){
 const r=Authenticate(token);if(typeof requestId!=='string'||!/^[-A-Za-z0-9_]{16,80}$/.test(requestId))Fail('CAPTURE_INPUT_INVALID');
 const requestHash=sha(requestId);if(r.requestHash&&r.requestHash!==requestHash)Fail('CAPTURE_REQUEST_REUSED',409);
 if(active.has(r.id)||active.size>=MAX_ACTIVE)Fail('CAPTURE_BUSY',429);
 const marker=Object.freeze({});active.set(r.id,marker);
 try{
  if(r.status==='AVAILABLE')store.Atomic(db=>{const row=State(db).items[r.id];if(!Available(row,db,false)||row.status!=='AVAILABLE')Fail('CAPTURE_NOT_AVAILABLE',403);const slots=DiskSlots();for(const x of Object.values(State(db).items))if(['UPLOADED','RECEIVING','DELETE_PENDING'].includes(x.status)&&!slots.ids.has(x.id)){slots.ids.add(x.id);slots.count++;}if(slots.count>=MAX_IMAGES)Fail('CAPTURE_CAPACITY',429);row.status='RECEIVING';row.requestHash=requestHash;State(db).revision++;});
  const ticket=Object.freeze({});tickets.set(ticket,{id:r.id,tokenHash:r.tokenHash,requestHash,marker});return ticket;
 }catch(e){if(active.get(r.id)===marker)active.delete(r.id);throw e;}
}
function Ticket(ticket){require('../operations/peace.registration-reset').AssertAvailable();if(stopped)Fail('CAPTURE_NOT_AVAILABLE',503);const t=tickets.get(ticket),db=store.Load(),r=t&&State(db).items[t.id];if(!t||active.get(t.id)!==t.marker||!r||r.tokenHash!==t.tokenHash||r.requestHash!==t.requestHash||!Available(r,db,true))Fail('CAPTURE_NOT_AVAILABLE',403);return {t,r,db};}
function EndUpload(ticket){
 const t=tickets.get(ticket);if(!t)return;
 if(active.get(t.id)===t.marker){
  try{const row=State().items[t.id];if(row?.status==='RECEIVING'&&row.requestHash===t.requestHash)store.Atomic(db=>{const r=State(db).items[t.id];if(r.status!=='RECEIVING'||r.requestHash!==t.requestHash)return;if(fs.existsSync(File(r.id))||!Available(r,db,false)){r.status='REVOKED';r.closedAt=Math.max(r.createdAt,Date.now());delete r.tokenSeed;}else r.status='AVAILABLE';State(db).revision++;});}catch(_){}
  active.delete(t.id);
 }
 tickets.delete(ticket);
}
function Aad(r){
 const fields=['COZY-DIAGNOSTIC-IMAGE-V1',r.id,r.memberId,String(r.epoch),r.imageSha512,String(r.bytes),String(r.width),String(r.height)];
 // Existing ciphertext has exactly the V1 fields above. New associated media
 // binds the resolved execution identity as well, without migrating old files.
 if(r.context)fields.push('COZY-DIAGNOSTIC-CONTEXT-V1',r.context.flowId,r.context.role,r.context.sessionId,r.context.artifactId,r.context.overlayId);
 return Buffer.from(fields.join('\n'));
}
function Key(db,id){return Buffer.from(crypto.hkdfSync('sha256',Buffer.from(db.secret,'hex'),Buffer.from(id),'COZY-DIAGNOSTIC-IMAGE-KEY-V1',32));}
function Encrypt(db,row,bytes){const key=Key(db,row.id),nonce=crypto.randomBytes(12);try{const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(Aad(row));return Buffer.concat([MAGIC,nonce,cipher.update(bytes),cipher.final(),cipher.getAuthTag()]);}finally{key.fill(0);}}
function Decrypt(db,row){
 const encoded=durable.ReadRegular(File(row.id),png.LIMITS.maxPngBytes+MAGIC.length+28),key=Key(db,row.id);let first,last,bytes;
 try{
  if(encoded.length!==row.bytes+MAGIC.length+28||!encoded.subarray(0,MAGIC.length).equals(MAGIC))Fail('CAPTURE_STORAGE_UNAVAILABLE',503);
  const decipher=crypto.createDecipheriv('aes-256-gcm',key,encoded.subarray(MAGIC.length,MAGIC.length+12));decipher.setAAD(Aad(row));decipher.setAuthTag(encoded.subarray(-16));
  first=decipher.update(encoded.subarray(MAGIC.length+12,-16));last=decipher.final();bytes=Buffer.concat([first,last]);
  if(digest(bytes)!==row.imageSha512){bytes.fill(0);Fail('CAPTURE_STORAGE_UNAVAILABLE',503);}return bytes;
 }finally{key.fill(0);encoded.fill(0);first?.fill(0);last?.fill(0);}
}
async function Upload(ticket,bytes){
 let normalized,encoded;
 try{
  const initial=Ticket(ticket),inputSha512=digest(bytes);
  if(initial.r.status==='UPLOADED'){if(initial.r.inputSha512!==inputSha512)Fail('CAPTURE_REQUEST_REUSED',409);return {version:1,status:'UPLOADED',receivedAt:initial.r.uploadedAt,duplicate:true};}
  normalized=await png.Normalize(bytes);
  const {r,db}=Ticket(ticket),at=Date.now();
  if(r.status!=='RECEIVING')Fail('CAPTURE_NOT_AVAILABLE',403);
  const row={...r,status:'UPLOADED',uploadedAt:at,retainedUntil:at+RETENTION,width:normalized.width,height:normalized.height,bytes:normalized.bytes.length,inputSha512,imageSha512:digest(normalized.bytes),consentVersion:1};delete row.tokenSeed;
  encoded=Encrypt(db,row,normalized.bytes);durable.Atomic(File(r.id),encoded,{createOnly:true});
  try{
   require('../storage/peace.desktop-operation-audit').Run('CAPTURE_UPLOAD','CUSTOMER_CAPABILITY',{subject:sha(r.id),bytes:row.bytes},next=>{const current=State(next).items[r.id];if(!Available(current,next,false)||current.status!=='RECEIVING'||current.requestHash!==r.requestHash)Fail('CAPTURE_NOT_AVAILABLE',403);State(next).items[r.id]=row;State(next).revision++;Validate(State(next));store.AfterCommit(()=>bounds.expired('image:'+row.id,row.uploadedAt,row.retainedUntil));});
  }catch(error){if(!error.authorityMayBeCommitted&&!error.published){DeleteFile(r.id);}throw error;}
  return {version:1,status:'UPLOADED',receivedAt:row.uploadedAt,duplicate:false};
 }catch(error){
  if(error.message==='CAPTURE_PNG_INVALID'){try{const {r}=Ticket(ticket);store.Atomic(db=>{const row=State(db).items[r.id];row.status='REVOKED';row.closedAt=Math.max(row.createdAt,Date.now());delete row.tokenSeed;State(db).revision++;});}catch(_){} }
  throw error;
 }finally{normalized?.bytes?.fill(0);encoded?.fill(0);EndUpload(ticket);}
}
function Image(memberId,id){require('../operations/peace.registration-reset').AssertAvailable();Ready();const db=store.Load(),r=AdminRow(db,memberId,id);Member(db,memberId,true);if(r.status!=='UPLOADED'||r.epoch!==Epoch(db)||!ContextAvailable(db,r)||bounds.expired('image:'+r.id,r.uploadedAt,r.retainedUntil))Fail('CAPTURE_NOT_AVAILABLE',403);return {bytes:Decrypt(db,r),capture:Public(r)};}
function Maintain(force=false){
 if(stopped||require('../operations/peace.registration-reset').IsDraining())return;
 Ready();const now=require('node:perf_hooks').performance.now();if(!force&&now>=lastMaintenance&&now-lastMaintenance<60000)return;lastMaintenance=now;
 const db=store.Load(),at=Date.now(),s=State(db),expire=[];
 for(const r of Object.values(s.items)){
  const invalidMember=db.members?.items[r.memberId]?.status!=='ACTIVE'||!ContextAvailable(db,r),invalidEpoch=r.epoch!==Epoch(db);
  if(['AVAILABLE','RECEIVING'].includes(r.status)&&(invalidMember||invalidEpoch||Expired(r)))expire.push({id:r.id,status:'EXPIRED'});
  if(r.status==='UPLOADED'&&(invalidMember||invalidEpoch||bounds.expired('image:'+r.id,r.uploadedAt,r.retainedUntil)))expire.push({id:r.id,status:'DELETE_PENDING'});
 }
 if(expire.length)store.Atomic(next=>{for(const x of expire){const r=State(next).items[x.id];r.status=x.status;r.closedAt=Math.max(r.createdAt,at);delete r.tokenSeed;}State(next).revision++;});
 const deleted=[];for(const r of Object.values(State().items))if(r.status==='DELETE_PENDING'){DeleteFile(r.id);deleted.push(r.id);}
 if(deleted.length)store.Atomic(next=>{for(const id of deleted){const r=State(next).items[id];r.status='DELETED';r.closedAt=Math.max(r.createdAt,at);}State(next).revision++;});
 const old=Object.values(State().items).filter(r=>['REVOKED','EXPIRED','DELETED'].includes(r.status)&&r.closedAt&&at-r.closedAt>=RETENTION).map(r=>r.id);
 if(old.length)store.Atomic(next=>{const current=State(next);for(const id of old){delete current.items[id];store.AfterCommit(()=>{bounds.forget(id);bounds.forget('image:'+id);});}for(const [key,r]of Object.entries(current.receipts))if(old.includes(r.captureId))delete current.receipts[key];current.revision++;});
 Sweep();
}
function Start(){if(started)return;stopped=false;Maintain(true);started=true;}
function Stop(){stopped=true;started=false;recovered=false;active.clear();}
module.exports={EligibleContexts,TTL,RETENTION,LIMITS:png.LIMITS,DIR,Empty,State,Validate,Create,List,Close,ArchiveMemberInState,Status,BeginUpload,Upload,EndUpload,Image,Maintain,Start,Stop};
