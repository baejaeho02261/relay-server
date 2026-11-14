'use strict';
// A fresh application installation, distinct from registration-only maintenance.
// Destruction runs only under the process-wide writer lock, before listeners or
// ordinary stores open. The small signed recovery journal is not client authority.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const config=require('../../config/peace.runtime-configuration');
const disk=require('../storage/peace.durable-file');
const SCOPE='WEB_ALL_DATA_KEYS_V1',PATH='/api/desktop/bootstrap/security-operations/web-reset',CONFIRMATION='웹 전체 초기화';
const CONTROL='.cozy-web-reset.control.json',KEY='.cozy-web-reset.control.key';
const ID=/^[a-f0-9]{64}$/,MAX_ENTRIES=200000,MAX_OPERATIONS=1024;
const PACKER=['URL','CA_FILE','CERT_FILE','KEY_FILE','SPKI_SHA512','TOOL_SHA512','PROFILE_A_SHA512','PROFILE_B_SHA512','PROFILE_O_SHA512','INPUT_A_SHA512','INPUT_B_SHA512','INPUT_O_SHA512'].map(s=>'DESKTOP_PACKER_'+s);
const WITNESS_MTLS=['CA_FILE','CERT_FILE','KEY_FILE','CA_PEM_B64','CERT_PEM_B64','KEY_PEM_B64','SERVER_SPKI_SHA512','INSTALLATION_ID'].map(s=>'DESKTOP_RECOVERY_WITNESS_'+s);
const RELAY_TLS=['RELAY_TLS_CERT_FILE','RELAY_TLS_KEY_FILE','RELAY_TLS_CA_FILE'];
const ENVIRONMENT=Object.freeze(['DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64','DESKTOP_ISSUED_A_SIGNING_KEYS_JSON','GAME_CUSTOM_PACKAGE_KEY_FILE','GAME_RELEASE_APPROVAL_KEY_B64','GAME_RELEASE_APPROVAL_KEY_FILE','CONNECT_TLS_CERT_FILE','CONNECT_TLS_KEY_FILE','VAPID_PUBLIC_KEY','VAPID_PRIVATE_KEY','QR_APPROVAL_SECRET','COZY_REGISTRATION_RESET_ID','COZY_REGISTRATION_RESET_SCOPE',...PACKER,...WITNESS_MTLS,...RELAY_TLS]);
const FILE_ENV=new Set(ENVIRONMENT.filter(n=>n.endsWith('_FILE')));
const KEEP=new Set([CONTROL,KEY,'.desktop-single-writer.sqlite','.desktop-single-writer.sqlite-journal','.desktop-single-writer.sqlite-wal','.desktop-single-writer.sqlite-shm']);
const AUTH_FIELDS=['version','id','scope','requestedAt','actorHash','requestSha512','expectedEpoch'];
let draining=false,restarting=false,restartTimer,initializing=false;
function Fail(code,status=409){const e=Error('WEB_RESET_'+code);e.desktopError=true;e.status=status;throw e;}
function Plain(v){return !!v&&Object.getPrototypeOf(v)===Object.prototype;}
function Exact(v,keys){return Plain(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));}
function Digest(value){return crypto.createHash('sha256').update(value).digest('hex');}
function Sync(){disk.SyncDirectory(config.DATA_DIR);}
function Root(){
 const configured=path.resolve(config.DATA_DIR),source=path.resolve(__dirname,'../..');
 const inside=(a,b)=>{const r=path.relative(a,b);return r===''||r!=='..'&&!r.startsWith('..'+path.sep)&&!path.isAbsolute(r);};
 const systemRoots=['/etc','/usr','/bin','/sbin','/lib','/lib64','/proc','/sys','/dev','/run','/var','/home','/root','/tmp','/opt','/workspace'];
 if(configured===path.parse(configured).root||systemRoots.includes(configured)||inside(configured,source)||inside(source,configured))Fail('DATA_ROOT_UNSAFE',503);
 const st=fs.lstatSync(configured);if(!st.isDirectory()||st.isSymbolicLink()||fs.realpathSync(configured)!==configured)Fail('DATA_ROOT_UNSAFE',503);
 return st;
}
function Witness(){return !!String(process.env.DESKTOP_RECOVERY_WITNESS_URL||'').trim()||!!String(process.env.DESKTOP_RECOVERY_WITNESS_DIR||'').trim()||process.env.DESKTOP_RECOVERY_WITNESS_REQUIRED==='1';}
function HostingRequest(env=process.env){
 const id=env.COZY_WEB_FULL_RESET_ONCE||'',scope=env.COZY_WEB_FULL_RESET_SCOPE||'';
 if(!id&&!scope)return null;
 if(!ID.test(id)||scope!==SCOPE)Fail('HOST_REQUEST_INVALID',503);
 return {id,scope};
}
function ValidateAuthorization(v){
 if(!Exact(v,AUTH_FIELDS)||v.version!==1||!ID.test(v.id||'')||v.scope!==SCOPE||!Number.isSafeInteger(v.requestedAt)||v.requestedAt<1||!ID.test(v.actorHash||'')||!/^[a-f0-9]{128}$/.test(v.requestSha512||'')||!Number.isSafeInteger(v.expectedEpoch)||v.expectedEpoch<0)Fail('AUTHORIZATION_INVALID',503);
 return v;
}
function ValidateDigestMap(v,allowed){
 if(!Plain(v)||Object.keys(v).some(k=>!allowed.includes(k)))Fail('CONTROL_INVALID',503);
 for(const values of Object.values(v))if(!Array.isArray(values)||values.length>1024||new Set(values).size!==values.length||values.some(x=>typeof x!=='string'||!ID.test(x)))Fail('CONTROL_INVALID',503);
 return v;
}
function ValidateControl(v){
 const fields=['version','phase','id','generation','requestedAt','startedAt','completedAt','root','counts','retired','references','spentIds','oldAuthorityHash'];
 if(!Exact(v,fields)||v.version!==1||!['DELETING','INITIALIZING','COMPLETE'].includes(v.phase)||!ID.test(v.id||'')||!Number.isSafeInteger(v.generation)||v.generation<1||!Number.isSafeInteger(v.requestedAt)||v.requestedAt<1||!Number.isSafeInteger(v.startedAt)||v.startedAt<v.requestedAt||!Number.isSafeInteger(v.completedAt)||v.completedAt<0||!Exact(v.root,['dev','ino'])||Object.values(v.root).some(x=>!Number.isSafeInteger(x)||x<0)||!Exact(v.counts,['files','directories','bytes'])||Object.values(v.counts).some(x=>!Number.isSafeInteger(x)||x<0)||!Array.isArray(v.spentIds)||v.spentIds.length<1||v.spentIds.length>MAX_OPERATIONS||new Set(v.spentIds).size!==v.spentIds.length||v.spentIds.some(x=>!ID.test(x))||!v.spentIds.includes(v.id)||!ID.test(v.oldAuthorityHash||''))Fail('CONTROL_INVALID',503);
 if((v.phase==='COMPLETE')!==(v.completedAt>=v.startedAt))Fail('CONTROL_INVALID',503);
 ValidateDigestMap(v.retired,ENVIRONMENT);ValidateDigestMap(v.references,[...FILE_ENV]);return v;
}
function ControlKey(create=false){
 const file=path.join(config.DATA_DIR,KEY);
 if(create&&!fs.existsSync(file))disk.Atomic(file,crypto.randomBytes(32),{createOnly:true});
 const key=disk.ReadRegular(file,32);if(key.length!==32){key.fill(0);Fail('CONTROL_KEY_INVALID',503);}return key;
}
function Mac(v,key){return crypto.createHmac('sha256',key).update('COZY-WEB-RESET-CONTROL-V1\n'+JSON.stringify(v)).digest('hex');}
function ReadControl(){
 const file=path.join(config.DATA_DIR,CONTROL);if(!fs.existsSync(file))return null;
 const bytes=disk.ReadRegular(file,256*1024),entry=require('../protocol/peace.strict-json').Parse(bytes,{maxBytes:256*1024}),key=ControlKey();
 try{if(!Exact(entry,['body','mac'])||!disk.SecretEqual(entry.mac,Mac(entry.body,key)))Fail('CONTROL_INVALID',503);return ValidateControl(entry.body);}finally{key.fill(0);}
}
function WriteControl(value){ValidateControl(value);const key=ControlKey(true);try{const bytes=Buffer.from(JSON.stringify({body:value,mac:Mac(value,key)}));if(bytes.length>256*1024)Fail('RECEIPT_CAPACITY',503);disk.Atomic(path.join(config.DATA_DIR,CONTROL),bytes);}finally{key.fill(0);}}
function Entries(){
 const root=Root(),list=[];let bytes=0;
 function visit(directory,relative='',depth=0){
  if(depth>64)Fail('STORAGE_LIMIT',503);
  for(const name of fs.readdirSync(directory).sort()){
   if(!relative&&KEEP.has(name))continue;
   const rel=relative?relative+'/'+name:name,absolute=path.join(directory,name),st=fs.lstatSync(absolute);
   if(st.dev!==root.dev||st.isSymbolicLink()||!st.isDirectory()&&(!st.isFile()||st.nlink!==1))Fail('STORAGE_ENTRY_UNSAFE',503);
   if(list.length>=MAX_ENTRIES)Fail('STORAGE_LIMIT',503);
   list.push({relative:rel,directory:st.isDirectory(),dev:st.dev,ino:st.ino});
   if(st.isDirectory())visit(absolute,rel,depth+1);else{bytes+=st.size;if(!Number.isSafeInteger(bytes))Fail('STORAGE_LIMIT',503);}
  }
 }
 visit(config.DATA_DIR);return {root,list,counts:{files:list.filter(x=>!x.directory).length,directories:list.filter(x=>x.directory).length,bytes}};
}
function PublicKeyFingerprint(encoded,issued=false){
 const bytes=Buffer.from(encoded,'base64');try{const key=crypto.createPublicKey(crypto.createPrivateKey(bytes));return issued?require('../bootstrap/peace.issued-a-signing').PublicIdentity(key).keyId:Digest(key.export({format:'der',type:'spki'}));}finally{bytes.fill(0);}
}
function MaterialFingerprint(bytes){try{return Digest(crypto.createPublicKey(crypto.createPrivateKey(bytes)).export({format:'der',type:'spki'}));}catch(_){try{return Digest(new crypto.X509Certificate(bytes).publicKey.export({format:'der',type:'spki'}));}catch(_){return Digest(bytes);}}}
function Fingerprints(name,value){
 if(typeof value!=='string'||!value)return {values:[],reference:''};
 if(FILE_ENV.has(name)){
  const reference=Digest(value);try{const bytes=disk.ReadRegular(value,1024*1024);try{return {values:[MaterialFingerprint(bytes)],reference};}finally{bytes.fill(0);}}catch(_){return {values:[],reference};}
 }
 if(name==='DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64'||name==='GAME_RELEASE_APPROVAL_KEY_B64')try{return {values:[PublicKeyFingerprint(value,name==='DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64')],reference:''};}catch(_){}
 if(name==='DESKTOP_ISSUED_A_SIGNING_KEYS_JSON')try{
  const rows=require('../protocol/peace.strict-json').Parse(value,{maxBytes:192000});if(!Plain(rows))throw Error();
  return {values:[...new Set(Object.values(rows).map(value=>{try{return PublicKeyFingerprint(value,true);}catch(_){return Digest(String(value));}}))].sort(),reference:''};
 }catch(_){}
 if(name.endsWith('_B64')||name.startsWith('VAPID_'))try{const bytes=Buffer.from(value,'base64url');try{return {values:[MaterialFingerprint(bytes)],reference:''};}finally{bytes.fill(0);}}catch(_){}
 return {values:[Digest(value)],reference:''};
}
function RetireEnvironment(previous,authority){
 const retired=structuredClone(previous?.retired||{}),references=structuredClone(previous?.references||{});
 for(const name of ENVIRONMENT){const fp=Fingerprints(name,process.env[name]);if(fp.values.length)retired[name]=[...new Set([...(retired[name]||[]),...fp.values])].sort();if(fp.reference)references[name]=[...new Set([...(references[name]||[]),fp.reference])].sort();}
 const issuedIds=Object.keys(authority?.issuedAKeyring?.keys||{});for(const name of ['DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64','DESKTOP_ISSUED_A_SIGNING_KEYS_JSON'])if(issuedIds.length)retired[name]=[...new Set([...(retired[name]||[]),...issuedIds])].sort();
 const oldResetIds=Object.keys(authority?.registrationResetReceipts||{});if(oldResetIds.length){retired.COZY_REGISTRATION_RESET_ID=[...new Set([...(retired.COZY_REGISTRATION_RESET_ID||[]),...oldResetIds.map(Digest)])].sort();retired.COZY_REGISTRATION_RESET_SCOPE=[...new Set([...(retired.COZY_REGISTRATION_RESET_SCOPE||[]),Digest('ABO_LICENSES_ISSUANCE_OPERATIONS_V1')])].sort();}
 ValidateDigestMap(retired,ENVIRONMENT);ValidateDigestMap(references,[...FILE_ENV]);return {retired,references};
}
function EnforceEnvironment(control){
 if(!control)return [];
 const disabled=[];
 for(const name of ENVIRONMENT){const fp=Fingerprints(name,process.env[name]),blocked=fp.values.some(x=>control.retired[name]?.includes(x))||!fp.values.length&&fp.reference&&control.references[name]?.includes(fp.reference);
  if(blocked){delete process.env[name];disabled.push(name);if(Object.hasOwn(config,name))config[name]='';}}
 // An old external-worker connection must not remain half-configured.
 if(disabled.some(n=>PACKER.includes(n)))for(const name of PACKER)delete process.env[name];
 if(disabled.some(n=>WITNESS_MTLS.includes(n)))for(const name of WITNESS_MTLS)delete process.env[name];
 if(disabled.some(n=>RELAY_TLS.includes(n)))for(const name of RELAY_TLS)delete process.env[name];
 if(disabled.some(n=>n==='CONNECT_TLS_CERT_FILE'||n==='CONNECT_TLS_KEY_FILE')){delete process.env.CONNECT_TLS_CERT_FILE;delete process.env.CONNECT_TLS_KEY_FILE;}
 return disabled;
}
function Operation(control){return control?{id:control.id,status:control.phase==='COMPLETE'?'COMPLETE':'RUNNING',requestedAt:control.requestedAt,completedAt:control.completedAt}:null;}
function Pending(){const value=require('../bootstrap/peace.desktop-bootstrap-store').Load().webResetAuthorization;return value===undefined?null:ValidateAuthorization(value);}
function Blocked(){
 const reasons=[];if(process.platform!=='linux'||!fs.constants.O_NOFOLLOW||!fs.constants.O_DIRECTORY)reasons.push('WEB_RESET_PLATFORM_UNSUPPORTED');if(config.HA_ENABLED)reasons.push('WEB_RESET_SINGLE_WRITER_REQUIRED');if(Witness())reasons.push('WEB_RESET_RECOVERY_WITNESS_REENROLLMENT_REQUIRED');
 try{Entries();}catch(error){reasons.push(error.desktopError?error.message:'WEB_RESET_STORAGE_UNAVAILABLE');}
 const b=require('../bootstrap/peace.desktop-bootstrap-store').Load();if(b.registrationResetAuthorization||b.registrationResetJob&&b.registrationResetJob.phase!=='COMPLETE')reasons.push('WEB_RESET_REGISTRATION_RESET_PENDING');
 const control=ReadControl();if((control?.spentIds.length||0)>=MAX_OPERATIONS)reasons.push('WEB_RESET_RECEIPT_CAPACITY');
 try{if(Buffer.byteLength(JSON.stringify(RetireEnvironment(control,b)))>180*1024)reasons.push('WEB_RESET_RECEIPT_CAPACITY');}catch(_){reasons.push('WEB_RESET_RECEIPT_CAPACITY');}
 return reasons;
}
function Status(id){
 if(id!==undefined&&(typeof id!=='string'||!ID.test(id)))Fail('ID_INVALID',400);
 const control=ReadControl(),pending=Pending(),blockedReasons=Blocked(),view=control&&(!id||id===control.id)?Operation(control):null;
 const operation=pending&&(!id||pending.id===id)?{id:pending.id,status:'QUEUED',requestedAt:pending.requestedAt,completedAt:0}:view;
 let counts;try{counts=Entries().counts;}catch(_){counts={files:0,directories:0,bytes:0};}
 return {scope:SCOPE,confirmation:CONFIRMATION,epoch:control?.generation||0,counts,operation,ready:blockedReasons.length===0&&!pending&&!draining,blockedReasons,
  retiredEnvironmentVariables:[...new Set([...Object.keys(control?.retired||{}),...ENVIRONMENT.filter(name=>typeof process.env[name]==='string'&&process.env[name].length>0)])].sort(),
  preserved:['Railway 서비스와 저장 볼륨','관리자 환경변수 로그인·네트워크 접속 설정','초기화 복구용 내부 트랜잭션 기록'],
  keyHandling:'OLD_ENV_APPLICATION_KEYS_QUARANTINED_UNTIL_REPLACED',oldEnvironmentValuesDeletedFromHosting:false};
}
function Schedule(body,session,ticket){
 const guard=require('../authentication/peace.desktop-admin-guard');if(!guard.ConsumeSingleAuthorization(ticket,session,'POST',PATH,body))Fail('NOT_AUTHORIZED',403);
 if(!Exact(body,['confirmation','expectedEpoch','requestId','scope'])||body.confirmation!==CONFIRMATION||body.scope!==SCOPE||!ID.test(body.requestId||'')||!Number.isSafeInteger(body.expectedEpoch)||body.expectedEpoch<0)Fail('REQUEST_INVALID',400);
 const control=ReadControl();if(control?.spentIds.includes(body.requestId)){if(control.id===body.requestId&&control.phase==='COMPLETE')return {operation:Operation(control),restartRequired:false};Fail('REQUEST_ALREADY_SPENT');}
 const current=Pending();if(current&&current.id!==body.requestId)Fail('IN_PROGRESS');if((control?.generation||0)!==body.expectedEpoch)Fail('EPOCH_CONFLICT');
 const reasons=Blocked();if(reasons.length)Fail(reasons[0].replace(/^WEB_RESET_/,''));
 if(!require('../network/peace.ha-coordinator').CanAcceptTraffic())Fail('SERVICE_UNAVAILABLE',503);
 if(!current){const authorization={version:1,id:body.requestId,scope:SCOPE,requestedAt:Date.now(),actorHash:Digest('ADMIN:'+session.id),requestSha512:require('../authentication/peace.admin-action-store').Binding('POST',PATH,body),expectedEpoch:body.expectedEpoch};ValidateAuthorization(authorization);
  require('../storage/peace.desktop-operation-audit').Run('WEB_ALL_DATA_RESET_REQUESTED','ADMIN:'+session.id,{subject:body.requestId},db=>{if(db.webResetAuthorization)Fail('IN_PROGRESS');db.webResetAuthorization=authorization;});}
 draining=true;require('../network/peace.ha-coordinator').Stop();restartTimer=setTimeout(Restart,500);restartTimer.unref();return {operation:{id:body.requestId,status:'QUEUED',requestedAt:Pending().requestedAt,completedAt:0},restartRequired:true};
}
function Restart(){if(restarting)return;restarting=true;clearTimeout(restartTimer);Promise.resolve(require('../../core/peace.lifecycle').Shutdown(1)).catch(()=>process.exit(1));}
function AfterResponse(res){if(!draining||restarting)return;res.once('finish',()=>setImmediate(Restart));res.once('close',()=>setImmediate(Restart));}
function IsDraining(){return draining;}
function DeleteEntries(control){
 const snapshot=Entries();if(snapshot.root.dev!==control.root.dev||snapshot.root.ino!==control.root.ino)Fail('DATA_ROOT_CHANGED',503);
 if(process.platform!=='linux'||!fs.constants.O_NOFOLLOW||!fs.constants.O_DIRECTORY)Fail('PLATFORM_UNSUPPORTED',503);
 const directories=new Map(snapshot.list.filter(x=>x.directory).map(x=>[x.relative,x]));
 const rootFd=fs.openSync(config.DATA_DIR,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 try{
  const opened=fs.fstatSync(rootFd);if(opened.dev!==control.root.dev||opened.ino!==control.root.ino)Fail('DATA_ROOT_CHANGED',503);
  for(const entry of snapshot.list.reverse()){
   const root=Root();if(root.dev!==control.root.dev||root.ino!==control.root.ino)Fail('DATA_ROOT_CHANGED',503);
   const parts=entry.relative.split('/'),name=parts.pop(),openedParents=[];let parentFd=rootFd,relative='';
   try{
    // Resolve every parent from an already open directory descriptor. A
    // substituted symlink cannot redirect unlink/rmdir outside this volume.
    for(const part of parts){
     relative=relative?relative+'/'+part:part;const expected=directories.get(relative);
     const fd=fs.openSync('/proc/self/fd/'+parentFd+'/'+part,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW),st=fs.fstatSync(fd);openedParents.push(fd);
     if(!expected||st.dev!==expected.dev||st.ino!==expected.ino)Fail('STORAGE_ENTRY_CHANGED',503);parentFd=fd;
    }
    const file='/proc/self/fd/'+parentFd+'/'+name,current=fs.lstatSync(file);
    if(current.dev!==entry.dev||current.ino!==entry.ino||current.isSymbolicLink()||(entry.directory?!current.isDirectory():!current.isFile()||current.nlink!==1))Fail('STORAGE_ENTRY_CHANGED',503);
    if(entry.directory)fs.rmdirSync(file);else fs.unlinkSync(file);
   }finally{for(const fd of openedParents.reverse())fs.closeSync(fd);}
  }
 }finally{fs.closeSync(rootFd);}
 Sync();if(Entries().list.length)Fail('INCOMPLETE',503);
 control.phase='INITIALIZING';WriteControl(control);
}
function PrepareStartup(){
 const host=HostingRequest(),control=ReadControl();
 if(control&&control.phase!=='COMPLETE'){
  Root();
  if(host&&!control.spentIds.includes(host.id)&&host.id!==control.id)Fail('AUTHORIZATION_CONFLICT',503);
  if(Witness())Fail('RECOVERY_WITNESS_REENROLLMENT_REQUIRED',503);
  if(control.phase==='DELETING'){DeleteEntries(control);return true;}
  EnforceEnvironment(control);initializing=true;return false;
 }
 // Avoid loading the authority or witness before ordinary startup on every boot.
 let peek;const file=path.join(config.DATA_DIR,'desktop-bootstrap','authority.json');
 if(fs.existsSync(file)){const raw=disk.ReadRegular(file,64*1024*1024);peek=require('../protocol/peace.strict-json').Parse(raw,{maxBytes:64*1024*1024,maxNodes:4000000}).webResetAuthorization;}
 const unusedHost=host&&!control?.spentIds.includes(host.id)?host:null;
 if(!unusedHost&&!peek){if(control)Root();EnforceEnvironment(control);return false;}
 if(process.platform!=='linux'||!fs.constants.O_NOFOLLOW||!fs.constants.O_DIRECTORY)Fail('PLATFORM_UNSUPPORTED',503);if(config.HA_ENABLED)Fail('SINGLE_WRITER_REQUIRED',503);if(Witness())Fail('RECOVERY_WITNESS_REENROLLMENT_REQUIRED',503);
 const snapshot=Entries();if(!fs.existsSync(file)&&snapshot.list.length)Fail('APPLICATION_OWNERSHIP_REQUIRED',503);
 const store=require('../bootstrap/peace.desktop-bootstrap-store'),before=store.Load(),web=Pending();
 if(unusedHost&&web&&unusedHost.id!==web.id)Fail('AUTHORIZATION_CONFLICT',503);
 const request=web||{version:1,id:unusedHost.id,scope:SCOPE,requestedAt:Date.now(),actorHash:Digest('HOSTING_OPERATOR'),requestSha512:crypto.createHash('sha512').update(unusedHost.id+'\n'+SCOPE).digest('hex'),expectedEpoch:control?.generation||0};ValidateAuthorization(request);
 if(request.expectedEpoch!==(control?.generation||0))Fail('EPOCH_CONFLICT',503);
 if(before.registrationResetAuthorization||before.registrationResetJob&&before.registrationResetJob.phase!=='COMPLETE')Fail('REGISTRATION_RESET_PENDING',503);
 if((control?.spentIds.length||0)>=MAX_OPERATIONS)Fail('RECEIPT_CAPACITY',503);
 const retired=RetireEnvironment(control,before),next={version:1,phase:'DELETING',id:request.id,generation:(control?.generation||0)+1,requestedAt:request.requestedAt,startedAt:Math.max(Date.now(),request.requestedAt),completedAt:0,root:{dev:snapshot.root.dev,ino:snapshot.root.ino},counts:snapshot.counts,...retired,spentIds:[...(control?.spentIds||[]),request.id],oldAuthorityHash:Digest(before.secret)};
 WriteControl(next);DeleteEntries(next);console.log('WEB_ALL_DATA_RESET_OLD_DATA_REMOVED');return true;
}
function ReplaceProcess(){
 // execve replaces all cached authority state without an unhealthy intermediate
 // deployment or a child whose parent exits and stops its container.
 if(process.platform==='linux'&&typeof process.execve==='function')process.execve(process.execPath,[process.execPath,...process.execArgv,...process.argv.slice(1)],process.env);
 process.exit(1);
}
function CompleteStartup(){
 if(!initializing)return false;const control=ReadControl();if(!control||control.phase!=='INITIALIZING')Fail('CONTROL_INVALID',503);
 const boot=require('../bootstrap/peace.desktop-bootstrap-store').Load();if(Digest(boot.secret)===control.oldAuthorityHash||['artifacts','active','launchers','flows','issueReceipts'].some(k=>Object.keys(boot[k]||{}).length)||boot.issuedAKeyring)Fail('FRESH_AUTHORITY_REQUIRED',503);
 if(Object.keys(require('../licensing/peace.desktop-licenses').DB().licenses).length)Fail('FRESH_AUTHORITY_REQUIRED',503);
 require('../network/peace.connect-transport-key').Load();require('../network/peace.connect-tls').Load();
 control.phase='COMPLETE';control.completedAt=Math.max(Date.now(),control.startedAt);WriteControl(control);initializing=false;console.log('WEB_ALL_DATA_RESET_COMPLETE');return true;
}
module.exports={SCOPE,PATH,CONFIRMATION,ENVIRONMENT,HostingRequest,ValidateAuthorization,PrepareStartup,ReplaceProcess,CompleteStartup,Status,Schedule,AfterResponse,IsDraining};
