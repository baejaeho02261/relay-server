'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{Worker}=require('node:worker_threads');
const format=require('./peace.custom-package-format');
const PREFIX='/api/desktop/bootstrap/packing/custom/jobs',ROOT=path.resolve(MODULE_RESOURCE_ROOT,'../..');
let current,stopped=false;
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function ReadRegular(p,max=64*1024*1024){
 const absolute=path.resolve(p),parts=absolute.split(path.sep);let cursor=path.parse(absolute).root;
 for(const part of parts.slice(1)){cursor=path.join(cursor,part);if(fs.lstatSync(cursor).isSymbolicLink())Fail('CUSTOM_PACKAGE_SYMLINK_FORBIDDEN');}
 const fd=fs.openSync(absolute,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
 try{const before=fs.fstatSync(fd);if(!before.isFile()||before.nlink!==1||before.size>max)Fail('CUSTOM_PACKAGE_FILE_INVALID');const b=Buffer.alloc(before.size);let offset=0;while(offset<b.length){const n=fs.readSync(fd,b,offset,Math.min(1048576,b.length-offset),offset);if(!n){b.fill(0);Fail('CUSTOM_PACKAGE_FILE_CHANGED');}offset+=n;}const extra=Buffer.alloc(1);if(fs.readSync(fd,extra,0,1,offset)!==0){b.fill(0);Fail('CUSTOM_PACKAGE_FILE_CHANGED');}const after=fs.fstatSync(fd);if(b.length!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs){b.fill(0);Fail('CUSTOM_PACKAGE_FILE_CHANGED');}return b;}finally{fs.closeSync(fd);}
}
function Key(){const f=process.env.GAME_CUSTOM_PACKAGE_KEY_FILE;if(!f||!path.isAbsolute(f))Fail('CUSTOM_PACKAGE_KEY_NOT_CONFIGURED',503);const absolute=path.resolve(f);const fold=p=>process.platform==='win32'?p.toLowerCase():p,comparable=fold(absolute),sourceRoots=[path.resolve(MODULE_RESOURCE_ROOT,'..'),path.join(ROOT,'Railway')];if(sourceRoots.some(p=>comparable===fold(p)||comparable.startsWith(fold(p)+path.sep)))Fail('CUSTOM_PACKAGE_KEY_IN_SOURCE_FORBIDDEN',503);const b=ReadRegular(f,32);if(b.length!==32){b.fill(0);Fail('CUSTOM_PACKAGE_KEY_INVALID',503);}const st=fs.statSync(f);if(process.platform!=='win32'&&(st.mode&0o077)){b.fill(0);Fail('CUSTOM_PACKAGE_KEY_PERMISSIONS',503);}return b;}
function Status(){try{const k=Key();k.fill(0);return {configured:true,engine:'GAME-CUSTOM-PACKAGE-V1',extension:'.gcpack',selfExecutable:false,allFunctionsVirtualized:false,sourceTreeAvailable:fs.existsSync(path.join(ROOT,'Railway')),reason:'ENCRYPTED_DATA_CONTAINER_NOT_EXE'};}catch(e){return {configured:false,engine:'GAME-CUSTOM-PACKAGE-V1',selfExecutable:false,allFunctionsVirtualized:false,reason:/^CUSTOM_PACKAGE_[A-Z_]+$/.test(e.message)?e.message:'CUSTOM_PACKAGE_CONFIGURATION_INVALID'};}}
function Check(session,method='POST'){const r=require("../authentication/peace.desktop-admin-guard").CheckSession(session,PREFIX,method);if(!r.ok)Fail(r.reason,r.status||403);if(!require("../../web/authentication/peace.web-auth").IsSessionActive(session))Fail('ADMIN_SESSION_EXPIRED',401);}
function Sources(){
 const m=JSON.parse(ReadRegular(path.join(ROOT,'Relay Server/maintenance/source-manifest.json'),2*1024*1024)),names=Object.keys(m.files||{}).filter(n=>n.startsWith('Railway/')).sort();
 if(m.version!==2||m.algorithm!=='sha512'||!names.length)Fail('CUSTOM_PACKAGE_SOURCE_MANIFEST_INVALID');const files=[];
 try{for(const n of names){if(!format.nameValid(n))Fail('CUSTOM_PACKAGE_ENTRY_INVALID');const bytes=ReadRegular(path.join(ROOT,n));if(sha(bytes)!==m.files[n]){bytes.fill(0);Fail('CUSTOM_PACKAGE_SOURCE_CHANGED',409);}files.push({name:n,bytes});}return files;}catch(e){for(const f of files)f.bytes.fill(0);throw e;}
}
function Inputs(body){
 if(body.kind==='sources'){if(Object.keys(body).length!==1)Fail('CUSTOM_PACKAGE_INPUT_INVALID');return {files:Sources(),metadata:{kind:'source-archive',allManifestNativeFiles:true,sourceCodeVirtualization:false}};}
 if(body.kind!=='artifacts'||Object.keys(body).length!==4||['A','B','O'].some(c=>typeof body[c]!=='string'||!/^[A-F0-9]{24}$/.test(body[c])))Fail('CUSTOM_PACKAGE_INPUT_INVALID');
 const b=require("../bootstrap/peace.desktop-bootstrap"),db=b.Initialize(),files=[],bindings={};b.AssertSecurityAvailable();
 try{for(const c of ['A','B','O']){const row=db.artifacts[body[c]];if(!row||row.component!==c)Fail('CUSTOM_PACKAGE_SOURCE_INVALID');const bytes=b.ReadArtifactBytes(row);if(sha(bytes)!==row.sha512){bytes.fill(0);Fail('CUSTOM_PACKAGE_SOURCE_CHANGED');}files.push({name:c+'.exe',bytes});bindings[c]={id:row.id,sha512:row.sha512};}return {files,metadata:{kind:'artifact-archive',bindings,executableBytesChanged:false,sourceCodeVirtualization:false}};}catch(e){for(const f of files)f.bytes.fill(0);throw e;}
}
function Clear(){if(current?.status==='RUNNING')return;current?.lease?.release();current?.bytes?.fill(0);current=undefined;}
function Prune(){if(current?.status!=='RUNNING'&&Date.now()>=current?.expiresAt)Clear();}
const timer=setInterval(Prune,30000);timer.unref();
function View(j){return {id:j.id,status:j.status,error:j.error||'',createdAt:j.createdAt,expiresAt:j.expiresAt||0,sha512:j.sha512||'',fileCount:j.fileCount||0,size:j.bytes?.length||0,kind:j.kind,format:'GAME-CUSTOM-PACKAGE-V1',extension:'.gcpack',selfExecutable:false,allFunctionsVirtualized:false,activeReleaseChanged:false};}
function Get(id,session){Check(session,'GET');Prune();if(!current||current.id!==id||current.owner!==session.id)Fail('CUSTOM_PACKAGE_JOB_NOT_FOUND',404);return current;}
function Estimate(body){
 let total=0;if(body.kind==='sources'){const m=JSON.parse(ReadRegular(path.join(ROOT,'Relay Server/maintenance/source-manifest.json'),2*1024*1024));for(const n of Object.keys(m.files||{}).filter(n=>n.startsWith('Railway/'))){if(!format.nameValid(n))Fail('CUSTOM_PACKAGE_INPUT_INVALID');const st=fs.lstatSync(path.join(ROOT,n));if(!st.isFile()||st.isSymbolicLink()||st.size>64*1024*1024)Fail('CUSTOM_PACKAGE_FILE_INVALID');total+=st.size;}}
 else {const db=require("../bootstrap/peace.desktop-bootstrap").Initialize();for(const c of ['A','B','O']){const row=db.artifacts[body[c]];if(!row||row.component!==c||!Number.isSafeInteger(row.size))Fail('CUSTOM_PACKAGE_SOURCE_INVALID');total+=row.size;}}
 if(total>format.MAX)Fail('CUSTOM_PACKAGE_SIZE_LIMIT');return Math.max(32*1024*1024,total*5+8*1024*1024);
}
function Begin(body,session){
 if(stopped)Fail('CUSTOM_PACKAGE_STOPPED',503);Check(session);Prune();if(!body||Object.getPrototypeOf(body)!==Object.prototype)Fail('CUSTOM_PACKAGE_INPUT_INVALID');if(current?.status==='RUNNING')Fail('CUSTOM_PACKAGE_BUSY',429);
 Clear();let key,inputs,lease;
 try{lease=require("../runtime/peace.server-resource-budget").Admit('custom-package',{key:session.id,bytes:Estimate(body)});key=Key();inputs=Inputs(body);}catch(e){key?.fill(0);lease?.release();throw e;}
 const j={id:crypto.randomBytes(16).toString('hex'),owner:session.id,lease,status:'RUNNING',kind:body.kind,createdAt:Date.now(),fileCount:inputs.files.length};current=j;
 let worker,deadline,done=false;
 function finish(error,box){if(done){box?.fill(0);return;}done=true;clearTimeout(deadline);worker?.terminate();j.expiresAt=Date.now()+600000;
  try{if(error)throw error;if(stopped||current!==j)Fail('CUSTOM_PACKAGE_CANCELLED',503);Check(session,'GET');if(!Buffer.isBuffer(box)||box.length<112||box.length>format.MAX+112)Fail('CUSTOM_PACKAGE_OUTPUT_INVALID');
   if(inputs.metadata.bindings){const db=require("../bootstrap/peace.desktop-bootstrap").Initialize();for(const b of Object.values(inputs.metadata.bindings))if(db.artifacts[b.id]?.sha512!==b.sha512)Fail('CUSTOM_PACKAGE_SOURCE_CHANGED',409);}
   j.bytes=box;j.sha512=sha(box);j.status='COMPLETE';j.lease?.retain();
   try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_CUSTOM_PACKAGE_CREATED',JSON.stringify({jobId:j.id,kind:j.kind,fileCount:j.fileCount,sha512:j.sha512,executable:false}));}catch(_){}
  }catch(e){box?.fill(0);j.lease?.release();j.status='FAILED';j.error=/^[A-Z][A-Z0-9_]{1,100}$/.test(e.message)?e.message:'CUSTOM_PACKAGE_FAILED';}
 }
 j.cancel=()=>{finish(Error('CUSTOM_PACKAGE_CANCELLED'));return worker?.terminate();};
 try{worker=new Worker(path.join(MODULE_RESOURCE_ROOT,"../tools/artifacts/peace.custom-package-worker.js"),{workerData:{files:inputs.files,key,metadata:inputs.metadata},resourceLimits:{maxOldGenerationSizeMb:128}});
  deadline=setTimeout(()=>finish(Error('CUSTOM_PACKAGE_TIMEOUT')),90000);deadline.unref();
  worker.once('message',m=>{const out=m.ok?Buffer.from(m.bytes):null;m.bytes?.fill(0);finish(m.ok?null:Error(m.error),out);});worker.once('error',()=>finish(Error('CUSTOM_PACKAGE_WORKER_FAILED')));worker.once('exit',code=>{if(!done)finish(Error('CUSTOM_PACKAGE_WORKER_EXITED'));});
 }catch(e){finish(e);}finally{key.fill(0);for(const f of inputs.files)f.bytes.fill(0);}
 return View(j);
}
function Output(id,session){const j=Get(id,session);if(j.status!=='COMPLETE'||!j.bytes)Fail('CUSTOM_PACKAGE_NOT_READY',409);return j;}
async function Stop(){if(stopped)return;stopped=true;clearInterval(timer);const job=current;const pending=job?.cancel?.();job?.lease?.release();job?.bytes?.fill(0);current=undefined;await pending;}
module.exports={Begin,Get,View,Output,Status,Sources,ReadRegular,Stop};
