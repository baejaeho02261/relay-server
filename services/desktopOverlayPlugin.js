'use strict';
// Administrator-published Win64 rendering library. All runtime access is bound
// to a completed license's independent overlay capability, never a B token.
const fs=require('node:fs'),crypto=require('node:crypto');
const store=require('./desktopBootstrapStore'),integrity=require('./desktopIntegrity');
const MAX_BYTES=16*1024*1024,CHUNK_SIZE=262144,INSTALL_MS=120000,REPORT_MS=120000,MAX_PENDING=128;
const EXPORT='GameOverlayRunV1',FILE_NAME='overlay.bin';
const pending=new Map(),downloads=new Map();
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
const Plain=v=>!!v&&Object.getPrototypeOf(v)===Object.prototype;
const Id=v=>typeof v==='string'&&/^[A-F0-9]{24}$/.test(v);
const Time=v=>Number.isSafeInteger(v)&&v>0;
const FILE_FIELDS=['sha256','crc64','xxh64','blake3'],CODE_FIELDS=['codeSha256','codeCrc64','codeXxh64','codeBlake3'],EXPORT_FIELDS=['exportTableSha256','exportTableCrc64','exportTableXxh64','exportTableBlake3'];
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Fields(v,names){if(!Plain(v)||Object.keys(v).some(k=>!names.includes(k))||names.some(k=>!Object.hasOwn(v,k)))Fail('OVERLAY_PLUGIN_INPUT_INVALID');}
function Atomic(fn){try{return store.Atomic(fn);}catch(error){if(error.desktopError)throw error;Fail(error.message==='BOOTSTRAP_STORAGE_RESTART_REQUIRED'?error.message:'STORAGE_SAVE_FAILED',503);}}
function Empty(){return {schema:1,revision:0,activeId:'',artifacts:{}};}
function State(db=store.Load()){return db.overlayPlugins||Empty();}
function HashFields(row){return [...FILE_FIELDS,...CODE_FIELDS,...EXPORT_FIELDS].every(k=>typeof row[k]==='string'&&(k.toLowerCase().endsWith('crc64')?/^[A-F0-9]{16}$/:k.toLowerCase().endsWith('xxh64')?/^[a-f0-9]{16}$/:/^[a-f0-9]{64}$/).test(row[k]));}
function ValidateState(s){
 Fields(s,['schema','revision','activeId','artifacts']);
 if(s.schema!==1||!Number.isSafeInteger(s.revision)||s.revision<0||!Plain(s.artifacts)||Object.keys(s.artifacts).length>128||s.activeId!==''&&!Id(s.activeId))Fail('OVERLAY_PLUGIN_STORAGE_INVALID',503);
 for(const [id,a]of Object.entries(s.artifacts))if(!Id(id)||!Plain(a)||a.id!==id||a.component!=='O'||a.abi!==1||a.architecture!=='win64'||a.exportName!==EXPORT||a.fileName!==FILE_NAME||a.codeAlgorithm!=='PE64-CODE-V1'||!HashFields(a)||!Number.isSafeInteger(a.size)||a.size<512||a.size>MAX_BYTES||!Time(a.createdAt)||typeof a.version!=='string'||a.version.length>40||!/^\d+(?:\.\d+){0,3}$/.test(a.version)||typeof a.compiledCfg!=='boolean')Fail('OVERLAY_PLUGIN_STORAGE_INVALID',503);
 for(const a of Object.values(s.artifacts)){if(a.releaseApproval!==undefined){Fields(a.releaseApproval,['keyId','signature']);if(!/^[a-f0-9]{64}$/.test(a.releaseApproval.keyId)||typeof a.releaseApproval.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(a.releaseApproval.signature)||Buffer.from(a.releaseApproval.signature,'base64').toString('base64')!==a.releaseApproval.signature)Fail('OVERLAY_PLUGIN_STORAGE_INVALID',503);}}
 if(s.activeId&&!s.artifacts[s.activeId])Fail('OVERLAY_PLUGIN_STORAGE_INVALID',503);
 return s;
}
function Reason(a,newUpload=false){
 if(!a)return 'OVERLAY_PLUGIN_NOT_PUBLISHED';
 const auth=require('./desktopSecurityAuthority'),policy=auth.Policy();
 if(policy.revokedSha256.includes(a.sha256))return 'SECURITY_RELEASE_REVOKED';
 if(!auth.VerifyApproval(a,policy))return 'SECURITY_RELEASE_SIGNATURE';
 if(a.releaseApproval&&!require('./desktopSecurityOperations').SignerAllowed(a.releaseApproval.keyId,newUpload))return 'SECURITY_SIGNER_NOT_ACTIVE';
 if(policy.requireCfg&&!a.compiledCfg)return 'SECURITY_CFG_BUILD_REQUIRED';
 return '';
}
function RequireArtifact(a){const reason=Reason(a);if(reason)Fail(reason,403);return a;}
function ValidatePE(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length>MAX_BYTES)Fail('OVERLAY_PLUGIN_TOO_LARGE',413);
 try{
  if(bytes.length<512||bytes.readUInt16LE(0)!==0x5a4d)throw Error();
  const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe+24>bytes.length||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664||(bytes.readUInt16LE(pe+22)&0x2002)!==0x2002)throw Error();
  const code=integrity.CodeImage(bytes),exports=require('./desktopPeExports').ExportTable(bytes,EXPORT);
  if(exports.status!=='MEASURED'||!exports.requiredExportRva)throw Error();
  return {code,exports};
 }catch(_){Fail('OVERLAY_PLUGIN_PE_INVALID');}
}
function Bytes(a){
 RequireArtifact(a);let fd;
 try{fd=fs.openSync(store.PluginPath(a.id),fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size!==a.size)throw Error();const bytes=fs.readFileSync(fd);if(sha(bytes)!==a.sha256)throw Error();return bytes;}
 catch(_){Fail('OVERLAY_PLUGIN_FILE_INVALID',503);}finally{if(fd!==undefined)fs.closeSync(fd);}
}
function Stage(version,bytes,approval,actor='ADMIN'){
 if(require('../config/config').HA_ENABLED)Fail('BOOTSTRAP_SINGLE_WRITER_REQUIRED',503);
 if(typeof version!=='string'||version.length>40||!/^\d+(?:\.\d+){0,3}$/.test(version))Fail('OVERLAY_PLUGIN_INPUT_INVALID');
 const {code,exports}=ValidatePE(bytes),auth=require('./desktopSecurityAuthority');
 if(approval!==undefined)Fields(approval,['keyId','signature']);
 const row={id:crypto.randomBytes(12).toString('hex').toUpperCase(),component:'O',version,abi:1,architecture:'win64',exportName:EXPORT,fileName:FILE_NAME,...integrity.Digests(bytes),codeSha256:code.sha256,codeCrc64:code.crc64,codeXxh64:code.xxh64,codeBlake3:code.blake3,codeAlgorithm:code.algorithm,exportTableSha256:exports.sha256,exportTableCrc64:exports.crc64,exportTableXxh64:exports.xxh64,exportTableBlake3:exports.blake3,size:bytes.length,createdAt:Date.now(),compiledCfg:auth.PeCapabilities(bytes).compiledCfg,...(approval?{releaseApproval:structuredClone(approval)}:{})};
 const reason=Reason(row,true);if(reason)Fail(reason,403);
 const same=Object.values(State().artifacts).find(a=>a.version===version&&a.sha256===row.sha256&&JSON.stringify(a.releaseApproval||null)===JSON.stringify(approval||null));if(same){Bytes(same);return View(same);}
 if(Object.keys(State().artifacts).length>=128)Fail('OVERLAY_PLUGIN_CAPACITY',409);
 require('./desktopSecurityOperations').AuditIntent('OVERLAY_PLUGIN_STAGE',actor);
 try{store.PublishBytes(row.id,bytes,true);}catch(_){Fail('STORAGE_SAVE_FAILED',503);}
 Atomic(db=>{db.overlayPlugins||=Empty();db.overlayPlugins.artifacts[row.id]=row;db.overlayPlugins.revision++;});
 return View(row);
}
function View(a){const auth=require('./desktopSecurityAuthority'),reason=Reason(a);const {releaseApproval,...publicRow}=a;return {...publicRow,active:State().activeId===a.id,signaturePresent:!!releaseApproval,signatureValid:!!releaseApproval&&auth.VerifyApproval(a,auth.Policy()),eligible:!reason,reason};}
function Overview(){const s=State();return {revision:s.revision,activeId:s.activeId,artifacts:Object.values(s.artifacts).map(View).sort((a,b)=>b.createdAt-a.createdAt),maxBytes:MAX_BYTES,ready:!!s.activeId&&!Reason(s.artifacts[s.activeId])};}
function Activate(body,actor='ADMIN'){
 Fields(body,['id','expectedRevision']);const s=State();if(!Id(body.id)||!s.artifacts[body.id])Fail('OVERLAY_PLUGIN_NOT_PUBLISHED',404);if(body.expectedRevision!==s.revision)Fail('OVERLAY_PLUGIN_CONFLICT',409);
 Bytes(s.artifacts[body.id]);require('./desktopSecurityOperations').AuditIntent('OVERLAY_PLUGIN_ACTIVATE',actor);
 Atomic(db=>{db.overlayPlugins||=Empty();if(db.overlayPlugins.revision!==body.expectedRevision)Fail('OVERLAY_PLUGIN_CONFLICT',409);db.overlayPlugins.activeId=body.id;db.overlayPlugins.revision++;});return Overview();
}
function Pin(){const s=State();return s.activeId?RequireArtifact(s.artifacts[s.activeId]).id:'';}
function Artifact(row){if(!row.pluginId)Fail('OVERLAY_PLUGIN_NOT_PUBLISHED',409);return RequireArtifact(State().artifacts[row.pluginId]);}
function ValidateSession(row,db){
 if(row.pluginId===undefined)return;
 if(!Id(row.pluginId)||!State(db).artifacts[row.pluginId]||!['PENDING','INSTALLING','READY'].includes(row.pluginPhase))throw Error('OVERLAY_PLUGIN_STORAGE_INVALID');
 if(row.pluginPhase!=='PENDING'&&(!Time(row.pluginInstallStartedAt)||!Time(row.pluginInstallExpiresAt)||row.pluginInstallStartedAt<row.createdAt||row.pluginInstallExpiresAt>row.pluginInstallStartedAt+INSTALL_MS||row.pluginInstallExpiresAt<=row.pluginInstallStartedAt))throw Error('OVERLAY_PLUGIN_STORAGE_INVALID');
 if(row.pluginPhase==='READY'&&(!Time(row.pluginVerifiedAt)||row.pluginVerifiedAt<row.pluginInstallStartedAt||row.pluginVerifiedAt>row.lastSeenAt))throw Error('OVERLAY_PLUGIN_STORAGE_INVALID');
}
function LiveDeadline(row){return row.pluginPhase==='INSTALLING'?row.pluginInstallExpiresAt:row.leaseExpiresAt;}
function CheckRuntime(row){
 if(!row.pluginId)return;
 Artifact(row);
 if(row.pluginPhase==='READY'&&(!row.pluginVerifiedAt||row.pluginVerifiedAt>Date.now()||Date.now()-row.pluginVerifiedAt>REPORT_MS))Fail('OVERLAY_PLUGIN_REPORT_REQUIRED',403);
}
function RequireReady(row){if(!row.pluginId)Fail('OVERLAY_PLUGIN_NOT_PUBLISHED',403);if(row.pluginPhase!=='READY')Fail('OVERLAY_PLUGIN_NOT_READY',409);}
function Prune(){const at=Date.now();for(const[id,x]of pending)if(x.expiresAt<=at)pending.delete(id);for(const[id,x]of downloads)if(x.expiresAt<=at)downloads.delete(id);}
function Host(row){const flow=store.Load().flows[row.flowId],a=store.Load().artifacts[flow.releaseId];return Object.fromEntries([...FILE_FIELDS,...CODE_FIELDS].map(k=>[k,a[k]]));}
function Manifest(row,license){
 const a=Artifact(row);Bytes(a);Prune();const at=Date.now();if(at<row.lastSeenAt||LiveDeadline(row)<=at)Fail('OVERLAY_EXPIRED',403);
 if(row.pluginPhase==='PENDING'){
  const end=Math.min(at+INSTALL_MS,license.expiresAt||Number.MAX_SAFE_INTEGER);if(end<=at)Fail('OVERLAY_EXPIRED',403);
  Atomic(db=>Object.assign(db.overlayState.sessions[row.id],{pluginPhase:'INSTALLING',pluginInstallStartedAt:at,pluginInstallExpiresAt:end}));row=store.Load().overlayState.sessions[row.id];
 }
 if(LiveDeadline(row)<=at)Fail('OVERLAY_EXPIRED',403);
 let report=pending.get(row.id);
 if(report?.completed){pending.delete(row.id);report=null;}
 if(!report){if(pending.size>=MAX_PENDING)Fail('OVERLAY_PLUGIN_BUSY',429);report={id:crypto.randomBytes(16).toString('hex'),pluginId:a.id,expiresAt:Math.min(at+REPORT_MS,row.pluginPhase==='INSTALLING'?row.pluginInstallExpiresAt:Number.MAX_SAFE_INTEGER,license.expiresAt||Number.MAX_SAFE_INTEGER),nextBatch:0,modules:[],hashes:[],batches:0,total:0,attempts:0};pending.set(row.id,report);}
 return {schema:1,pluginId:a.id,abi:1,architecture:'win64',exportName:EXPORT,fileName:FILE_NAME,version:a.version,size:a.size,chunkSize:CHUNK_SIZE,...Object.fromEntries([...FILE_FIELDS,...CODE_FIELDS,...EXPORT_FIELDS,'codeAlgorithm'].map(k=>[k,a[k]])),host:Host(row),installExpiresAt:row.pluginInstallExpiresAt,reportId:report.id,reportExpiresAt:report.expiresAt,serverTime:at};
}
function Chunk(row,body){
 const a=Artifact(row);if(body.pluginId!==a.id||!Number.isSafeInteger(body.offset)||body.offset<0||body.offset>=a.size||body.offset%CHUNK_SIZE)Fail('OVERLAY_PLUGIN_INPUT_INVALID');
 if(row.pluginPhase!=='INSTALLING'||row.pluginInstallExpiresAt<=Date.now())Fail('OVERLAY_PLUGIN_INSTALL_CLOSED',403);
 Prune();let q=downloads.get(row.id);if(!q){if(downloads.size>=MAX_PENDING)Fail('OVERLAY_PLUGIN_BUSY',429);q={expiresAt:row.pluginInstallExpiresAt,offsets:new Map()};downloads.set(row.id,q);}
 const repeated=q.offsets.get(body.offset)||0;if(repeated>=3)Fail('OVERLAY_PLUGIN_DOWNLOAD_LIMIT',429);q.offsets.set(body.offset,repeated+1);
 const size=Math.min(CHUNK_SIZE,a.size-body.offset),bytes=Buffer.alloc(size);let fd;
 try{fd=fs.openSync(store.PluginPath(a.id),fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size!==a.size)throw Error();let read=0;while(read<size){const n=fs.readSync(fd,bytes,read,size-read,body.offset+read);if(!n)throw Error();read+=n;}}
 catch(_){Fail('OVERLAY_PLUGIN_FILE_INVALID',503);}finally{if(fd!==undefined)fs.closeSync(fd);}
 if(row.pluginInstallExpiresAt<=Date.now())Fail('OVERLAY_EXPIRED',403);
 return {pluginId:a.id,offset:body.offset,size,data:bytes.toString('base64')};
}
function ExactPlugin(module,a){return module.name.toLowerCase()===FILE_NAME&&module.status==='MATCH_LOCAL_FILE'&&module.codeStatus==='MATCH_LOCAL_FILE'&&module.exportTableStatus==='MEASURED'&&FILE_FIELDS.every(k=>module['file'+k[0].toUpperCase()+k.slice(1)]===a[k])&&[...CODE_FIELDS,...EXPORT_FIELDS].every(k=>module[k]===a[k]);}
function Own(payload,row){const own=payload.own,host=Host(row);return own?.status==='MEASURED'&&FILE_FIELDS.every(k=>own['file'+k[0].toUpperCase()+k.slice(1)]===host[k])&&CODE_FIELDS.every(k=>own[k]===host[k]);}
function Report(row,body,license){
 const a=Artifact(row);Prune();const report=pending.get(row.id);
 if(body.pluginId!==a.id||!report||body.reportId!==report.id||report.pluginId!==a.id||report.expiresAt<=Date.now())Fail('OVERLAY_PLUGIN_REPORT_INVALID',403);
 if(typeof body.payload!=='string'||Buffer.byteLength(body.payload)>8192)Fail('OVERLAY_PLUGIN_INPUT_INVALID');
 const reports=require('./desktopIntegrityReports'),payload=reports.Payload(body.payload);
 if(payload.check!=='MODULE_INVENTORY'||payload.hashVersion!==2||payload.snapshotId!==report.id||payload.truncated||payload.batchCount>256||payload.totalModules>1024||payload.measuredModules>payload.totalModules||payload.scope!=='current-process'||payload.trust!=='client-reported'||payload.complete!==(payload.batchIndex===payload.batchCount-1)||!Own(payload,row))Fail('OVERLAY_PLUGIN_REPORT_MISMATCH',403);
 if(++report.attempts>payload.batchCount*3+8)Fail('OVERLAY_PLUGIN_REPORT_LIMIT',429);
 const metadata=JSON.stringify([payload.hashVersion,payload.batchCount,payload.truncated,payload.totalModules,payload.measuredModules,payload.scope,payload.trust]);
 if(report.metadata&&report.metadata!==metadata)Fail('OVERLAY_PLUGIN_REPORT_MISMATCH',403);report.metadata=metadata;
 const digest=sha(body.payload);
 if(payload.batchIndex<report.nextBatch){if(report.hashes[payload.batchIndex]!==digest)Fail('OVERLAY_PLUGIN_REPORT_REPLAY',409);return {pluginId:a.id,accepted:true,status:report.completed?'READY':'PARTIAL',nextBatch:report.nextBatch,leaseExpiresAt:row.leaseExpiresAt,serverTime:Date.now()};}
 if(payload.batchIndex!==report.nextBatch||report.batches&&report.batches!==payload.batchCount||report.nextBatch&&report.total!==payload.totalModules||report.modules.length+payload.modules.length>1024)Fail('OVERLAY_PLUGIN_REPORT_INVALID',409);
 report.batches=payload.batchCount;report.total=payload.totalModules;report.modules.push(...payload.modules);report.hashes.push(digest);report.nextBatch++;
 if(!payload.complete)return {pluginId:a.id,accepted:true,status:'PARTIAL',nextBatch:report.nextBatch,leaseExpiresAt:row.leaseExpiresAt,serverTime:Date.now()};
 if(report.modules.length!==report.total||report.modules.filter(m=>m.name.toLowerCase()===FILE_NAME).length!==1||!report.modules.some(m=>ExactPlugin(m,a)))Fail('OVERLAY_PLUGIN_REPORT_MISMATCH',403);
 const actualMeasured=report.modules.filter(m=>m.fileSha256&&m.fileCrc64&&m.codeSha256&&m.codeCrc64&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(m.status)&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(m.codeStatus)).length;
 if(actualMeasured!==payload.measuredModules)Fail('OVERLAY_PLUGIN_REPORT_MISMATCH',403);
 const comparisons=report.modules.filter(m=>m.name.toLowerCase()!==FILE_NAME).map(m=>reports.CompareModule(m,2));
 if(comparisons.some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH'))Fail('OVERLAY_PLUGIN_REPORT_MISMATCH',403);
 const policy=reports.Policy();if(policy.enabled&&policy.requiredModules.some(name=>comparisons.filter(m=>m.name.toLowerCase()===name.toLowerCase()).length!==1||!comparisons.some(m=>m.name.toLowerCase()===name.toLowerCase()&&m.serverComparison==='MATCH_REGISTERED_BASELINE'&&m.exportTableVerified&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(m.status)&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(m.codeStatus)&&(!policy.requireExtendedHashes||m.extendedHashesVerified))))Fail('INTEGRITY_SNAPSHOT_REQUIRED',403);
 Bytes(a);const at=Date.now(),end=Math.min(at+30000,license.expiresAt||Number.MAX_SAFE_INTEGER);if(end<=at||at<row.lastSeenAt||LiveDeadline(row)<=at||report.expiresAt<=at)Fail('OVERLAY_EXPIRED',403);
 Atomic(db=>Object.assign(db.overlayState.sessions[row.id],{pluginPhase:'READY',pluginVerifiedAt:at,lastSeenAt:at,leaseExpiresAt:end}));report.completed=true;report.expiresAt=Math.min(at+60000,license.expiresAt||Number.MAX_SAFE_INTEGER);report.modules=[];downloads.delete(row.id);
 return {pluginId:a.id,accepted:true,status:'READY',nextBatch:report.nextBatch,leaseExpiresAt:end,serverTime:at};
}
function Retire(id){pending.delete(id);downloads.delete(id);}
const messages={OVERLAY_PLUGIN_NOT_PUBLISHED:'운영 게시된 오버레이 플러그인이 없습니다.',OVERLAY_PLUGIN_PE_INVALID:'Win64 DLL과 GameOverlayRunV1 내보내기를 확인하세요.',OVERLAY_PLUGIN_TOO_LARGE:'오버레이 플러그인은 최대 16MiB입니다.',OVERLAY_PLUGIN_INPUT_INVALID:'플러그인 파일과 버전 정보를 확인하세요.',OVERLAY_PLUGIN_CONFLICT:'플러그인 목록이 변경되었습니다. 다시 조회하세요.',OVERLAY_PLUGIN_FILE_INVALID:'게시된 플러그인 파일 무결성을 확인할 수 없습니다.',OVERLAY_PLUGIN_NOT_READY:'오버레이 모듈 확인이 아직 완료되지 않았습니다.',OVERLAY_PLUGIN_REPORT_MISMATCH:'오버레이 또는 실행 프로그램의 무결성 확인이 일치하지 않습니다.',OVERLAY_PLUGIN_REPORT_REQUIRED:'오버레이 모듈 무결성을 다시 확인하세요.',SECURITY_RELEASE_SIGNATURE:'현재 신뢰하는 서명 키와 파일 승인 JSON을 확인하세요.',SECURITY_SIGNER_NOT_ACTIVE:'현재 사용할 수 없는 파일 서명 키입니다.',SECURITY_CFG_BUILD_REQUIRED:'현재 서버 정책에 맞는 CFG 빌드를 게시하세요.'};
module.exports={messages,MAX_BYTES,CHUNK_SIZE,INSTALL_MS,REPORT_MS,Stage,Activate,Overview,ValidateState,ValidateSession,Pin,LiveDeadline,CheckRuntime,RequireReady,Manifest,Chunk,Report,Retire};
