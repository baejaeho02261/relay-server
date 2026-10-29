'use strict';
const measurementPlan=require('./peace.measurement-plan-contract');
const measurementStatus=require('./peace.measurement-status');
// Server-resident diagnostics. Signatures prove possession of the current
// session key, not truthful execution or hardware attestation on an owned PC.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),config=require("../../config/peace.runtime-configuration");
const deadline=require("../runtime/peace.desktop-deadline");
const requestProtocol=require("../protocol/peace.desktop-request-protocol");
const receipts=requestProtocol.CreateReceipts({conflict:'INTEGRITY_REPORT_REQUEST_REUSED'});
const DIR=path.join(config.DATA_DIR,'desktop-integrity-reports'),FILE=path.join(DIR,'reports.json'),KEY=path.join(DIR,'authority.key');
const MAX_PAYLOAD=24576,MAX_REPORTS=512,MAX_PENDING=1024,TTL=30000;
const MAX_MODULES=1024,MAX_BATCHES=256,SNAPSHOT_TTL=600000,FRESHNESS={A:180000,B:120000,O:120000};
const DEFAULT_MODULES=['ntdll.dll','kernel32.dll','kernelbase.dll'];
const OVERLAY_START_REASONS=new Set(['OVERLAY_PREPARE_FAILED','OVERLAY_LAUNCH_FAILED','OVERLAY_TRANSFER_FAILED','HANDOFF_KEY_EXPORT_FAILED','HANDOFF_CIPHER_FAILED','HANDOFF_DELEGATION_INVALID','HANDOFF_BOOTSTRAP_INVALID','HANDOFF_CHILD_BINDING_INVALID','HANDOFF_PROCESS_CREATE_FAILED','HANDOFF_PIPE_TIMEOUT','HANDOFF_PIPE_FAILED','HANDOFF_CHILD_EXITED','HANDOFF_READY_TIMEOUT','HANDOFF_WAIT_FAILED']);
function Anchor(){return require("../licensing/peace.desktop-journal-head").Create(FILE+'.head',secret,'DESKTOP_INTEGRITY');}
function Mark(data,raw){return {seq:data.revision,hash:crypto.createHash('sha256').update(raw).digest('hex')};}
let poisoned=false;
let secret,loaded=false,revision=0,records=[],baselines=[],observations=[],registrationResetReceipts={},pending=new Map(),rates=new Map();
let policy={enabled:false,requireExtendedHashes:false,requiredModules:DEFAULT_MODULES.slice(),revision:0,updatedAt:0,actor:''};
const snapshots=new Map(),finishedSnapshots=new Map();
const sha=value=>crypto.createHash('sha512').update(value).digest('hex');
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Plain(value){return value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;}
function ValidateResetReceipts(value,limit){
 if(!Plain(value)||Object.keys(value).length>1024)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');
 for(const [id,r]of Object.entries(value))if(!/^[a-f0-9]{64}$/.test(id)||!Plain(r)||Object.keys(r).sort().join(',')!=='at,baselines,observations,records,revision'||!Number.isSafeInteger(r.at)||r.at<1||!Number.isSafeInteger(r.revision)||r.revision<1||r.revision>limit||['records','baselines','observations'].some(k=>!Number.isSafeInteger(r[k])||r[k]<0))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');
 return value;
}
function Keys(value,allowed){if(!Plain(value)||Object.keys(value).some(key=>!allowed.includes(key)))Fail('INTEGRITY_REPORT_INVALID');}
function Digest(value,size){if(value===''||value===null||value===undefined)return '';if(typeof value!=='string'||!new RegExp('^[a-fA-F0-9]{'+size+'}$').test(value))Fail('INTEGRITY_REPORT_INVALID');return size===16?value.toUpperCase():value.toLowerCase();}
function ExtendedDigest(value,size){if(value===''||value===null||value===undefined)return '';if(typeof value!=='string'||!new RegExp('^[a-f0-9]{'+size+'}$').test(value))Fail('INTEGRITY_REPORT_INVALID');return value;}
const EXTENDED_FIELDS=['fileXxh3_128','fileBlake3','codeXxh3_128','codeBlake3','exportTableXxh3_128','exportTableBlake3'];
function HasExtendedPair(row,prefix){return typeof row[prefix+'Xxh3_128']==='string'&&/^[a-f0-9]{32}$/.test(row[prefix+'Xxh3_128'])&&typeof row[prefix+'Blake3']==='string'&&/^[a-f0-9]{64}$/.test(row[prefix+'Blake3']);}
function ExtendedComparison(row,baseline,prefix){const fields=[prefix+'Xxh3_128',prefix+'Blake3'];return {mismatch:fields.some(key=>row[key]&&baseline[key]&&row[key]!==baseline[key]),verified:HasExtendedPair(row,prefix)&&HasExtendedPair(baseline,prefix)&&fields.every(key=>row[key]===baseline[key])};}
function AuditBinding(machineId){return /^[A-F0-9]{64}$/.test(machineId||'')?require("../devices/peace.desktop-device-registry").BindingId(machineId):'';}
function Identifier(value){if(value===undefined||value==='')return '';if(typeof value!=='string'||!/^[-A-Za-z0-9_]{1,100}$/.test(value))Fail('INTEGRITY_REPORT_INVALID');return value;}
function Token(value){if(typeof value!=='string'||!/^[-A-Z0-9_]{1,64}$/.test(value))Fail('INTEGRITY_REPORT_INVALID');return value;}
function ReadFile(file){const st=fs.lstatSync(file);if(st.isSymbolicLink()||!st.isFile())throw Error('INTEGRITY_REPORT_STORAGE_INVALID');return fs.readFileSync(file);}
function Mac(payload){return crypto.createHmac('sha256',secret).update('GAME-INTEGRITY-REPORTS-V1\n'+JSON.stringify(payload)).digest('hex');}
function Blake3Mac(payload){const h=require("../cryptography/peace.extended-hashes"),key=h.Blake3DeriveKey('cozy.Client.Server.IntegrityReports.Store.v2',secret);const bytes=Buffer.from(JSON.stringify(payload));try{return h.Blake3Keyed(key,bytes).toString('hex');}finally{key.fill(0);bytes.fill(0);}}
// KMAC authenticates the canonical store's SHA-512 digest under a distinct
// HKDF key/domain. Native SHA-512 bounds the JS Keccak work for large journals;
// this versioned construction does not substitute a hash for a secret MAC.
function KmacMac(payload){const bytes=Buffer.from(JSON.stringify(payload));let digest;try{digest=crypto.createHash('sha512').update(bytes).digest();return require("../cryptography/peace.kmac256.js").ServerMac(secret,digest,'GAME-INTEGRITY-REPORTS-STORE-V3');}finally{bytes.fill(0);digest?.fill(0);}}
function Load(){
 if(poisoned)throw Error('INTEGRITY_REPORT_RESTART_REQUIRED');if(loaded)return;let created=false;fs.mkdirSync(DIR,{recursive:true,mode:0o700});
 if(!fs.existsSync(KEY)){created=true;if(fs.existsSync(FILE))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');const fd=fs.openSync(KEY,'wx',0o600);try{fs.writeFileSync(fd,crypto.randomBytes(32));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 if(!created&&!fs.existsSync(FILE))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');
 secret=ReadFile(KEY);if(secret.length!==32)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');
 if(fs.existsSync(FILE)){const raw=ReadFile(FILE),envelope=require("../protocol/peace.strict-json").Parse(raw,{maxBytes:64*1024*1024,maxNodes:4000000});const data=envelope?.data;if(!data||![1,2,3].includes(data.version)||!Number.isSafeInteger(data.revision)||!Array.isArray(data.records)||data.records.length>MAX_REPORTS||!require("../protocol/peace.strict-json").SecretEqual(envelope.mac,Mac(data))||data.version>=2&&!require("../protocol/peace.strict-json").SecretEqual(envelope.blake3Mac,Blake3Mac(data))||data.version===3&&!require("../protocol/peace.strict-json").SecretEqual(envelope.kmac256Mac,KmacMac(data)))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');Anchor().Open(Mark(data,raw),!fs.existsSync(FILE+'.head'));revision=data.revision;registrationResetReceipts=ValidateResetReceipts(data.registrationResetReceipts||{},revision);records=data.records;observations=data.observations||[];if(!Array.isArray(observations)||observations.length>4096)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');baselines=data.baselines||[];if(!Array.isArray(baselines)||baselines.length>256)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');if(data.policy){try{ValidatePolicy(data.policy,true);}catch(_){throw Error('INTEGRITY_REPORT_STORAGE_INVALID');}policy={requireExtendedHashes:false,...data.policy};}for(const row of records)if(row.snapshotFinal&&row.snapshotId)finishedSnapshots.set(SnapshotKey(row.stage,row.stage==='A'?row.flowId:row.sessionId,row.snapshotId),row.at+900000);}
 if(created)Save([]);loaded=true;
}
function Save(next){
 if(poisoned)throw Error('INTEGRITY_REPORT_RESTART_REQUIRED');
 const data={version:3,revision:revision+1,records:next,baselines,policy,observations,...(Object.keys(registrationResetReceipts).length?{registrationResetReceipts}:{})};
 const raw=Buffer.from(JSON.stringify({data,mac:Mac(data),blake3Mac:Blake3Mac(data),kmac256Mac:KmacMac(data)})),nextHead=Mark(data,raw);let previous,published=false;
 try{
  if(fs.existsSync(FILE)){const before=ReadFile(FILE),old=require("../protocol/peace.strict-json").Parse(before,{maxBytes:64*1024*1024,maxNodes:4000000});previous=Mark(old.data,before);Anchor().Prepare(previous,nextHead);}
  require("../storage/peace.durable-file").Atomic(FILE,raw,{createOnly:!previous});published=true;
  if(previous)Anchor().Settle(nextHead);else Anchor().Open(nextHead,true);
 }catch(error){if(published||error.published)poisoned=true;else if(previous)try{Anchor().Open(previous);}catch(_){poisoned=true;}throw error;}
 finally{raw.fill(0);}
 revision=data.revision;records=next;
}
function Module(row,hashVersion=3){
 Keys(row,['name','status','fileSha512','fileCrc64','codeSha512','codeCrc64','codeStatus','executableSections','exportCount','codeExportCount','forwardedExportCount','exportCoverage','exportTableSha512','exportTableCrc64','exportTableStatus','failurePhase',...EXTENDED_FIELDS]);
 if(typeof row.name!=='string'||!row.name.length||row.name.length>180||/[\\/:\x00-\x1f\x7f]/.test(row.name))Fail('INTEGRITY_REPORT_INVALID');
 const allowed=['UNVERIFIED_BASELINE','LOCAL_DIFFERENCE','READ_ERROR','SKIPPED_LIMIT','FILE_UNAVAILABLE','MATCH_LOCAL_FILE','NAME_TOO_LONG','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'];
 if(!allowed.includes(row.status)||row.codeStatus&&!allowed.includes(row.codeStatus))Fail('INTEGRITY_REPORT_INVALID');
 const result={name:row.name,status:row.status,codeStatus:row.codeStatus||'UNVERIFIED_BASELINE',fileSha512:Digest(row.fileSha512,128),fileCrc64:Digest(row.fileCrc64,16),codeSha512:Digest(row.codeSha512,128),codeCrc64:Digest(row.codeCrc64,16)};
 if(row.failurePhase!==undefined){if(!Number.isInteger(row.failurePhase)||row.failurePhase<0||row.failurePhase>9)Fail('INTEGRITY_REPORT_INVALID');result.failurePhase=row.failurePhase;}
 for(const key of EXTENDED_FIELDS)result[key]=ExtendedDigest(row[key],key.endsWith('Xxh3_128')?32:64);
 for(const key of ['executableSections','exportCount','codeExportCount','forwardedExportCount'])if(row[key]!==undefined){if(!Number.isInteger(row[key])||row[key]<0||row[key]>1000000)Fail('INTEGRITY_REPORT_INVALID');result[key]=row[key];}
 if(row.exportCoverage!==undefined){if(!['SECTION_HASHED','NO_EXPORTS','INVALID_EXPORT_TABLE','NOT_MEASURED'].includes(row.exportCoverage))Fail('INTEGRITY_REPORT_INVALID');result.exportCoverage=row.exportCoverage;}
 if(row.exportTableStatus!==undefined){if(!['MEASURED','NO_EXPORTS','UNSUPPORTED_EXPORT_LAYOUT','READ_ERROR'].includes(row.exportTableStatus))Fail('INTEGRITY_REPORT_INVALID');result.exportTableStatus=row.exportTableStatus;result.exportTableSha512=Digest(row.exportTableSha512,128);result.exportTableCrc64=Digest(row.exportTableCrc64,16);if(row.exportTableStatus==='MEASURED'&&(!result.exportTableSha512||!result.exportTableCrc64))Fail('INTEGRITY_REPORT_INVALID');}
 if(hashVersion===3&&((result.fileSha512||result.fileCrc64)&&!HasExtendedPair(result,'file')||(result.codeSha512||result.codeCrc64)&&!HasExtendedPair(result,'code')||result.exportTableStatus==='MEASURED'&&!HasExtendedPair(result,'exportTable')))Fail('INTEGRITY_REPORT_INVALID');
 return result;
}
function ThreadInventory(value){
 Keys(value,['version','status','enumerated','knownImage','unknownStart','unreadable','truncated']);
 if(Object.keys(value).length!==7||value.version!==1||!['COMPLETE','PARTIAL','UNAVAILABLE'].includes(value.status)||typeof value.truncated!=='boolean')Fail('INTEGRITY_REPORT_INVALID');
 for(const key of ['enumerated','knownImage','unknownStart','unreadable'])if(!Number.isInteger(value[key])||value[key]<0||value[key]>1024)Fail('INTEGRITY_REPORT_INVALID');
 if(value.enumerated!==value.knownImage+value.unknownStart+value.unreadable||value.status==='COMPLETE'&&(value.unreadable!==0||value.truncated)||value.status==='UNAVAILABLE'&&(value.enumerated!==0||value.truncated))Fail('INTEGRITY_REPORT_INVALID');
 // Observation only: an unknown start can be a legitimate runtime/JIT thread.
 // These counts carry no addresses, thread IDs, or server authorization claim.
 return {version:1,status:value.status,enumerated:value.enumerated,knownImage:value.knownImage,unknownStart:value.unknownStart,unreadable:value.unreadable,truncated:value.truncated};
}
function DeviceSignals(value){
 Keys(value,['version','status','scope','algorithm','diskCount','nicCount','digest','truncated']);
 if(Object.keys(value).length!==8||value.version!==1||!['NOT_REQUESTED','MEASURED','PARTIAL','UNAVAILABLE'].includes(value.status)||value.algorithm!=='BLAKE3-KEYED-256'||typeof value.truncated!=='boolean'||!Number.isInteger(value.diskCount)||value.diskCount<0||value.diskCount>8||!Number.isInteger(value.nicCount)||value.nicCount<0||value.nicCount>64)Fail('INTEGRITY_REPORT_INVALID');
 const count=value.diskCount+value.nicCount;
 if(value.status==='NOT_REQUESTED'){
  if(value.scope!==''||value.digest!==''||count!==0||value.truncated)Fail('INTEGRITY_REPORT_INVALID');
 }else{
  if(typeof value.scope!=='string'||!/^[a-f0-9]{128}$/.test(value.scope))Fail('INTEGRITY_REPORT_INVALID');
  if(value.status==='UNAVAILABLE'){if(count!==0||value.digest!=='')Fail('INTEGRITY_REPORT_INVALID');}
  else if(!count||typeof value.digest!=='string'||!/^[a-f0-9]{64}$/.test(value.digest)||value.status==='MEASURED'&&value.truncated)Fail('INTEGRITY_REPORT_INVALID');
 }
 // Session/challenge-scoped client diagnostics; no raw disk/NIC IDs, stable
 // device binding, hardware attestation, or automatic authorization decision.
 return {version:1,status:value.status,scope:value.scope,algorithm:value.algorithm,diskCount:value.diskCount,nicCount:value.nicCount,digest:value.digest,truncated:value.truncated};
}
function Payload(text){
 if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>MAX_PAYLOAD)Fail('INTEGRITY_REPORT_INVALID');let p;try{p=require("../protocol/peace.strict-json").Parse(text);}catch(_){Fail('INTEGRITY_REPORT_INVALID');}
 Keys(p,['version','hashVersion','check','reason','own','modules','snapshotId','batchIndex','batchCount','complete','truncated','totalModules','measuredModules','scope','trust','crcLayers','ownMeasurement','measurementContract','measurementPlanVersion','measurementStartedTick','measurementFinishedTick','moduleGenerationStable','moduleGenerationStatus','threadInventory','deviceSignals','coverage']);
 if(p.version!==1||p.hashVersion!==3||!['OWN_IMAGE','MODULE_INVENTORY','OVERLAY_START'].includes(p.check))Fail('INTEGRITY_REPORT_INVALID');Token(p.reason);
 if(p.check==='OVERLAY_START'){
  // A failed startup is a signed client diagnostic, never hash evidence or an
  // authority observation. Do not accept client-supplied paths or free text.
  Keys(p,['version','hashVersion','check','reason']);if(!OVERLAY_START_REASONS.has(p.reason))Fail('INTEGRITY_REPORT_INVALID');return p;
 }
 if(p.own){
  Keys(p.own,['codeSha512','codeCrc64','fileSha512','fileCrc64','status','fileXxh3_128','fileBlake3','codeXxh3_128','codeBlake3']);
  if(!measurementStatus.IsStatus(p.own.status))Fail('INTEGRITY_REPORT_INVALID');
  const own={status:p.own.status,codeSha512:Digest(p.own.codeSha512,128),codeCrc64:Digest(p.own.codeCrc64,16)};
  // Older approved clients omit this pair. If either field is sent, require
  // both and compare the exact pinned file separately from normalized code.
  // In particular A is compared with its issued bytes, not the A template.
  const hasFileSha=Object.hasOwn(p.own,'fileSha512'),hasFileCrc=Object.hasOwn(p.own,'fileCrc64');
  if(hasFileSha!==hasFileCrc)Fail('INTEGRITY_REPORT_INVALID');
  if(hasFileSha){
   own.fileSha512=Digest(p.own.fileSha512,128);own.fileCrc64=Digest(p.own.fileCrc64,16);
   if(own.status==='MEASURED'&&(!own.fileSha512||!own.fileCrc64))Fail('INTEGRITY_REPORT_INVALID');
  }
  for(const key of EXTENDED_FIELDS.slice(0,4))own[key]=ExtendedDigest(p.own[key],key.endsWith('Xxh3_128')?32:64);
  p.own=own;
  if(own.status==='MEASURED'&&(!own.codeSha512||!own.codeCrc64||p.hashVersion===3&&(!HasExtendedPair(own,'file')||!HasExtendedPair(own,'code'))))Fail('INTEGRITY_REPORT_INVALID');
 }
 if(p.check==='OWN_IMAGE'&&!p.own)Fail('INTEGRITY_REPORT_INVALID');
 if((p.own?.status==='MEASURED'||p.crcLayers!==undefined)&&!require("../runtime/peace.desktop-crc-policy").Validate(p.crcLayers))Fail('INTEGRITY_REPORT_INVALID');
 if(p.ownMeasurement!==undefined&&!measurementPlan.ValidateOwnMetadata(p.ownMeasurement,p.own?.status,p.crcLayers))Fail('INTEGRITY_REPORT_INVALID');
 if(p.modules!==undefined&&(!Array.isArray(p.modules)||p.modules.length>16))Fail('INTEGRITY_REPORT_INVALID');p.modules=(p.modules||[]).map(row=>Module(row,p.hashVersion));
 if(p.moduleGenerationStatus!==undefined&&p.check!=='MODULE_INVENTORY')Fail('INTEGRITY_REPORT_INVALID');
 if(p.deviceSignals!==undefined){if(p.check!=='MODULE_INVENTORY')Fail('INTEGRITY_REPORT_INVALID');p.deviceSignals=DeviceSignals(p.deviceSignals);}
 if(p.threadInventory!==undefined){if(p.check!=='MODULE_INVENTORY')Fail('INTEGRITY_REPORT_INVALID');p.threadInventory=ThreadInventory(p.threadInventory);}
 if(p.check==='MODULE_INVENTORY'){
  if(p.measurementContract!==undefined&&p.measurementContract!==measurementPlan.CONTRACT)Fail('INTEGRITY_REPORT_INVALID');
  if(p.measurementPlanVersion!==undefined){
   if(p.measurementPlanVersion!==1||!Number.isSafeInteger(p.measurementStartedTick)||!Number.isSafeInteger(p.measurementFinishedTick)||p.measurementStartedTick<0||p.measurementFinishedTick<p.measurementStartedTick||p.measurementFinishedTick-p.measurementStartedTick>60000||typeof p.moduleGenerationStable!=='boolean'||!['FULL','PARTIAL','SAMPLED'].includes(p.coverage)||p.complete&&!p.moduleGenerationStable||p.coverage==='FULL'&&(!p.complete||p.truncated||p.measuredModules!==p.totalModules))Fail('INTEGRITY_REPORT_INVALID');
   if(p.moduleGenerationStatus!==undefined&&(!['TRACKED_STABLE','TRACKED_CHANGED','UNSUPPORTED','TRACKING_FAILED'].includes(p.moduleGenerationStatus)||p.moduleGenerationStable!==(p.moduleGenerationStatus==='TRACKED_STABLE')))Fail('INTEGRITY_REPORT_INVALID');
  }else if(['measurementContract','measurementStartedTick','measurementFinishedTick','moduleGenerationStable','moduleGenerationStatus','threadInventory','deviceSignals','coverage'].some(k=>p[k]!==undefined))Fail('INTEGRITY_REPORT_INVALID');
  Identifier(p.snapshotId);if(!p.snapshotId||!Number.isInteger(p.batchIndex)||!Number.isInteger(p.batchCount)||p.batchCount<1||p.batchCount>MAX_BATCHES||p.batchIndex<0||p.batchIndex>=p.batchCount||typeof p.complete!=='boolean'||typeof p.truncated!=='boolean'||!Number.isInteger(p.totalModules)||p.totalModules<0||p.totalModules>65535||!Number.isInteger(p.measuredModules)||p.measuredModules<0||p.measuredModules>MAX_MODULES)Fail('INTEGRITY_REPORT_INVALID');
 }
 return p;
}
function Record(input){
 Load();if(!Plain(input)||!['A','B','O'].includes(input.stage)||!['VERIFIED','REJECTED','CLIENT_DIAGNOSTIC'].includes(input.status))Fail('INTEGRITY_REPORT_INVALID');
 const record={id:crypto.randomBytes(12).toString('hex').toUpperCase(),at:Date.now(),stage:input.stage,check:Token(input.check),status:input.status,reason:Token(input.reason||input.status),machineId:Identifier(input.machineId),flowId:Identifier(input.flowId),sessionId:Identifier(input.sessionId),artifactId:Identifier(input.artifactId),source:input.trusted===true?'SERVER_COMPARISON':'SIGNED_CLIENT_REPORT',attested:false,
  expectedSha512:Digest(input.expectedSha512,128),observedSha512:Digest(input.observedSha512,128),expectedCrc64:Digest(input.expectedCrc64,16),observedCrc64:Digest(input.observedCrc64,16),hashVersion:3,extendedHashesVerified:input.hashVersion===3&&input.extendedHashesVerified===true};
 for(const prefix of ['expected','observed','expectedFile','observedFile'])for(const algorithm of ['Xxh3_128','Blake3'])record[prefix+algorithm]=ExtendedDigest(input[prefix+algorithm],algorithm==='Xxh3_128'?32:64);
 if(input.check==='OWN_CODE')for(const field of ['fileExtendedVerified','codeExtendedVerified'])record[field]=input.hashVersion===3&&input[field]===true;
 if(input.check==='OWN_CODE'){
  record.pointerGraphReported=input.ownMeasurement?.pointerGraph!==undefined;
  record.pointerGraphVerified=input.pointerGraphVerified===true;
  record.fileHashesReported=input.fileHashesReported===true;
  record.fileHashesVerified=record.fileHashesReported&&input.fileHashesVerified===true;
  if(record.fileHashesReported)for(const prefix of ['expectedFile','observedFile']){
   record[prefix+'Sha512']=Digest(input[prefix+'Sha512'],128);
   record[prefix+'Crc64']=Digest(input[prefix+'Crc64'],16);
  }
 }
 if(input.modules){record.modules=input.modules.map(row=>Module(row,record.hashVersion)).map(row=>CompareModule(row,record.hashVersion));if(record.modules.some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH')){record.status='REJECTED';record.reason='KNOWN_MODULE_CODE_MISMATCH';record.source='SERVER_COMPARISON';}}
 if(input.crcComparison)record.crcComparison=input.crcComparison;
 for(const key of ['ownMeasurement','snapshotId','batchIndex','batchCount','complete','truncated','totalModules','measuredModules','snapshotStatus','snapshotReceivedBatches','snapshotReasons','snapshotDiagnostics','snapshotFinal','strictPolicyRevision','planAssurance','requiredMeasurementPlanVersion','requiredModuleResults','duplicateModuleNames','duplicateModuleCount','measurementContract','measurementPlanVersion','measurementStartedTick','measurementFinishedTick','moduleGenerationStable','moduleGenerationStatus','threadInventory','deviceSignals','coverage'])if(input[key]!==undefined)record[key]=input[key];
 if(input.measurementStatus!==undefined){if(!measurementStatus.IsStatus(input.measurementStatus))Fail('INTEGRITY_REPORT_INVALID');record.measurementStatus=input.measurementStatus;}
 // Repeated successes update a bounded current observation; retain rejection
 // evidence even during frequent authentication and inventory collection.
 const next=records.filter(row=>!(record.status==='VERIFIED'&&row.status==='VERIFIED'&&row.sessionId===record.sessionId&&row.stage===record.stage&&row.check===record.check));next.push(record);
 if(next.length>MAX_REPORTS){const index=next.findIndex((row,i)=>i<next.length-1&&row.status!=='REJECTED');next.splice(index>=0?index:0,1);}
 const previousObservations=observations;
 if(record.snapshotFinal){observations=observations.filter(row=>row.at>Date.now()-900000&&!(row.stage===record.stage&&row.sessionId===record.sessionId&&row.flowId===record.flowId));if(observations.length>=4096){observations=previousObservations;Fail('INTEGRITY_SNAPSHOT_LIMIT',429);}observations.push({at:record.at,stage:record.stage,sessionId:record.sessionId,flowId:record.flowId,snapshotId:record.snapshotId,snapshotStatus:record.snapshotStatus,strictPolicyRevision:record.strictPolicyRevision,measurementPlanVersion:record.measurementPlanVersion||0,planAssurance:record.planAssurance||'LEGACY_UNVERSIONED',coverage:record.coverage||'UNSPECIFIED'});}
 try{Save(next);}catch(error){observations=previousObservations;throw error;}
 // A diagnostic event only after the complete snapshot is persisted. Its
 // expiry is the existing RequireSnapshot boundary, not a new grant.
 if(record.snapshotFinal&&record.snapshotStatus==='COMPLETE_PASS')try{
  require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_MODULE_SNAPSHOT_ACCEPTED',JSON.stringify({stage:record.stage,sessionId:record.sessionId,flowId:record.flowId,snapshotId:record.snapshotId,acceptedAt:record.at,expiresAt:record.at+FRESHNESS[record.stage],status:record.status,coverage:record.coverage,measuredModules:record.measuredModules,totalModules:record.totalModules,strictPolicyRevision:record.strictPolicyRevision,attested:false}));
 }catch(_){console.error('MODULE_SNAPSHOT_AUDIT_FAILED');}
 if(record.status==='REJECTED')require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_INTEGRITY_REJECTED',JSON.stringify({reportId:record.id,stage:record.stage,check:record.check,reason:record.reason,sessionId:record.sessionId,bindingId:AuditBinding(record.machineId),...(record.snapshotDiagnostics?{snapshotDiagnostics:record.snapshotDiagnostics}:{})}));
 return record;
}
function Auth(body){return require("../bootstrap/peace.desktop-bootstrap").AuthenticateIntegrityReport(body);}
const AUTH_FIELDS=['stage','action','sessionId','sessionToken','machineId','binarySha512','binaryCrc64','codeSha512','codeCrc64'];
function Prune(){const clock=deadline.Now(),at=clock.wall;for(const [id,c] of pending)if(deadline.Expired(c,clock))pending.delete(id);for(const [id,r] of rates)if(r.until<=at)rates.delete(id);for(const [id,until] of finishedSnapshots)if(until<=at)finishedSnapshots.delete(id);for(const [id,snapshot] of snapshots)if(snapshot.expiresAt<=at){snapshots.delete(id);finishedSnapshots.set(id,at+900000);Record({...snapshot.fields,status:'CLIENT_DIAGNOSTIC',check:'MODULE_SNAPSHOT',reason:'SNAPSHOT_TIMEOUT',snapshotId:snapshot.snapshotId,snapshotStatus:'TIMED_OUT',snapshotFinal:true,snapshotReasons:['INCOMPLETE_SNAPSHOT'],strictPolicyRevision:snapshot.policyRevision});}}
function Challenge(body){
 Keys(body,AUTH_FIELDS);const row=Auth(body),context=row.reportContextId||row.sessionId;Prune();const at=Date.now(),rate=rates.get(context)||{until:at+60000,count:0};
 if(rate.count>=256||pending.size>=MAX_PENDING||rates.size>=4096&&!rates.has(context))Fail('INTEGRITY_REPORT_RATE_LIMIT',429);rate.count++;rates.set(context,rate);
 const report={reportId:crypto.randomBytes(24).toString('hex'),nonce:crypto.randomBytes(24).toString('hex'),...deadline.After(TTL),sessionId:context};pending.set(report.reportId,report);return {reportId:report.reportId,nonce:report.nonce,expiresAt:report.expiresAt};
}
function Canonical(sessionId,challenge,payload){return ['GAME-INTEGRITY-REPORT-V2',sessionId,challenge.reportId,challenge.nonce,String(challenge.expiresAt),sha(payload)].join('\n');}
function ReceiptBinding(row){Load();return requestProtocol.Fingerprint('report.submit',{artifactId:row.integrityArtifact?.id,policy:Policy(),authorityRevision:require("../security/peace.desktop-security-authority").Policy().revision,operationsRevision:require("../security/peace.desktop-security-operations").Revision(),baselines:baselines.slice().sort((a,b)=>a.id.localeCompare(b.id))});}
function Submit(body){
 Keys(body,[...AUTH_FIELDS,'reportId','payload','signature']);
 const receipt=receipts.get(body.reportId,'report.submit',body);
 if(receipt){
  // Only the exact previously signed request may recover a terminal denial.
  // Retained credential hashes cannot authorize measurements or fresh grants.
  const current=receipt.response.terminate===true?require("../bootstrap/peace.desktop-bootstrap").AuthenticateIntegrityReceipt(body):Auth(body);
  if((current.reportContextId||current.sessionId)!==receipt.meta.context||current.publicKey!==receipt.meta.publicKey)Fail('INTEGRITY_REPORT_CHALLENGE_INVALID',401);
  if(!receipt.response.terminate&&ReceiptBinding(current)!==receipt.meta.binding)Fail('INTEGRITY_REPORT_CHALLENGE_INVALID',401);
  return receipt.response;
 }
 const row=Auth(body),context=row.reportContextId||row.sessionId;Prune();const challenge=pending.get(body.reportId);
 if(!challenge||challenge.sessionId!==context)Fail('INTEGRITY_REPORT_CHALLENGE_INVALID',401);pending.delete(body.reportId);
 const payload=Payload(body.payload);try{measurementPlan.Assert(payload,row.integrityArtifact,row.integrityArtifact.pointerGraphSlots,{graph:false});}catch(error){Fail(error.message,400);}if(typeof body.signature!=='string'||!/^[A-Za-z0-9+/]{342}==$/.test(body.signature))Fail('INTEGRITY_REPORT_SIGNATURE_INVALID',401);
 const bytes=Buffer.from(body.signature,'base64'),key=require("../licensing/peace.desktop-licenses").ParseKey(row.publicKey).key;
 if(bytes.length!==256||bytes.toString('base64')!==body.signature||!require('./peace.desktop-proof-work').Verify(row.publicKey,Canonical(context,challenge,body.payload),body.signature))Fail('INTEGRITY_REPORT_SIGNATURE_INVALID',401);
 // Parsing and native signature verification can cross the issued deadline.
 if(deadline.Expired(challenge))Fail('INTEGRITY_REPORT_CHALLENGE_INVALID',401);
 const artifact=row.integrityArtifact;if(!artifact)Fail('INTEGRITY_REPORT_BASELINE_UNAVAILABLE',503);
 const binding=ReceiptBinding(row);
 if(deadline.Expired(challenge))Fail('INTEGRITY_REPORT_CHALLENGE_INVALID',401);
 function Complete(response){receipts.put(body.reportId,'report.submit',body,response,{context,publicKey:row.publicKey,binding});return response;}
 const fields={stage:row.stage||'B',machineId:row.machineId,sessionId:row.sessionId,flowId:row.id,artifactId:artifact.id,check:payload.check,reason:payload.reason,hashVersion:payload.hashVersion};
 let result;
 const graphReason=measurementPlan.GraphReason(payload,artifact,artifact.pointerGraphSlots);
 if(graphReason){
  require('../security/peace.desktop-security-authority').Invalidate(row,row.stage||'B',graphReason);
  require('../bootstrap/peace.desktop-bootstrap').Revoke(row.sessionId,{reason:'INTEGRITY_'+graphReason},'INTEGRITY_REPORT');
  result=Record({...fields,check:'OWN_CODE',status:'REJECTED',reason:graphReason,measurementStatus:payload.own.status,ownMeasurement:payload.ownMeasurement,pointerGraphVerified:false,trusted:true});
  return Complete({accepted:true,status:'REJECTED',reportId:result.id,terminate:true});
 }
 if(payload.check==='OVERLAY_START'){
  if(fields.stage!=='B')Fail('INTEGRITY_REPORT_INVALID');
  result=Record({...fields,status:'CLIENT_DIAGNOSTIC',trusted:false});
  require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_OVERLAY_START_FAILED',JSON.stringify({reportId:result.id,stage:'B',flowId:row.id,sessionId:row.sessionId,bindingId:AuditBinding(row.machineId),reason:payload.reason,source:'SIGNED_CLIENT_REPORT',attested:false}));
  // Receipt only: do not refresh, invalidate or grant execution authority.
  return Complete({accepted:true,status:'CLIENT_DIAGNOSTIC',reportId:result.id,terminate:false});
 }
 if(measurementStatus.IsFailure(payload.own?.status)&&require("../security/peace.desktop-security-authority").UsesAuthority(row,row.stage||'B')){
  const reason=measurementStatus.FailureReason(payload.own.status);
  require("../security/peace.desktop-security-authority").Invalidate(row,row.stage||'B',reason);
  result=Record({...fields,check:'OWN_CODE',status:'CLIENT_DIAGNOSTIC',reason,measurementStatus:payload.own.status,ownMeasurement:payload.ownMeasurement,crcComparison:require("../runtime/peace.desktop-crc-policy").Compare(payload.crcLayers,artifact.crcLayers),trusted:false});
  return Complete({accepted:true,status:'CLIENT_DIAGNOSTIC',reportId:result.id,terminate:false});
 }
 if(payload.own){if(payload.ownMeasurement)fields.ownMeasurement=payload.ownMeasurement;fields.pointerGraphVerified=payload.own.status==='MEASURED'&&artifact.ownMeasurementVersion>=2&&require('./peace.pointer-graph-contract').Compare(payload.ownMeasurement?.pointerGraph,artifact.pointerGraphSlots).matched;const own=payload.own,crcComparison=require("../runtime/peace.desktop-crc-policy").Compare(payload.crcLayers,artifact.crcLayers),codeComparison=ExtendedComparison(own,artifact,'code'),fileComparison=ExtendedComparison(own,artifact,'file');
  const fileHashesReported=Object.hasOwn(own,'fileSha512'),fileHashesVerified=own.status==='MEASURED'&&fileHashesReported&&own.fileSha512===artifact.sha512&&own.fileCrc64===artifact.crc64;
  const rejectionReason=measurementStatus.IsFailure(own.status)?(own.status==='READ_ERROR'?'MEASUREMENT_FAILED':own.status):!crcComparison.matched?crcComparison.reason:own.codeSha512!==artifact.codeSha512||own.codeCrc64!==artifact.codeCrc64?'CODE_HASH_MISMATCH':fileHashesReported&&!fileHashesVerified?'FILE_HASH_MISMATCH':codeComparison.mismatch?'CODE_EXTENDED_HASH_MISMATCH':fileComparison.mismatch?'FILE_EXTENDED_HASH_MISMATCH':require("../security/peace.desktop-security-authority").Policy().requireCompleteCrcLayers&&!crcComparison.complete?'CRC_COVERAGE_INCOMPLETE':'';
  const matches=!rejectionReason,fileExtendedVerified=own.status==='MEASURED'&&payload.hashVersion===3&&fileComparison.verified,codeExtendedVerified=own.status==='MEASURED'&&payload.hashVersion===3&&codeComparison.verified;
  // Pair equality is an independent observation, not an overall execution PASS.
  // Incomplete CRC coverage must not turn matching file/code hashes into failures.
  const extendedHashesVerified=fileExtendedVerified&&codeExtendedVerified,unverifiedExtended=payload.hashVersion===3&&matches&&!extendedHashesVerified;
  if(!matches)require("../bootstrap/peace.desktop-bootstrap").Revoke(row.sessionId,{reason:'INTEGRITY_'+rejectionReason},'INTEGRITY_REPORT');
  result=Record({...fields,check:'OWN_CODE',measurementStatus:own.status,status:matches?unverifiedExtended?'CLIENT_DIAGNOSTIC':'VERIFIED':'REJECTED',reason:matches?unverifiedExtended?'EXTENDED_BASELINE_UNAVAILABLE':'BASELINE_MATCH':rejectionReason,trusted:true,extendedHashesVerified,fileExtendedVerified,codeExtendedVerified,fileHashesReported,fileHashesVerified,...(fileHashesReported?{expectedFileSha512:artifact.sha512,observedFileSha512:own.fileSha512,expectedFileCrc64:artifact.crc64,observedFileCrc64:own.fileCrc64}:{}),crcComparison,expectedSha512:artifact.codeSha512,observedSha512:own.codeSha512,expectedCrc64:artifact.codeCrc64,observedCrc64:own.codeCrc64,expectedXxh3_128:artifact.codeXxh3_128,observedXxh3_128:own.codeXxh3_128,expectedBlake3:artifact.codeBlake3,observedBlake3:own.codeBlake3,expectedFileXxh3_128:artifact.fileXxh3_128,observedFileXxh3_128:own.fileXxh3_128,expectedFileBlake3:artifact.fileBlake3,observedFileBlake3:own.fileBlake3});
  if(!matches){return Complete({accepted:true,status:'REJECTED',reportId:result.id,terminate:true});}
 }
 if(payload.check==='MODULE_INVENTORY'){Load();if(payload.modules.map(module=>CompareModule(module,payload.hashVersion)).some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH')){require("../bootstrap/peace.desktop-bootstrap").Revoke(row.sessionId,{reason:'INTEGRITY_KNOWN_MODULE_CODE_MISMATCH'},'INTEGRITY_REPORT');result=Record({...fields,status:'CLIENT_DIAGNOSTIC',modules:payload.modules,trusted:false});}else result=AcceptSnapshot(row,fields,payload); }
 if(result.status==='REJECTED'){return Complete({accepted:true,status:result.status,reportId:result.id,terminate:true});}
 return Complete({accepted:true,status:result.status,reportId:result.id,terminate:false});
}
function Execute(body){if(!Plain(body))Fail('INTEGRITY_REPORT_INVALID');if(body.action==='challenge'){requestProtocol.Purpose('report.challenge');return Challenge(body);}if(body.action==='submit'){requestProtocol.Purpose('report.submit');return Submit(body);}Fail('INTEGRITY_REPORT_INVALID');}
function List(query={}){Load();const machineId=String(query.machineId||''),sessionId=String(query.sessionId||'');if(machineId&&!/^[A-F0-9]{64}$/.test(machineId)||sessionId&&!/^[-A-Za-z0-9_]{1,100}$/.test(sessionId))Fail('INTEGRITY_REPORT_INVALID');return {items:records.filter(row=>(!machineId||row.machineId===machineId)&&(!sessionId||row.sessionId===sessionId)).slice(-100).reverse(),revision,serverTime:Date.now(),scope:'SHA-512, CRC64-ECMA, XXH3-128 and BLAKE3 comparisons cover files, executable sections and registered DLL export tables. Measurements are client-reported, not hardware attestation.',policy:Policy(),attested:false,limit:100};}
// Member projections select by exact retained flow/session identities, never a
// fingerprint-to-human heuristic. Index all retained rows before paging so a
// busy customer cannot hide another customer's reports behind the global 100.
function MemberIndex(){Load();return records.map(r=>({id:r.id,at:r.at,flowId:r.flowId||'',sessionId:r.sessionId||'',stage:r.stage,status:r.status,reason:r.reason||'',check:r.check,source:r.source,attested:false,hasMismatch:r.modules?.some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH')===true}));}
function MemberRecords(ids){Load();if(!Array.isArray(ids)||ids.length>100||new Set(ids).size!==ids.length||ids.some(id=>typeof id!=='string'||!/^[-A-Za-z0-9_]{1,100}$/.test(id)))Fail('INTEGRITY_REPORT_INVALID');const wanted=new Set(ids);return records.filter(r=>wanted.has(r.id)).map(r=>structuredClone(r));}
function CompareModule(row,hashVersion=3){
 const baseline=baselines.find(b=>b.hashVersion===3&&b.name.toLowerCase()===row.name.toLowerCase()&&b.fileSha512===row.fileSha512);
 const unverified={fileExtendedVerified:false,codeExtendedVerified:false,exportTableExtendedVerified:false,extendedHashesVerified:false};
 if(!baseline)return {...row,...unverified,serverComparison:'UNVERIFIED_BASELINE'};
 const exportComparable=baseline.exportTableStatus==='MEASURED'&&baseline.exportTableSha512&&baseline.exportTableCrc64;
 const exportMatches=!exportComparable||row.exportTableStatus===undefined||row.exportTableStatus==='MEASURED'&&row.exportTableSha512===baseline.exportTableSha512&&row.exportTableCrc64===baseline.exportTableCrc64;
 const fileExtended=ExtendedComparison(row,baseline,'file'),codeExtended=ExtendedComparison(row,baseline,'code'),exportExtended=ExtendedComparison(row,baseline,'exportTable');
 const matches=row.fileCrc64===baseline.fileCrc64&&row.codeSha512===baseline.codeSha512&&row.codeCrc64===baseline.codeCrc64&&exportMatches&&!fileExtended.mismatch&&!codeExtended.mismatch&&!exportExtended.mismatch;
 const fileExtendedVerified=hashVersion===3&&fileExtended.verified,codeExtendedVerified=hashVersion===3&&codeExtended.verified,exportTableExtendedVerified=hashVersion===3&&!!exportComparable&&row.exportTableStatus==='MEASURED'&&exportExtended.verified;
 const expected={};for(const field of EXTENDED_FIELDS)expected['expected'+field[0].toUpperCase()+field.slice(1)]=baseline[field]||'';
 return {...row,...expected,baselineId:baseline.id,serverComparison:matches?'MATCH_REGISTERED_BASELINE':'REGISTERED_BASELINE_MISMATCH',expectedCodeSha512:baseline.codeSha512,expectedCodeCrc64:baseline.codeCrc64,exportTableVerified:!!exportComparable&&row.exportTableStatus==='MEASURED'&&!!exportMatches,expectedExportTableSha512:baseline.exportTableSha512||'',expectedExportTableCrc64:baseline.exportTableCrc64||'',fileExtendedVerified,codeExtendedVerified,exportTableExtendedVerified,extendedHashesVerified:matches&&fileExtendedVerified&&codeExtendedVerified&&exportTableExtendedVerified};
}
function RegisterBaseline(name,label,bytes,actor){
 Load();if(typeof name!=='string'||name.length>64||!/^[-A-Za-z0-9_. ]{1,160}\.dll$/i.test(name)||typeof label!=='string'||label.length>120||/[\x00-\x1f\x7f]/.test(label)||!Buffer.isBuffer(bytes)||bytes.length>32*1024*1024)Fail('INTEGRITY_BASELINE_INVALID');
 const integrity=require('./peace.desktop-integrity');let code;try{const pe=bytes.length>=64?bytes.readUInt32LE(0x3c):0;if(pe<64||pe+24>bytes.length||!(bytes.readUInt16LE(pe+22)&0x2000))Fail('INTEGRITY_BASELINE_INVALID');code=integrity.CodeImage(bytes);}catch(_){Fail('INTEGRITY_BASELINE_INVALID');}const file=integrity.Digests(bytes);
 const exportTable=require("../artifacts/peace.desktop-pe-exports").ExportTable(bytes),exportFields={exportTableStatus:exportTable.status,exportTableSha512:exportTable.sha512||'',exportTableCrc64:exportTable.crc64||'',fileXxh3_128:file.xxh3_128,fileBlake3:file.blake3,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3,exportTableXxh3_128:exportTable.xxh3_128||'',exportTableBlake3:exportTable.blake3||''};
 const old=baselines.find(b=>b.name.toLowerCase()===name.toLowerCase()&&b.fileSha512===file.sha512);if(old){if(Object.entries(exportFields).every(([key,value])=>old[key]===value))return old;const previous={...old};Object.assign(old,exportFields);try{Save(records);}catch(error){for(const key of Object.keys(old))delete old[key];Object.assign(old,previous);throw error;}return old;}
 if(baselines.length>=256)Fail('INTEGRITY_BASELINE_LIMIT',409);
 const row={id:crypto.randomBytes(12).toString('hex').toUpperCase(),name,label,hashVersion:3,fileSha512:file.sha512,fileCrc64:file.crc64,codeSha512:code.sha512,codeCrc64:code.crc64,...exportFields,createdAt:Date.now(),actor:String(actor||'ADMIN').slice(0,120)};
 baselines.push(row);try{Save(records);}catch(error){baselines.pop();throw error;}return row;
}
function Baselines(){Load();return {items:baselines.slice(),revision,serverTime:Date.now()};}
function ValidatePolicy(value,stored=false){
 Keys(value,stored?['enabled','requireExtendedHashes','requiredModules','revision','updatedAt','actor']:['enabled','requireExtendedHashes','requiredModules']);
 if(value.requireExtendedHashes!==undefined&&typeof value.requireExtendedHashes!=='boolean')Fail('INTEGRITY_POLICY_INVALID');
 if(typeof value.enabled!=='boolean'||!Array.isArray(value.requiredModules)||value.requiredModules.length<1||value.requiredModules.length>16||value.requiredModules.some(name=>typeof name!=='string'||(!stored&&name.length>64)||!/^[-A-Za-z0-9_.]{1,120}\.dll$/i.test(name))||new Set(value.requiredModules.map(name=>name.toLowerCase())).size!==value.requiredModules.length)Fail('INTEGRITY_POLICY_INVALID');
 if(stored&&(!Number.isSafeInteger(value.revision)||value.revision<0||!Number.isSafeInteger(value.updatedAt)||value.updatedAt<0||typeof value.actor!=='string'||value.actor.length>160))Fail('INTEGRITY_POLICY_INVALID');
}
function BaselineReady(b,extended=false){return b.hashVersion===3&&b.exportTableStatus==='MEASURED'&&(!extended||['file','code','exportTable'].every(prefix=>HasExtendedPair(b,prefix)));}
function Policy(){Load();const unsupportedRequiredModules=policy.requiredModules.filter(name=>name.length>64),missingExtendedBaselines=policy.requiredModules.filter(name=>name.length>64||!baselines.some(b=>b.name.toLowerCase()===name.toLowerCase()&&BaselineReady(b,true))),missingBaselines=policy.requiredModules.filter(name=>name.length>64||!baselines.some(b=>b.name.toLowerCase()===name.toLowerCase()&&BaselineReady(b,policy.requireExtendedHashes)));return {...policy,requireExtendedHashes:policy.requireExtendedHashes===true,requiredModules:policy.requiredModules.slice(),baselineReady:missingBaselines.length===0,missingBaselines,missingExtendedBaselines,unsupportedRequiredModules,maxModuleNameLength:64,freshnessMs:{...FRESHNESS},snapshotAssemblyMs:SNAPSHOT_TTL,maxModules:MAX_MODULES,maxBatches:MAX_BATCHES,attested:false};}
function SetPolicy(value,actor){
 Load();ValidatePolicy(value);const requiredModules=value.requiredModules.map(name=>name.toLowerCase()),requireExtendedHashes=value.requireExtendedHashes===true;
 if(value.enabled&&requiredModules.some(name=>!baselines.some(b=>b.name.toLowerCase()===name&&BaselineReady(b,requireExtendedHashes))))Fail('INTEGRITY_POLICY_BASELINE_MISSING',409);
 const previous=policy;policy={enabled:value.enabled,requireExtendedHashes,requiredModules,revision:previous.revision+1,updatedAt:Date.now(),actor:String(actor||'ADMIN').slice(0,160)};
 try{Save(records);}catch(error){policy=previous;throw error;}
 require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_INTEGRITY_POLICY',JSON.stringify({enabled:policy.enabled,requireExtendedHashes,requiredModules,revision:policy.revision,actor:policy.actor}));return Policy();
}
function SnapshotKey(stage,context,id){return stage+':'+context+':'+id;}
function RevokeSnapshot(row,reason){require("../bootstrap/peace.desktop-bootstrap").Revoke(row.sessionId,{reason},'INTEGRITY_REPORT');}
function SnapshotConflict(row,key,reason){
 const snapshot=snapshots.get(key),required=policy.enabled||measurementPlan.Required(row.integrityArtifact)===1;snapshots.delete(key);finishedSnapshots.set(key,Date.now()+900000);if(required)RevokeSnapshot(row,reason);
 if(snapshot)Record({...snapshot.fields,check:'MODULE_SNAPSHOT',status:required?'REJECTED':'CLIENT_DIAGNOSTIC',reason,snapshotId:snapshot.snapshotId,snapshotStatus:required?'COMPLETE_REJECTED':'INCOMPLETE',snapshotFinal:true,complete:false,snapshotReasons:[reason],strictPolicyRevision:snapshot.policyRevision});
 Fail(reason,409);
}
function AcceptSnapshot(row,fields,payload){
 Load();const stage=row.stage||'B',context=row.reportContextId||row.sessionId,key=SnapshotKey(stage,context,payload.snapshotId);
 if(finishedSnapshots.has(key))Fail('INTEGRITY_SNAPSHOT_REPLAY',409);
 const metadata=JSON.stringify([payload.hashVersion,payload.batchCount,payload.complete,payload.truncated,payload.totalModules,payload.measuredModules,payload.scope||'',payload.trust||'',payload.measurementContract??null,payload.measurementPlanVersion??null,payload.measurementStartedTick??null,payload.measurementFinishedTick??null,payload.moduleGenerationStable??null,payload.moduleGenerationStatus??null,payload.threadInventory??null,payload.deviceSignals??null,payload.coverage??null]);
 let snapshot=snapshots.get(key);
 if(!snapshot){
  if(snapshots.size>=128||finishedSnapshots.size>=8192||[...snapshots.values()].filter(s=>s.context===context).length>=2)Fail('INTEGRITY_SNAPSHOT_LIMIT',429);
  snapshot={context,fields,snapshotId:payload.snapshotId,metadata,policyRevision:policy.revision,expiresAt:Date.now()+SNAPSHOT_TTL,batches:new Map(),names:new Set(),duplicateNames:new Set(),duplicateCount:0,modules:[]};snapshots.set(key,snapshot);
 }
 if(snapshot.metadata!==metadata||snapshot.batches.has(payload.batchIndex))SnapshotConflict(row,key,'INTEGRITY_SNAPSHOT_CONFLICT');
 if(snapshot.policyRevision!==policy.revision)SnapshotConflict(row,key,'INTEGRITY_SNAPSHOT_POLICY_CHANGED');
 for(const module of payload.modules){const name=module.name.toLowerCase();if(snapshot.names.has(name)){
   // Optional unloaded/long-name modules can legitimately share a diagnostic
   // placeholder. Never interpret those collisions as a proven duplicate DLL.
   if(policy.enabled&&policy.requiredModules.includes(name))SnapshotConflict(row,key,'INTEGRITY_SNAPSHOT_DUPLICATE_MODULE');
   snapshot.duplicateCount++;if(snapshot.duplicateNames.size<16)snapshot.duplicateNames.add(name);
  }snapshot.names.add(name);} 
 if(snapshot.modules.length+payload.modules.length>MAX_MODULES)SnapshotConflict(row,key,'INTEGRITY_SNAPSHOT_LIMIT');
 snapshot.modules.push(...payload.modules);snapshot.batches.set(payload.batchIndex,true);
 const final=snapshot.batches.size===payload.batchCount,base={...fields,...Object.fromEntries(['measurementContract','measurementPlanVersion','measurementStartedTick','measurementFinishedTick','moduleGenerationStable','moduleGenerationStatus','threadInventory','deviceSignals','coverage'].filter(k=>payload[k]!==undefined).map(k=>[k,payload[k]])),planAssurance:measurementPlan.Assurance(payload),requiredMeasurementPlanVersion:measurementPlan.Required(row.integrityArtifact),status:'CLIENT_DIAGNOSTIC',modules:payload.modules,snapshotId:payload.snapshotId,batchIndex:payload.batchIndex,batchCount:payload.batchCount,complete:false,truncated:payload.truncated,totalModules:payload.totalModules,measuredModules:payload.measuredModules,strictPolicyRevision:snapshot.policyRevision,snapshotReceivedBatches:snapshot.batches.size,duplicateModuleNames:[...snapshot.duplicateNames],duplicateModuleCount:snapshot.duplicateCount,trusted:false};
 if(!final)return Record({...base,snapshotStatus:'RECEIVING',snapshotReasons:[]});
 snapshots.delete(key);finishedSnapshots.set(key,Date.now()+900000);
 const reasons=[];if(measurementPlan.Required(row.integrityArtifact)&&!measurementPlan.Complete(payload))reasons.push('MEASUREMENT_PLAN_INCOMPLETE');if(payload.measurementPlanVersion!==undefined&&(!payload.moduleGenerationStable||payload.coverage==='SAMPLED'))reasons.push('MEASUREMENT_GENERATION_INCOMPLETE');if(['UNSUPPORTED','TRACKING_FAILED'].includes(payload.moduleGenerationStatus))reasons.push('MEASUREMENT_GENERATION_'+payload.moduleGenerationStatus);const moduleRows=snapshot.modules.map(module=>CompareModule(module,payload.hashVersion));if(moduleRows.some(m=>['READ_ERROR','UNSUPPORTED_EXPORT_LAYOUT'].includes(m.exportTableStatus)))reasons.push('MEASUREMENT_EXPORT_INCOMPLETE');const actualMeasured=moduleRows.filter(m=>!['READ_ERROR','UNSUPPORTED_EXPORT_LAYOUT'].includes(m.exportTableStatus)&&m.fileSha512&&m.fileCrc64&&m.codeSha512&&m.codeCrc64&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'].includes(m.status)&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'].includes(m.codeStatus)).length;
 if(!payload.complete||payload.truncated||payload.scope!=='current-process'||payload.trust!=='client-reported')reasons.push('INCOMPLETE_SNAPSHOT');
 if(snapshot.modules.length!==payload.totalModules||actualMeasured!==payload.measuredModules||payload.totalModules<1)reasons.push('INVALID_SNAPSHOT_COUNTS');
 const requiredModuleResults=policy.requiredModules.map(name=>{const module=moduleRows.find(m=>m.name.toLowerCase()===name);let reason='BASELINE_MATCH';if(!module)reason='REQUIRED_MODULE_MISSING';else if(!module.fileSha512||!module.codeSha512||['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'].includes(module.status)||['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'].includes(module.codeStatus))reason='REQUIRED_MODULE_READ_FAILED';else if(module.serverComparison==='REGISTERED_BASELINE_MISMATCH')reason='REQUIRED_MODULE_CODE_MISMATCH';else if(module.serverComparison!=='MATCH_REGISTERED_BASELINE'||!module.exportTableVerified)reason='REQUIRED_MODULE_UNVERIFIED';else if(policy.requireExtendedHashes&&!module.extendedHashesVerified)reason='REQUIRED_MODULE_EXTENDED_UNVERIFIED';if(policy.enabled&&reason!=='BASELINE_MATCH')reasons.push(reason);return {name,reason,baselineId:module?.baselineId||'',extendedHashesVerified:module?.extendedHashesVerified===true};});
 const unique=[...new Set(reasons)],accepted=unique.length===0,reject=(policy.enabled||measurementPlan.Required(row.integrityArtifact)>0)&&!accepted;
 if(reject)RevokeSnapshot(row,'INTEGRITY_'+unique[0]);
 return Record({...base,check:'MODULE_SNAPSHOT',status:reject?'REJECTED':policy.enabled&&accepted?'VERIFIED':'CLIENT_DIAGNOSTIC',reason:accepted?'BASELINE_MATCH':unique[0],complete:accepted,snapshotStatus:accepted?'COMPLETE_PASS':reject?'COMPLETE_REJECTED':'INCOMPLETE',snapshotFinal:true,snapshotReasons:unique,snapshotDiagnostics:require("../runtime/peace.desktop-snapshot-diagnostics").Summarize(payload,snapshot.modules,unique),requiredModuleResults,extendedHashesVerified:payload.hashVersion===3&&requiredModuleResults.every(item=>item.reason==='BASELINE_MATCH'&&item.extendedHashesVerified)});
}
// Called only after bootstrap authentication. A fresh complete server-assembled
// inventory is required when the administrator has explicitly armed policy.
// A signed client measurement still cannot attest an uncompromised verifier.
function RequireSnapshot(row,stage){
 Load();const db=require("../bootstrap/peace.desktop-bootstrap-store").Load(),artifact=db.artifacts[stage==='A'?db.launchers[row.launcherId]?.artifactId:row.releaseId],requiredPlan=measurementPlan.Required(artifact);if(!policy.enabled&&!requiredPlan)return;
 const candidates=observations.filter(item=>item.stage===stage&&item.sessionId===row.sessionId&&item.flowId===row.id).sort((a,b)=>b.at-a.at),last=candidates[0];
 let reason='';if(!last)reason='INTEGRITY_SNAPSHOT_REQUIRED';else if(last.strictPolicyRevision!==policy.revision)reason='INTEGRITY_SNAPSHOT_POLICY_CHANGED';else if(requiredPlan&&(last.measurementPlanVersion!==requiredPlan||last.planAssurance!=='COHERENT_PLAN_V1'||last.coverage!=='FULL'))reason='INTEGRITY_MEASUREMENT_PLAN_REQUIRED';else if(last.snapshotStatus!=='COMPLETE_PASS')reason='INTEGRITY_SNAPSHOT_REQUIRED';else if(Date.now()-last.at>FRESHNESS[stage]||last.at>Date.now()+1000)reason='INTEGRITY_SNAPSHOT_STALE';
 if(!reason)return {expiresAt:last.at+FRESHNESS[stage]};RevokeSnapshot(row,reason);Record({stage,sessionId:row.sessionId,flowId:row.id,machineId:row.machineId,check:'MODULE_POLICY',status:'REJECTED',reason,trusted:true,strictPolicyRevision:policy.revision});Fail(reason,403);
}

function RetireContext(row){const ids=new Set([row.id,row.sessionId]);for(const [id,value]of pending)if(ids.has(value.sessionId))pending.delete(id);receipts.deleteWhere((meta,response)=>ids.has(meta.context)&&!response.terminate);for(const id of ids)rates.delete(id);for(const id of snapshots.keys())if([...ids].some(value=>id.includes(':'+value+':')))snapshots.delete(id);for(const id of finishedSnapshots.keys())if([...ids].some(value=>id.includes(':'+value+':')))finishedSnapshots.delete(id);}
function InvalidateVolatile(){pending.clear();rates.clear();receipts.clear();snapshots.clear();finishedSnapshots.clear();}
// Clear observations through the existing authenticated forward write. Policy,
// authority key and rollback witnesses remain in force.
function ResetRegistrations(operationId){
 require('../operations/peace.registration-reset-stores').AssertAuthorized(operationId);Load();
 const prior=registrationResetReceipts[operationId];if(prior)return {...prior,duplicate:true};
 if(Object.keys(registrationResetReceipts).length>=1024)Fail('REGISTRATION_RESET_RECEIPT_CAPACITY',409);
 const result={at:Date.now(),revision:revision+1,records:records.length,baselines:baselines.length,observations:observations.length},previous={baselines,observations,registrationResetReceipts};
 baselines=[];observations=[];registrationResetReceipts={...registrationResetReceipts,[operationId]:result};
 try{Save([]);}catch(error){baselines=previous.baselines;observations=previous.observations;registrationResetReceipts=previous.registrationResetReceipts;throw error;}
 InvalidateVolatile();return {...result,duplicate:false};
}
function RegistrationStatus(){Load();return {records:records.length,baselines:baselines.length,observations:observations.length,revision,resetReceipts:Object.keys(registrationResetReceipts).length,policy:{...policy,requiredModules:[...policy.requiredModules]}};}
function ProofTasks(body){
 if(body.action!=='submit')return [];const challenge=pending.get(body.reportId);if(!challenge)return [];
 const row=Auth(body);return [require('./peace.desktop-proof-work').Job(row.publicKey,Canonical(row.reportContextId||row.sessionId,challenge,body.payload),body.signature)];
}
module.exports={ProofTasks,InvalidateVolatile,RetireContext,Execute,Record,List,MemberIndex,MemberRecords,Payload,Canonical,RegisterBaseline,Baselines,Policy,SetPolicy,RequireSnapshot,MAX_PAYLOAD,FILE,KEY,ResetRegistrations,RegistrationStatus};
