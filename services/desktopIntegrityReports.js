'use strict';
// Server-resident diagnostics. Signatures prove possession of the current
// session key, not truthful execution or hardware attestation on an owned PC.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),config=require('../config/config');
const DIR=path.join(config.DATA_DIR,'desktop-integrity-reports'),FILE=path.join(DIR,'reports.json'),KEY=path.join(DIR,'authority.key');
const MAX_PAYLOAD=10240,MAX_REPORTS=512,MAX_PENDING=1024,TTL=30000;
const MAX_MODULES=1024,MAX_BATCHES=128,SNAPSHOT_TTL=600000,FRESHNESS={A:180000,B:120000};
const DEFAULT_MODULES=['ntdll.dll','kernel32.dll','kernelbase.dll'];
let secret,loaded=false,revision=0,records=[],baselines=[],observations=[],pending=new Map(),rates=new Map();
let policy={enabled:false,requiredModules:DEFAULT_MODULES.slice(),revision:0,updatedAt:0,actor:''};
const snapshots=new Map(),finishedSnapshots=new Map();
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Plain(value){return value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;}
function Keys(value,allowed){if(!Plain(value)||Object.keys(value).some(key=>!allowed.includes(key)))Fail('INTEGRITY_REPORT_INVALID');}
function Digest(value,size){if(value===''||value===null||value===undefined)return '';if(typeof value!=='string'||!new RegExp('^[a-fA-F0-9]{'+size+'}$').test(value))Fail('INTEGRITY_REPORT_INVALID');return size===16?value.toUpperCase():value.toLowerCase();}
function Identifier(value){if(value===undefined||value==='')return '';if(typeof value!=='string'||!/^[-A-Za-z0-9_]{1,100}$/.test(value))Fail('INTEGRITY_REPORT_INVALID');return value;}
function Token(value){if(typeof value!=='string'||!/^[-A-Z0-9_]{1,64}$/.test(value))Fail('INTEGRITY_REPORT_INVALID');return value;}
function ReadFile(file){const st=fs.lstatSync(file);if(st.isSymbolicLink()||!st.isFile())throw Error('INTEGRITY_REPORT_STORAGE_INVALID');return fs.readFileSync(file);}
function Mac(payload){return crypto.createHmac('sha256',secret).update('GAME-INTEGRITY-REPORTS-V1\n'+JSON.stringify(payload)).digest('hex');}
function Load(){
 if(loaded)return;let created=false;fs.mkdirSync(DIR,{recursive:true,mode:0o700});
 if(!fs.existsSync(KEY)){created=true;if(fs.existsSync(FILE))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');const fd=fs.openSync(KEY,'wx',0o600);try{fs.writeFileSync(fd,crypto.randomBytes(32));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 if(!created&&!fs.existsSync(FILE))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');
 secret=ReadFile(KEY);if(secret.length!==32)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');
 if(fs.existsSync(FILE)){const envelope=JSON.parse(ReadFile(FILE));const data=envelope?.data;if(!data||data.version!==1||!Number.isSafeInteger(data.revision)||!Array.isArray(data.records)||data.records.length>MAX_REPORTS||envelope.mac!==Mac(data))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');revision=data.revision;records=data.records;observations=data.observations||[];if(!Array.isArray(observations)||observations.length>4096)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');baselines=data.baselines||[];if(!Array.isArray(baselines)||baselines.length>256)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');if(data.policy){try{ValidatePolicy(data.policy,true);}catch(_){throw Error('INTEGRITY_REPORT_STORAGE_INVALID');}policy=data.policy;}for(const row of records)if(row.snapshotFinal&&row.snapshotId)finishedSnapshots.set(SnapshotKey(row.stage,row.stage==='A'?row.flowId:row.sessionId,row.snapshotId),row.at+900000);}
 if(created)Save([]);loaded=true;
}
function Save(next){
 const data={version:1,revision:revision+1,records:next,baselines,policy,observations},tmp=FILE+'.'+crypto.randomBytes(8).toString('hex')+'.tmp',fd=fs.openSync(tmp,'wx',0o600);
 try{fs.writeFileSync(fd,JSON.stringify({data,mac:Mac(data)}));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 try{fs.renameSync(tmp,FILE);if(process.platform!=='win32'){const dir=fs.openSync(DIR,'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}}catch(error){try{fs.unlinkSync(tmp);}catch(_){}throw error;}
 revision=data.revision;records=next;
}
function Module(row){
 Keys(row,['name','status','fileSha256','fileCrc64','codeSha256','codeCrc64','codeStatus','executableSections','exportCount','codeExportCount','forwardedExportCount','exportCoverage','exportTableSha256','exportTableCrc64','exportTableStatus']);
 if(typeof row.name!=='string'||!row.name.length||row.name.length>180||/[\\/:\x00-\x1f\x7f]/.test(row.name))Fail('INTEGRITY_REPORT_INVALID');
 const allowed=['UNVERIFIED_BASELINE','LOCAL_DIFFERENCE','READ_ERROR','SKIPPED_LIMIT','FILE_UNAVAILABLE','MATCH_LOCAL_FILE','NAME_TOO_LONG'];
 if(!allowed.includes(row.status)||row.codeStatus&&!allowed.includes(row.codeStatus))Fail('INTEGRITY_REPORT_INVALID');
 const result={name:row.name,status:row.status,codeStatus:row.codeStatus||'UNVERIFIED_BASELINE',fileSha256:Digest(row.fileSha256,64),fileCrc64:Digest(row.fileCrc64,16),codeSha256:Digest(row.codeSha256,64),codeCrc64:Digest(row.codeCrc64,16)};
 for(const key of ['executableSections','exportCount','codeExportCount','forwardedExportCount'])if(row[key]!==undefined){if(!Number.isInteger(row[key])||row[key]<0||row[key]>1000000)Fail('INTEGRITY_REPORT_INVALID');result[key]=row[key];}
 if(row.exportCoverage!==undefined){if(!['SECTION_HASHED','NO_EXPORTS','INVALID_EXPORT_TABLE','NOT_MEASURED'].includes(row.exportCoverage))Fail('INTEGRITY_REPORT_INVALID');result.exportCoverage=row.exportCoverage;}if(row.exportTableStatus!==undefined){if(!['MEASURED','NO_EXPORTS','UNSUPPORTED_EXPORT_LAYOUT','READ_ERROR'].includes(row.exportTableStatus))Fail('INTEGRITY_REPORT_INVALID');result.exportTableStatus=row.exportTableStatus;result.exportTableSha256=Digest(row.exportTableSha256,64);result.exportTableCrc64=Digest(row.exportTableCrc64,16);if(row.exportTableStatus==='MEASURED'&&(!result.exportTableSha256||!result.exportTableCrc64))Fail('INTEGRITY_REPORT_INVALID');}return result;
}
function Payload(text){
 if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>MAX_PAYLOAD)Fail('INTEGRITY_REPORT_INVALID');let p;try{p=JSON.parse(text);}catch(_){Fail('INTEGRITY_REPORT_INVALID');}
 Keys(p,['version','check','reason','own','modules','snapshotId','batchIndex','batchCount','complete','truncated','totalModules','measuredModules','scope','trust']);
 if(p.version!==1||!['OWN_IMAGE','MODULE_INVENTORY'].includes(p.check))Fail('INTEGRITY_REPORT_INVALID');Token(p.reason);
 if(p.own){Keys(p.own,['codeSha256','codeCrc64','status']);if(!['MEASURED','READ_ERROR'].includes(p.own.status))Fail('INTEGRITY_REPORT_INVALID');p.own={status:p.own.status,codeSha256:Digest(p.own.codeSha256,64),codeCrc64:Digest(p.own.codeCrc64,16)};if(p.own.status==='MEASURED'&&(!p.own.codeSha256||!p.own.codeCrc64))Fail('INTEGRITY_REPORT_INVALID');}
 if(p.check==='OWN_IMAGE'&&!p.own)Fail('INTEGRITY_REPORT_INVALID');
 if(p.modules!==undefined&&(!Array.isArray(p.modules)||p.modules.length>16))Fail('INTEGRITY_REPORT_INVALID');p.modules=(p.modules||[]).map(Module);
 if(p.check==='MODULE_INVENTORY'){
  Identifier(p.snapshotId);if(!p.snapshotId||!Number.isInteger(p.batchIndex)||!Number.isInteger(p.batchCount)||p.batchCount<1||p.batchCount>MAX_BATCHES||p.batchIndex<0||p.batchIndex>=p.batchCount||typeof p.complete!=='boolean'||typeof p.truncated!=='boolean'||!Number.isInteger(p.totalModules)||p.totalModules<0||p.totalModules>65535||!Number.isInteger(p.measuredModules)||p.measuredModules<0||p.measuredModules>MAX_MODULES)Fail('INTEGRITY_REPORT_INVALID');
 }
 return p;
}
function Record(input){
 Load();if(!Plain(input)||!['A','B'].includes(input.stage)||!['VERIFIED','REJECTED','CLIENT_DIAGNOSTIC'].includes(input.status))Fail('INTEGRITY_REPORT_INVALID');
 const record={id:crypto.randomBytes(12).toString('hex').toUpperCase(),at:Date.now(),stage:input.stage,check:Token(input.check),status:input.status,reason:Token(input.reason||input.status),machineId:Identifier(input.machineId),flowId:Identifier(input.flowId),sessionId:Identifier(input.sessionId),artifactId:Identifier(input.artifactId),source:input.trusted===true?'SERVER_COMPARISON':'SIGNED_CLIENT_REPORT',attested:false,
  expectedSha256:Digest(input.expectedSha256,64),observedSha256:Digest(input.observedSha256,64),expectedCrc64:Digest(input.expectedCrc64,16),observedCrc64:Digest(input.observedCrc64,16)};
 if(input.modules){record.modules=input.modules.map(Module).map(CompareModule);if(record.modules.some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH')){record.status='REJECTED';record.reason='KNOWN_MODULE_CODE_MISMATCH';record.source='SERVER_COMPARISON';}}
 for(const key of ['snapshotId','batchIndex','batchCount','complete','truncated','totalModules','measuredModules','snapshotStatus','snapshotReceivedBatches','snapshotReasons','snapshotFinal','strictPolicyRevision','requiredModuleResults','duplicateModuleNames','duplicateModuleCount'])if(input[key]!==undefined)record[key]=input[key];
 // Repeated successes update a bounded current observation; retain rejection
 // evidence even during frequent authentication and inventory collection.
 const next=records.filter(row=>!(record.status==='VERIFIED'&&row.status==='VERIFIED'&&row.sessionId===record.sessionId&&row.stage===record.stage&&row.check===record.check));next.push(record);
 if(next.length>MAX_REPORTS){const index=next.findIndex((row,i)=>i<next.length-1&&row.status!=='REJECTED');next.splice(index>=0?index:0,1);}
 const previousObservations=observations;
 if(record.snapshotFinal){observations=observations.filter(row=>row.at>Date.now()-900000&&!(row.stage===record.stage&&row.sessionId===record.sessionId&&row.flowId===record.flowId));if(observations.length>=4096){observations=previousObservations;Fail('INTEGRITY_SNAPSHOT_LIMIT',429);}observations.push({at:record.at,stage:record.stage,sessionId:record.sessionId,flowId:record.flowId,snapshotId:record.snapshotId,snapshotStatus:record.snapshotStatus,strictPolicyRevision:record.strictPolicyRevision});}
 try{Save(next);}catch(error){observations=previousObservations;throw error;}
 if(record.status==='REJECTED')require('../storage/audit').LogEvent('DESKTOP_INTEGRITY_REJECTED',JSON.stringify({reportId:record.id,stage:record.stage,check:record.check,reason:record.reason,sessionId:record.sessionId,machineId:record.machineId}));
 return record;
}
function Auth(body){return require('./desktopBootstrap').AuthenticateIntegrityReport(body);}
const AUTH_FIELDS=['stage','action','sessionId','sessionToken','machineId','binarySha256','binaryCrc64','codeSha256','codeCrc64'];
function Prune(){const at=Date.now();for(const [id,c] of pending)if(c.expiresAt<=at)pending.delete(id);for(const [id,r] of rates)if(r.until<=at)rates.delete(id);for(const [id,until] of finishedSnapshots)if(until<=at)finishedSnapshots.delete(id);for(const [id,snapshot] of snapshots)if(snapshot.expiresAt<=at){snapshots.delete(id);finishedSnapshots.set(id,at+900000);Record({...snapshot.fields,status:'CLIENT_DIAGNOSTIC',check:'MODULE_SNAPSHOT',reason:'SNAPSHOT_TIMEOUT',snapshotId:snapshot.snapshotId,snapshotStatus:'TIMED_OUT',snapshotFinal:true,snapshotReasons:['INCOMPLETE_SNAPSHOT'],strictPolicyRevision:snapshot.policyRevision});}}
function Challenge(body){
 Keys(body,AUTH_FIELDS);const row=Auth(body),context=row.reportContextId||row.sessionId;Prune();const at=Date.now(),rate=rates.get(context)||{until:at+60000,count:0};
 if(rate.count>=128||pending.size>=MAX_PENDING||rates.size>=4096&&!rates.has(context))Fail('INTEGRITY_REPORT_RATE_LIMIT',429);rate.count++;rates.set(context,rate);
 const report={reportId:crypto.randomBytes(24).toString('hex'),nonce:crypto.randomBytes(24).toString('hex'),expiresAt:at+TTL,sessionId:context};pending.set(report.reportId,report);return {reportId:report.reportId,nonce:report.nonce,expiresAt:report.expiresAt};
}
function Canonical(sessionId,challenge,payload){return ['GAME-INTEGRITY-REPORT-V1',sessionId,challenge.reportId,challenge.nonce,String(challenge.expiresAt),sha(payload)].join('\n');}
function Submit(body){
 Keys(body,[...AUTH_FIELDS,'reportId','payload','signature']);const row=Auth(body),context=row.reportContextId||row.sessionId;Prune();const challenge=pending.get(body.reportId);
 if(!challenge||challenge.sessionId!==context)Fail('INTEGRITY_REPORT_CHALLENGE_INVALID',401);pending.delete(body.reportId);
 const payload=Payload(body.payload);if(typeof body.signature!=='string'||!/^[A-Za-z0-9+/]{342}==$/.test(body.signature))Fail('INTEGRITY_REPORT_SIGNATURE_INVALID',401);
 const bytes=Buffer.from(body.signature,'base64'),key=require('./desktopLicenses').ParseKey(row.publicKey).key;
 if(bytes.length!==256||bytes.toString('base64')!==body.signature||!crypto.verify('sha256',Buffer.from(Canonical(context,challenge,body.payload),'utf8'),{key,padding:crypto.constants.RSA_PKCS1_PADDING},bytes))Fail('INTEGRITY_REPORT_SIGNATURE_INVALID',401);
 const artifact=row.integrityArtifact;if(!artifact)Fail('INTEGRITY_REPORT_BASELINE_UNAVAILABLE',503);
 const fields={stage:row.stage||'B',machineId:row.machineId,sessionId:row.sessionId,flowId:row.id,artifactId:artifact.id,check:payload.check,reason:payload.reason};
 let result;
 if(payload.own){const own=payload.own,matches=own.status==='MEASURED'&&own.codeSha256===artifact.codeSha256&&own.codeCrc64===artifact.codeCrc64;
  if(!matches)require('./desktopBootstrap').Revoke(row.sessionId,{reason:own.status==='READ_ERROR'?'INTEGRITY_MEASUREMENT_FAILED':'INTEGRITY_CODE_HASH_MISMATCH'},'INTEGRITY_REPORT');
  result=Record({...fields,check:'OWN_CODE',status:matches?'VERIFIED':'REJECTED',reason:matches?'BASELINE_MATCH':own.status==='READ_ERROR'?'MEASUREMENT_FAILED':'CODE_HASH_MISMATCH',trusted:true,expectedSha256:artifact.codeSha256,observedSha256:own.codeSha256,expectedCrc64:artifact.codeCrc64,observedCrc64:own.codeCrc64});
  if(!matches){return {accepted:true,status:'REJECTED',reportId:result.id,terminate:true};}
 }
 if(payload.check==='MODULE_INVENTORY'){Load();if(payload.modules.map(CompareModule).some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH')){require('./desktopBootstrap').Revoke(row.sessionId,{reason:'INTEGRITY_KNOWN_MODULE_CODE_MISMATCH'},'INTEGRITY_REPORT');result=Record({...fields,status:'CLIENT_DIAGNOSTIC',modules:payload.modules,trusted:false});}else result=AcceptSnapshot(row,fields,payload); }
 if(result.status==='REJECTED'){return {accepted:true,status:result.status,reportId:result.id,terminate:true};}
 return {accepted:true,status:result.status,reportId:result.id,terminate:false};
}
function Execute(body){if(!Plain(body))Fail('INTEGRITY_REPORT_INVALID');if(body.action==='challenge')return Challenge(body);if(body.action==='submit')return Submit(body);Fail('INTEGRITY_REPORT_INVALID');}
function List(query={}){Load();const machineId=String(query.machineId||''),sessionId=String(query.sessionId||'');if(machineId&&!/^[A-F0-9]{64}$/.test(machineId)||sessionId&&!/^[-A-Za-z0-9_]{1,100}$/.test(sessionId))Fail('INTEGRITY_REPORT_INVALID');return {items:records.filter(row=>(!machineId||row.machineId===machineId)&&(!sessionId||row.sessionId===sessionId)).slice(-100).reverse(),revision,serverTime:Date.now(),scope:'Readonly executable sections, including API implementations in registered DLLs. Measurements are client-reported, not hardware attestation.',policy:Policy(),attested:false,limit:100};}
function CompareModule(row){
 const baseline=baselines.find(b=>b.name.toLowerCase()===row.name.toLowerCase()&&b.fileSha256===row.fileSha256);
 if(!baseline)return {...row,serverComparison:'UNVERIFIED_BASELINE'};
 const exportComparable=baseline.exportTableStatus==='MEASURED'&&baseline.exportTableSha256&&baseline.exportTableCrc64;
 const exportMatches=!exportComparable||row.exportTableStatus===undefined||row.exportTableStatus==='MEASURED'&&row.exportTableSha256===baseline.exportTableSha256&&row.exportTableCrc64===baseline.exportTableCrc64;
 const matches=row.fileCrc64===baseline.fileCrc64&&row.codeSha256===baseline.codeSha256&&row.codeCrc64===baseline.codeCrc64&&exportMatches;
 return {...row,baselineId:baseline.id,serverComparison:matches?'MATCH_REGISTERED_BASELINE':'REGISTERED_BASELINE_MISMATCH',expectedCodeSha256:baseline.codeSha256,expectedCodeCrc64:baseline.codeCrc64,exportTableVerified:!!exportComparable&&row.exportTableStatus==='MEASURED'&&!!exportMatches,expectedExportTableSha256:baseline.exportTableSha256||'',expectedExportTableCrc64:baseline.exportTableCrc64||''};
}
function RegisterBaseline(name,label,bytes,actor){
 Load();if(typeof name!=='string'||name.length>64||!/^[-A-Za-z0-9_. ]{1,160}\.dll$/i.test(name)||typeof label!=='string'||label.length>120||/[\x00-\x1f\x7f]/.test(label)||!Buffer.isBuffer(bytes)||bytes.length>32*1024*1024)Fail('INTEGRITY_BASELINE_INVALID');
 const integrity=require('./desktopIntegrity');let code;try{const pe=bytes.length>=64?bytes.readUInt32LE(0x3c):0;if(pe<64||pe+24>bytes.length||!(bytes.readUInt16LE(pe+22)&0x2000))Fail('INTEGRITY_BASELINE_INVALID');code=integrity.CodeImage(bytes);}catch(_){Fail('INTEGRITY_BASELINE_INVALID');}const file=integrity.Digests(bytes);
 const exportTable=require('./desktopPeExports').ExportTable(bytes),exportFields={exportTableStatus:exportTable.status,exportTableSha256:exportTable.sha256||'',exportTableCrc64:exportTable.crc64||''};
 const old=baselines.find(b=>b.name.toLowerCase()===name.toLowerCase()&&b.fileSha256===file.sha256);if(old){if(old.exportTableStatus===exportFields.exportTableStatus&&old.exportTableSha256===exportFields.exportTableSha256&&old.exportTableCrc64===exportFields.exportTableCrc64)return old;const previous={...old};Object.assign(old,exportFields);try{Save(records);}catch(error){for(const key of Object.keys(old))delete old[key];Object.assign(old,previous);throw error;}return old;}
 if(baselines.length>=256)Fail('INTEGRITY_BASELINE_LIMIT',409);
 const row={id:crypto.randomBytes(12).toString('hex').toUpperCase(),name,label,fileSha256:file.sha256,fileCrc64:file.crc64,codeSha256:code.sha256,codeCrc64:code.crc64,...exportFields,createdAt:Date.now(),actor:String(actor||'ADMIN').slice(0,120)};
 baselines.push(row);try{Save(records);}catch(error){baselines.pop();throw error;}return row;
}
function Baselines(){Load();return {items:baselines.slice(),revision,serverTime:Date.now()};}
function ValidatePolicy(value,stored=false){
 Keys(value,stored?['enabled','requiredModules','revision','updatedAt','actor']:['enabled','requiredModules']);
 if(typeof value.enabled!=='boolean'||!Array.isArray(value.requiredModules)||value.requiredModules.length<1||value.requiredModules.length>16||value.requiredModules.some(name=>typeof name!=='string'||(!stored&&name.length>64)||!/^[-A-Za-z0-9_.]{1,120}\.dll$/i.test(name))||new Set(value.requiredModules.map(name=>name.toLowerCase())).size!==value.requiredModules.length)Fail('INTEGRITY_POLICY_INVALID');
 if(stored&&(!Number.isSafeInteger(value.revision)||value.revision<0||!Number.isSafeInteger(value.updatedAt)||value.updatedAt<0||typeof value.actor!=='string'||value.actor.length>160))Fail('INTEGRITY_POLICY_INVALID');
}
function Policy(){Load();const unsupportedRequiredModules=policy.requiredModules.filter(name=>name.length>64),missingBaselines=policy.requiredModules.filter(name=>name.length>64||!baselines.some(b=>b.name.toLowerCase()===name&&b.exportTableStatus==='MEASURED'));return {...policy,requiredModules:policy.requiredModules.slice(),baselineReady:missingBaselines.length===0,missingBaselines,unsupportedRequiredModules,maxModuleNameLength:64,freshnessMs:{...FRESHNESS},snapshotAssemblyMs:SNAPSHOT_TTL,maxModules:MAX_MODULES,maxBatches:MAX_BATCHES,attested:false};}
function SetPolicy(value,actor){
 Load();ValidatePolicy(value);const requiredModules=value.requiredModules.map(name=>name.toLowerCase());
 if(value.enabled&&requiredModules.some(name=>!baselines.some(b=>b.name.toLowerCase()===name&&b.exportTableStatus==='MEASURED')))Fail('INTEGRITY_POLICY_BASELINE_MISSING',409);
 const previous=policy;policy={enabled:value.enabled,requiredModules,revision:previous.revision+1,updatedAt:Date.now(),actor:String(actor||'ADMIN').slice(0,160)};
 try{Save(records);}catch(error){policy=previous;throw error;}
 require('../storage/audit').LogEvent('DESKTOP_INTEGRITY_POLICY',JSON.stringify({enabled:policy.enabled,requiredModules,revision:policy.revision,actor:policy.actor}));return Policy();
}
function SnapshotKey(stage,context,id){return stage+':'+context+':'+id;}
function RevokeSnapshot(row,reason){require('./desktopBootstrap').Revoke(row.sessionId,{reason},'INTEGRITY_REPORT');}
function SnapshotConflict(row,key,reason){
 const snapshot=snapshots.get(key);snapshots.delete(key);finishedSnapshots.set(key,Date.now()+900000);if(policy.enabled)RevokeSnapshot(row,reason);
 if(snapshot)Record({...snapshot.fields,check:'MODULE_SNAPSHOT',status:policy.enabled?'REJECTED':'CLIENT_DIAGNOSTIC',reason,snapshotId:snapshot.snapshotId,snapshotStatus:policy.enabled?'COMPLETE_REJECTED':'INCOMPLETE',snapshotFinal:true,complete:false,snapshotReasons:[reason],strictPolicyRevision:snapshot.policyRevision});
 Fail(reason,409);
}
function AcceptSnapshot(row,fields,payload){
 Load();const stage=row.stage||'B',context=row.reportContextId||row.sessionId,key=SnapshotKey(stage,context,payload.snapshotId);
 if(finishedSnapshots.has(key))Fail('INTEGRITY_SNAPSHOT_REPLAY',409);
 const metadata=JSON.stringify([payload.batchCount,payload.complete,payload.truncated,payload.totalModules,payload.measuredModules,payload.scope||'',payload.trust||'']);
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
 const final=snapshot.batches.size===payload.batchCount,base={...fields,status:'CLIENT_DIAGNOSTIC',modules:payload.modules,snapshotId:payload.snapshotId,batchIndex:payload.batchIndex,batchCount:payload.batchCount,complete:false,truncated:payload.truncated,totalModules:payload.totalModules,measuredModules:payload.measuredModules,strictPolicyRevision:snapshot.policyRevision,snapshotReceivedBatches:snapshot.batches.size,duplicateModuleNames:[...snapshot.duplicateNames],duplicateModuleCount:snapshot.duplicateCount,trusted:false};
 if(!final)return Record({...base,snapshotStatus:'RECEIVING',snapshotReasons:[]});
 snapshots.delete(key);finishedSnapshots.set(key,Date.now()+900000);
 const reasons=[],moduleRows=snapshot.modules.map(CompareModule),actualMeasured=moduleRows.filter(m=>m.fileSha256&&m.fileCrc64&&m.codeSha256&&m.codeCrc64&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(m.status)&&!['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(m.codeStatus)).length;
 if(!payload.complete||payload.truncated||payload.scope!=='current-process'||payload.trust!=='client-reported')reasons.push('INCOMPLETE_SNAPSHOT');
 if(snapshot.modules.length!==payload.totalModules||actualMeasured!==payload.measuredModules||payload.totalModules<1)reasons.push('INVALID_SNAPSHOT_COUNTS');
 const requiredModuleResults=policy.requiredModules.map(name=>{const module=moduleRows.find(m=>m.name.toLowerCase()===name);let reason='BASELINE_MATCH';if(!module)reason='REQUIRED_MODULE_MISSING';else if(!module.fileSha256||!module.codeSha256||['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(module.status)||['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG'].includes(module.codeStatus))reason='REQUIRED_MODULE_READ_FAILED';else if(module.serverComparison==='REGISTERED_BASELINE_MISMATCH')reason='REQUIRED_MODULE_CODE_MISMATCH';else if(module.serverComparison!=='MATCH_REGISTERED_BASELINE'||!module.exportTableVerified)reason='REQUIRED_MODULE_UNVERIFIED';if(policy.enabled&&reason!=='BASELINE_MATCH')reasons.push(reason);return {name,reason,baselineId:module?.baselineId||''};});
 const unique=[...new Set(reasons)],accepted=unique.length===0,reject=policy.enabled&&!accepted;
 if(reject)RevokeSnapshot(row,'INTEGRITY_'+unique[0]);
 return Record({...base,check:'MODULE_SNAPSHOT',status:reject?'REJECTED':policy.enabled&&accepted?'VERIFIED':'CLIENT_DIAGNOSTIC',reason:accepted?'BASELINE_MATCH':unique[0],complete:accepted,snapshotStatus:accepted?'COMPLETE_PASS':policy.enabled?'COMPLETE_REJECTED':'INCOMPLETE',snapshotFinal:true,snapshotReasons:unique,requiredModuleResults});
}
// Called only after bootstrap authentication. A fresh complete server-assembled
// inventory is required when the administrator has explicitly armed policy.
// A signed client measurement still cannot attest an uncompromised verifier.
function RequireSnapshot(row,stage){
 Load();if(!policy.enabled)return;
 const candidates=observations.filter(item=>item.stage===stage&&item.sessionId===row.sessionId&&item.flowId===row.id).sort((a,b)=>b.at-a.at),last=candidates[0];
 let reason='';if(!last)reason='INTEGRITY_SNAPSHOT_REQUIRED';else if(last.strictPolicyRevision!==policy.revision)reason='INTEGRITY_SNAPSHOT_POLICY_CHANGED';else if(last.snapshotStatus!=='COMPLETE_PASS')reason='INTEGRITY_SNAPSHOT_REQUIRED';else if(Date.now()-last.at>FRESHNESS[stage]||last.at>Date.now()+1000)reason='INTEGRITY_SNAPSHOT_STALE';
 if(!reason)return;RevokeSnapshot(row,reason);Record({stage,sessionId:row.sessionId,flowId:row.id,machineId:row.machineId,check:'MODULE_POLICY',status:'REJECTED',reason,trusted:true,strictPolicyRevision:policy.revision});Fail(reason,403);
}

module.exports={Execute,Record,List,Payload,Canonical,RegisterBaseline,Baselines,Policy,SetPolicy,RequireSnapshot,MAX_PAYLOAD,FILE,KEY};
