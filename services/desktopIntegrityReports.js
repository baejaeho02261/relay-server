'use strict';
// Server-resident diagnostics. Signatures prove possession of the current
// session key, not truthful execution or hardware attestation on an owned PC.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),config=require('../config/config');
const DIR=path.join(config.DATA_DIR,'desktop-integrity-reports'),FILE=path.join(DIR,'reports.json'),KEY=path.join(DIR,'authority.key');
const MAX_PAYLOAD=10240,MAX_REPORTS=512,MAX_PENDING=1024,TTL=30000;
let secret,loaded=false,revision=0,records=[],baselines=[],pending=new Map(),rates=new Map();
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
 if(fs.existsSync(FILE)){const envelope=JSON.parse(ReadFile(FILE));const data=envelope?.data;if(!data||data.version!==1||!Number.isSafeInteger(data.revision)||!Array.isArray(data.records)||data.records.length>MAX_REPORTS||envelope.mac!==Mac(data))throw Error('INTEGRITY_REPORT_STORAGE_INVALID');revision=data.revision;records=data.records;baselines=data.baselines||[];if(!Array.isArray(baselines)||baselines.length>256)throw Error('INTEGRITY_REPORT_STORAGE_INVALID');}
 if(created)Save([]);loaded=true;
}
function Save(next){
 const data={version:1,revision:revision+1,records:next,baselines},tmp=FILE+'.'+crypto.randomBytes(8).toString('hex')+'.tmp',fd=fs.openSync(tmp,'wx',0o600);
 try{fs.writeFileSync(fd,JSON.stringify({data,mac:Mac(data)}));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 try{fs.renameSync(tmp,FILE);if(process.platform!=='win32'){const dir=fs.openSync(DIR,'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}}catch(error){try{fs.unlinkSync(tmp);}catch(_){}throw error;}
 revision=data.revision;records=next;
}
function Module(row){
 Keys(row,['name','status','fileSha256','fileCrc64','codeSha256','codeCrc64','codeStatus']);
 if(typeof row.name!=='string'||!row.name.length||row.name.length>180||/[\\/:\x00-\x1f\x7f]/.test(row.name))Fail('INTEGRITY_REPORT_INVALID');
 const allowed=['UNVERIFIED_BASELINE','LOCAL_DIFFERENCE','READ_ERROR','SKIPPED_LIMIT','FILE_UNAVAILABLE','MATCH_LOCAL_FILE'];
 if(!allowed.includes(row.status)||row.codeStatus&&!allowed.includes(row.codeStatus))Fail('INTEGRITY_REPORT_INVALID');
 return {name:row.name,status:row.status,codeStatus:row.codeStatus||'UNVERIFIED_BASELINE',fileSha256:Digest(row.fileSha256,64),fileCrc64:Digest(row.fileCrc64,16),codeSha256:Digest(row.codeSha256,64),codeCrc64:Digest(row.codeCrc64,16)};
}
function Payload(text){
 if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>MAX_PAYLOAD)Fail('INTEGRITY_REPORT_INVALID');let p;try{p=JSON.parse(text);}catch(_){Fail('INTEGRITY_REPORT_INVALID');}
 Keys(p,['version','check','reason','own','modules','snapshotId','batchIndex','batchCount','complete','truncated','totalModules','measuredModules','scope','trust']);
 if(p.version!==1||!['OWN_IMAGE','MODULE_INVENTORY'].includes(p.check))Fail('INTEGRITY_REPORT_INVALID');Token(p.reason);
 if(p.own){Keys(p.own,['codeSha256','codeCrc64','status']);if(!['MEASURED','READ_ERROR'].includes(p.own.status))Fail('INTEGRITY_REPORT_INVALID');p.own={status:p.own.status,codeSha256:Digest(p.own.codeSha256,64),codeCrc64:Digest(p.own.codeCrc64,16)};if(p.own.status==='MEASURED'&&(!p.own.codeSha256||!p.own.codeCrc64))Fail('INTEGRITY_REPORT_INVALID');}
 if(p.check==='OWN_IMAGE'&&!p.own)Fail('INTEGRITY_REPORT_INVALID');
 if(p.modules!==undefined&&(!Array.isArray(p.modules)||p.modules.length>16))Fail('INTEGRITY_REPORT_INVALID');p.modules=(p.modules||[]).map(Module);
 if(p.check==='MODULE_INVENTORY'){
  Identifier(p.snapshotId);if(!p.snapshotId||!Number.isInteger(p.batchIndex)||!Number.isInteger(p.batchCount)||p.batchCount<1||p.batchCount>16||p.batchIndex<0||p.batchIndex>=p.batchCount||typeof p.complete!=='boolean'||typeof p.truncated!=='boolean'||!Number.isInteger(p.totalModules)||p.totalModules<0||p.totalModules>65535||!Number.isInteger(p.measuredModules)||p.measuredModules<0||p.measuredModules>256)Fail('INTEGRITY_REPORT_INVALID');
 }
 return p;
}
function Record(input){
 Load();if(!Plain(input)||!['A','B'].includes(input.stage)||!['VERIFIED','REJECTED','CLIENT_DIAGNOSTIC'].includes(input.status))Fail('INTEGRITY_REPORT_INVALID');
 const record={id:crypto.randomBytes(12).toString('hex').toUpperCase(),at:Date.now(),stage:input.stage,check:Token(input.check),status:input.status,reason:Token(input.reason||input.status),machineId:Identifier(input.machineId),flowId:Identifier(input.flowId),sessionId:Identifier(input.sessionId),artifactId:Identifier(input.artifactId),source:input.trusted===true?'SERVER_COMPARISON':'SIGNED_CLIENT_REPORT',attested:false,
  expectedSha256:Digest(input.expectedSha256,64),observedSha256:Digest(input.observedSha256,64),expectedCrc64:Digest(input.expectedCrc64,16),observedCrc64:Digest(input.observedCrc64,16)};
 if(input.modules){record.modules=input.modules.map(Module).map(CompareModule);if(record.modules.some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH')){record.status='REJECTED';record.reason='KNOWN_MODULE_CODE_MISMATCH';record.source='SERVER_COMPARISON';}}
 for(const key of ['snapshotId','batchIndex','batchCount','complete','truncated','totalModules','measuredModules'])if(input[key]!==undefined)record[key]=input[key];
 // Repeated successes update a bounded current observation; retain rejection
 // evidence even during frequent authentication and inventory collection.
 const next=records.filter(row=>!(record.status==='VERIFIED'&&row.status==='VERIFIED'&&row.sessionId===record.sessionId&&row.stage===record.stage&&row.check===record.check));next.push(record);
 if(next.length>MAX_REPORTS){const index=next.findIndex((row,i)=>i<next.length-1&&row.status!=='REJECTED');next.splice(index>=0?index:0,1);}Save(next);
 if(record.status==='REJECTED')require('../storage/audit').LogEvent('DESKTOP_INTEGRITY_REJECTED',JSON.stringify({reportId:record.id,stage:record.stage,check:record.check,reason:record.reason,sessionId:record.sessionId,machineId:record.machineId}));
 return record;
}
function Auth(body){return require('./desktopBootstrap').AuthenticateIntegrityReport(body);}
const AUTH_FIELDS=['stage','action','sessionId','sessionToken','machineId','binarySha256','binaryCrc64','codeSha256','codeCrc64'];
function Prune(){const at=Date.now();for(const [id,c] of pending)if(c.expiresAt<=at)pending.delete(id);for(const [id,r] of rates)if(r.until<=at)rates.delete(id);}
function Challenge(body){
 Keys(body,AUTH_FIELDS);const row=Auth(body),context=row.reportContextId||row.sessionId;Prune();const at=Date.now(),rate=rates.get(context)||{until:at+60000,count:0};
 if(rate.count>=24||pending.size>=MAX_PENDING||rates.size>=4096&&!rates.has(context))Fail('INTEGRITY_REPORT_RATE_LIMIT',429);rate.count++;rates.set(context,rate);
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
 if(payload.check==='MODULE_INVENTORY'){Load();if(payload.modules.map(CompareModule).some(m=>m.serverComparison==='REGISTERED_BASELINE_MISMATCH'))require('./desktopBootstrap').Revoke(row.sessionId,{reason:'INTEGRITY_KNOWN_MODULE_CODE_MISMATCH'},'INTEGRITY_REPORT');result=Record({...fields,status:'CLIENT_DIAGNOSTIC',modules:payload.modules,snapshotId:payload.snapshotId,batchIndex:payload.batchIndex,batchCount:payload.batchCount,complete:payload.complete,truncated:payload.truncated,totalModules:payload.totalModules,measuredModules:payload.measuredModules,trusted:false});}
 if(result.status==='REJECTED'){return {accepted:true,status:result.status,reportId:result.id,terminate:true};}
 return {accepted:true,status:result.status,reportId:result.id,terminate:false};
}
function Execute(body){if(!Plain(body))Fail('INTEGRITY_REPORT_INVALID');if(body.action==='challenge')return Challenge(body);if(body.action==='submit')return Submit(body);Fail('INTEGRITY_REPORT_INVALID');}
function List(query={}){Load();const machineId=String(query.machineId||''),sessionId=String(query.sessionId||'');if(machineId&&!/^[A-F0-9]{64}$/.test(machineId)||sessionId&&!/^[-A-Za-z0-9_]{1,100}$/.test(sessionId))Fail('INTEGRITY_REPORT_INVALID');return {items:records.filter(row=>(!machineId||row.machineId===machineId)&&(!sessionId||row.sessionId===sessionId)).slice(-100).reverse(),revision,serverTime:Date.now(),scope:'Own immutable executable sections and registered file digests; module inventory is client-reported, without a trusted OS baseline.',attested:false,limit:100};}
function CompareModule(row){
 const baseline=baselines.find(b=>b.name.toLowerCase()===row.name.toLowerCase()&&b.fileSha256===row.fileSha256);
 if(!baseline)return {...row,serverComparison:'UNVERIFIED_BASELINE'};
 const matches=row.fileCrc64===baseline.fileCrc64&&row.codeSha256===baseline.codeSha256&&row.codeCrc64===baseline.codeCrc64;
 return {...row,baselineId:baseline.id,serverComparison:matches?'MATCH_REGISTERED_BASELINE':'REGISTERED_BASELINE_MISMATCH',expectedCodeSha256:baseline.codeSha256,expectedCodeCrc64:baseline.codeCrc64};
}
function RegisterBaseline(name,label,bytes,actor){
 Load();if(typeof name!=='string'||!/^[-A-Za-z0-9_. ]{1,160}\.dll$/i.test(name)||typeof label!=='string'||label.length>120||/[\x00-\x1f\x7f]/.test(label)||!Buffer.isBuffer(bytes)||bytes.length>32*1024*1024)Fail('INTEGRITY_BASELINE_INVALID');
 const integrity=require('./desktopIntegrity');let code;try{const pe=bytes.length>=64?bytes.readUInt32LE(0x3c):0;if(pe<64||pe+24>bytes.length||!(bytes.readUInt16LE(pe+22)&0x2000))Fail('INTEGRITY_BASELINE_INVALID');code=integrity.CodeImage(bytes);}catch(_){Fail('INTEGRITY_BASELINE_INVALID');}const file=integrity.Digests(bytes);
 const old=baselines.find(b=>b.name.toLowerCase()===name.toLowerCase()&&b.fileSha256===file.sha256);if(old)return old;
 if(baselines.length>=256)Fail('INTEGRITY_BASELINE_LIMIT',409);
 const row={id:crypto.randomBytes(12).toString('hex').toUpperCase(),name,label,fileSha256:file.sha256,fileCrc64:file.crc64,codeSha256:code.sha256,codeCrc64:code.crc64,createdAt:Date.now(),actor:String(actor||'ADMIN').slice(0,120)};
 baselines.push(row);try{Save(records);}catch(error){baselines.pop();throw error;}return row;
}
function Baselines(){Load();return {items:baselines.slice(),revision,serverTime:Date.now()};}
module.exports={Execute,Record,List,Payload,Canonical,RegisterBaseline,Baselines,MAX_PAYLOAD,FILE,KEY};
