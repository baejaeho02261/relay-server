'use strict';
// Actual signed report handler/storage tests plus explicitly labelled planning
// models and native source contracts. No Delphi/Windows execution is claimed.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-overlay-inventory-'));
process.env.DATA_DIR=temporary;process.env.HA_ENABLED='0';
const {Isolated}=require('../fixtures/protocol/peace.completion-6-10-fixture');
const {ReadContractFile}=require('../fixtures/source/peace.native-string-contract');
const plan=require('../../services/integrity/peace.measurement-plan-contract');
const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const publicKey=require('../../services/network/peace.connect-transport-key').PublicBlob(keys.publicKey).toString('base64');
const artifact={id:'OVERLAY_ARTIFACT',measurementPlanVersion:1};
const row={id:'OVERLAY_FLOW',sessionId:'OVERLAY_SESSION',reportContextId:'OVERLAY_SESSION',releaseId:artifact.id,stage:'O',machineId:'A'.repeat(64),publicKey,integrityArtifact:artifact};
const revoked=[];
const reports=Isolated('services/integrity/peace.desktop-integrity-reports.js',[],{
 '../bootstrap/peace.desktop-bootstrap':{AuthenticateIntegrityReport:()=>row,AuthenticateIntegrityReceipt:()=>row,Revoke:(_id,b)=>revoked.push(b.reason)},
 '../bootstrap/peace.desktop-bootstrap-store':{Load:()=>({artifacts:{[artifact.id]:artifact},launchers:{}})},
 '../security/peace.desktop-security-authority':{Policy:()=>({revision:1}),UsesAuthority:()=>false},
 '../security/peace.desktop-security-operations':{Revision:()=>1},
 '../../storage/audit/peace.audit.js':{LogEvent(){}}
});
let count=0;function check(name,fn){fn();count++;console.log('PASS '+name);}
function moduleRow(i,name='module-'+i+'.dll'){return {name,status:'UNVERIFIED_BASELINE',codeStatus:'MATCH_LOCAL_FILE',fileSha512:'a'.repeat(128),fileCrc64:'A'.repeat(16),fileXxh3_128:'b'.repeat(32),fileBlake3:'c'.repeat(64),codeSha512:'d'.repeat(128),codeCrc64:'D'.repeat(16),codeXxh3_128:'e'.repeat(32),codeBlake3:'f'.repeat(64),exportTableStatus:'MEASURED',exportCoverage:'SECTION_HASHED',exportTableSha512:'1'.repeat(128),exportTableCrc64:'1'.repeat(16),exportTableXxh3_128:'2'.repeat(32),exportTableBlake3:'3'.repeat(64),executableSections:3,exportCount:1000,codeExportCount:900,forwardedExportCount:100,failurePhase:0};}
const rows=Array.from({length:87},(_,i)=>moduleRow(i));
function metadata(all,snapshotId=crypto.randomUUID()){return {version:1,check:'MODULE_INVENTORY',reason:'PERIODIC',snapshotId,complete:true,truncated:false,totalModules:all.length,measuredModules:all.length,scope:'current-process',trust:'client-reported',measurementContract:plan.CONTRACT,measurementPlanVersion:1,measurementStartedTick:10000,measurementFinishedTick:39999,moduleGenerationStable:true,moduleGenerationStatus:'TRACKED_STABLE',coverage:'FULL'};}
function envelope(text,reportId='X'.repeat(160),signature='X'.repeat(1024)){return {operation:'report',tlsPinVersion:1,body:{stage:'O',sessionId:row.sessionId,sessionToken:'TOKEN',machineId:row.machineId,action:'submit',reportId,signature,payload:text}};}
const bytes=x=>Buffer.byteLength(JSON.stringify(x));
function packing(all,meta){
 const empty={...meta,batchIndex:255,batchCount:256,hashVersion:3,modules:[]};
 const payloadBytes=bytes(empty),escapedBytes=bytes(JSON.stringify(empty)),overhead=bytes(envelope(''))-2;
 const largest=Math.max(0,...all.map(bytes)),escapedLargest=Math.max(0,...all.map(v=>bytes(JSON.stringify(v))-2));
 let size=16;
 while(size>0&&(payloadBytes+(largest+1)*size>24576||overhead+escapedBytes+(escapedLargest+1)*size>32768))size--;
 if(size<1)throw Error('NO_ROW_FITS');
 const count=Math.max(1,Math.ceil(all.length/size));if(count>256)throw Error('TOO_MANY_BATCHES');
 return {size,count,batches:Array.from({length:count},(_,index)=>({...meta,batchIndex:index,batchCount:count,hashVersion:3,modules:all.slice(index*size,(index+1)*size)}))};
}
function submit(payload){
 const common={stage:'O',sessionId:row.sessionId,sessionToken:'TOKEN',machineId:row.machineId};
 const challenge=reports.Execute({...common,action:'challenge'}),text=JSON.stringify(payload);
 const signature=crypto.sign('sha256',Buffer.from(reports.Canonical(row.reportContextId,challenge,text)),keys.privateKey).toString('base64');
 const request={...common,action:'submit',reportId:challenge.reportId,payload:text,signature};
 return {request,response:reports.Execute(request)};
}
try{
 check('real signed O handler assembles 87 complete modules in six bounded batches',()=>{
  const packed=packing(rows,metadata(rows));assert.equal(packed.size,16);assert.equal(packed.count,6);
  let result;
  for(const [index,batch]of packed.batches.entries()){
   assert.ok(bytes(batch)<=24576);assert.ok(bytes(envelope(JSON.stringify(batch)))<=32768);
   result=submit(batch);assert.equal(result.response.terminate,false);
   if(index<packed.count-1){assert.equal(result.response.snapshotBudget,undefined);assert.throws(()=>reports.RequireSnapshot(row,'O'),/INTEGRITY_SNAPSHOT_REQUIRED/);}
  }
  assert.equal(result.response.snapshotBudget.snapshotId,packed.batches[0].snapshotId);
  assert.deepEqual(reports.RequireSnapshot(row,'O'),{expiresAt:result.response.snapshotBudget.expiresAt});
  const revision=reports.List().revision;assert.deepEqual(reports.Execute(result.request),result.response);assert.equal(reports.List().revision,revision);
  const record=reports.List({sessionId:row.sessionId}).items.find(x=>x.snapshotFinal&&x.snapshotId===packed.batches[0].snapshotId);
  assert.equal(record.totalModules,87);assert.equal(record.measuredModules,87);assert.equal(record.attested,false);
 });
 check('real payload parser accepts Unicode and quote names within both byte limits',()=>{
  const unusual=Array.from({length:70},(_,i)=>moduleRow(i,'한글표지"'.repeat(34)+i+'.dll'));
  const packed=packing(unusual,metadata(unusual));
  for(const batch of packed.batches){assert.ok(bytes(batch)<=24576);assert.ok(bytes(envelope(JSON.stringify(batch)))<=32768);assert.equal(reports.Payload(JSON.stringify(batch)).modules.length,batch.modules.length);}
  assert.ok(packed.size<16);assert.deepEqual(packed.batches.flatMap(x=>x.modules),unusual);
 });
 check('packing model rejects an impossible row without submitting a partial snapshot',()=>{
  assert.throws(()=>packing([{...moduleRow(0),name:'x'.repeat(40000)}],metadata([0])),/NO_ROW_FITS/);
 });
 check('real server does not allow a seventeenth module or mixed generation metadata',()=>{
  assert.throws(()=>reports.Payload(JSON.stringify({...metadata(rows),hashVersion:3,batchIndex:0,batchCount:6,modules:rows.slice(0,17)})),/INTEGRITY_REPORT_INVALID/);
  const packed=packing(rows,metadata(rows));submit(packed.batches[0]);
  assert.throws(()=>submit({...packed.batches[1],measurementFinishedTick:40000}),/INTEGRITY_SNAPSHOT_CONFLICT/);
 });
 check('exhausted loader race stays PARTIAL and real server rejects it',()=>{
  const one=[moduleRow(0)];const partial={...metadata(one),hashVersion:3,batchIndex:0,batchCount:1,complete:false,moduleGenerationStable:false,moduleGenerationStatus:'TRACKED_CHANGED',coverage:'PARTIAL',modules:one};
  const r=submit(partial).response;assert.equal(r.terminate,true);assert.equal(r.snapshotBudget,undefined);
  assert.throws(()=>reports.RequireSnapshot(row,'O'),/INTEGRITY_MEASUREMENT_PLAN_REQUIRED|INTEGRITY_SNAPSHOT_REQUIRED/);
 });
 check('planning model: six-row startup can exceed the unchanged 90-second bound',()=>{
  // Explicit network/collection model, not an observed client benchmark.
  const initialWork=40000,perBatch=4000,deadline=90000;
  assert.ok(initialWork+Math.ceil(rows.length/6)*perBatch>=deadline);
  assert.ok(initialWork+packing(rows,metadata(rows)).count*perBatch<deadline);
 });
 check('source contract: O budgets actual metadata, escaped envelope and largest row',()=>{
  const src=ReadContractFile(path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas'),'utf8');
  for(const needle of ['CreateModulePayload(255, 256)','SubmitOverhead := SubmitOverheadBytes','LargestEncodedModuleBytes','BatchSize := 16','Batch.Count < BatchSize','if BatchSize < 1 then InvalidResponse','if BatchCount > 256 then InvalidResponse'])assert.ok(src.includes(needle),needle);
  assert.doesNotMatch(src,/BatchCount := \(Total \+ 5\) div 6|Batch.Count < 6/);
 });
 check('source contract: retry is whole-snapshot bounded and uses existing strict classifier',()=>{
  const src=ReadContractFile(path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas'),'utf8');
  const scan=src.slice(src.indexOf('  CollectionStarted := CozyTick;'),src.indexOf('    Modules := Snapshot.GetValue',src.indexOf('  CollectionStarted := CozyTick;')));
  for(const needle of ['ModuleInventoryGenerationRetryable(Snapshot)','GenerationRetries >= 2','CollectionNow - CollectionStarted >= 90000','FreeAndNil(Snapshot)','Assigned(Cancelled) and Cancelled()'])assert.ok(scan.includes(needle),needle);
  assert.doesNotMatch(scan,/Send\(|AddPair\(/);
  const worker=ReadContractFile(path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas'),'utf8');
  assert.match(worker,/FInitialDeadline := CozyTick \+ 90000/);
 });
 console.log('PASS '+count+' overlay inventory checks; Delphi/Windows runtime NOT_RUN');
}finally{fs.rmSync(temporary,{recursive:true,force:true});}
