'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-measurement-6-10-'));process.env.DATA_DIR=temp;process.env.HA_ENABLED='0';
const {Isolated,PE}=require("../fixtures/protocol/peace.completion-6-10-fixture"),contract=require("../../services/integrity/peace.measurement-plan-contract"),work=require("../../services/runtime/peace.desktop-work-queue");
let n=0;async function check(name,fn){await fn();n++;console.log('PASS '+name);}
const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),publicKey=require("../../services/network/peace.connect-transport-key").PublicBlob(keys.publicKey).toString('base64');
const artifact={id:'TEST_ARTIFACT',measurementPlanVersion:1},row={id:'TEST_FLOW',sessionId:'TEST_SESSION',reportContextId:'TEST_SESSION',releaseId:artifact.id,stage:'B',machineId:'A'.repeat(64),publicKey,integrityArtifact:artifact},revoked=[];
const reports=Isolated("services/integrity/peace.desktop-integrity-reports.js",['observations:()=>observations'],{"../bootstrap/peace.desktop-bootstrap":{AuthenticateIntegrityReport:()=>row,AuthenticateIntegrityReceipt:()=>row,Revoke:(_s,b)=>revoked.push(b.reason)},"../bootstrap/peace.desktop-bootstrap-store":{Load:()=>({artifacts:{[artifact.id]:artifact},launchers:{}})},"../security/peace.desktop-security-authority":{Policy:()=>({revision:1}),UsesAuthority:()=>false},"../security/peace.desktop-security-operations":{Revision:()=>1},"../../storage/audit/peace.audit.js":{LogEvent:()=>{}}});
const moduleRow=(name='sample.dll')=>({name,status:'UNVERIFIED_BASELINE',codeStatus:'UNVERIFIED_BASELINE',fileSha512:'a'.repeat(128),fileCrc64:'B'.repeat(16),codeSha512:'c'.repeat(128),codeCrc64:'D'.repeat(16),fileXxh3_128:'e'.repeat(32),fileBlake3:'f'.repeat(64),codeXxh3_128:'1'.repeat(32),codeBlake3:'2'.repeat(64)});
function payload(changes={}){return {version:1,hashVersion:3,check:'MODULE_INVENTORY',reason:'PERIODIC',snapshotId:crypto.randomUUID(),batchIndex:0,batchCount:1,complete:true,truncated:false,totalModules:1,measuredModules:1,scope:'current-process',trust:'client-reported',measurementContract:contract.CONTRACT,measurementPlanVersion:1,measurementStartedTick:10000,measurementFinishedTick:10100,moduleGenerationStable:true,coverage:'FULL',modules:[moduleRow()],...changes};}
const common={stage:'B',sessionId:row.sessionId,sessionToken:'TEST_TOKEN',machineId:row.machineId};
function request(data){const challenge=reports.Execute({...common,action:'challenge'}),text=JSON.stringify(data),signature=crypto.sign('sha256',Buffer.from(reports.Canonical(row.reportContextId,challenge,text)),keys.privateKey).toString('base64');return {...common,action:'submit',reportId:challenge.reportId,payload:text,signature};}
function submit(data){return reports.Execute(request(data));}
(async()=>{try{
 await check('approved initialized section declares plan; tail overlay alone never enables it',()=>{assert.equal(contract.ArtifactVersion(PE()),1);const plain=require("../fixtures/bootstrap/peace.desktop-bootstrap-fixture").PE('A','no-capability');assert.equal(contract.ArtifactVersion(plain),0);assert.equal(contract.ArtifactVersion(Buffer.concat([plain,Buffer.from(contract.CONTRACT)])),0);const utf=Buffer.from(plain);Buffer.from(contract.CONTRACT,'utf16le').copy(utf,600);assert.equal(contract.ArtifactVersion(utf),1);assert.throws(()=>contract.ArtifactVersion(Buffer.alloc(512)),/BOOTSTRAP_PE_INVALID/);});
 await check('marker in corrupt/uninitialized sections does not grant v1',()=>{const b=PE(),pe=b.readUInt32LE(60),table=pe+24+240;b.writeUInt32LE(0x40000080,table+36);assert.equal(contract.ArtifactVersion(b),0);b.writeUInt32LE(0xffffffff,table+16);assert.throws(()=>contract.ArtifactVersion(b),/BOOTSTRAP_PE_INVALID/);});
 await check('v1 artifact requires every plan field, not client declared version alone',()=>{for(const key of contract.FIELDS){const p=payload();delete p[key];assert.throws(()=>contract.Assert(p,artifact),/INTEGRITY_MEASUREMENT_PLAN_REQUIRED/);}assert.throws(()=>contract.Assert(payload({measurementContract:'UNKNOWN'}),artifact));});
 await check('parser rejects backward/oversized/unsafe ticks, unknown version, unstable full coverage',()=>{for(const change of [{measurementFinishedTick:9999},{measurementFinishedTick:70001},{measurementStartedTick:2**53},{measurementPlanVersion:2},{moduleGenerationStable:false},{coverage:'FULL',truncated:true},{coverage:'FULL',measuredModules:0},{coverage:'MAYBE'},{measurementContract:'UNKNOWN'},{unrecognizedCritical:true}])assert.throws(()=>reports.Payload(JSON.stringify(payload(change))),/INTEGRITY_REPORT_INVALID/);});
 await check('missing legacy metadata rejected for new artifact, with real signed request',()=>{const p=payload();for(const key of contract.FIELDS)delete p[key];assert.throws(()=>submit(p),/INTEGRITY_MEASUREMENT_PLAN_REQUIRED/);});
 await check('new artifact requires a complete observation even with optional baseline policy disabled',()=>{assert.equal(reports.Policy().enabled,false);assert.throws(()=>reports.RequireSnapshot(row,'B'),/INTEGRITY_SNAPSHOT_REQUIRED/);});
 await check('actual worker proof and original handler assemble coherent FULL snapshot; no machine attestation',async()=>{const body=request(payload()),jobs=reports.ProofTasks(body),result=await require("../../services/integrity/peace.desktop-proof-work").Run(jobs,()=>reports.Execute(body),{deadline:performance.now()+10000,key:'measurement'});assert.equal(result.accepted,true);assert.equal(result.terminate,false);const last=reports.List({sessionId:row.sessionId}).items.find(x=>x.snapshotFinal);assert.equal(last.snapshotStatus,'COMPLETE_PASS');assert.equal(last.planAssurance,'COHERENT_PLAN_V1');assert.equal(last.coverage,'FULL');assert.equal(last.attested,false);assert.equal(last.status,'CLIENT_DIAGNOSTIC');assert.deepEqual(result.snapshotBudget,{version:1,snapshotId:last.snapshotId,serverTime:last.at,expiresAt:last.at+120000});assert.deepEqual(reports.RequireSnapshot(row,'B'),{expiresAt:result.snapshotBudget.expiresAt});assert.deepEqual(reports.Execute(body),result);});
 await check('retained own-file failures survive signed inventory and cannot be counted as FULL',()=>{for(const status of ['FILE_CHANGED','CANCELLED','DEADLINE_EXCEEDED']){const failed={name:'retained-client.exe',status,codeStatus:status};const partial=submit(payload({modules:[failed],coverage:'PARTIAL',measuredModules:0}));assert.equal(partial.terminate,true);const recorded=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===partial.reportId);assert.equal(recorded.modules[0].status,status);assert.equal(recorded.coverage,'PARTIAL');assert.equal(recorded.snapshotStatus,'COMPLETE_REJECTED');const falseFull=submit(payload({modules:[failed]}));assert.equal(falseFull.terminate,true);const denied=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===falseFull.reportId);assert(denied.snapshotReasons.includes('INVALID_SNAPSHOT_COUNTS'));}});
 await check('loader notification state is signed, preserved, and cannot be mixed across batches',()=>{const accepted=submit(payload({moduleGenerationStatus:'TRACKED_STABLE'}));assert.equal(accepted.accepted,true);assert.equal(reports.List({sessionId:row.sessionId}).items.find(x=>x.id===accepted.reportId).moduleGenerationStatus,'TRACKED_STABLE');const id=crypto.randomUUID();submit(payload({snapshotId:id,batchCount:2,totalModules:2,measuredModules:2,modules:[moduleRow('one.dll')],moduleGenerationStatus:'TRACKED_STABLE'}));assert.throws(()=>submit(payload({snapshotId:id,batchIndex:1,batchCount:2,totalModules:2,measuredModules:2,modules:[moduleRow('two.dll')]})),/INTEGRITY_SNAPSHOT_CONFLICT/);});
 await check('unsupported or failed loader observation remains explicit PARTIAL',()=>{for(const status of ['UNSUPPORTED','TRACKING_FAILED','TRACKED_CHANGED']){const reply=submit(payload({moduleGenerationStatus:status,moduleGenerationStable:false,coverage:'PARTIAL',complete:false})),item=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===reply.reportId);assert.equal(reply.terminate,true);assert.equal(item.moduleGenerationStatus,status);assert(item.snapshotReasons.includes('MEASUREMENT_GENERATION_INCOMPLETE'));if(status!=='TRACKED_CHANGED')assert(item.snapshotReasons.includes('MEASUREMENT_GENERATION_'+status));}});
 await check('failed or unsupported export measurement never counts as a fully measured module',()=>{for(const exportTableStatus of ['READ_ERROR','UNSUPPORTED_EXPORT_LAYOUT']){const reply=submit(payload({modules:[{...moduleRow(),exportTableStatus}]})),item=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===reply.reportId);assert.equal(reply.terminate,true);assert(item.snapshotReasons.includes('MEASUREMENT_EXPORT_INCOMPLETE'));assert(item.snapshotReasons.includes('INVALID_SNAPSHOT_COUNTS'));}});
 await check('thread start observation remains signed diagnostic, with no JIT false rejection',()=>{const threadInventory={version:1,status:'COMPLETE',enumerated:2,knownImage:1,unknownStart:1,unreadable:0,truncated:false};const reply=submit(payload({threadInventory}));assert.equal(reply.accepted,true);assert.deepEqual(reports.List({sessionId:row.sessionId}).items.find(x=>x.id===reply.reportId).threadInventory,threadInventory);const id=crypto.randomUUID();submit(payload({snapshotId:id,batchCount:2,totalModules:2,measuredModules:2,modules:[moduleRow('one.dll')],threadInventory}));assert.throws(()=>submit(payload({snapshotId:id,batchIndex:1,batchCount:2,totalModules:2,measuredModules:2,modules:[moduleRow('two.dll')],threadInventory:{...threadInventory,knownImage:2,unknownStart:0}})),/INTEGRITY_SNAPSHOT_CONFLICT/);});
 await check('optional device digest is diagnostic and bound consistently across signed batches',()=>{const deviceSignals={version:1,status:'MEASURED',scope:'a'.repeat(128),algorithm:'BLAKE3-KEYED-256',diskCount:1,nicCount:1,digest:'b'.repeat(64),truncated:false};const reply=submit(payload({deviceSignals}));assert.equal(reply.accepted,true);const item=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===reply.reportId);assert.deepEqual(item.deviceSignals,deviceSignals);assert.equal(item.attested,false);const id=crypto.randomUUID();submit(payload({snapshotId:id,batchCount:2,totalModules:2,measuredModules:2,modules:[moduleRow('one.dll')],deviceSignals}));assert.throws(()=>submit(payload({snapshotId:id,batchIndex:1,batchCount:2,totalModules:2,measuredModules:2,modules:[moduleRow('two.dll')],deviceSignals:{...deviceSignals,scope:'c'.repeat(128)}})),/INTEGRITY_SNAPSHOT_CONFLICT/);});
 await check('mixed time metadata cannot be assembled across signed batches',()=>{const id=crypto.randomUUID();submit(payload({snapshotId:id,batchCount:2,totalModules:2,measuredModules:2,modules:[moduleRow('one.dll')]}));assert.throws(()=>submit(payload({snapshotId:id,batchIndex:1,batchCount:2,totalModules:2,measuredModules:2,measurementFinishedTick:10101,modules:[moduleRow('two.dll')]})),/INTEGRITY_SNAPSHOT_CONFLICT/);assert(revoked.includes('INTEGRITY_SNAPSHOT_CONFLICT'));});
 await check('sample/partial outcomes never satisfy required FULL',()=>{for(const coverage of ['SAMPLED','PARTIAL']){const result=submit(payload({coverage,complete:false}));assert.equal(result.terminate,true);assert.equal(Object.hasOwn(result,'snapshotBudget'),false);const item=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===result.reportId);assert.equal(item.snapshotStatus,'COMPLETE_REJECTED');assert.equal(item.complete,false);assert.throws(()=>reports.RequireSnapshot(row,'B'),/INTEGRITY_MEASUREMENT_PLAN_REQUIRED|INTEGRITY_SNAPSHOT_REQUIRED/);}});
 await check('explicit legacy plan remains diagnostic and cannot be relabelled coherent',()=>{artifact.measurementPlanVersion=0;const p=payload();for(const k of contract.FIELDS)delete p[k];const reply=submit(p),item=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===reply.reportId);assert.equal(item.planAssurance,'LEGACY_UNVERSIONED');artifact.measurementPlanVersion=1;assert.throws(()=>reports.RequireSnapshot(row,'B'),/INTEGRITY_MEASUREMENT_PLAN_REQUIRED/);});
 await check('new complete report ages out and rejects foreign context',()=>{submit(payload());const observation=reports.__probe.observations().find(x=>x.sessionId===row.sessionId);observation.at=Date.now()-121000;assert.throws(()=>reports.RequireSnapshot(row,'B'),/INTEGRITY_SNAPSHOT_STALE/);assert.throws(()=>reports.RequireSnapshot({...row,sessionId:'OTHER'},'B'),/INTEGRITY_SNAPSHOT_REQUIRED/);});
 await check('87-module renewal cannot be spread over 30-second download checkpoints',()=>{
  const date=Date.now;let clock=date()+1000000;Date.now=()=>clock;
  const before={id:row.id,sessionId:row.sessionId,reportContextId:row.reportContextId};
  Object.assign(row,{id:'SLOW_FLOW',sessionId:'SLOW_SESSION',reportContextId:'SLOW_SESSION'});common.sessionId=row.sessionId;
  try{
   const first=submit(payload()),originalExpiry=first.snapshotBudget.expiresAt,id=crypto.randomUUID();
   const modules=Array.from({length:87},(_,i)=>moduleRow('slow-'+i+'.dll'));
   clock+=60000;
   for(let batch=0;batch<3;batch++){
    const reply=submit(payload({snapshotId:id,batchIndex:batch,batchCount:15,totalModules:87,measuredModules:87,modules:modules.slice(batch*6,batch*6+6)}));
    assert.equal(reply.terminate,false);assert.equal(Object.hasOwn(reply,'snapshotBudget'),false);
    assert.equal(reports.__probe.observations().find(x=>x.sessionId===row.sessionId).at,first.snapshotBudget.serverTime);
    if(batch<2){assert.deepEqual(reports.RequireSnapshot(row,'B'),{expiresAt:originalExpiry});clock+=30000;}
   }
   clock=originalExpiry+1;
   assert.throws(()=>reports.RequireSnapshot(row,'B'),/INTEGRITY_SNAPSHOT_STALE/);
  }finally{Date.now=date;Object.assign(row,before);common.sessionId=row.sessionId;}
 });
 await check('complete 15-batch renewal before the next slow download gets exact bounded expiry; replay never renews it',()=>{
  const date=Date.now;let clock=date()+2000000;Date.now=()=>clock;
  const before={id:row.id,sessionId:row.sessionId,reportContextId:row.reportContextId};
  Object.assign(row,{id:'BOUNDED_FLOW',sessionId:'BOUNDED_SESSION',reportContextId:'BOUNDED_SESSION'});common.sessionId=row.sessionId;
  try{
   const initial=submit(payload()),originalExpiry=initial.snapshotBudget.expiresAt,id=crypto.randomUUID();
   const modules=Array.from({length:87},(_,i)=>moduleRow('bounded-'+i+'.dll'));
   let body,result;clock+=60000;
   for(let batch=0;batch<15;batch++){
    clock+=1000;body=request(payload({snapshotId:id,batchIndex:batch,batchCount:15,totalModules:87,measuredModules:87,modules:modules.slice(batch*6,batch*6+6)}));result=reports.Execute(body);
    assert.equal(result.terminate,false);
    if(batch<14){assert.equal(Object.hasOwn(result,'snapshotBudget'),false);assert.deepEqual(reports.RequireSnapshot(row,'B'),{expiresAt:originalExpiry});}
   }
   assert.deepEqual(result.snapshotBudget,{version:1,snapshotId:id,serverTime:clock,expiresAt:clock+120000});
   assert.deepEqual(reports.RequireSnapshot(row,'B'),{expiresAt:result.snapshotBudget.expiresAt});
   const revision=reports.List().revision;clock+=20000;
   assert.deepEqual(reports.Execute(body),result);assert.equal(reports.List().revision,revision);
   row.reportContextId='FOREIGN_CONTEXT';assert.throws(()=>reports.Execute(body),/INTEGRITY_REPORT_CHALLENGE_INVALID/);row.reportContextId=row.sessionId;
   // Two slow chunk windows remain inside the original completed observation.
   clock+=60000;assert.deepEqual(reports.RequireSnapshot(row,'B'),{expiresAt:result.snapshotBudget.expiresAt});
   clock=result.snapshotBudget.expiresAt+1;assert.throws(()=>reports.RequireSnapshot(row,'B'),/INTEGRITY_SNAPSHOT_STALE/);
  }finally{Date.now=date;Object.assign(row,before);common.sessionId=row.sessionId;}
 });
 await check('packed complete snapshots fit a whole slow download and child handoff without relaxing the 120-second lease',()=>{
  function simulate(rowsPerBatch,offset){
   const date=Date.now;let clock=date()+offset;Date.now=()=>clock;
   const before={id:row.id,sessionId:row.sessionId,reportContextId:row.reportContextId};
   Object.assign(row,{id:'DOWNLOAD_FLOW_'+rowsPerBatch,sessionId:'DOWNLOAD_SESSION_'+rowsPerBatch,reportContextId:'DOWNLOAD_SESSION_'+rowsPerBatch});common.sessionId=row.sessionId;
   try{
    const modules=Array.from({length:87},(_,i)=>moduleRow('download-'+i+'.dll'));
    const batchCount=Math.ceil(modules.length/rowsPerBatch),start=clock;
    let latest=submit(payload()).snapshotBudget,localDeadline=clock+117700;
    let nextSnapshot=clock+Math.min(60000,117700-(20000+batchCount*2300+7000)-30000);
    let nextVerify=clock+30000,cycles=0,verifications=0,reportsSent=0,minMargin=Infinity;
    function fresh(){
     assert(clock<localDeadline,'native conservative snapshot deadline crossed');
     assert.deepEqual(reports.RequireSnapshot(row,'B'),{expiresAt:latest.expiresAt});
     minMargin=Math.min(minMargin,localDeadline-clock);
    }
    function verify(force=false){
     if(!force&&clock<nextVerify)return;
     fresh();clock+=7000;fresh();nextVerify=clock+30000;verifications++;
    }
    function snapshot(){
     const began=clock,id=crypto.randomUUID();let finalRequestAt=0;
     for(let batch=0;batch<batchCount;batch++){
      fresh();verify();if(batch===0){clock+=20000;fresh();}
      const data=payload({snapshotId:id,batchIndex:batch,batchCount,totalModules:87,measuredModules:87,modules:modules.slice(batch*rowsPerBatch,(batch+1)*rowsPerBatch)});
      const requestAt=clock,body=request(data);clock+=2300;fresh();
      const reply=reports.Execute(body);reportsSent++;assert.equal(reply.terminate,false);
      if(batch<batchCount-1){assert.equal(Object.hasOwn(reply,'snapshotBudget'),false);fresh();}
      else{finalRequestAt=requestAt;latest=reply.snapshotBudget;assert.deepEqual(latest,{version:1,snapshotId:id,serverTime:clock,expiresAt:clock+120000});}
     }
     localDeadline=finalRequestAt+120000;
     const duration=clock-began;
     nextSnapshot=Math.max(clock,Math.min(clock+60000,localDeadline-duration-30000));
     fresh();cycles++;
    }
    function checkpoint(force=false){fresh();if(force||clock>=nextSnapshot)snapshot();verify(force);}
    // Model the complete transfer, not just one renewal. The service receives
    // actual signed reports; only network/collection time and auth are isolated.
    for(let chunk=0;chunk<36;chunk++){
     checkpoint();clock+=chunk===12?15000:2300;fresh();
    }
    const downloadMs=clock-start;
    checkpoint(true);const preChildMs=clock-start;
    // A bounded child-ready wait keeps the same maintenance checkpoints.
    const childReady=clock+20000;
    while(clock<childReady){clock=Math.min(childReady,clock+1000);checkpoint();}
    const result={rowsPerBatch,batchCount,chunkCount:36,downloadMs,preChildMs,totalMs:clock-start,cycles,verifications,reportsSent,minSnapshotMarginMs:minMargin};
    clock=latest.expiresAt+1;assert.throws(()=>reports.RequireSnapshot(row,'B'),/INTEGRITY_SNAPSHOT_STALE/);
    return result;
   }finally{Date.now=date;Object.assign(row,before);common.sessionId=row.sessionId;}
  }
  const baseline=simulate(6,3000000),packed=simulate(16,4000000);
  assert(baseline.downloadMs>300000,'six-row batches must reproduce transfer budget exhaustion');
  assert(baseline.totalMs>410000,'six-row batches must reproduce total startup budget exhaustion');
  assert(packed.downloadMs<300000,'complete packed transfer must fit the existing download deadline');
  assert(packed.totalMs<410000,'complete packed startup must fit the existing parent deadline');
  console.log(JSON.stringify({scenario:'slow-whole-overlay-download',baseline,packed,serverSnapshotTtlMs:120000,nativeExecuted:false}));
 });
 await check('child-ready callbacks yield after one pending batch and observe 90s/100s readiness before 110s',()=>{
  function waitForChild(readyAfter,offset){
   const date=Date.now;let clock=date()+offset;Date.now=()=>clock;
   const before={id:row.id,sessionId:row.sessionId,reportContextId:row.reportContextId};
   Object.assign(row,{id:'WAIT_FLOW_'+offset,sessionId:'WAIT_SESSION_'+offset,reportContextId:'WAIT_SESSION_'+offset});common.sessionId=row.sessionId;
   try{
    const initial=submit(payload()).snapshotBudget;clock+=7000;
    const start=clock,id=crypto.randomUUID(),modules=Array.from({length:87},(_,i)=>moduleRow('wait-'+i+'.dll'));
    const oldLocalDeadline=start+110700;let localDeadline=oldLocalDeadline,licenseDeadline=start+120000,nextVerify=start+30000;
    let latest=initial,batch=0,pending=false,completed=false,callbacks=0,partialReplies=0;
    function fresh(){assert(clock<localDeadline);assert(clock<licenseDeadline);assert.deepEqual(reports.RequireSnapshot(row,'B'),{expiresAt:latest.expiresAt});}
    function verify(){if(clock<nextVerify)return;fresh();const old=licenseDeadline;clock+=7000;assert(clock<old);fresh();licenseDeadline=clock+120000;nextVerify=clock+30000;}
    while(true){
     // The real waiter checks READY before invoking the next maintenance step.
     fresh();if(readyAfter!==null&&clock-start>=readyAfter)break;
     if(readyAfter===null&&completed)break;
     clock+=1000;callbacks++;fresh();
     if(!completed&&(pending||clock-start>=39900)){
      pending=true;verify();if(batch===0){clock+=20000;fresh();}
      const data=payload({snapshotId:id,batchIndex:batch,batchCount:6,totalModules:87,measuredModules:87,modules:modules.slice(batch*16,(batch+1)*16)});
      const requestAt=clock,body=request(data);
      // A delayed pair makes READY arrive while a renewal remains pending.
      clock+=batch===0?25000:2300;fresh();const reply=reports.Execute(body);
      assert.equal(reply.terminate,false);batch++;
      if(batch<6){assert.equal(Object.hasOwn(reply,'snapshotBudget'),false);partialReplies++;assert.equal(latest.snapshotId,initial.snapshotId);}
      else{latest=reply.snapshotBudget;localDeadline=requestAt+120000;completed=true;pending=false;}
      fresh();
     }
     verify();
    }
    fresh();const observedAfter=clock-start;
    if(readyAfter!==null){
     assert(observedAfter<110000);assert(pending);assert.equal(completed,false);
     assert.equal(latest.snapshotId,initial.snapshotId,'partial batches cannot grant a receipt before handoff');
    }else{assert(completed);assert(clock<oldLocalDeadline,'no-ready continuation must finish before its old complete snapshot expires');}
    return {readyAfter,observedAfter,callbacks,partialReplies,completed};
   }finally{Date.now=date;Object.assign(row,before);common.sessionId=row.sessionId;}
  }
  const ready90=waitForChild(90000,5000000),ready100=waitForChild(100000,6000000);
  // Separate no-ready branch only: actual handoff exits as soon as READY is
  // observed and does not depend on completing the remaining B report batches.
  const noReady=waitForChild(null,7000000);
  console.log(JSON.stringify({scenario:'bounded-child-ready-callbacks',ready90,ready100,noReady,nativeExecuted:false}));
 });
 await check('UTF-8 and escaped Unicode/quote module batches obey both fixed transport caps with every row retained',()=>{
  const bound={...common,sessionId:'B'.repeat(24),sessionToken:'s'.repeat(43),binarySha512:'a'.repeat(128),binaryCrc64:'B'.repeat(16),codeSha512:'c'.repeat(128),codeCrc64:'D'.repeat(16)};
  const threadInventory={version:1,status:'COMPLETE',enumerated:12,knownImage:11,unknownStart:1,unreadable:0,truncated:false};
  const deviceSignals={version:1,status:'MEASURED',scope:'e'.repeat(128),algorithm:'BLAKE3-KEYED-256',diskCount:8,nicCount:64,digest:'f'.repeat(64),truncated:false};
  const utf8=value=>Buffer.byteLength(value,'utf8'),encoded=value=>utf8(JSON.stringify(value));
  const envelope=(body)=>({operation:'report',tlsPinVersion:1,body});
  const overhead=utf8(JSON.stringify(envelope({...bound,action:'submit',reportId:'X'.repeat(160),signature:'X'.repeat(1024),payload:''})))-2;
  for(const kind of ['unicode','quotes','mixed']){
   const modules=Array.from({length:87},(_,i)=>{
    const repeated=kind==='unicode'?'界'.repeat(170):kind==='quotes'?'"'.repeat(170):'한😀"'.repeat(40);
    const name=repeated+'-'+i+'.dll';assert(name.length<=180);
    return {...moduleRow(name),exportCount:10,codeExportCount:8,forwardedExportCount:2,executableSections:3,exportCoverage:'SECTION_HASHED',exportTableStatus:'MEASURED',exportTableSha512:'a'.repeat(128),exportTableCrc64:'B'.repeat(16),exportTableXxh3_128:'c'.repeat(32),exportTableBlake3:'d'.repeat(64)};
   });
   const id=crypto.randomUUID(),metadata=payload({snapshotId:id,batchIndex:255,batchCount:256,totalModules:87,measuredModules:87,moduleGenerationStatus:'TRACKED_STABLE',threadInventory:structuredClone(threadInventory),deviceSignals:structuredClone(deviceSignals),modules:[]});
   const metadataText=JSON.stringify(metadata),largest=Math.max(...modules.map(m=>utf8(JSON.stringify(m)))),largestEncoded=Math.max(...modules.map(m=>encoded(JSON.stringify(m))-2));
   let batchSize=16;
   while(batchSize>0&&(utf8(metadataText)+(largest+1)*batchSize>24576||overhead+encoded(metadataText)+(largestEncoded+1)*batchSize>32768))batchSize--;
   assert(batchSize>0);assert(batchSize<=16);const batchCount=Math.ceil(modules.length/batchSize),sent=[];
   let last,maxPayload=0,maxEnvelope=0;
   for(let batch=0;batch<batchCount;batch++){
    const rows=modules.slice(batch*batchSize,(batch+1)*batchSize),data={...structuredClone(metadata),batchIndex:batch,batchCount,modules:rows};
    const challenge=reports.Execute({...bound,action:'challenge'}),text=JSON.stringify(data);
    const body={...bound,action:'submit',reportId:challenge.reportId,payload:text,signature:crypto.sign('sha256',Buffer.from(reports.Canonical(row.reportContextId,challenge,text)),keys.privateKey).toString('base64')};
    const inner=utf8(text),outer=utf8(JSON.stringify(envelope(body)));maxPayload=Math.max(maxPayload,inner);maxEnvelope=Math.max(maxEnvelope,outer);
    assert(inner<=24576);assert(outer<=32768);assert.equal(data.batchCount,batchCount);assert.deepEqual(data.threadInventory,threadInventory);assert.deepEqual(data.deviceSignals,deviceSignals);
    last=reports.Execute(body);assert.equal(last.terminate,false);sent.push(...rows.map(m=>m.name));
    if(batch<batchCount-1)assert.equal(Object.hasOwn(last,'snapshotBudget'),false);
   }
   assert.deepEqual(sent,modules.map(m=>m.name));assert.equal(new Set(sent).size,87);
   const item=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===last.reportId);
   assert.equal(item.snapshotStatus,'COMPLETE_PASS');assert.equal(item.totalModules,87);assert.equal(item.measuredModules,87);assert.equal(last.snapshotBudget.snapshotId,id);
   assert.throws(()=>reports.Payload(JSON.stringify({...metadata,batchIndex:0,batchCount:1,modules:Array(17).fill(moduleRow())})),/INTEGRITY_REPORT_INVALID/);
   console.log(JSON.stringify({scenario:'bounded-unicode-module-packing',kind,batchSize,batchCount,maxPayload,maxEnvelope,rowsRetained:sent.length}));
  }
 });
 console.log(JSON.stringify({suite:'completion-measurement-6-10',groups:n,status:'PASS',actualSignatures:true,actualReportFiles:true,isolatedAuthorization:true,nativeExecuted:false}));
 }catch(e){console.error(e);process.exitCode=1;}finally{await Promise.all([work.auth,work.pe,work.proof,work.renewalProof,work.tpmAttestation].map(q=>q.close()));fs.rmSync(temp,{recursive:true,force:true});}})();
