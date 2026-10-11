'use strict';
// Real filesystem/crypto unit tests. NO server lock bypass or production hooks.
// Isolated module overrides inject precisely timed disk/audit failures only here.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),Module=require('node:module');
const {spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),data=fs.mkdtempSync(path.join(os.tmpdir(),'game-storage-11-14-'));
process.env.DATA_DIR=data;process.env.HA_ENABLED='0';delete process.env.DESKTOP_RECOVERY_WITNESS_DIR;delete process.env.DESKTOP_RECOVERY_WITNESS_REQUIRED;
const disk=require('../services/durableFile');
function fresh(name){delete require.cache[require.resolve('../services/'+name)];return require('../services/'+name);}
function isolated(name,overrides={}){const file=path.join(root,'services',name+'.js'),m=new Module(file,module),real=Module.createRequire(file);m.filename=file;m.paths=Module._nodeModulePaths(path.dirname(file));m.require=n=>Object.hasOwn(overrides,n)?overrides[n]:real(n);m._compile(fs.readFileSync(file,'utf8'),file);return m.exports;}
const zero={seq:0,hash:'0'.repeat(64)},one={seq:1,hash:'1'.repeat(64)},two={seq:2,hash:'2'.repeat(64)};
function initial(j){const state=j.Load().state,next=structuredClone(state);next.revision=1;next.signingSecret='a'.repeat(64);next.licenses.TEST={id:'TEST',status:'AVAILABLE',consumed:false};j.Commit(state,next);return next;}
function consume(j,previous){const next=structuredClone(previous);next.revision++;next.licenses.TEST.status='USED';next.licenses.TEST.consumed=true;next.receipts.REQUEST={result:'USED',operationId:'7'.repeat(64)};j.Commit(previous,next);return next;}
function snapshot(j,previous){const next=structuredClone(previous);next.revision++;j.Commit(previous,next,{fullSnapshot:true});return next;}
const cases={
 'journal-restart-compaction':()=>{
  let j=require('../services/desktopJournal'),s=initial(j);s=consume(j,s);s=snapshot(j,s);const secret=s.signingSecret,result=j.Rotate();assert.equal(result.sequence,3);assert.equal(fs.statSync(j.FILE).size,0);
  j=fresh('desktopJournal');const loaded=j.Load();assert(loaded.exists);assert.deepEqual(loaded.state,s);assert.equal(loaded.state.signingSecret,secret);
  const next=structuredClone(s);next.revision++;next.licenses.REVOKED={id:'REVOKED',status:'REVOKED',consumed:false};j.Commit(s,next);assert.equal(fresh('desktopJournal').Load().state.licenses.REVOKED.status,'REVOKED');
  assert.throws(()=>j.Commit(next,{...next,revision:next.revision+1,licenses:{}}),/CORRUPT/);
 },
 'checkpoint-head-binding':()=>{
  let j=require('../services/desktopJournal'),s=snapshot(j,consume(j,initial(j)));j.Rotate();
  const envelope=JSON.parse(fs.readFileSync(j.SNAP,'utf8')),auth=JSON.parse(fs.readFileSync(j.KEY,'utf8'));
  // Even access to the LOCAL MAC key cannot replace snapshot state while keeping
  // the externally observed record hash: the full snapshot is hashed in the head.
  envelope.body.record.body.licenses[0].consumed=false;
  envelope.mac=crypto.createHmac('sha256',Buffer.from(auth.secret,'hex')).update('GAME-LICENSE-CHECKPOINT-V1\n'+JSON.stringify(envelope.body)).digest('hex');
  fs.writeFileSync(j.SNAP,JSON.stringify(envelope));assert.throws(()=>fresh('desktopJournal').Load(),/CORRUPT/);
 },
 'checkpoint-crash-before-tail-clear':()=>{
  const j=require('../services/desktopJournal'),s=snapshot(j,consume(j,initial(j))),before=fs.readFileSync(j.FILE);j.Rotate();
  fs.writeFileSync(j.FILE,before);assert.deepEqual(fresh('desktopJournal').Load().state,s);
  const last=before.subarray(0,before.length-5);fs.writeFileSync(j.FILE,last);assert.throws(()=>fresh('desktopJournal').Load(),/CORRUPT/);
 },
 'checkpoint-missing-archive':()=>{
  const j=require('../services/desktopJournal');snapshot(j,consume(j,initial(j)));j.Rotate();const cp=JSON.parse(fs.readFileSync(j.SNAP));fs.unlinkSync(path.join(j.SEGMENTS,cp.body.segment.file));assert.throws(()=>fresh('desktopJournal').Load());
 },
 'journal-no-rollback-after-durable-commit':()=>{
  const normal=require('../services/desktopJournal'),s=initial(normal),factory=require('../services/desktopJournalHead');let fail=true;
  const j=isolated('desktopJournal',{'./desktopJournalHead':{Create(...args){const h=factory.Create(...args);return {...h,Settle(x){if(fail&&x.seq===2){fail=false;throw Error('AFTER_DURABLE_APPEND');}return h.Settle(x);}};}}});j.Load();
  assert.throws(()=>consume(j,s),/AFTER_DURABLE_APPEND/);assert.throws(()=>j.Load(),/RESTART_REQUIRED/);const recovered=fresh('desktopJournal').Load().state;assert.equal(recovered.licenses.TEST.consumed,true);assert.equal(recovered.revision,2);
 },
 'journal-before-fsync-no-success':()=>{
  const j=require('../services/desktopJournal'),s=initial(j);let fail=true;
  const fake=Object.create(fs);fake.writeSync=function(...args){if(fail){fail=false;throw Error('ENOSPC_INJECTED');}return fs.writeSync(...args);};
  const faulty=isolated('desktopJournal',{'node:fs':fake});faulty.Load();assert.throws(()=>consume(faulty,s),/ENOSPC_INJECTED/);assert.equal(fresh('desktopJournal').Load().state.licenses.TEST.consumed,false);
 },
 'journal-partial-final-append':()=>{
  const j=require('../services/desktopJournal'),s=initial(j);fs.appendFileSync(j.FILE,'{"seq":2');assert.deepEqual(fresh('desktopJournal').Load().state,s);assert(fs.readFileSync(j.FILE,'utf8').endsWith('\n'));
 },
 'journal-partial-first-append-after-checkpoint':()=>{
  const j=require('../services/desktopJournal'),s=snapshot(j,consume(j,initial(j)));j.Rotate();
  fs.appendFileSync(j.FILE,'{"seq":4,"prev":');assert.deepEqual(fresh('desktopJournal').Load().state,s);assert.equal(fs.statSync(j.FILE).size,0);
  fs.appendFileSync(j.FILE,'{"seq":1,');assert.throws(()=>fresh('desktopJournal').Load(),/CORRUPT/);
 },
 'witness-high-water-crash-choices':()=>{
  const dir=path.join(data,'witness');fs.mkdirSync(dir);const {WitnessFile}=require('../services/recoveryWitnessFile'),w=new WitnessFile(dir);w.enroll({DESKTOP_JOURNAL:zero});
  w.prepare('DESKTOP_JOURNAL',zero,one);w.open('DESKTOP_JOURNAL',zero);w.assertCurrent('DESKTOP_JOURNAL',zero);
  w.prepare('DESKTOP_JOURNAL',zero,one);w.open('DESKTOP_JOURNAL',one);w.assertCurrent('DESKTOP_JOURNAL',one);
  assert.throws(()=>w.open('DESKTOP_JOURNAL',zero),/ROLLBACK/);assert.throws(()=>w.prepare('DESKTOP_JOURNAL',zero,one),/CONFLICT/);assert.throws(()=>w.enroll({DESKTOP_JOURNAL:zero}),/ALREADY_ENROLLED/);
  w.prepare('DESKTOP_JOURNAL',one,two);w.settle('DESKTOP_JOURNAL',two);assert.equal(w.status().heads.DESKTOP_JOURNAL.sequence,2);
 },
 'witness-old-entire-data-backup-rejected':()=>{
  const dir=path.join(data,'separate-witness');fs.mkdirSync(dir);const {WitnessFile}=require('../services/recoveryWitnessFile'),w=new WitnessFile(dir);w.enroll({DESKTOP_JOURNAL:zero});
  const factory=isolated('desktopJournalHead',{'./desktopRecoveryWitness':{Head:()=>({Open:x=>w.open('DESKTOP_JOURNAL',x),Prepare:(a,b)=>w.prepare('DESKTOP_JOURNAL',a,b),Settle:x=>w.settle('DESKTOP_JOURNAL',x)})}});
  const j=isolated('desktopJournal',{'./desktopJournalHead':factory}),s=initial(j),files=[j.FILE,j.KEY,j.FILE+'.head'],backup=files.map(p=>fs.readFileSync(p));consume(j,s);
  files.forEach((p,i)=>fs.writeFileSync(p,backup[i]));const restored=isolated('desktopJournal',{'./desktopJournalHead':factory});assert.throws(()=>restored.Load(),/RECOVERY_ROLLBACK_DETECTED/);
 },
 'bootstrap-local-whole-file-rollback-rejected':()=>{
  let s=require('../services/desktopBootstrapStore');const db=s.Load(),old=fs.readFileSync(path.join(s.DIR,'authority.json'));s.Atomic(n=>{n.serverRecovery={version:1,epoch:1,receipts:{}};});fs.writeFileSync(path.join(s.DIR,'authority.json'),old);assert.throws(()=>fresh('desktopBootstrapStore').Load(),/DESKTOP_BOOTSTRAP_CORRUPT/);
 },
 'audit-outbox-commit-and-repair':()=>{
  const store=require('../services/desktopBootstrapStore');store.Load();let failCommit=true,events=new Map();
  const audit=isolated('desktopOperationAudit',{'../storage/audit':{AppendOperationEvent(id,type,event){if(event.phase==='COMMITTED'&&failCommit)return {ok:false};events.set(id,{type,event});return {ok:true};}}});
  audit.Run('TEST_CHANGE','OPERATOR',{secret:'must not be logged',subject:'1'.repeat(64)},db=>{db.auditTestMarker=1;});
  assert.equal(store.Load().auditTestMarker,1);assert.equal(Object.values(store.Load().serverAuditOutbox)[0].acked,false);audit.Validate(store.Load().serverAuditOutbox);const tampered=structuredClone(store.Load().serverAuditOutbox);Object.values(tampered)[0].intent.auditEventId='0'.repeat(64);assert.throws(()=>audit.Validate(tampered),/OUTBOX_INVALID/);
  failCommit=false;audit.Drain();assert.equal(Object.values(store.Load().serverAuditOutbox)[0].acked,true);assert.equal(events.size,2);
  events=new Map();audit.Drain({reconcile:true});assert.equal(events.size,2);assert(!JSON.stringify([...events.values()]).includes('must not'));
 },
 'audit-unavailable-before-mutation':()=>{
  const store=require('../services/desktopBootstrapStore');store.Load();const before=store.Load().revision;let ran=false;
  const audit=isolated('desktopOperationAudit',{'../storage/audit':{AppendOperationEvent:()=>({ok:false})}});assert.throws(()=>audit.Run('NO_AUDIT','ADMIN',{},()=>{ran=true;}),/AUDIT_UNAVAILABLE/);assert.equal(ran,false);assert.equal(store.Load().revision,before);
 },
 'device-identity-is-not-tpm-proof':()=>{
  const store=require('../services/desktopBootstrapStore'),device=require('../services/desktopDeviceRegistry'),machine='A'.repeat(64);store.Load();
  store.Atomic(db=>{device.ObserveVerified(db,{machineId:machine,deviceId:'B'.repeat(64)},'A');});device.Validate(store.Load().deviceRegistry);
  const listing=device.List();assert.equal(listing.items[0].assurance,'APP_KEY_POSSESSION');assert.equal(listing.tpmAttested,false);assert(!JSON.stringify(store.Load().deviceRegistry).includes(machine));
  store.Atomic(db=>{const r=db.deviceRegistry.bindings[listing.items[0].id];r.status='RETIRED';r.retiredAt=Date.now();r.proofs=[];});assert.throws(()=>device.AssertMachineAllowed(machine),/RETIRED/);
 },
 'orphan-quarantine-preserves-and-rechecks':()=>{
  const store=require('../services/desktopBootstrapStore');store.Load();fs.mkdirSync(path.join(data,'audit'),{recursive:true});const o=require('../services/desktopOrphanFiles');
  const name='A'.repeat(24)+'.exe',file=path.join(store.DIR,name);fs.writeFileSync(file,'test-owned-artifact');const candidate=o.Scan().items.find(x=>x.name===name);assert(candidate.eligible);
  const result=o.Quarantine({name,sha512:candidate.sha512});assert.equal(result.status,'QUARANTINED');assert(!fs.existsSync(file));assert.throws(()=>o.Delete({id:result.id,sha512:result.sha512}),/RETENTION_OR_REFERENCE/);
  assert.throws(()=>o.Quarantine({name:'../secret',sha512:candidate.sha512}),/INPUT_INVALID/);
  const linked='B'.repeat(24)+'.exe';fs.symlinkSync(path.join(store.DIR,'authority.json'),path.join(store.DIR,linked));assert.equal(o.Scan().items.find(x=>x.name===linked).eligible,false);
 },
 'recovery-epoch-revokes-without-local-permit':()=>{
  const store=require('../services/desktopBootstrapStore');store.Load();fs.mkdirSync(path.join(data,'audit'),{recursive:true});const recovery=require('../services/desktopRecovery');
  const input={requestId:'RECOVERY_0001',expectedEpoch:0,reasonCode:'RECOVERY_DRILL'};const result=recovery.Apply(input,'TEST_OPERATOR');assert.equal(result.epoch,1);assert.throws(()=>recovery.Assert({serverEpoch:0}),/EPOCH_REVOKED/);assert.doesNotThrow(()=>recovery.Assert({serverEpoch:1}));
  assert.equal(recovery.Apply(input,'TEST_OPERATOR').duplicate,true);assert.throws(()=>recovery.Apply({...input,reasonCode:'SECURITY_INCIDENT'},'TEST_OPERATOR'),/REQUEST_REUSED/);assert.equal(recovery.Status().offlineAuthorization,false);
  assert.equal(fresh('desktopBootstrapStore').Load().serverRecovery.epoch,1);
 },
 'orphan-rename-failure-restart-same-operation':()=>{
  const store=require('../services/desktopBootstrapStore');store.Load();fs.mkdirSync(path.join(data,'audit'),{recursive:true});const file='C'.repeat(24)+'.exe';fs.writeFileSync(path.join(store.DIR,file),'interrupted quarantine');
  const normal=require('../services/desktopOrphanFiles'),bad=isolated('desktopOrphanFiles',{'node:fs':{...fs,renameSync(from,to){fs.renameSync(from,to);throw Error('INJECTED_AFTER_RENAME');}}});const item=normal.Scan().items.find(x=>x.name===file);
  assert.throws(()=>bad.Quarantine({name:file,sha512:item.sha512}),/INJECTED_AFTER_RENAME/);const pending=Object.values(store.Load().orphanQuarantine)[0];assert.equal(pending.status,'PENDING');const op=pending.quarantineOperation.operationId;
  assert.equal(normal.RecoverPending().resumed,1);const final=store.Load().orphanQuarantine[pending.id];assert.equal(final.status,'QUARANTINED');assert.equal(final.quarantineOperation.operationId,op);assert(Object.values(store.Load().serverAuditOutbox).some(x=>x.event.operationId===op&&x.intent.operationId===op));
 },
 'orphan-delete-loss-idempotent-and-tombstone':()=>{
  const store=require('../services/desktopBootstrapStore');store.Load();fs.mkdirSync(path.join(data,'audit'),{recursive:true});const file='D'.repeat(24)+'.exe';fs.writeFileSync(path.join(store.DIR,file),'test-only deletion fixture');
  const normal=require('../services/desktopOrphanFiles'),item=normal.Scan().items.find(x=>x.name===file),row=normal.Quarantine({name:file,sha512:item.sha512});const clock=Date.now;
  try{Date.now=()=>row.quarantinedAt+normal.GRACE_MS+1;
   const bad=isolated('desktopOrphanFiles',{'node:fs':{...fs,unlinkSync(file){fs.unlinkSync(file);throw Error('INJECTED_AFTER_UNLINK');}}});assert.throws(()=>bad.Delete({id:row.id,sha512:row.sha512}),/INJECTED_AFTER_UNLINK/);const pending=store.Load().orphanQuarantine[row.id];assert.equal(pending.status,'DELETE_PENDING');const op=pending.deleteOperation.operationId;
   assert.equal(normal.Delete({id:row.id,sha512:row.sha512}).deleted,true);assert.equal(normal.Delete({id:row.id,sha512:row.sha512}).duplicate,true);assert.equal(store.Load().orphanQuarantine[row.id].deleteOperation.operationId,op);assert.equal(store.Load().orphanQuarantine[row.id].status,'DELETED');
  }finally{Date.now=clock;}
 },
 'orphan-retries-repeat-failed-directory-fences':()=>{
  const store=require('../services/desktopBootstrapStore');store.Load();fs.mkdirSync(path.join(data,'audit'),{recursive:true});const file='E'.repeat(24)+'.exe';fs.writeFileSync(path.join(store.DIR,file),'directory durability fixture');
  const normal=require('../services/desktopOrphanFiles'),item=normal.Scan().items.find(x=>x.name===file),faulty=isolated('desktopOrphanFiles',{'./durableFile':{...disk,SyncDirectory(){throw Error('DIRECTORY_FSYNC_FAILED');}}});
  assert.throws(()=>faulty.Quarantine({name:file,sha512:item.sha512}),/DIRECTORY_FSYNC_FAILED/);const pending=Object.values(store.Load().orphanQuarantine)[0];assert.equal(pending.status,'PENDING');assert.equal(fs.existsSync(path.join(store.DIR,file)),false);
  assert.throws(()=>faulty.Quarantine({name:file,sha512:item.sha512}),/DIRECTORY_FSYNC_FAILED/);assert.equal(store.Load().orphanQuarantine[pending.id].status,'PENDING');
  const row=normal.Quarantine({name:file,sha512:item.sha512}),clock=Date.now;
  try{Date.now=()=>row.quarantinedAt+normal.GRACE_MS+1;
   assert.throws(()=>faulty.Delete({id:row.id,sha512:row.sha512}),/DIRECTORY_FSYNC_FAILED/);assert.equal(store.Load().orphanQuarantine[row.id].status,'DELETE_PENDING');
   assert.throws(()=>faulty.Delete({id:row.id,sha512:row.sha512}),/DIRECTORY_FSYNC_FAILED/);assert.equal(store.Load().orphanQuarantine[row.id].status,'DELETE_PENDING');assert.equal(normal.Delete({id:row.id,sha512:row.sha512}).deleted,true);
  }finally{Date.now=clock;}
 },
 'device-replacement-keeps-license-history':()=>{
  const store=require('../services/desktopBootstrapStore'),device=require('../services/desktopDeviceRegistry');store.Load();fs.mkdirSync(path.join(data,'audit'),{recursive:true});
  store.Atomic(db=>device.ObserveVerified(db,{machineId:'A'.repeat(64),deviceId:'B'.repeat(64)},'A'));const licenseBefore=JSON.stringify(require('../services/desktopLicenses').DB()),before=device.List(),input={oldBindingId:before.items[0].id,newMachineId:'C'.repeat(64),expectedRevision:before.revision,requestId:'REPLACE_TEST_1',reasonCode:'TPM_RESET'};
  const result=device.Replace(input,'TEST_ADMIN');assert.equal(result.licenseCarryOver,false);assert.equal(device.Replace(input,'TEST_ADMIN').duplicate,true);assert.throws(()=>device.Replace({...input,reasonCode:'ADMIN_RECOVERY'},'TEST_ADMIN'),/REQUEST_REUSED/);assert.throws(()=>device.AssertMachineAllowed('A'.repeat(64)),/RETIRED/);assert.doesNotThrow(()=>device.AssertMachineAllowed('C'.repeat(64)));assert.equal(JSON.stringify(require('../services/desktopLicenses').DB()),licenseBefore);assert.equal(device.List().items.find(x=>x.id===result.newBindingId).assurance,'IDENTIFIED_ONLY');device.Validate(fresh('desktopBootstrapStore').Load().deviceRegistry);
 },
 'license-checkpoint-command-replay-and-audit':()=>{
  fs.mkdirSync(path.join(data,'audit'),{recursive:true});const journal=require('../services/desktopJournal'),before=journal.Load().state,id='A'.repeat(24),next={...before,revision:1,signingSecret:'a'.repeat(64),licenses:{[id]:{id,status:'AVAILABLE',keyHash:'b'.repeat(64),consumed:false,expiresAt:0,issuanceNonce:'c'.repeat(48)}}};journal.Commit(before,next);
  // Only the derived general-DB mirror is replaced here, not journal persistence.
  const licenses=isolated('desktopLicenses',{'../storage/database':{SaveDatabase:()=>true}}),input={requestId:'CHECKPOINT_001',expectedRevision:1};const result=licenses.CreateCheckpoint(input,'TEST_ADMIN');assert.equal(result.compacted,true);assert.equal(licenses.CreateCheckpoint(input,'TEST_ADMIN').duplicate,true);assert.throws(()=>licenses.CreateCheckpoint({...input,expectedRevision:0},'TEST_ADMIN'),/REQUEST_REUSED/);assert.equal(licenses.ReconcileCheckpoints(),0);const restored=fresh('desktopJournal').Load().state;assert.equal(restored.licenses[id].keyHash,next.licenses[id].keyHash);assert(Object.keys(restored.receipts).some(x=>x.startsWith('CHECKPOINT:')));
 },
 'license-checkpoint-resumes-before-rotation':()=>{
  fs.mkdirSync(path.join(data,'audit'),{recursive:true});const journal=require('../services/desktopJournal'),input={requestId:'CHECKPOINT_CRASH_1',expectedRevision:0};
  const broken=isolated('desktopLicenses',{'../storage/database':{SaveDatabase:()=>true},'./desktopJournal':{...journal,Rotate(){throw Error('INJECTED_BEFORE_ROTATE');}}});
  assert.throws(()=>broken.CreateCheckpoint(input,'TEST_ADMIN'),/INJECTED_BEFORE_ROTATE/);assert.equal(fs.existsSync(journal.SNAP),false);assert(fs.statSync(journal.FILE).size>0);
  const restored=fresh('desktopJournal'),licenses=isolated('desktopLicenses',{'../storage/database':{SaveDatabase:()=>true},'./desktopJournal':restored});
  const result=licenses.CreateCheckpoint(input,'TEST_ADMIN');assert.equal(result.duplicate,true);assert.equal(result.compacted,true);assert.equal(fs.statSync(journal.FILE).size,0);assert.equal(Object.keys(restored.Load().state.receipts).length,1);
 },
 'license-checkpoint-old-retry-does-not-rotate-new-state':()=>{
  fs.mkdirSync(path.join(data,'audit'),{recursive:true});const journal=require('../services/desktopJournal'),input={requestId:'CHECKPOINT_CRASH_2',expectedRevision:0};
  const broken=isolated('desktopLicenses',{'../storage/database':{SaveDatabase:()=>true},'./desktopJournal':{...journal,Rotate(){throw Error('INJECTED_BEFORE_ROTATE');}}});
  assert.throws(()=>broken.CreateCheckpoint(input,'TEST_ADMIN'),/INJECTED_BEFORE_ROTATE/);
  const before=journal.Load().state,next=structuredClone(before);next.revision++;next.receipts.LATER={result:'PRESERVED'};journal.Commit(before,next);const bytes=fs.readFileSync(journal.FILE);
  const licenses=isolated('desktopLicenses',{'../storage/database':{SaveDatabase:()=>true}}),result=licenses.CreateCheckpoint(input,'TEST_ADMIN');
  assert.equal(result.duplicate,true);assert.equal(result.compacted,false);assert.equal(result.checkpointRequired,true);assert.deepEqual(fs.readFileSync(journal.FILE),bytes);assert.deepEqual(journal.Load().state.receipts.LATER,{result:'PRESERVED'});
 },
 'startup-refuses-old-integrity-store-before-mirror-write':()=>{
  require('../services/desktopLicenses').DB();const machine=require('../services/desktopMachinePolicy');machine.Load();const bootstrap=require('../services/desktopBootstrapStore');bootstrap.Load();const reports=require('../services/desktopIntegrityReports');reports.Policy();
  const files=[reports.FILE,reports.FILE+'.head'],old=files.map(file=>fs.readFileSync(file));reports.Record({stage:'A',status:'CLIENT_DIAGNOSTIC',check:'OWN_CODE',reason:'READ_ERROR'});
  const readHead=file=>JSON.parse(fs.readFileSync(file)).body.current,witnessDir=fs.mkdtempSync(path.join(os.tmpdir(),'game-independent-witness-'));
  try{
   new (require('../services/recoveryWitnessFile').WitnessFile)(witnessDir).enroll({DESKTOP_JOURNAL:zero,DESKTOP_MACHINE_POLICY:readHead(machine.FILE+'.head'),DESKTOP_BOOTSTRAP:readHead(path.join(bootstrap.DIR,'authority.json.head')),DESKTOP_INTEGRITY:readHead(reports.FILE+'.head')});
   files.forEach((file,i)=>fs.writeFileSync(file,old[i]));
   const child=spawnSync(process.execPath,['server.js'],{cwd:root,env:{...process.env,STORAGE_ENGINE:'json',DESKTOP_RECOVERY_WITNESS_DIR:witnessDir,DESKTOP_RECOVERY_WITNESS_REQUIRED:'1'},encoding:'utf8',timeout:10000});
   assert.equal(child.status,1,child.stderr);assert.match(child.stderr,/RECOVERY_ROLLBACK_DETECTED/);assert.equal(fs.existsSync(path.join(data,'relay-identities.json')),false);assert(!child.stdout.includes('HTTP Port:'));assert(!child.stdout.includes('DATABASE_'));
  }finally{fs.rmSync(witnessDir,{recursive:true,force:true});}
 },
 'witness-configuration-fails-closed':()=>{
  const adapter=require('../services/desktopRecoveryWitness');assert.equal(adapter.Status().wholeBackupRollbackProtected,false);process.env.DESKTOP_RECOVERY_WITNESS_REQUIRED='1';assert.throws(()=>adapter.Get(),/WITNESS_REQUIRED/);delete process.env.DESKTOP_RECOVERY_WITNESS_REQUIRED;assert.throws(()=>adapter.Resolve(data),/INDEPENDENT/);fs.mkdirSync(path.join(data,'nested'));assert.throws(()=>adapter.Resolve(path.join(data,'nested')),/INDEPENDENT/);assert.throws(()=>adapter.Resolve(path.dirname(data)),/INDEPENDENT/);
 },
 'strict-input-and-admin-boundary-contract':()=>{
  const guard=require('../services/desktopAdminGuard'),prefix='/api/desktop/bootstrap/server-state/';
  for(const p of ['recover-sessions','device-replacement','orphan-quarantine','orphan-delete','journal-checkpoint']){assert(guard.IsMutation(prefix+p));assert(guard.ReauthenticationRequired(prefix+p));assert.equal(guard.CheckSession({role:'viewer',id:'TEST'},prefix+p).ok,false);assert.equal(guard.CheckSession({role:'admin',id:'TEST'},prefix+p).reason,'ADMIN_REAUTH_REQUIRED');}
 },
};
(async()=>{try{const which=process.argv[2];if(which){assert(cases[which]);await cases[which]();console.log('PASS '+which);}else{let passed=0;for(const name of Object.keys(cases)){const p=spawnSync(process.execPath,[__filename,name],{cwd:root,encoding:'utf8',timeout:30000});process.stdout.write(p.stdout||'');process.stderr.write(p.stderr||'');assert.equal(p.status,0,name);passed++;}console.log('SERVER STORAGE PASS: '+passed+' groups; host startup/lock exercised, Windows execution not exercised');}}catch(e){console.error(e.stack);process.exitCode=1;}finally{fs.rmSync(data,{recursive:true,force:true});}})();
