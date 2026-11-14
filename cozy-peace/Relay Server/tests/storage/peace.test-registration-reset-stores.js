'use strict';
// Real isolated stores and restart/rollback checks; no uploaded executable runs.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const root=path.resolve(__dirname,'../..'),directory=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-registration-reset-stores-'));
Object.assign(process.env,{DATA_DIR:directory,STORAGE_ENGINE:'json',NODE_ENV:'test',HA_ENABLED:'0',DESKTOP_RECOVERY_WITNESS_DIR:'',DESKTOP_RECOVERY_WITNESS_URL:'',DESKTOP_RECOVERY_WITNESS_REQUIRED:'0'});
delete process.env.COZY_REGISTRATION_RESET_ID;delete process.env.COZY_REGISTRATION_RESET_SCOPE;
const id='e1'.repeat(32),sha=bytes=>crypto.createHash('sha512').update(bytes).digest('hex'),reject=fn=>assert.throws(fn,{message:'REGISTRATION_RESET_NOT_AUTHORIZED'});
function restart(source){const result=cp.spawnSync(process.execPath,['-e',source],{cwd:root,env:process.env,encoding:'utf8',timeout:30000});assert.equal(result.status,0,result.stderr||result.stdout);return result.stdout;}
function dll(){
 const bytes=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture').PE('B','registration reset baseline'),pe=bytes.readUInt32LE(0x3c),opt=pe+24;
 bytes.writeUInt16LE(bytes.readUInt16LE(pe+22)|0x2000,pe+22);bytes.writeUInt32LE(0x1100,opt+112);bytes.writeUInt32LE(0x80,opt+116);bytes.fill(0,768,896);bytes.writeUInt32LE(0x1150,780);bytes.writeUInt32LE(1,784);bytes.writeUInt32LE(1,788);bytes.writeUInt32LE(1,792);bytes.writeUInt32LE(0x1130,796);bytes.writeUInt32LE(0x1134,800);bytes.writeUInt32LE(0x1138,804);bytes.writeUInt32LE(0x1000,816);bytes.writeUInt32LE(0x1140,820);bytes.write('ApiFunction\0',832,'ascii');bytes.write('fixture.dll\0',848,'ascii');return bytes;
}
try{
 require('../../core/peace.utilities').EnsureDirs();require('../../storage/audit/peace.audit').LoadRecentAudit();
 const bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap-store'),prepare=require('../../services/bootstrap/peace.desktop-registration-reset'),machine=require('../../services/devices/peace.desktop-machine-policy'),integrity=require('../../services/integrity/peace.desktop-integrity-reports'),workspace=require('../../services/operations/peace.desktop-workspace-store'),helper=require('../../services/operations/peace.registration-reset-stores');
 bootstrap.Load();workspace.Load();machine.Load();integrity.Policy();
 machine.Set('A'.repeat(64),false,{reason:'Reset fixture existing PC',requestId:'reset-fixture-machine'},'TEST');
 integrity.RegisterBaseline('ntdll.dll','Reset fixture',dll(),'TEST');integrity.SetPolicy({enabled:true,requireExtendedHashes:true,requiredModules:['ntdll.dll']},'TEST');
 integrity.Record({stage:'B',check:'RESET_FIXTURE',status:'CLIENT_DIAGNOSTIC',sessionId:'B'.repeat(24),snapshotFinal:true,snapshotId:'reset-fixture',snapshotStatus:'COMPLETE_PASS',strictPolicyRevision:integrity.Policy().revision});
 workspace.Atomic(next=>{next.metadata['A'.repeat(24)]={note:'existing',tags:[],revision:1};next.jobs['b'.repeat(32)]={id:'b'.repeat(32),kind:'CREATE',status:'QUEUED',createdAt:Date.now(),items:[{status:'PENDING',input:{label:'existing'}}]};next.receipts.fixture={jobId:'b'.repeat(32)};next.releaseNotes['A'.repeat(24)+':'+ 'B'.repeat(24)]={note:'existing',updatedAt:Date.now(),updatedBy:'TEST'};},{kind:'RESET_FIXTURE',actor:'TEST'});
 const policy=helper.Counts().integrity.policy,keys={machine:sha(fs.readFileSync(machine.KEY)),integrity:sha(fs.readFileSync(integrity.KEY)),bootstrap:bootstrap.Load().secret},oldMachine=fs.readFileSync(machine.FILE),oldIntegrity=fs.readFileSync(integrity.FILE),oldWorkspace=fs.readFileSync(workspace.FILE);
 reject(()=>helper.Run(id));assert.deepEqual(fs.readFileSync(machine.FILE),oldMachine);assert.deepEqual(fs.readFileSync(integrity.FILE),oldIntegrity);assert.deepEqual(fs.readFileSync(workspace.FILE),oldWorkspace);
 Object.assign(process.env,{COZY_REGISTRATION_RESET_ID:id,COZY_REGISTRATION_RESET_SCOPE:helper.SCOPE});reject(()=>helper.Run(id));
 prepare.Prepare(id);const before=helper.Counts();assert.equal(before.machine.bindings,1);assert.equal(before.integrity.baselines,1);assert.equal(before.integrity.observations,1);
 process.env.COZY_REGISTRATION_RESET_SCOPE='WRONG_SCOPE';reject(()=>helper.Run(id));process.env.COZY_REGISTRATION_RESET_SCOPE=helper.SCOPE;reject(()=>helper.Run('e2'.repeat(32)));
 const result=helper.Run(id),after=helper.Counts();assert.equal(result.machine.bindings,1);assert.equal(result.machine.receipts,1);assert.equal(result.integrity.baselines,1);assert.equal(result.integrity.records,1);assert.equal(result.workspace.metadata,1);
 for(const key of ['bindings','receipts'])assert.equal(after.machine[key],0);for(const key of ['records','baselines','observations'])assert.equal(after.integrity[key],0);for(const key of ['metadata','jobs','receipts','releaseNotes'])assert.equal(after.workspace[key],0);
 assert.deepEqual(after.integrity.policy,policy);assert.equal(integrity.Policy().enabled,true);assert.equal(integrity.Policy().baselineReady,false);assert.equal(sha(fs.readFileSync(machine.KEY)),keys.machine);assert.equal(sha(fs.readFileSync(integrity.KEY)),keys.integrity);assert.equal(bootstrap.Load().secret,keys.bootstrap);
 assert.ok(after.machine.sequence>before.machine.sequence);assert.ok(after.integrity.revision>before.integrity.revision);assert.ok(after.workspace.revision>before.workspace.revision);
 assert.equal(bootstrap.Load().workspaceJournal.current.revision,workspace.Load().revision);assert.equal(bootstrap.Load().workspaceJournal.current.sha512,sha(fs.readFileSync(workspace.FILE)));
 // A lost coordinator response must not clear new records on a retry, including
 // after machine-journal compaction and a fresh process loading every store.
 machine.Set('C'.repeat(64),false,{reason:'Registration after reset step',requestId:'reset-new-machine'},'TEST');integrity.Record({stage:'A',check:'RESET_NEW_RECORD',status:'CLIENT_DIAGNOSTIC'});workspace.Atomic(next=>{next.metadata['D'.repeat(24)]={note:'new',tags:[],revision:1};},{kind:'RESET_NEW_METADATA',actor:'TEST'});
 machine.Compact();const later=helper.Counts(),repeated=helper.Run(id);assert.equal(repeated.machine.duplicate,true);assert.equal(repeated.integrity.duplicate,true);assert.equal(repeated.workspace.duplicate,true);assert.deepEqual(helper.Counts(),later);
 const inspectPath=JSON.stringify(require.resolve('../../services/operations/peace.registration-reset-stores')),assertPath=JSON.stringify(require.resolve('node:assert/strict'));
 const child=`const assert=require(${assertPath}),helper=require(${inspectPath}),before=helper.Counts(),r=helper.Run(${JSON.stringify(id)});assert.equal(before.machine.bindings,1);assert.equal(before.integrity.records,1);assert.equal(before.workspace.metadata,1);assert.equal(r.machine.duplicate,true);assert.deepEqual(helper.Counts(),before);console.log('RESTART_RESET_RECEIPTS_OK');`;
 assert.match(restart(child),/RESTART_RESET_RECEIPTS_OK/);
 // The existing authenticated heads still reject pre-reset file rollback.
 fs.writeFileSync(integrity.FILE,oldIntegrity);const childFailure=cp.spawnSync(process.execPath,['-e',`require(${inspectPath}).Counts()`],{cwd:root,env:process.env,encoding:'utf8',timeout:30000});assert.notEqual(childFailure.status,0);assert.match(childFailure.stderr,/DESKTOP_INTEGRITY_CORRUPT/);
 console.log('REGISTRATION RESET STORES PASS: authorization, forward heads, unchanged keys and policy, empty registrations, workspace binding, restart/compaction replay, rollback refusal.');
}finally{fs.rmSync(directory,{recursive:true,force:true});}
