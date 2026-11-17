'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const c=require('../../services/observability/peace.lifecycle-event-contract');
const root=path.resolve(__dirname,'../..'),native=path.resolve(root,'../Railway/Cozy.Source/Cozy.Lifecycle'),available=fs.existsSync(native);
test('native enum tables exactly derive from the deployed role/event/status schema',{skip:!available},()=>{
 const source=ReadContractFile(path.join(root,'contracts/runtime/peace.lifecycle-events-v1.json'),'utf8');
 assert.equal(ReadContractFile(path.join(native,'Cozy.Lifecycle.Events.inc'),'utf8'),require('../../tools/build/peace.generate-lifecycle-contract').render(source));
 const sourceUnit=ReadContractFile(path.join(native,'Cozy.Lifecycle.Contracts.pas'),'utf8');
 assert(sourceUnit.includes('{$I Cozy.Lifecycle.Events.inc}'));
});
test('all role pairs and event/status combinations share one explicit allowlist',()=>{
 let accepted=0;
 for(const reporter of [...c.spec.roles,'X'])for(const target of [...c.spec.roles,'X'])for(const e of c.spec.events)for(const status of [...new Set(c.spec.events.flatMap(x=>x.statuses)),'INVALID']){
  const roleAllowed=c.spec.roles.includes(reporter)&&c.spec.roles.includes(target)&&(reporter===target||c.spec.parentRole[reporter]===target||c.spec.failedChildRole[reporter]===target);
  const expected=roleAllowed&&e.statuses.includes(status)&&(reporter===target||e.scope==='self-or-parent')&&!(reporter===target&&e.selfForbidden?.includes(status))&&!(e.scope==='A-self'&&(reporter!=='A'||target!=='A'));
  assert.equal(c.combinationAllowed(reporter,target,e.name,status),expected,JSON.stringify({reporter,target,event:e.name,status}));if(expected)accepted++;
 }
 assert(accepted>0);
});
test('one-use batches reject duplicate/backward/false parent success and retain transfer order',()=>{
 assert(c.validate([{event:'CLOSE_RESPONSE',status:'ACKNOWLEDGED'},{event:'SHUTDOWN_BEGIN',status:'REQUESTED'}],'B','B'));
 assert(!c.validate([{event:'FILE_CLEANUP',status:'REMOVED'}],'O','B'));
 assert(!c.validate([{event:'FILE_CLEANUP',status:'FAILED'},{event:'PROCESS_EXIT',status:'OBSERVED'}],'O','B'));
 assert(!c.validate([{event:'PROCESS_EXIT',status:'TIMEOUT'},{event:'FILE_CLEANUP',status:'REMOVED'}],'B','A'));
 assert(c.validate([{event:'PROCESS_EXIT',status:'OBSERVED'},{event:'FILE_CLEANUP',status:'REMOVED'}],'B','A'));
 assert(c.validate([{event:'PROCESS_EXIT',status:'OBSERVED'},{event:'FILE_CLEANUP',status:'REMOVED'}],'B','O'));
 assert(!c.validate([{event:'SHUTDOWN_BEGIN',status:'REQUESTED'}],'B','O'));
 assert(!c.validate([{event:'FILE_CLEANUP',status:'REMOVED'}],'B','O'));
 assert(!c.validate([{event:'SHUTDOWN_BEGIN',status:'REQUESTED'},{event:'SHUTDOWN_BEGIN',status:'REQUESTED'}],'B','B'));
 // Stored events are checked individually. Batch ordering is enforced at new
 // ingestion, without erasing or refusing valid historical individual rows.
 assert(c.validate([{event:'FILE_CLEANUP',status:'REMOVED'}],'O','B',{ordered:false}));
});
test('diagnostic locking is nonblocking and actual observations remain separate',{skip:!available},()=>{
 const s=ReadContractFile(path.join(native,'Cozy.Lifecycle.pas'),'utf8').replaceAll('\r','');
 const note=s.split('procedure TLifecycleReporter.Note(')[1].split('procedure TLifecycleReporter.ObserveCleanup(')[0];
 assert.match(note,/if not TMonitor.Enter\(FLock,0\) then Exit/);
 assert(note.indexOf("Entry.AddPair('status'")<note.indexOf('C.Events.AddElement(Entry)'));
 assert.match(s,/C.EventState.Submitted := True/);
 assert.match(s,/if \(Reply = nil\) or \(Tick >= DeadlineTick\) then Exit/);
 assert.match(s,/Observation.ExitObserved and not Observation.ExitTimedOut/);
 assert.match(s,/Observation.FileRemoved and Observation.CleanupAttempted/);
});

test('closed runtime diagnostics cannot claim authority or another role failure',()=>{
 assert(c.validate([{event:'RENEWAL_FAILED',status:'TIMEOUT'},{event:'UI_RUNTIME_FAILURE',status:'FAILED'},{event:'SHUTDOWN_BEGIN',status:'REQUESTED'}],'O','O'));
 assert(c.validate([{event:'RENEWAL_FAILED',status:'FAILED'}],'O','O'));
 assert(!c.validate([{event:'RENEWAL_FAILED',status:'OBSERVED'}],'O','O'));
 assert(!c.validate([{event:'RENEWAL_FAILED',status:'TIMEOUT'}],'O','B'));
 assert(!c.validate([{event:'UI_RUNTIME_FAILURE',status:'FAILED'},{event:'UI_RUNTIME_FAILURE',status:'FAILED'}],'O','O'));
 const ui=fs.readFileSync(path.join(root,'public/scripts/desktop/peace.admin-desktop-server-state.js'),'utf8');
 assert.match(ui,/RENEWAL_FAILED:'오버레이 갱신 실패'/);assert.match(ui,/UI_RUNTIME_FAILURE:'오버레이 화면 오류'/);
});

test('startup stages are closed, role-bound and distinct from observed child exit',()=>{
 for(const stage of c.spec.startupStages){
  for(const role of ['A','B','O'])assert.equal(c.validate([{event:'STARTUP_FAILURE',status:'FAILED',exitCode:stage.code}],role,role),stage.roles.includes(role));
 }
 for(const code of [0,31029,31110,0x100000000,-1,NaN])assert(!c.validate([{event:'STARTUP_FAILURE',status:'FAILED',exitCode:code}],'A','A'));
 assert(!c.validate([{event:'STARTUP_FAILURE',status:'FAILED',exitCode:31107}],'B','A'));
 assert(!c.validate([{event:'STARTUP_FAILURE',status:'FAILED'}],'A','A'));
 assert.equal(c.childStartupStage(31006).label,'자식 역할 API 준비');assert.equal(c.childStartupStage(1),null);
});
test('A and B export only bounded handoff metadata with a separate observed child exit',{skip:!available},()=>{
 const railway=path.resolve(native,'..'),launcher=ReadContractFile(path.join(railway,'Cozy.Application/Cozy.Launcher.pas'),'utf8'),api=ReadContractFile(path.join(railway,'Cozy.Platform/Cozy.Api.pas'),'utf8');
 for(const source of [launcher,api]){assert.match(source,/EHandoff\(E\).StageCode >= 31101/);assert.match(source,/EHandoff\(E\).StageCode <= 31109/);assert.match(source,/FailedChild.ExitObserved and FailedChild.ExitCodeKnown/);assert.match(source,/'STARTUP_FAILURE'/);}
 const failure=launcher.slice(launcher.indexOf('StartupNativeError := 0;'),launcher.indexOf('finally\n    if Protection'));
 assert.doesNotMatch(failure,/GetLastError|E.Message/);assert.match(launcher,/begin FailedChild := Observation; end/);
});
