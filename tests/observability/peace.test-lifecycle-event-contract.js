'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const c=require('../../services/observability/peace.lifecycle-event-contract');
const root=path.resolve(__dirname,'../..'),native=path.resolve(root,'../Railway/Cozy.Source/Cozy.Lifecycle'),available=fs.existsSync(native);
test('native enum tables exactly derive from the deployed role/event/status schema',{skip:!available},()=>{
 const source=fs.readFileSync(path.join(root,'contracts/runtime/peace.lifecycle-events-v1.json'),'utf8');
 assert.equal(fs.readFileSync(path.join(native,'Cozy.Lifecycle.Events.inc'),'utf8'),require('../../tools/build/peace.generate-lifecycle-contract').render(source));
 const sourceUnit=fs.readFileSync(path.join(native,'Cozy.Lifecycle.Contracts.pas'),'utf8');
 assert(sourceUnit.includes('{$I Cozy.Lifecycle.Events.inc}'));
});
test('all role pairs and event/status combinations share one explicit allowlist',()=>{
 let accepted=0;
 for(const reporter of [...c.spec.roles,'X'])for(const target of [...c.spec.roles,'X'])for(const e of c.spec.events)for(const status of [...new Set(c.spec.events.flatMap(x=>x.statuses)),'INVALID']){
  const roleAllowed=c.spec.roles.includes(reporter)&&c.spec.roles.includes(target)&&(reporter===target||c.spec.parentRole[reporter]===target);
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
 assert(!c.validate([{event:'SHUTDOWN_BEGIN',status:'REQUESTED'},{event:'SHUTDOWN_BEGIN',status:'REQUESTED'}],'B','B'));
 // Stored events are checked individually. Batch ordering is enforced at new
 // ingestion, without erasing or refusing valid historical individual rows.
 assert(c.validate([{event:'FILE_CLEANUP',status:'REMOVED'}],'O','B',{ordered:false}));
});
test('diagnostic locking is nonblocking and actual observations remain separate',{skip:!available},()=>{
 const s=fs.readFileSync(path.join(native,'Cozy.Lifecycle.pas'),'utf8').replaceAll('\r','');
 const note=s.split('procedure TLifecycleReporter.Note(')[1].split('procedure TLifecycleReporter.ObserveCleanup(')[0];
 assert.match(note,/if not TMonitor.Enter\(FLock,0\) then Exit/);
 assert(note.indexOf("Entry.AddPair('status'")<note.indexOf('C.Events.AddElement(Entry)'));
 assert.match(s,/C.EventState.Submitted := True/);
 assert.match(s,/if \(Reply = nil\) or \(Tick >= DeadlineTick\) then Exit/);
 assert.match(s,/Observation.ExitObserved and not Observation.ExitTimedOut/);
 assert.match(s,/Observation.FileRemoved and Observation.CleanupAttempted/);
});
