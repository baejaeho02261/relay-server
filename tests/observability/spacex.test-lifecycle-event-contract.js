'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/spacex.native-string-contract");
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const c=require('../../services/observability/spacex.lifecycle-event-contract');
const root=path.resolve(__dirname,'../..'),native=path.resolve(root,'../Desktop/SpaceX.Source/SpaceX.Lifecycle'),available=fs.existsSync(native);
test('native enum tables exactly derive from the deployed role/event/status schema',{skip:!available},()=>{
 const source=ReadContractFile(path.join(root,'contracts/runtime/spacex.lifecycle-events-v1.json'),'utf8');
 assert.equal(ReadContractFile(path.join(native,'SpaceX.Lifecycle.Events.inc'),'utf8'),require('../../tools/build/spacex.generate-lifecycle-contract').render(source));
 const sourceUnit=ReadContractFile(path.join(native,'SpaceX.Lifecycle.Contracts.pas'),'utf8');
 assert(sourceUnit.includes('{$I SpaceX.Lifecycle.Events.inc}'));
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
 const s=ReadContractFile(path.join(native,'SpaceX.Lifecycle.pas'),'utf8').replaceAll('\r','');
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
 const ui=fs.readFileSync(path.join(root,'public/scripts/desktop/spacex.admin-desktop-server-state.js'),'utf8');
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
 const railway=path.resolve(native,'..'),launcher=ReadContractFile(path.join(railway,'SpaceX.Application/SpaceX.Launcher.pas'),'utf8'),api=ReadContractFile(path.join(railway,'SpaceX.Platform/SpaceX.Api.pas'),'utf8');
 for(const source of [launcher,api]){assert.match(source,/EHandoff\(E\).StageCode >= 31101/);assert.match(source,/EHandoff\(E\).StageCode <= 31109/);assert.match(source,/FailedChild.ExitObserved and FailedChild.ExitCodeKnown/);assert.match(source,/'STARTUP_FAILURE'/);}
 const failure=launcher.slice(launcher.indexOf('StartupNativeError := 0;'),launcher.indexOf('finally\n    if Protection'));
 assert.doesNotMatch(failure,/GetLastError|E.Message/);assert.match(launcher,/begin FailedChild := Observation; end/);
});


test('B pre-claim stages remain closed child-exit annotations with complete native coverage',()=>{
 const codes=[...Array.from({length:11},(_,i)=>31200+i),...Array.from({length:17},(_,i)=>31300+i),...Array.from({length:7},(_,i)=>31400+i)];
 assert.equal(new Set(c.spec.childStartupStages.map(stage=>stage.code)).size,c.spec.childStartupStages.length);
 for(const code of codes){
  const stage=c.childStartupStage(code);assert.equal(stage.code,code);assert(stage.label.length>0);
  for(const role of c.spec.roles)assert.equal(c.startupStage(code,role),null,'child code is never an authoritative self-stage');
 }
 for(const code of [31211,31317,31407,'31404',NaN])assert.equal(c.childStartupStage(code),null);
 assert.equal(c.childStartupStage(31314).label,'B 코드 무결성 측정 계획 생성');
 assert.equal(c.childStartupStage(31404).label,'B Claim 서버 요청');
 assert.equal(c.startupStage(31107,'A').label,'자식 초기 응답 대기');
 if(!available)return;
 const railway=path.resolve(native,'..'),sources=['SpaceX.License/SpaceX.License.Session.pas','SpaceX.Handoff/SpaceX.Handoff.pas','SpaceX.Application/SpaceX.Bootstrap.pas'].map(file=>ReadContractFile(path.join(railway,file),'utf8'));
 const nativeCodes=sources.flatMap(source=>[...source.matchAll(/\bStage\((31[234]\d{2})\)/g)].map(match=>Number(match[1])));
 const claim=sources[2].split('function TBootstrapClient.Claim(')[1].split('function TBootstrapClient.InvokeServerPolicy(')[0];
 assert.match(claim,/DiagnosticCode\^ := 31400;/);nativeCodes.push(31400);
 assert.deepEqual(nativeCodes.sort((a,b)=>a-b),codes);
});


test('A download phases use self stages and never imply a B claim',()=>{
 for(let code=31501;code<=31507;code++){
  assert.equal(c.startupStage(code,'A').code,code);
  for(const role of ['B','O'])assert.equal(c.startupStage(code,role),null);
  assert.equal(c.childStartupStage(code),null);
 }
 assert.equal(c.startupStage(31501,'A').label,'B 파일 수신');
 if(!available)return;
 const source=ReadContractFile(path.resolve(native,'../SpaceX.Application/SpaceX.Launcher.pas'),'utf8');
 const download=source.split('function DownloadVerifiedBinary(')[1].split('function RunLauncher(')[0];
 assert.deepEqual([...download.matchAll(/\bStage\((315\d{2})\)/g)].map(match=>Number(match[1])),[31501,31502,31503,31504,31505,31506,31507]);
 assert.match(source,/DownloadVerifiedBinary\(Client, Flow, BinaryPath, CreatedInfo, Lifecycle, Protection, @Result\)/);
 const diagnostic=source.slice(source.indexOf('StartupNativeError := 0;'),source.indexOf('{ No exception text, credentials or diagnostic files'));
 assert.match(diagnostic,/Lifecycle\.Prepare\('A', Flow\.FlowID, Flow\.DownloadTicket,\s*TLifecycleReporter\.Tick \+ 1500, True\);/);
 assert(diagnostic.indexOf('Lifecycle.Prepare(')<diagnostic.indexOf("Lifecycle.Note('A', 'STARTUP_FAILURE'"));
 assert.doesNotMatch(diagnostic.slice(diagnostic.indexOf('Lifecycle.Prepare(')),/Result\s*:=/);
});
