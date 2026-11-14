'use strict';
// Source call-graph contracts, not native execution or a tamper-proof claim.
// Real signing/dispatch/replay behavior is tested separately by response-paths.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {test}=require('node:test');
const file=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas');
const raw=fs.readFileSync(file,'utf8');
// Preserve quoted text while removing comments; patterns cannot pass on comments.
function code(text){return text.replace(/'(?:''|[^'])*'|\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g,s=>s.startsWith("'")?s:'');}
function methods(text){
 const clean=code(text),matches=[...clean.matchAll(/^(?:procedure|function|constructor|destructor)\s+([A-Za-z_][A-Za-z0-9_.]*)\b/gm)],out=new Map();
 for(let i=0;i<matches.length;i++)out.set(matches[i][1],clean.slice(matches[i].index,matches[i+1]?.index??clean.length));
 return out;
}
const bodies=methods(raw),channels=['Trust','Driver','Integrity'];
function get(name,map=bodies){assert.ok(map.has(name),'missing native method '+name);return map.get(name);}
function assertPath(name,map=bodies){
 const worker=get('T'+name+'Worker.Execute',map),step=get('TCozyNHWResponseChannel.'+name+'Step',map),submit=get('TCozyNHWResponseChannel.Submit'+name,map);
 assert.match(worker,new RegExp('FOwner\\.'+name+'Step\\b'));
 assert.match(step,new RegExp('Submit'+name+'\\(FPendingEvent'));
 assert.match(step,new RegExp('AcknowledgeDetectionBatch\\(rpc'+name+', FPendingBatch\\)'));
 assert.ok(step.indexOf('Submit'+name+'(')<step.indexOf('AcknowledgeDetectionBatch('),'ACK precedes verified submission');
 for(const other of channels.filter(x=>x!==name)){
  assert.doesNotMatch(step,new RegExp('\\bSubmit'+other+'\\b'));
  assert.doesNotMatch(submit,new RegExp('\\bSubmit'+other+'\\b'));
 }
 assert.match(submit,new RegExp('FChannel <> rpc'+name));
 assert.match(submit,new RegExp('Event\\.Channel <> rpc'+name));
 assert.ok(submit.includes("Bind(Body, 'nhw"+name+"Challenge')"));
 assert.ok(submit.includes("Bind(Body, 'nhw"+name+"Submit')"));
 assert.ok(submit.includes("Canonical := 'COZY-NHW-"+name.toUpperCase()+"-RESPONSE-V1'"));
 assert.ok(submit.includes('FSecurity.Sign(Canonical)'));
 assert.equal((submit.match(/FTransport\.PostJSON\(/g)||[]).length,2,'channel lacks its own challenge and submission');
 assert.ok(submit.includes("ReadText(Challenge,'channel',16) <> '"+name.toLowerCase()+"'"));
 assert.ok(submit.includes("ReadText(Reply,'channel',16) <> '"+name.toLowerCase()+"'"));
 for(const field of ['sequence','digest','epoch','scope'])assert.ok(submit.includes("ReadText(Reply,'"+field+"'"));
 assert.ok(submit.includes("not ReadBoolean(Reply,'accepted') or ReadBoolean(Reply,'attested')"));
 const replyCheck=submit.indexOf('Reply.Count <> 10');
 assert.ok(replyCheck>=0,'v3 receipt must validate every response field');
 assert.ok(submit.indexOf("ReadBoolean(Reply,'stopped')")>replyCheck);
 assert.ok(submit.indexOf("ApplyServerReceipt(Reply.GetValue('peerContext'),Epoch,ReceiptStarted)")>replyCheck,'peer cache must only consume a checked server receipt');
 assert.ok(submit.includes('if FPendingBody = nil then'));
 assert.ok(submit.includes("Answer := FTransport.PostJSON('security', FPendingBody, 3000)"));
 assert.ok(submit.includes("Answer.GetValue('error').Value = 'SECURITY_CHALLENGE_INVALID'"));
 assert.ok(submit.includes('FPendingEvent.Tick := ObserverClockTick'));
 assert.doesNotMatch(submit,/FPendingBatch\s*:=|Records\[[^\]]+\]\.(?:FirstTick|LastTick)\s*:=/);
}
for(const name of channels)test(name+' has its own complete challenge/sign/send/ACK control path',()=>assertPath(name));
test('there is no generic response Submit dispatcher and shared encoder cannot perform responses',()=>{
 assert.ok(!bodies.has('TCozyNHWResponseChannel.Submit'));
 assert.doesNotMatch(code(raw),/\bSubmit\s*\(/);
 const encoder=get('EncodeDetectionPayload');
 assert.doesNotMatch(encoder,/FTransport|FSecurity|FPending|FServerStop|AcknowledgeDetectionBatch|\.PostJSON\(|\.Sign\(|ApplyAuthenticatedServerStop/);
 assert.ok(encoder.includes('NHWDetectionBatchCapacity'));
});
test('removing one submission control body leaves the other two complete source paths',()=>{
 for(const disabled of channels){
  const changed=new Map(bodies);changed.set('TCozyNHWResponseChannel.Submit'+disabled,'procedure disabled; begin end;');
  assert.throws(()=>assertPath(disabled,changed));
  for(const surviving of channels.filter(x=>x!==disabled))assertPath(surviving,changed);
 }
});
const authorityBodies=methods(fs.readFileSync(path.join(path.dirname(file),'Cozy.NHW.Authority.pas'),'utf8'));
function assertBoundedDrain(map=bodies,authority=authorityBodies){
 const own=name=>get('TCozyNHWResponseChannel.'+name,map);
 assert.match(own('WakeForFlush'),/TInterlocked\.Exchange\(FDraining, 1\)/);
 assert.match(own('WakeForFlush'),/TInterlocked\.Exchange\(FFlush, 1\)/);
 assert.match(own('EndFlush'),/TInterlocked\.Exchange\(FDraining, 0\)/);
 const prepare=own('PrepareBatch');
 assert.match(prepare,/FlushRequested\s*:=\s*TInterlocked\.Exchange\(FFlush, 0\)\s*<>\s*0/);
 assert.match(prepare,/FLastAttempt\s*<>\s*0[\s\S]*not FlushRequested[\s\S]*ObserverClockTick\s*-\s*FLastAttempt\s*<\s*1000[\s\S]*then Exit/);
 assert.doesNotMatch(prepare,/FDraining/); // No flush-wide retry bypass.
 assert.match(prepare,/if Result then\s*begin\s*FDetectionGuard\.SecurityContext\.PrepareLocalIdentity;\s*FLastAttempt\s*:=\s*ObserverClockTick;\s*end;/);
 let resets=0;
 for(const [name,body] of map){
  const count=(body.match(/FLastAttempt\s*:=\s*0/g)||[]).length;
  if(count)assert.ok(channels.some(channel=>name==='TCozyNHWResponseChannel.'+channel+'Step'));
  resets+=count;
 }
 assert.equal(resets,3);
 for(const channel of channels){
  const step=own(channel+'Step'),submit=step.indexOf('Submit'+channel+'(FPendingEvent');
  const acknowledge=step.indexOf('AcknowledgeDetectionBatch(rpc'+channel),clear=step.indexOf('ClearPending;',acknowledge),reset=step.indexOf('FLastAttempt := 0');
  assert.ok(submit>=0&&acknowledge>submit&&clear>acknowledge&&reset>clear,channel);
  assert.match(step.slice(clear,reset+20),/if TInterlocked\.CompareExchange\(FDraining, 0, 0\)\s*<>\s*0 then FLastAttempt\s*:=\s*0/);
  assert.ok(step.indexOf('finally',reset)>reset);
  assert.doesNotMatch(step,/\bexcept\b/); // Failed submit cannot fall through to progress/reset.
  assert.match(get('T'+channel+'Worker.Execute',map),new RegExp('try FOwner\\.'+channel+'Step; except[\\s\\S]*?end;\\s*if not FOwner\\.Wait then Exit;'));
 }
 assert.match(own('Wait'),/FWake\.WaitFor\(50\)/);
 const drain=get('TCozyNHWAuthority.FlushSecurityReports',authority);
 assert.match(drain,/if TimeoutMS\s*>\s*7000 then TimeoutMS\s*:=\s*7000/);
 assert.match(drain,/try[\s\S]*ObserverClockTick\s*-\s*Started\s*>=\s*TimeoutMS[\s\S]*finally[\s\S]*FResponses\[Channel\]\.EndFlush/);
}
test('bounded drain advances acknowledged batches, retains failure backoff and always exits drain mode',()=>{
 assertBoundedDrain();
 const journal=fs.readFileSync(path.join(path.dirname(file),'Cozy.NHW.DetectionJournal.pas'),'utf8');
 assert.match(code(journal),/NHWDetectionBatchCapacity\s*=\s*12/);
 assert.match(get('EncodeDetectionPayload'),/Length\(TEncoding\.UTF8\.GetBytes\(PayloadText\)\)>16384/,'context batches must retain the bounded deployed wire contract');
});
test('a global retry bypass, premature progress reset or missing drain cleanup is detected',()=>{
 const bypass=new Map(bodies),prepare='TCozyNHWResponseChannel.PrepareBatch';
 bypass.set(prepare,get(prepare).replace('not FlushRequested','not FlushRequested and (FDraining = 0)'));
 assert.throws(()=>assertBoundedDrain(bypass));
 for(const channel of channels){
  const changed=new Map(bodies),name='TCozyNHWResponseChannel.'+channel+'Step',body=get(name);
  const reset='if TInterlocked.CompareExchange(FDraining, 0, 0) <> 0 then FLastAttempt := 0;';
  changed.set(name,body.replace(reset,'').replace('Submit'+channel+'(FPendingEvent',reset+' Submit'+channel+'(FPendingEvent'));
  assert.throws(()=>assertBoundedDrain(changed));
 }
 const noCleanup=new Map(authorityBodies),name='TCozyNHWAuthority.FlushSecurityReports';
 noCleanup.set(name,get(name,authorityBodies).replace('FResponses[Channel].EndFlush','FResponses[Channel].HasPending'));
 assert.throws(()=>assertBoundedDrain(bodies,noCleanup));
});

// Recovery may request an ordinary measurement; it must never manufacture a
// lease, perform API work on a sensor callback, or race the inventory owner.
test('coverage revalidation stays bounded and is consumed by each role owner',()=>{
 const native=path.resolve(path.dirname(file),'..'),read=p=>code(fs.readFileSync(path.join(native,p),'utf8'));
 const guard=methods(read('Cozy.Security.NHW/Cozy.NHW.Guard.pas'));
 const record=get('TCozyNHWGuard.RecordIntegrityDetections',guard);
 for(const kind of ['dkETWLoss','dkCoverageGap','dkObservationUncertain','dkSensorPressure','dkTraceGap','dkKernelTelemetryGap'])assert.ok(record.includes(kind));
 assert.match(record,/Tick-UInt64\(Previous\)>=30000/);
 assert.match(record,/TInterlocked\.Exchange\(FRevalidationRequested,1\)/);
 assert.doesNotMatch(record,/PostJSON|CheckIntegrity|CollectModule|MaintainLease|\bRefresh\b|Renew|StopAndJoin/);
 assert.match(get('TCozyNHWGuard.ConsumeRevalidationRequest',guard),/TInterlocked\.Exchange\(FRevalidationRequested,0\)/);
 const a=read('Cozy.Application/Cozy.Launcher.pas');
 assert.match(a,/CozyTick - Started >= DownloadDeadlineMS[\s\S]*?Watch\.ConsumeRevalidationRequest[\s\S]*?Assigned\(Revalidate\) then Revalidate\(\);\s*RequireLauncherWatch\(Watch\);\s*Bytes := Client\.Chunk/);
 const b=methods(read('Cozy.Platform/Cozy.Api.pas')),modules=get('TGameApi.ReportModulesIfDue',b);
 assert.match(modules,/\(FModuleSnapshot = nil\) and \(FNHWGuard <> nil\) and\s*FNHWGuard\.ConsumeRevalidationRequest then\s*begin\s*CheckIntegrityCore;\s*FNextModules := 0;\s*end/);
 assert.ok(modules.indexOf('RequireModuleSnapshotLease;')>modules.indexOf('ConsumeRevalidationRequest'));
 const o=read('Cozy.Overlay/Cozy.Overlay.pas');
 assert.match(o,/if FParentRetirementDone and \(FWatch <> nil\) and\s*FWatch\.ConsumeRevalidationRequest then\s*begin\s*FLastSnapshotAt := 0;\s*NextCheck := CozyTick;\s*end;\s*if not FParentRetirementDone/);
 const etw=methods(read('Cozy.Security.NHW/Cozy.NHW.ETW.pas')),recover=get('TETWMonitor.TryRecover',etw);
 assert.match(recover,/if Stopping or \(Tick = 0\) then Exit/);
 assert.match(recover,/ProcessingStopped then Exit;\s*if WaitForSingleObject\(FWorker.Handle, 0\) <> WAIT_OBJECT_0 then Exit/);
 assert.match(recover,/Tick - FLastRecoveryTick < ETW_RECOVERY_BACKOFF_MS/);
 assert.match(recover,/MarkCallbackLoss;\s*TryStartAt\(Tick\)/);
 assert.match(read('Cozy.Security.NHW/Cozy.NHW.Engine.pas'),/KernelTrace.TryRecover\(WinTick64\);\s*KernelTrace.Drain/);
});
