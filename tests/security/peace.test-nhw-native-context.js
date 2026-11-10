'use strict';
// Native source contracts. These execute on Node, not on Windows/dcc64.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {test}=require('node:test');
const root=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW');
const read=name=>fs.readFileSync(path.join(root,'Cozy.NHW.'+name+'.pas'),'utf8');
const clean=text=>text.replace(/'(?:''|[^'])*'|\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g,s=>s.startsWith("'")?s:'');
function methods(source){
 const code=clean(source), matches=[...code.matchAll(/^(?:function|procedure|constructor|destructor)\s+([\w.]+)/gm)];
 return new Map(matches.map((m,i)=>[m[1],code.slice(m.index,matches[i+1]?.index??code.length)]));
}
const context=methods(read('Context')),journal=methods(read('DetectionJournal'));
const method=(map,name)=>{assert.ok(map.has(name),name);return map.get(name);};

function checkReceipt(map){
 const body=method(map,'TCozySecurityContext.ApplyServerReceipt');
 for(const text of ["Text(Obj,'epoch') <> Epoch","'SERVER_BOUND_CLIENT_OBSERVATION'",
  'Sequence <= FLastServerSequence','Peer','SelfIndex','Peers[SelfIndex].CreationTime<>FLocal.CreationTime',
  'Peers[SelfIndex].ImageSHA256<>FLocal.ImageSHA256','Peers[SelfIndex].ImageSHA512<>FLocal.ImageSHA512',
  "Number(Item,'ttlMs')",'if PID>TTL then PID:=TTL','NHW_PEER_DUPLICATE','NHW_PEER_IDENTITY_INVALID'])
  assert.ok(body.includes(text),text);
 assert.ok(body.indexOf('Sequence <= FLastServerSequence')<body.indexOf('Move(Peers, FPeers'));
 assert.ok(body.includes('RequestElapsed>=UInt64(TTL)'));
 assert.ok(body.includes('Dec(PID,Int64(RequestElapsed))'));
 assert.ok(body.includes('ValidRolePhase(string(Peers[I].Role),S)'));
}
test('peer cache is exact identity/epoch/sequence/TTL bound and is not hardware authority',()=>checkReceipt(context));
test('dropping the receipt replay guard is caught',()=>{
 const altered=new Map(context),name='TCozySecurityContext.ApplyServerReceipt';
 altered.set(name,method(altered,name).replace('Sequence <= FLastServerSequence','Sequence < 0'));
 assert.throws(()=>checkReceipt(altered));
});
test('actual actor lifetime is required and target state is never promoted to an actor',()=>{
 const body=method(context,'TCozySecurityContext.ActorObservation');
 for(const text of ['ActorPID=0','ActorCreation=0','Peer.PID<>ActorPID','Peer.CreationTime<>ActorCreation','Peer.ExpiresTick<=Tick'])
  assert.ok(body.includes(text),text);
 assert.ok(body.includes("Result.ActorClass := 'EXTERNAL'"));
 assert.ok(body.includes('Result.AccessMask := AccessMask'));
 const unknown=method(context,'TCozySecurityContext.Observation');
 assert.ok(unknown.includes("Result.ActorClass := 'UNKNOWN'"));
 assert.doesNotMatch(unknown,/TRUSTED_|ActorIdentity\s*:=\s*FLocal/);
 const token=method(context,'NHWNoteTokenDelta');
 assert.ok(token.includes("ActorObservation(0,0,TargetPID,'TOKEN_STATE'"));
});
test('all typed kinds are covered before logging, with separately retained benign observations',()=>{
 const engine=clean(read('Engine'));
 assert.match(engine,/ReportKinds := Detected \+ NHWContextObservations/);
 assert.match(engine,/for Kind := Low\(TDetectionKind\) to High\(TDetectionKind\) do\s*if Kind in ReportKinds then/);
 assert.ok(engine.indexOf('NHWBeginContextCycle(')<engine.indexOf('KernelTrace.WakeHandle'));
 const guard=methods(read('Guard'));
 for(const channel of ['Trust','Driver','Integrity']){
  const body=method(guard,'TCozyNHWGuard.Record'+channel+'Detections');
  assert.ok(body.includes('Low(TDetectionKind) to High(TDetectionKind)'));
  assert.ok(body.includes('NHWReadDetectionContext(Kind, FSecurityContext)'));
  assert.ok(body.includes('AppendContext([Kind]'));
 }
});
test('each response path freezes the peer envelope and processes only an authenticated reply',()=>{
 const transport=methods(read('ResponseTransport'));
 for(const channel of ['Trust','Driver','Integrity']){
  const step=method(transport,'TCozyNHWResponseChannel.'+channel+'Step');
  assert.ok(step.indexOf('if not FHasPending then')<step.indexOf('FPendingPeer := FDetectionGuard.SecurityContext.PeerPayload'));
  const submit=method(transport,'TCozyNHWResponseChannel.Submit'+channel);
  assert.ok(submit.includes('Batch, FPendingPeer, PayloadText, DigestText'));
  assert.ok(submit.indexOf('ApplyServerReceipt')>submit.indexOf('Reply.Count <> 10'));
  assert.ok(submit.includes('ReceiptStarted := FPendingReceiptStarted'));
  assert.ok(submit.includes("ApplyServerReceipt(Reply.GetValue('peerContext'),Epoch,ReceiptStarted)"));
 }
 const encoder=method(transport,'EncodeDetectionPayload');
 assert.ok(encoder.includes("Payload.AddPair('version', TJSONNumber.Create(4))"));
 assert.ok(encoder.includes("Detection.AddPair('signal'"));
 assert.ok(encoder.includes("Detection.AddPair('context', NHWContextJSON"));
 assert.ok(encoder.includes('>16384'));
 assert.doesNotMatch(encoder,/\.PostJSON\(|\.Sign\(|ApplyServerReceipt/);
});
test('journal keeps independent bounded actor lanes and preserves original attack time until ACK',()=>{
 const source=clean(read('DetectionJournal'));
 assert.match(source,/NHWDetectionBatchCapacity = 12/);
 assert.match(source,/NHWDetectionContextLanes = 4/);
 const append=method(journal,'TNHWDetectionJournal.AppendContext');
 assert.ok(append.includes('NHWSameObservationContext'));
 assert.ok(append.includes('FDeferred[Origin,Kind,Lane]:=Deferred'));
 assert.ok(append.includes('NHWContextRisk(Item.Context) > NHWContextRisk(Context)'));
 const defer=append.indexOf('FDeferred[Origin,Kind,Lane]:=Deferred');
 assert.ok(append.indexOf('Continue;',defer)<append.indexOf('Item.LastTick := Tick',defer));
 const ack=method(journal,'TNHWDetectionJournal.Acknowledge');
 assert.ok(ack.includes('Item.ContextLane >= NHWDetectionContextLanes'));
 assert.ok(ack.includes('FDeferred[Item.Origin,Item.Kind,Item.ContextLane].Revision>Item.Revision'));
});
test('context has no application-unit dependencies or local disk writer and clears RAM on shutdown',()=>{
 const source=clean(read('Context'));
 assert.doesNotMatch(source,/Cozy\.Integrity\b|Cozy\.Security\b|WriteFile\(|TFileStream\.Create|SaveToFile|AppendAllText/);
 assert.match(method(context,'TCozySecurityContext.Clear'),/FillChar\(FPeers, SizeOf\(FPeers\), 0\)/);
 assert.match(method(context,'NHWLeaveSensorContext'),/FillChar\(CycleContext,SizeOf\(CycleContext\),0\)/);
 assert.match(method(context,'NHWCaptureProcessIdentity'),/NHWCancellationRequested/);
 const prepare=method(context,'TCozySecurityContext.PrepareLocalIdentity');
 assert.match(prepare,/FILE_SHARE_READ or FILE_SHARE_DELETE/);
 assert.match(prepare,/except[\s\S]*finally TInterlocked\.Exchange\(FPreparing,0\)/);
 assert.match(method(context,'TCozySecurityContext.Clear'),/if FLock=nil then Exit/);
});
test('coverage recovery remains bounded background work and does not count as an attack vote',()=>{
 const engine=clean(read('Engine'));
 assert.match(engine,/KernelTrace\.TryRecover\(WinTick64\);\s*KernelTrace\.Drain/);
 const guard=methods(read('Guard'));
 assert.match(method(guard,'TCozyNHWGuard.ConsumeRevalidationRequest'),/TInterlocked\.Exchange\(FRevalidationRequested,0\)/);
 assert.match(method(guard,'TCozyNHWGuard.RecordIntegrityDetections'),/Tick-UInt64\(Previous\)>=30000/);
});

function checkFirstReceiptClock(source){
 const transport=methods(source);
 for(const channel of ['Trust','Driver','Integrity']){
  const submit=method(transport,'TCozyNHWResponseChannel.Submit'+channel);
  assert.match(submit,/if FPendingReceiptStarted = 0 then\s*FPendingReceiptStarted := ObserverClockTick;\s*ReceiptStarted := FPendingReceiptStarted;/);
  assert.equal((submit.match(/FPendingReceiptStarted\s*:=/g)||[]).length,1);
  assert.doesNotMatch(submit,/FPendingReceiptStarted\s*:=\s*0/);
 }
 const clear=method(transport,'TCozyNHWResponseChannel.ClearPending');
 assert.match(clear,/FPendingReceiptStarted := 0/);
 const outsideClear=[...transport].filter(([name])=>name!=='TCozyNHWResponseChannel.ClearPending').map(([,body])=>body).join('\n');
 assert.doesNotMatch(outsideClear,/FPendingReceiptStarted\s*:=\s*0/);
}
test('lost ACK retries keep the original receipt TTL clock until the immutable batch is cleared',()=>{
 const source=read('ResponseTransport');
 checkFirstReceiptClock(source);
 assert.throws(()=>checkFirstReceiptClock(source.replace('if FPendingReceiptStarted = 0 then','if True then')));
});
