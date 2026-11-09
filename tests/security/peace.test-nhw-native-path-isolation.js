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
 assert.ok(submit.indexOf("ReadBoolean(Reply,'stopped')")>submit.indexOf('Reply.Count <> 9'));
 assert.ok(submit.includes('if FPendingBody = nil then'));
 assert.ok(submit.includes("Answer := FTransport.PostJSON('security', FPendingBody, 3000)"));
 assert.ok(submit.includes("Answer.GetValue('error').Value = 'SECURITY_CHALLENGE_INVALID'"));
 assert.ok(submit.includes('FPendingEvent.Tick := WinTick64'));
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
