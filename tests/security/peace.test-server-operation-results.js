'use strict';
// Isolated state-machine checks of production module. Authentication is stubbed
// here for deterministic capacity/clocks; real auth+TLS is covered separately.
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
function fixture() {
 const filename=path.resolve(__dirname,'../../services/security/peace.server-policy-operations.js');
 const state={wall:1790000000000,mono:0,revision:1,operationsRevision:1,evals:0,live:true,fresh:true,valid:true};
 const artifact={id:'artifact',sha512:'a'.repeat(128)},record={policySha512:'b'.repeat(128)};
 const row={id:'A'.repeat(24),publicKey:'fixture-public-key',launcherId:'launcher'};
 const fail=code=>{throw Error(code);};
 const mocks={
  'result-test-clock':{now:()=>state.wall},
  '../runtime/peace.desktop-deadline':{After:ms=>({expiresAt:state.wall+ms,mono:state.mono+ms}),Expired:r=>state.wall>=r.expiresAt||state.mono>=r.mono},
  '../bootstrap/peace.desktop-bootstrap-store':{Load:()=>({artifacts:{artifact},launchers:{launcher:{artifactId:'artifact'}}})},
  './peace.server-policy-registry':{InvocationRecord:()=>record},
  '../artifacts/peace.server-policy-protection':{EvaluateServerPolicy:()=>{state.evals++;return 42;}},
  '../bootstrap/peace.desktop-bootstrap':{EnsureSecurityAvailable:()=>{},AuthenticateIntegrityReport:b=>{if(!state.live)fail('SESSION_REVOKED');if(b.sessionToken!=='t'.repeat(24))fail('SESSION_TOKEN_INVALID');return row;},RequireFlowPair:()=>{}},
  '../devices/peace.desktop-device-identity':{AssertSession:()=>{}},
  './peace.desktop-security-authority':{Policy:()=>({revision:state.revision}),RequireArtifact:()=>{},RequireFresh:()=>{if(!state.fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');}},
  './peace.desktop-security-operations':{Revision:()=>state.operationsRevision},
  '../integrity/peace.desktop-integrity-reports':{RequireSnapshot:()=>{}},
  '../integrity/peace.desktop-proof-work':{Verify:()=>state.valid},
  '../protocol/peace.desktop-request-protocol':{Resolve:()=>{}}
 };
 const mod=new Module(filename,module);mod.filename=filename;mod.paths=Module._nodeModulePaths(path.dirname(filename));
 mod.require=name=>Object.hasOwn(mocks,name)?mocks[name]:module.require(name);
 mod._compile("'use strict';const Date=require('result-test-clock');\n"+fs.readFileSync(filename,'utf8'),filename);
 const rpc=mod.exports;
 let sequence=0;
 const request=(context=1)=>({action:'challenge',stage:'A',sessionId:context.toString(16).toUpperCase().padStart(24,'0'),sessionToken:'t'.repeat(24),machineId:'B'.repeat(64),requestId:'request-'+(++sequence),policyId:'c'.repeat(64),functionId:2,args:[17,25]});
 const challenge=b=>{const c=rpc.Execute(b);return {...b,action:'invoke',challengeId:c.challengeId,signature:'a'.repeat(342)+'=='};};
 const advance=ms=>{state.wall+=ms;state.mono+=ms;};
 return {rpc,state,artifact,record,row,request,challenge,advance};
}
test('result capacity is reserved before evaluation, never evicts a live receipt',()=>{
 const f=fixture();let first;
 for(let i=0;i<2048;i++){const input=f.challenge(f.request(1+Math.floor(i/32)));if(!first)first=input;assert.equal(f.rpc.Execute(input).result,42);}
 assert.equal(f.state.evals,2048);
 const overflow=f.challenge(f.request(100));
 assert.throws(()=>f.rpc.Execute(overflow),/COZY_OPERATION_CAPACITY/);
 assert.equal(f.state.evals,2048);
 assert.equal(f.rpc.Execute({...first,action:'result'}).result,42);
 assert.equal(f.state.evals,2048);
});
test('result lifetime starts at commit, is never renewed by reads and is bounded by both clocks',()=>{
 const f=fixture(),input=f.challenge(f.request());f.advance(25000);f.rpc.Execute(input);
 f.advance(6000); // Original 30 second challenge has expired, committed result has not.
 assert.equal(f.rpc.Execute({...input,action:'result'}).result,42);
 f.advance(23999);assert.equal(f.rpc.Execute({...input,action:'result'}).result,42);
 f.advance(1);assert.throws(()=>f.rpc.Execute({...input,action:'result'}),/RESULT_UNAVAILABLE/);
 assert.equal(f.state.evals,1);
 const next=f.challenge(f.request());f.rpc.Execute(next);f.state.mono+=30000;
 assert.throws(()=>f.rpc.Execute({...next,action:'result'}),/RESULT_UNAVAILABLE/);
});
test('failed lookup cannot consume a good receipt; every retained binding is checked',()=>{
 const f=fixture(),input=f.challenge(f.request());const original=f.rpc.Execute(input),lookup={...input,action:'result'};
 for(const patch of [{signature:'b'.repeat(342)+'=='},{args:[17,26]},{requestId:'other-request'},
  {machineId:'C'.repeat(64)},{sessionId:'F'.repeat(24)},{policyId:'d'.repeat(64)},
  {functionId:3},{challengeId:'e'.repeat(48)},{sessionToken:'u'.repeat(24)}])
  assert.throws(()=>f.rpc.Execute({...lookup,...patch}),/RESULT_UNAVAILABLE|SESSION_TOKEN_INVALID/);
 for(const [object,key,value] of [[f.state,'revision',2],[f.state,'operationsRevision',2],
  [f.row,'publicKey','changed-key'],[f.artifact,'id','changed-artifact'],
  [f.artifact,'sha512','f'.repeat(128)],[f.record,'policySha512','e'.repeat(128)]]){
  const old=object[key];object[key]=value;assert.throws(()=>f.rpc.Execute(lookup),/RESULT_UNAVAILABLE/);object[key]=old;
 }
 for(const flag of ['live','fresh']){f.state[flag]=false;assert.throws(()=>f.rpc.Execute(lookup),/SESSION_REVOKED|SECURITY_FRESH_OBSERVATION_REQUIRED/);f.state[flag]=true;}
 const copy=f.rpc.Execute(lookup);copy.result=99;assert.deepEqual(f.rpc.Execute(lookup),original);assert.equal(f.state.evals,1);
});
test('pending/failed requests have no result; consumed request tombstones outlive result and retire on shutdown',()=>{
 const f=fixture(),base=f.request(),input=f.challenge(base);
 assert.throws(()=>f.rpc.Execute({...input,action:'result'}),/RESULT_UNAVAILABLE/);
 f.rpc.Execute(input);assert.throws(()=>f.rpc.Execute(input),/CHALLENGE_INVALID/);
 f.advance(30001);assert.throws(()=>f.rpc.Execute({...input,action:'result'}),/RESULT_UNAVAILABLE/);
 assert.throws(()=>f.rpc.Execute(base),/REQUEST_REUSED/);assert.equal(f.state.evals,1);
 const bad=f.challenge(f.request());f.state.valid=false;assert.throws(()=>f.rpc.Execute(bad),/SIGNATURE_INVALID/);f.state.valid=true;
 assert.throws(()=>f.rpc.Execute({...bad,action:'result'}),/RESULT_UNAVAILABLE/);
 assert.throws(()=>f.rpc.Execute(bad),/CHALLENGE_INVALID/);assert.equal(f.state.evals,1);
 const good=f.challenge(f.request());f.rpc.Execute(good);f.rpc.Stop();
 assert.throws(()=>f.rpc.Execute({...good,action:'result'}),/RESULT_UNAVAILABLE/);
});
test('clock rollback and explicit session retirement invalidate retained results',()=>{
 const f=fixture(),input=f.challenge(f.request());f.rpc.Execute(input);f.state.wall--;
 assert.throws(()=>f.rpc.Execute({...input,action:'result'}),/RESULT_UNAVAILABLE/);f.state.wall++;
 assert.throws(()=>f.rpc.Execute({...input,action:'result'}),/RESULT_UNAVAILABLE/);
 const next=f.challenge(f.request());f.rpc.Execute(next);f.rpc.RetireContext({id:next.sessionId},'A');
 assert.throws(()=>f.rpc.Execute({...next,action:'result'}),/RESULT_UNAVAILABLE/);
 assert.equal(f.state.evals,2);
});
