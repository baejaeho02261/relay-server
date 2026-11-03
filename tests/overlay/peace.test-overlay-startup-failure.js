'use strict';
// Real progress handler/RSA verification over isolated synthetic authority.
// These reports describe client observations, never Windows rendering proof.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {OverlayFixture}=require('../fixtures/security/peace.security-state-test-fixture');
const tracker=require('../../services/overlay/peace.desktop-overlay-startup');
const audit=require('../../storage/audit/peace.audit.js'),originalLog=audit.LogEvent,events=[];
audit.LogEvent=(kind,payload)=>events.push({kind,...JSON.parse(payload)});
process.once('exit',()=>{audit.LogEvent=originalLog;});
const stages=['BINDING','FONT_READ','FONT_DATA','CREATE','RESIZE','GPU_IDENTITY','FLOATING_POINT','UNKNOWN'];
function fixture(){const f=OverlayFixture();f.row.status='CLAIMED';return f;}
function signed(f,{phase='FAILED',sequence=12,elapsedMs=5000,failure}={}){
 const b={action:'overlayProgress',sessionId:f.row.sessionId,sessionToken:'TOKEN',sequence,phase,elapsedMs,signature:'pending',...(failure===undefined?{}:{failure})};
 b.signature=crypto.sign('sha256',Buffer.from(tracker.Canonical(b)),f.keys.privateKey).toString('base64');return b;
}
function rejected(fn,pattern=/INVALID/){assert.throws(fn,pattern);}

test('legacy V1 canonical bytes and FAILED reports remain unchanged',()=>{
 const f=fixture(),b=signed(f);
 assert.equal(tracker.Canonical(b),['GAME-OVERLAY-PROGRESS-V1',f.row.sessionId,12,'FAILED',5000].join('\n'));
 assert.deepEqual(f.api.__probe.Progress(b),{recorded:true});
 assert.equal(Object.hasOwn(tracker.View(f.row.sessionId),'failure'),false);
});
test('generated request admission accepts V1/V2 and rejects malformed failure shapes and ranges',()=>{
 const packet=require('../../services/protocol/peace.packet-schema'),f=fixture(),legacy=signed(f),modern=signed(f,{failure:{version:1,stage:'CREATE',code:-2147024882}});
 for(const body of [legacy,modern])assert.deepEqual(packet.ParseRequest(JSON.stringify({operation:'bootstrap',body})).body,body);
 for(const code of [-2147483648,0,2147483647])assert.deepEqual(packet.ValidateRequest('bootstrap',{...modern,failure:{...modern.failure,code}}).failure.code,code);
 for(const failure of [null,{...modern.failure,code:-2147483649},{...modern.failure,code:2147483648},{...modern.failure,code:1.5},{...modern.failure,code:'0'},
  {...modern.failure,stage:'<img>'},{...modern.failure,version:2},{...modern.failure,secret:'PRIVATE'},{version:1,stage:'CREATE'}])
  rejected(()=>packet.ParseRequest(JSON.stringify({operation:'bootstrap',body:{...modern,failure}})),/SCHEMA_INVALID/);
 // Structural admission is not domain authorization: only FAILED may carry it.
 const misplaced={...modern,phase:'GPU_BEGIN'};packet.ValidateRequest('bootstrap',misplaced);
 rejected(()=>f.api.__probe.Progress(misplaced),/OVERLAY_PROGRESS_INVALID/);assert.equal(f.calls.writes,0);
});
test('V2 signs closed stage and signed HRESULT without changing authority',()=>{
 const f=fixture(),failure={version:1,stage:'CREATE',code:-2147024882},b=signed(f,{failure});
 assert.equal(tracker.Canonical(b),['GAME-OVERLAY-PROGRESS-V2',f.row.sessionId,12,'FAILED',5000,1,'CREATE',-2147024882].join('\n'));
 const before=JSON.stringify([f.row,f.parent,f.license]);
 assert.deepEqual(f.api.__probe.Progress(b),{recorded:true});
 assert.equal(JSON.stringify([f.row,f.parent,f.license]),before);assert.equal(f.calls.writes,0);assert.equal(f.calls.fresh,0);
 const v=tracker.View(f.row.sessionId);assert.deepEqual(v.failure,failure);assert.equal(v.attested,false);assert.equal(v.source,'SIGNED_CLIENT_REPORT');
 const e=events.find(x=>x.sessionId===f.row.sessionId);assert.deepEqual(e.failure,failure);assert.equal(e.attested,false);
 for(const secret of [b.sessionToken,f.keys.privateKey.export({type:'pkcs8',format:'pem'})])assert.ok(!JSON.stringify(e).includes(secret));
 assert.equal(tracker.FailureLabel(failure),'CREATE · 0x8007000E');
});
test('initial resize HRESULT and Windows exception codes survive signed admission without authority changes',()=>{
 const packet=require('../../services/protocol/peace.packet-schema');
 for(const [stage,code,hex]of [['RESIZE',-2005270527,'887A0001'],['RESIZE',-1073741819,'C0000005'],['CREATE',-1073741819,'C0000005']]){
  const f=fixture(),failure={version:1,stage,code},b=signed(f,{failure});
  const before=JSON.stringify([f.row,f.parent,f.license]);
  const admitted=packet.ParseRequest(JSON.stringify({operation:'bootstrap',body:b})).body;
  assert.deepEqual(f.api.__probe.Progress(admitted),{recorded:true});
  assert.deepEqual(tracker.View(f.row.sessionId).failure,failure);
  assert.equal(tracker.FailureLabel(tracker.View(f.row.sessionId).failure),stage+' · 0x'+hex);
  assert.equal(JSON.stringify([f.row,f.parent,f.license]),before);
  assert.equal(f.calls.writes,0);assert.equal(f.calls.fresh,0);
  assert.deepEqual(events.find(x=>x.sessionId===f.row.sessionId).failure,failure);
  rejected(()=>packet.ParseRequest(JSON.stringify({operation:'bootstrap',body:{...b,failure:{...failure,address:'0x1234'}}})),/SCHEMA_INVALID/);
  rejected(()=>f.api.__probe.Progress({...b,failure:{...failure,code:0}}),/PROOF_INVALID/);
 }
});
test('closed CPU admission codes identify their gate without relabeling legacy or driver errors',()=>{
 const cases=[
  [-2147171839,'8004C201','CPU 컨텍스트 할당 실패'],
  [-2147171838,'8004C202','CPU 고정 메모리 예약 실패'],
  [-2147171837,'8004C203','폰트 복사 메모리 할당 실패'],
  [-2147171836,'8004C204','프레임·업로드용 여유 메모리 확보 실패']
 ];
 for(const [code,hex,label]of cases){
  const f=fixture(),failure={version:1,stage:'CREATE',code},before=JSON.stringify([f.row,f.parent,f.license]);
  assert.deepEqual(f.api.__probe.Progress(signed(f,{failure})),{recorded:true});
  assert.equal(JSON.stringify([f.row,f.parent,f.license]),before);assert.equal(f.calls.writes,0);
  assert.equal(tracker.FailureLabel(tracker.View(f.row.sessionId).failure),'CREATE · 0x'+hex+' · '+label);
  assert.equal(tracker.FailureLabel({...failure,stage:'FONT_DATA'}),'FONT_DATA · 0x'+hex);
 }
 assert.equal(tracker.FailureLabel({version:1,stage:'CREATE',code:-2147024882}),'CREATE · 0x8007000E');
 assert.equal(tracker.FailureLabel({version:1,stage:'CREATE',code:-2147171835}),'CREATE · 0x8004C205');
 assert.equal(tracker.FailureLabel({version:1,stage:'CREATE',code:0}),'CREATE · 원인 코드 없음');
 // The input has no free-text field, and unknown signed32 values display only
 // their numeric code. They cannot select a native gate description.
 assert.equal(tracker.FailureLabel({version:1,stage:'CREATE',code:-2005270523}),'CREATE · 0x887A0005');
 // Cross-language contract: when the private native source is present, its
 // public C constants and Delphi classifier must agree with these wire codes.
 // Relay-only deployments intentionally contain neither native source nor a
 // Delphi compiler; the real signed-handler cases above still execute there.
 const fs=require('node:fs'),path=require('node:path'),root=path.resolve(__dirname,'../../../Railway');
 if(fs.existsSync(root)){
  const {ReadContractFile}=require('../fixtures/source/peace.native-string-contract');
  const header=ReadContractFile(path.join(root,'Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h'),'utf8');
  for(const [name,code]of [['HOST_CONTEXT',-2147171839],['HOST_ARENA',-2147171838],['FONT_COPY',-2147171837],['FRAME_RESERVE',-2147171836]])
   assert.match(header,new RegExp('\\bGI_ERROR_'+name+'\\s*=\\s*'+code+'\\b'));
  const state=ReadContractFile(path.join(root,'Cozy.Source/Cozy.Overlay/Cozy.Overlay.State.pas'),'utf8');
  assert.match(state,/\$8004C201,\s*\$8004C202,\s*\$8004C203,\s*\$8004C204:\s*Result := 'OVERLAY_GRAPHICS_RESOURCE_ADMISSION_FAILED'/);
  assert.match(state,/\$8007000E:\s*Result := 'OVERLAY_GRAPHICS_OUT_OF_MEMORY'/);
 }
});
test('failure is copied on admission and projection; exact retries never refresh retention',()=>{
 const f=fixture(),first=signed(f,{phase:'GPU_BEGIN',sequence:3,elapsedMs:50});f.api.__probe.Progress(first);
 const until=tracker.View(f.row.sessionId).until,b=signed(f,{failure:{version:1,stage:'CREATE',code:-2147024882}});
 const originalNow=Date.now,at=originalNow();Date.now=()=>at+1000;
 try{f.api.__probe.Progress(b);}finally{Date.now=originalNow;}
 const old=tracker.View(f.row.sessionId),count=events.length;
 assert.equal(old.until,until);assert.deepEqual(f.api.__probe.Progress(b),{recorded:true});assert.deepEqual(tracker.View(f.row.sessionId),old);assert.equal(events.length,count);
 b.failure.code=1;old.failure.stage='UNKNOWN';
 assert.deepEqual(tracker.View(f.row.sessionId).failure,{version:1,stage:'CREATE',code:-2147024882});
 rejected(()=>f.api.__probe.Progress(b),/PROOF_INVALID/);
 const changed=signed(f,{failure:{version:1,stage:'CREATE',code:1}});rejected(()=>f.api.__probe.Progress(changed),/REPLAY/);
 const stripped=signed(f);rejected(()=>f.api.__probe.Progress(stripped),/REPLAY/);
});
test('an old signed report cannot recreate retention after eviction or a fresh tracker process',()=>{
 const {Isolated}=require('../fixtures/protocol/peace.completion-6-10-fixture'),f=fixture(),b=signed(f,{failure:{version:1,stage:'CREATE',code:-2147024882}});
 const until=f.row.claimedAt+180000;f.row.sessionExpiresAt=until+60000;f.parent.sessionExpiresAt=until+60000;f.license.expiresAt=0;
 f.api.__probe.Progress(b);assert.equal(tracker.View(f.row.sessionId).until,until);
 const originalNow=Date.now;Date.now=()=>until;
 try{
  const count=events.length;rejected(()=>f.api.__probe.Progress(b),/OVERLAY_PROGRESS_EXPIRED/);assert.equal(events.length,count);
  assert.equal(tracker.View(f.row.sessionId).phase,'NOT_REPORTED');
  const fresh=Isolated('services/overlay/peace.desktop-overlay-startup.js',[],{'../../storage/audit/peace.audit.js':{LogEvent(){throw Error('LATE_AUDIT');}}});
  rejected(()=>fresh.Record(f.row,b),/OVERLAY_PROGRESS_EXPIRED/);assert.equal(f.calls.writes,0);
 }finally{Date.now=originalNow;}
});
test('all stage values and signed32 endpoints are bounded; property order is irrelevant',()=>{
 for(const stage of stages)for(const code of [-2147483648,0,2147483647]){
  const f=fixture(),b=signed(f,{failure:{code,stage,version:1}});
  assert.deepEqual(f.api.__probe.Progress(b),{recorded:true});assert.equal(tracker.View(f.row.sessionId).failure.code,code);
 }
});
test('malformed or misplaced diagnostics cannot enter the report or timeline label',()=>{
 const f=fixture(),base=signed(f),valid={version:1,stage:'CREATE',code:0};
 for(const failure of [null,[],{},'CREATE',{...valid,version:2},{...valid,stage:'C:\\private\\token'},
  {...valid,stage:'create'},{...valid,code:-2147483649},{...valid,code:2147483648},{...valid,code:0.5},
  {...valid,code:'0'},{...valid,code:NaN},{...valid,code:Infinity},{...valid,message:'private'},
  {...valid,path:'C:\\private'},Object.assign(Object.create(null),valid)]){
  rejected(()=>tracker.Parse({...base,failure}));assert.equal(tracker.FailureLabel(failure),'');
 }
 for(const phase of ['CLAIMED','GPU_BEGIN','GPU_READY','AUTHORIZED','VISIBLE'])rejected(()=>tracker.Parse({...base,phase,failure:valid}));
 assert.equal(tracker.View(f.row.sessionId).phase,'NOT_REPORTED');
});
test('stage and native code are covered by RSA proof and cannot be transplanted',()=>{
 const f=fixture(),b=signed(f,{failure:{version:1,stage:'CREATE',code:-2147024882}});
 for(const failure of [{...b.failure,code:0},{...b.failure,stage:'FONT_READ'}])rejected(()=>f.api.__probe.Progress({...b,failure}),/PROOF_INVALID/);
 const downgraded={...b};delete downgraded.failure;rejected(()=>f.api.__probe.Progress(downgraded),/PROOF_INVALID/);
 rejected(()=>f.api.__probe.Progress({...b,signature:Buffer.alloc(256).toString('base64')}),/PROOF_INVALID/);
 rejected(()=>f.api.__probe.Progress({...b,sessionToken:'WRONG'}),/SESSION_INVALID/);
 assert.equal(tracker.View(f.row.sessionId).phase,'NOT_REPORTED');
});
test('revocation and expiry deny failure diagnostics without new authority or audit records',()=>{
 for(const mode of ['EXPIRED','REVOKED']){
  const f=fixture(),b=signed(f,{failure:{version:1,stage:'CREATE',code:-2147024882}});f.row.status=mode;
  const before=events.length;rejected(()=>f.api.__probe.Progress(b),/EXPIRED|REVOKED|CLOSED/);assert.equal(events.length,before);assert.equal(f.calls.writes,0);
 }
 const f=fixture(),b=signed(f,{failure:{version:1,stage:'CREATE',code:-2147024882}});f.revoked.add('O');
 rejected(()=>f.api.__probe.Progress(b),/RELEASE_REVOKED/);assert.equal(tracker.View(f.row.sessionId).phase,'NOT_REPORTED');
});
test('FAILED observation does not authorize subsequent verification or replace missing proof',()=>{
 const f=fixture();f.api.__probe.Progress(signed(f,{failure:{version:1,stage:'FLOATING_POINT',code:0}}));
 f.denyFresh();rejected(()=>f.api.__probe.Verify(f.verify),/FRESH_OBSERVATION/);assert.equal(f.calls.writes,0);
 assert.equal(tracker.FailureLabel({version:1,stage:'FLOATING_POINT',code:0}),'FLOATING_POINT · 원인 코드 없음');
 assert.doesNotMatch(tracker.FailureLabel({version:1,stage:'UNKNOWN',code:0}),/0x00000000/);
});
test('member/license timeline formats bounded failure and excludes other licenses or raw details',()=>{
 const {Isolated}=require('../fixtures/protocol/peace.completion-6-10-fixture');
 const events=[
  {time:2,type:'DESKTOP_OVERLAY_PROGRESS',detail:JSON.stringify({licenseId:'LICENSE',phase:'FAILED',elapsedMs:5000,failure:{version:1,stage:'CREATE',code:-2147024882}})},
  {time:3,type:'DESKTOP_OVERLAY_PROGRESS',detail:JSON.stringify({licenseId:'OTHER',phase:'FAILED',elapsedMs:5001,failure:{version:1,stage:'FONT_READ',code:0}})},
  {time:4,type:'DESKTOP_OVERLAY_PROGRESS',detail:JSON.stringify({licenseId:'LICENSE',phase:'FAILED',elapsedMs:5002,failure:{version:1,stage:'C:\\private\\token',code:0}})}
 ];
 const boot={launchers:{},flows:{F:{id:'F',licenseId:'LICENSE',sessionId:'PARENT',releaseId:'B',createdAt:1,status:'CLAIMED'}},artifacts:{B:{version:'1',sha512:'a'.repeat(128)}}};
 const workspace=Isolated('services/operations/peace.desktop-workspace.js',[],{
  '../../core/peace.runtime-state':{events},
  './peace.desktop-workspace-store':{Load:()=>({metadata:{}})},
  '../licensing/peace.desktop-licenses':{Detail:id=>({license:{id,issuedAt:1}})},
  '../bootstrap/peace.desktop-bootstrap':{SessionView:row=>row},
  '../bootstrap/peace.desktop-bootstrap-store':{Load:()=>boot},
  '../storage/peace.desktop-storage-space':{},
  '../members/peace.desktop-members':{LicenseMembership:()=>({memberId:'EXPLICIT_MEMBER'})},
  '../observability/peace.desktop-lifecycle-trace':{Flow:()=>({})}
 });
 const detail=workspace.Detail('LICENSE'),progress=detail.timeline.filter(x=>x.type==='DESKTOP_OVERLAY_PROGRESS');
 assert.equal(progress.length,2);assert.ok(progress.some(x=>x.label.includes('CREATE · 0x8007000E')));
 assert.ok(progress.every(x=>x.source==='SIGNED_CLIENT_REPORT'&&x.attested===false&&x.label.includes('클라이언트 보고')));
 assert.doesNotMatch(JSON.stringify(detail),/FONT_READ|private|token|failure/);
});
