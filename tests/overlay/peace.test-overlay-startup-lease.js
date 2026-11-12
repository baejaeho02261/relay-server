'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const {OverlayFixture}=require("../fixtures/security/peace.security-state-test-fixture"),tracker=require("../../services/overlay/peace.desktop-overlay-startup");
const native=n=>ReadContractFile(path.resolve(MODULE_RESOURCE_ROOT,'../../Railway',n),'utf8');
function Progress(f,phase='CLAIMED',sequence=1,elapsedMs=100){const b={action:'overlayProgress',sessionId:f.row.sessionId,sessionToken:'TOKEN',sequence,phase,elapsedMs,signature:'pending'};b.signature=crypto.sign('sha256',Buffer.from(tracker.Canonical(b)),f.keys.privateKey).toString('base64');return b;}
test('verified startup observation changes no authority row or license',()=>{const f=OverlayFixture();f.row.status='CLAIMED';const before=JSON.stringify([f.row,f.parent,f.license]),b=Progress(f);assert.equal(f.api.__probe.Progress(b).recorded,true);assert.equal(JSON.stringify([f.row,f.parent,f.license]),before);assert.equal(f.calls.writes,0);assert.equal(tracker.View(f.row.sessionId).attested,false);});
test('wrong session token and bad signature cannot record startup',()=>{const f=OverlayFixture();f.row.status='CLAIMED';const b=Progress(f);assert.throws(()=>f.api.__probe.Progress({...b,sessionToken:'WRONG'}),/SESSION_INVALID/);assert.throws(()=>f.api.__probe.Progress({...b,signature:crypto.randomBytes(256).toString('base64')}),/PROOF_INVALID/);assert.equal(tracker.View(f.row.sessionId).phase,'NOT_REPORTED');});
test('expired and revoked O cannot produce accepted progress',()=>{for(const mode of ['REVOKED','EXPIRED']){const f=OverlayFixture();f.row.status=mode;assert.throws(()=>f.api.__probe.Progress(Progress(f)),/REVOKED|EXPIRED|CLOSED/);}});
test('signed VISIBLE is explicitly not a renewal or a server rendering attestation',()=>{const f=OverlayFixture();f.row.status='CLAIMED';const expiry=f.row.sessionExpiresAt;f.api.__probe.Progress(Progress(f,'VISIBLE',11,50000));assert.equal(f.row.sessionExpiresAt,expiry);assert.equal(f.calls.writes,0);assert.equal(tracker.View(f.row.sessionId).source,'SIGNED_CLIENT_REPORT');assert.throws(()=>f.api.__probe.Progress(Progress(f,'FAILED',12,51000)),/REPLAY/);});
test('exact repeated diagnostic is idempotent without renewed retention',()=>{const f=OverlayFixture();f.row.status='CLAIMED';const b=Progress(f);f.api.__probe.Progress(b);const old=tracker.View(f.row.sessionId);f.api.__probe.Progress(b);assert.deepEqual(tracker.View(f.row.sessionId),old);});
test('out-of-order diagnostics and arbitrary fields/phases fail closed',()=>{const f=OverlayFixture();f.row.status='CLAIMED';f.api.__probe.Progress(Progress(f,'GPU_READY',4,400));assert.throws(()=>f.api.__probe.Progress(Progress(f,'OWN_BEGIN',3,500)),/REPLAY/);assert.throws(()=>f.api.__probe.Progress(Progress(f,'OWN_BEGIN',5,100)),/REPLAY/);const b=Progress(f,'OWN_BEGIN',5,600);for(const patch of [{phase:'EXECUTE'},{command:'cmd'},{elapsedMs:180001},{sequence:33},{phase:'A'.repeat(200)}])assert.throws(()=>tracker.Parse({...b,...patch}),/INVALID/);});
test('no startup event creates a fresh measurement or bypasses its gate',()=>{const f=OverlayFixture();f.row.status='CLAIMED';f.api.__probe.Progress(Progress(f,'AUTHORIZED',10,100));f.denyFresh();assert.throws(()=>f.api.__probe.Verify(f.verify),/FRESH_OBSERVATION/);});
test('O session lease bounded by actual authority freshness',()=>{const expires=Date.now()+20000,f=OverlayFixture({observationExpiry:expires});f.row.status='CLAIMED';const result=f.api.__probe.Verify(f.verify);assert.equal(result.expiresAt,expires);assert.equal(f.row.sessionExpiresAt,expires);});
test('O lease bounded by module snapshot expiry as well',()=>{const expiry=Date.now()+15000,f=OverlayFixture({observationExpiry:Date.now()+30000,snapshotExpiry:expiry});f.row.status='CLAIMED';assert.equal(f.api.__probe.Verify(f.verify).expiresAt,expiry);});
test('expired authority/snapshot cannot issue even a positive ACTIVE response',()=>{for(const opts of [{observationExpiry:Date.now()-1},{snapshotExpiry:Date.now()-1}]){const f=OverlayFixture(opts);f.row.status='CLAIMED';assert.throws(()=>f.api.__probe.Verify(f.verify),/FRESH_OBSERVATION/);assert.equal(f.calls.writes,0);}});
test('shortened snapshot during commit rejects previously computed longer lease',()=>{const f=OverlayFixture({snapshotExpiry:Date.now()+25000});f.row.status='CLAIMED';f.beforeWrite(()=>f.options.snapshotExpiry=Date.now()+1000);assert.throws(()=>f.api.__probe.Verify(f.verify),/FRESH_OBSERVATION/);assert.equal(f.row.lastVerifiedAt,undefined);});
test('same observation returns same response and does not grant additional time',()=>{const f=OverlayFixture({observationExpiry:Date.now()+20000});f.row.status='CLAIMED';const a=f.api.__probe.Verify(f.verify),writes=f.calls.writes;f.options.observationExpiry=Date.now()+60000;const b=f.api.__probe.Verify(f.verify);assert.deepEqual(b,a);assert.equal(f.calls.writes,writes);});
test('B-to-O transfer never extends existing O authorization',()=>{const f=OverlayFixture({observationExpiry:Date.now()+30000});f.row.status='CLAIMED';const granted=f.api.__probe.Verify(f.verify).expiresAt;assert.equal(f.api.__probe.Commit(f.commit).status,'TRANSFERRED');assert.ok(f.row.sessionExpiresAt<=granted);assert.equal(f.parent.status,'CLOSED');});
test('later source revocation blocks renewal despite recent startup progress',()=>{const f=OverlayFixture();f.row.status='CLAIMED';f.api.__probe.Progress(Progress(f,'GPU_READY',4,100));f.revoked.add('O');assert.throws(()=>f.api.__probe.Verify(f.verify),/RELEASE_REVOKED/);});
// These are SOURCE CONTRACT checks, not Delphi compilation or rendered frames.
test('native pre-authorization reentrancy cannot poison yet-unacquired lease (source)',()=>{const s=native("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas"),start=s.indexOf('function TOverlayWindow.AuthorityValid'),end=s.indexOf('function TOverlayWindow.Run',start),fn=s.slice(start,end);assert.ok(fn.indexOf('if FAuthorizing then Exit(False)')<fn.indexOf('FShouldClose()'));assert.ok(fn.indexOf('if FAuthorizing then Exit(False)')<fn.indexOf('FFailed := True'));assert.match(s,/finally FAuthorizing := False; end;/);assert.ok(s.indexOf('AuthorizeBeforeShow();')<s.indexOf('ApiShowWindow(FWindow, SW_SHOWNORMAL)'));});
test('110s startup ready bound is absolute; ordinary pipe/AB stays 45s (source)',()=>{const s=native("Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas");assert.match(s,/HandoffTimeoutMS = 45000/);assert.match(s,/OverlayReadyTimeoutMS = 110000/);assert.match(s,/if PreserveParent then\s+Inc\(Deadline, OverlayReadyTimeoutMS - HandoffTimeoutMS\)/);assert.equal((s.match(/Inc\(Deadline, OverlayReadyTimeoutMS/g)||[]).length,1);});
test('native expired old lease cannot be revived by repeated server receipt (source)',()=>{const s=native("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas");assert.match(s,/PreviousDeadline := FLeaseDeadlineTick;\s+FLeaseDeadlineTick := 0;/);assert.match(s,/FLeaseDeadlineTick := VerifyRequestTick \+ UInt64\(Result\)/);assert.match(s,/ServerTime = FLastLeaseServerTime/);assert.match(s,/if PreviousDeadline < FLeaseDeadlineTick then FLeaseDeadlineTick := PreviousDeadline/);assert.match(s,/if ServerTime < FLastLeaseServerTime then InvalidResponse/);});
test('no API-removal shortcut for virtual memory or synchronization (source)',()=>{const ci=native("Cozy.Source/Cozy.Integrity/Cozy.CodeIntegrity.pas");assert.match(ci,/VirtualQuery/);assert.ok(!ci.includes('ReadProcessMemory'));for(const n of ["Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas","Cozy.Source/Cozy.Integrity/Cozy.Integrity.pas","Cozy.Source/Cozy.Integrity/Cozy.ModuleInventory.pas"]){assert.match(native(n),/THandle\(NativeInt\(-1\)\)/);assert.ok(!/Slot_GetCurrentProcess\s*:=/.test(native(n)));}});
test('290s download timeout remains a separately named A deadline (source)',()=>{const s=native("Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas");assert.match(s,/290000/);assert.match(s,/BOOTSTRAP_DOWNLOAD_DEADLINE/);assert.match(native("Cozy.Source/Cozy.Overlay/Cozy.Overlay.State.pas"),/if Delay > 10000 then Delay := 10000/);});
test('role resource inputs and mandatory prebuild preserve version/manifest without a custom icon (source)',()=>{
  // A's resource deliberately is not distributable before its new public trust
  // anchor is installed. A fresh source tree must compile the reviewed RC input
  // before Delphi; a checked-in generated resource is not a prerequisite.
  const shared=native('Cozy.Build/Cozy.ReleaseMetadata.targets');
  assert.match(shared,/<Target Name="PrepareCozyReleaseMetadata"[\s\S]*?BeforeTargets="[^"\n]*_PasCoreCompile[^"\n]*PrepareOverlayNative"/);
  assert.match(shared,/<Error Condition="!Exists\('\$\(BDS\)\\bin\\brcc32\.exe'\)"/);
  assert.match(shared,/<Exec Condition="'\$\(_GameRole\)'=='A' or '\$\(_GameRole\)'=='B'"[\s\S]*?brcc32\.exe&quot; -fo&quot;\$\(_GameProjectName\)Resources\.res&quot; &quot;\$\(_GameProjectName\)\.rc&quot;/);
  assert.ok(shared.indexOf('Cozy.Prepare-IssuedATrust.ps1')<shared.indexOf('brcc32.exe&quot; -fo'));
  assert.doesNotMatch(shared,/ContinueOnError="(?:true|WarnAndContinue)"|IgnoreExitCode="true"/i);
  for(const name of ['Cozy.Client','Cozy.Launcher','Cozy.Overlay']){
    const base='Cozy.Projects/'+name+'/'+name,rc=native(base+'.rc'),project=native(base+'.dproj');
    assert.match(rc,new RegExp('^1 24 "'+name.replaceAll('.','\\.')+'\\.manifest"','m'));
    assert.match(rc,/^1 VERSIONINFO\s*\r?\n\s*FILEVERSION /m);
    assert.doesNotMatch(rc,/\b(?:ICON|GROUP_ICON)\s+(?:"|\d)|\bMAINICON\s+ICON/i);
    assert.match(native(base+'.dpr'),new RegExp("\\{\\$R '"+name.replaceAll('.','\\.')+"Resources\\.res'\\}"));
    assert.match(project,/<Import Project="\.\.\\\.\.\\Cozy\.Build\\Cozy\.ReleaseMetadata\.targets"/);
    assert.match(project,/<Icon_MainIcon\s*\/>/);
  }
  const overlay=native('Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dproj');
  assert.match(overlay,/<Target Name="PrepareOverlayNative" BeforeTargets="PreBuildEvent;_PasCoreCompile"/);
  const compile=overlay.indexOf('brcc32.exe&quot; -fo&quot;Cozy.OverlayResources.pending.res'),
    audit=overlay.indexOf('Cozy.Assert-OverlayManifest.ps1',compile),publish=overlay.indexOf('<Move SourceFiles="$(MSBuildProjectDirectory)\\Cozy.OverlayResources.pending.res"');
  assert.ok(compile>=0&&compile<audit&&audit<publish,'O publishes only the compiled and manifest-audited resource');
  assert.doesNotMatch(overlay,/ContinueOnError="(?:true|WarnAndContinue)"|IgnoreExitCode="true"/i);
});
test('any supplied generated resource is structurally valid and retains version/manifest without icons',()=>{
  for(const name of ['Cozy.Client','Cozy.Launcher','Cozy.Overlay']){
    const file=path.resolve(MODULE_RESOURCE_ROOT,'../../Railway','Cozy.Projects',name,name+'Resources.res');
    if(!fs.existsSync(file))continue; // Validated source/prebuild contract above covers a clean tree.
    const b=fs.readFileSync(file),types=[];let at=0;
    assert.ok(b.length>=32);
    while(at<b.length){
      assert.ok(at+12<=b.length);
      const size=b.readUInt32LE(at),head=b.readUInt32LE(at+4);
      assert.ok(head>=12&&at+head+size<=b.length);
      if(b.readUInt16LE(at+8)===0xffff)types.push(b.readUInt16LE(at+10));
      at=(at+head+size+3)&~3;
      assert.ok(at<=b.length);
    }
    assert.equal(at,b.length);
    assert.ok(!types.includes(3)&&!types.includes(14));
    assert.ok(types.includes(16)&&types.includes(24));
  }
});
test('Delphi declaration order and TProc<string> callback signature stay compatible (source)',()=>{const c=native("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas"),o=native("Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas");assert.ok(c.indexOf('FTransferConfirmed, FCapturePrivacy: Boolean;')<c.indexOf('procedure StartupPhaseCore'));assert.match(o,/procedure\(Phase: string\)/);assert.doesNotMatch(o,/procedure\(const Phase: string\)/);});
test('test-only lease observation binds actual verify request and bounded duration (source)',()=>{const c=native("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas"),o=native("Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas"),f=native("Cozy.Source/Cozy.Application/Cozy.ProductFaults.pas");assert.match(c,/FLeaseRequestTick := VerifyRequestTick/);assert.match(c,/FLeaseRequestTick := PreviousRequestTick/);assert.match(c,/Result <> FLastLeaseDuration/);assert.match(o,/ProductFaultLeaseGranted\(FClient.LeaseRequestTick, UInt64\(Lease\), Deadline\)/);assert.match(f,/\(LeaseMs > 0\) and \(LeaseMs <= 120000\)/);assert.doesNotMatch(f,/LeaseMs = 120000/);});
function ShortLease(){const r=require('./peace.test-overlay-lease-expiry').Result(),n=r.nativeEvents[0],s=r.fixture.lease;n.leaseMs=45000;n.deadlineTick=n.requestStartedTick+n.leaseMs;r.leaseWindow.hiddenTick=n.deadlineTick+30;r.overlayExitTick=n.deadlineTick+100;s.expiresAt=s.authorizedAt+n.leaseMs;s.serverObservedAt=s.expiresAt+100;s.prunedAt=s.expiresAt+51;s.prunedElapsedMs=45050;s.monotonicElapsedMs=45099;return r;}
test('expiry validator accepts an independently observed shorter 45-second grant',()=>{const r=ShortLease();assert.equal(require("../../tools/runtime/peace.product-fault-tests").Evaluate(r.scenario,r).outcome,'PASS');});
test('expiry validator rejects a mismatched claimed duration even when both are positive',()=>{const r=ShortLease();r.fixture.lease.expiresAt-=1;assert.equal(require("../../tools/runtime/peace.product-fault-tests").Evaluate(r.scenario,r).outcome,'FAIL');});
test('authority fault validators accept exact shorter native/server grants without faking runtime',()=>{const fixture=require("../fixtures/security/peace.security-authority-test-fixture"),c=require("../../tools/security/peace.security-authority-contract");for(const id of c.CASES.slice(1)){const r=fixture.Evidence(id),g=r.nativeEvents[0];g.leaseMs=45000;g.deadlineTick=g.requestStartedTick+45000;r.fixture.lease.expiresAt=r.fixture.lease.authorizedAt+45000;r.denialObservedAt=r.fixture.lease.expiresAt+100;if(id==='authority-local-stop-held')r.nativeEvents[1].observedTick=g.deadlineTick+10;assert.equal(c.EvaluateCase(id,r).outcome,'PASS');}});
test('authority fault validator rejects server/native duration mismatch and nonnumeric server times',()=>{const fixture=require("../fixtures/security/peace.security-authority-test-fixture"),c=require("../../tools/security/peace.security-authority-contract");for(const mutate of [r=>r.fixture.lease.expiresAt--,r=>r.fixture.lease.authorizedAt=String(r.fixture.lease.authorizedAt),r=>{r.nativeEvents[0].leaseMs=120001;r.nativeEvents[0].deadlineTick=220001;}]){const r=fixture.Evidence('authority-report-stopped');mutate(r);assert.equal(c.EvaluateCase('authority-report-stopped',r).outcome,'FAIL');}});
