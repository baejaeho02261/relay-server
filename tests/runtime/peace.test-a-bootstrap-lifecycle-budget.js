'use strict';
// Release regression for 2026-11-12 A->B flow. This is a source/wire contract,
// not proof of compiling the Pascal project or executing Win64 A/B/O.
const {test}=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs');
const {ReadContractFile}=require('../fixtures/source/peace.native-string-contract');
const base=path.resolve(__dirname,'../../../Railway/Cozy.Source');
const read=(p)=>ReadContractFile(path.join(base,p),'utf8');
const nativePresent=fs.existsSync(path.join(base,'Cozy.Application/Cozy.Bootstrap.pas'));
const requireNative=t=>{if(nativePresent)return true;t.skip('Delphi Win64 source is in the full Google Drive ZIP, not the relay-only Docker context');return false;};
const fromServer=(p)=>fs.readFileSync(path.join(__dirname,'../../',p),'utf8');

test('A transfer has exactly one 780s budget and 120s gap before server flow expiration',t=>{
 if(!requireNative(t))return;
 const boot=read('Cozy.Application/Cozy.Bootstrap.pas');
 const launcher=read('Cozy.Application/Cozy.Launcher.pas');
 const server=fromServer('services/bootstrap/peace.desktop-bootstrap.js');
 const match=/BootstrapDownloadBudgetMS\s*=\s*(\d+);/.exec(boot);
 assert.ok(match,'shared constant');
 const clientMs=Number(match[1]);
 assert.equal(clientMs,780000);
 const flowMs=Number(/\bFLOW_MS\s*=\s*(\d+)/.exec(server)[1]);
 assert.equal(flowMs,900000);
 assert.ok(flowMs-clientMs>=120000,'reserve finish/handoff window');
 assert.equal((boot.match(/BootstrapDownloadBudgetMS\s*=/g)||[]).length,1,'single source of truth');
 assert.match(boot,/Deadline\s*>\s*FFlowStarted\s*\+\s*BootstrapDownloadBudgetMS/);
 assert.match(boot,/CozyTick\s*-\s*FFlowStarted\s*>=\s*BootstrapDownloadBudgetMS/);
 assert.match(launcher,/CozyTick\s*-\s*Started\s*>=\s*BootstrapDownloadBudgetMS/);
 assert.doesNotMatch(boot,/CozyTick\s*-\s*FFlowStarted\s*>=\s*290000/);
 assert.doesNotMatch(launcher,/DownloadDeadlineMS\s*=\s*300000/);
});

test('A timeout and verified image cleanup errors remain distinct diagnostic outcomes',t=>{
 if(!requireNative(t))return;
 const launcher=read('Cozy.Application/Cozy.Launcher.pas');
 const handoff=read('Cozy.Handoff/Cozy.Handoff.pas');
 const lifecycle=read('Cozy.Lifecycle/Cozy.Lifecycle.pas');
 const serverTrace=fromServer('services/observability/peace.desktop-lifecycle-trace.js');
 assert.match(fs.readFileSync(path.join(base,'Cozy.Application/Cozy.Launcher.pas'),'utf8'),/raise EBootstrap\.Create\(CozyText_Launcher_BOOTSTRAP_DOWNLOAD_DEADLINE_32bf226e\)/);
 assert.match(launcher,/RemoveOwnImage\(LauncherHash, Config\.ImageInfo, @CleanupError\)/);
 assert.match(fs.readFileSync(path.join(base,'Cozy.Application/Cozy.Launcher.pas'),'utf8'),/CozyText_Launcher_FAILED_8963bda6,[\s\S]{0,100}CleanupError/);
 assert.match(handoff,/procedure RemoveOwnImage\(const ExpectedSHA512: string;[\s\S]{0,140}NativeError: PCardinal/);
 assert.match(handoff,/OpenSafeImage\(Path, True, Info, False, False, NativeError\)/);
 assert.match(handoff,/UnlinkVerifiedOwnImage\(Handle, Path, ExpectedSHA512, ExpectedInfo,[\s\S]{0,75}NativeError/);
 assert.match(lifecycle,/Kind = leDownloadDeadline/);
 assert.match(serverTrace,/e\.event==='DOWNLOAD_DEADLINE'\?900000:600000/);
 // Authenticated reporting remains diagnostic-only; no server authorization
 // can be granted by submitting a timeout or cleanup record.
 assert.match(serverTrace,/Diagnostic authority is deliberately separate from runtime authority/);
});

test('B/O handoff and security contracts are not widened to fix an A download timeout',t=>{
 if(!requireNative(t))return;
 const handoff=read('Cozy.Handoff/Cozy.Handoff.pas');
 assert.match(handoff,/HandoffTimeoutMS\s*=\s*45000/);
 assert.match(handoff,/OverlayReadyTimeoutMS\s*=\s*110000/);
 assert.match(handoff,/SameIdentity\(Info, ExpectedInfo\)/);
 assert.match(handoff,/UnlinkVerifiedOwnImage/);
 const source=fromServer('services/bootstrap/peace.desktop-bootstrap.js');
 assert.match(source,/HANDOFF_MS\s*=\s*120000/);
});
