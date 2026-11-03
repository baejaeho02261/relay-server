'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
// Real services and signed requests with synthetic PE data; no Windows execution.
// All writes are restricted to a fresh temporary server DATA_DIR.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-key-window-'));
Object.assign(process.env,{DATA_DIR:dir,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require("../../core/peace.utilities.js").EnsureDirs();
const b=require("../../services/bootstrap/peace.desktop-bootstrap"),d=require("../../services/licensing/peace.desktop-licenses"),w=require("../../services/operations/peace.desktop-workspace"),F=require("../fixtures/bootstrap/peace.desktop-bootstrap-fixture");
let passed=0;
function test(name,fn){fn();passed++;console.log('PASS '+name);}
function bad(fn,code){assert.throws(fn,e=>e.message===code,code);}
function proof(dev,session,action,extra,requestId=crypto.randomUUID()){
 const payloadJSON=JSON.stringify({...F.Evidence(dev,session),bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken,...extra});
 const base={action,requestId,deviceId:dev.deviceId,publicKey:dev.publicKey,payloadHash:F.sha512(payloadJSON)},challenge=d.Challenge(base);
 F.ObserveLicense(dev,action,requestId,sha512(payloadJSON),JSON.parse(payloadJSON));
 return{...base,challengeId:challenge.challengeId,payloadJSON,signature:F.Sign(dev,challenge.canonical)};
}
function openIssued(dev,issue){
 const parent=F.Device();parent.machineId=dev.machineId;const {begin}=F.BeginIssued(parent,issue);
 F.Download(begin);return F.Claim(parent,begin,F.Finish(parent,begin),dev);
}
try{
 let issue,body,dev,session,key,result,requestId,oldIssue,reserved,other,secondDev,secondSession;
 test('Manual B publishes with no automatic-assignment capability',()=>{const v=F.CurrentCohort({version:'92.0',marker:'KEY_WINDOW'}).selected.B;assert.equal(v.backgroundVersion,0);assert.equal(d.List().items.length,0);});
 test('A can be issued while the server contains zero licenses',()=>{body={requestId:crypto.randomUUID(),label:'License recipient'};issue=b.IssueLauncher(body,'TEST');assert.ok(issue.launcherId);assert.equal(d.List().items.length,0);assert.ok(!Object.hasOwn(b.Initialize().launchers[issue.launcherId],'assignedLicenseId'));});
 test('Repeated A issue request returns the same file without making a license',()=>{assert.equal(b.IssueLauncher(body,'TEST').launcherId,issue.launcherId);assert.equal(d.List().items.length,0);});
 test('The issued A profile has no license key, license ID or automatic marker',()=>{const text=JSON.stringify(F.Config(b.LauncherBytes(issue.launcherId)));for(const word of ['licenseKey','licenseId','assignedLicenseId','SERVER_ASSIGNED_V1'])assert.ok(!text.includes(word));});
 test('A download and B claim succeed before any license is issued',()=>{dev=F.Device();session=openIssued(dev,issue);assert.equal(d.List().items.length,0);assert.equal(b.Execute({action:'status',sessionId:session.sessionId,sessionToken:session.sessionToken}).licenseId,'');});
 test('A manual B session rejects the old automatic marker',()=>{bad(()=>d.Execute(proof(dev,session,'redeem',{licenseKey:'SERVER_ASSIGNED_V1'})),'DESKTOP_KEY_INVALID');assert.equal(d.List().items.length,0);});
 test('Missing and unknown keys do not implicitly consume or create licenses',()=>{bad(()=>d.Execute(proof(dev,session,'redeem',{licenseKey:''})),'DESKTOP_KEY_INVALID');bad(()=>d.Execute(proof(dev,session,'redeem',{licenseKey:'0'.repeat(64)})),'DESKTOP_KEY_INVALID');assert.equal(d.List().items.length,0);});
 test('A key can be created separately after A issuance and B claim',()=>{key=d.Create({productId:'cleaner.pubg',label:'User key',requestId:crypto.randomUUID()},'TEST');assert.equal(key.license.status,'AVAILABLE');assert.equal(b.Initialize().launchers[issue.launcherId].assignedLicenseId,undefined);});
 test('Tampering with the signed request still fails without consuming the key',()=>{const p=proof(dev,session,'redeem',{licenseKey:key.licenseKey});p.signature='A'.repeat(342)+'==';bad(()=>d.Execute(p),'DESKTOP_PROOF_INVALID');assert.equal(d.Detail(key.license.id).license.status,'AVAILABLE');});
 test('The entered key is consumed by the original signed proof path',()=>{requestId=crypto.randomUUID();result=d.Execute(proof(dev,session,'redeem',{licenseKey:key.licenseKey,appVersion:'92.0'},requestId));assert.equal(result.licenseId,key.license.id);assert.equal(result.status,'USED');assert.ok(result.activationToken);});
 test('Lost-response retry uses the existing receipt without consuming a second key',()=>{const r=d.Execute(proof(dev,session,'redeem',{licenseKey:key.licenseKey,appVersion:'92.0'},requestId));assert.equal(r.activationToken,result.activationToken);assert.equal(d.List().items.length,1);});
 test('The workspace still links A issuance, B claim and entered-key authentication',()=>{const info=w.Detail(key.license.id);assert.ok(info.timeline.some(x=>x.type==='LAUNCHER_ISSUED'&&x.launcherId===issue.launcherId));assert.ok(info.timeline.some(x=>x.type==='B_CLAIMED'));assert.ok(w.Query({q:'License recipient'}).items.some(x=>x.id===key.license.id));assert.ok(w.Query({q:issue.launcherId}).items.some(x=>x.id===key.license.id));assert.ok(!JSON.stringify(info).includes(result.activationToken));assert.ok(!JSON.stringify(info).includes(key.licenseKey));});
 test('Normal license renewal and release remain signed and session-bound',()=>{assert.equal(d.Execute(proof(dev,session,'verify',{activationToken:result.activationToken})).licenseId,key.license.id);assert.equal(d.Execute(proof(dev,session,'release',{activationToken:result.activationToken})).released,true);});
 test('A consumed KEY is not reset or allowed on a different fresh device',()=>{const x=F.Device(),s=F.Session(x);bad(()=>d.Execute(proof(x,s,'redeem',{licenseKey:key.licenseKey})),'DESKTOP_KEY_USED');assert.equal(d.Detail(key.license.id).license.consumed,true);});
 test('An explicit reserved A keeps its assignment metadata with a manual-input B',()=>{F.CurrentCohort({version:'92.1',marker:'KEY_WINDOW_RESTORED'});reserved=d.Create({productId:'cleaner.pubg',label:'Historical reserved key',requestId:crypto.randomUUID()},'TEST');oldIssue=b.IssueLauncher({requestId:crypto.randomUUID(),label:'old reserved A',licenseId:reserved.license.id},'TEST');secondDev=F.Device();secondSession=openIssued(secondDev,oldIssue);});
 test('Historical A assignment cannot auto-authorize the new license-window build',()=>{bad(()=>d.Execute(proof(secondDev,secondSession,'redeem',{licenseKey:'SERVER_ASSIGNED_V1'})),'DESKTOP_KEY_INVALID');assert.equal(d.Detail(reserved.license.id).license.status,'AVAILABLE');});
 test('The user-entered valid KEY wins over unused historical A assignment metadata',()=>{other=d.Create({productId:'cleaner.pubg',label:'Actually entered key',requestId:crypto.randomUUID()},'TEST');const r=d.Execute(proof(secondDev,secondSession,'redeem',{licenseKey:other.licenseKey}));assert.equal(r.licenseId,other.license.id);assert.equal(d.Detail(reserved.license.id).license.status,'AVAILABLE');assert.equal(b.Initialize().launchers[oldIssue.launcherId].assignedLicenseId,reserved.license.id);assert.equal(w.Detail(reserved.license.id).flows.length,0);assert.ok(w.Detail(other.license.id).flows.some(x=>x.launcherId===oldIssue.launcherId));});
 test('B license window preserves manual key ownership, authenticated handoff and worker cleanup',()=>{
  const native=path.resolve(MODULE_RESOURCE_ROOT,'../../Railway');
  const text=ReadContractFile(path.join(native,'Cozy.Source/Cozy.License/Cozy.License.Session.pas'),'utf8');
  const window=ReadContractFile(path.join(native,'Cozy.Source/Cozy.License/Cozy.License.Window.pas'),'utf8');
  const entry=text.split('function RunLicenseClient: Integer;').at(-1);
  assert(entry.indexOf('Context.CompleteClaimAndCleanup(')<entry.indexOf('RunLicenseWindow('));
  for(const word of ['Worker := TLicenseWorker.Create(Api);','Worker.SubmitKey(Key)','Worker.RequestStop;','Worker.StopAndJoin;','Worker.Free;'])assert(entry.includes(word),word);
  for(const word of ['procedure TLicenseWindow.PasteKey;','FreeAndNil(Key)','ImGuiLicenseScene(FContext, Phase, FKey.Count, FElapsed)','FKey.Clear'])assert(window.includes(word),word);
  assert(text.includes('FCommands.Complete(WorkerTransferred);'));
  assert(window.includes('State = WorkerTransferred'));
  assert(entry.indexOf('Worker.Free;')<entry.indexOf('Api.Free;'));
  assert(!text.includes('SERVER_ASSIGNED_V1'));
  assert(!ReadContractFile(path.join(native,'Cozy.Source/Cozy.Platform/Cozy.Api.pas'),'utf8').includes('SERVER_ASSIGNED_V1'));
  assert(!fs.existsSync(path.join(native,'Cozy.Source/Cozy.Application/Cozy.Console.pas')));
 });
 console.log(`KEY license window: ${passed} scenarios passed. Server proofs/fixtures and source checks only; Windows UI not executed.`);
}catch(e){console.error(e);process.exitCode=1;}
finally{w.Stop();fs.rmSync(dir,{recursive:true,force:true});}
