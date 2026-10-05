'use strict';
// Real server storage, policy and signature gates with synthetic PE fixtures.
// These tests do not claim a Delphi build or Windows overlay execution.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-deployment-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../core/utils').EnsureDirs();
const boot=require('../services/desktopBootstrap'),store=require('../services/desktopBootstrapStore');
const auth=require('../services/desktopSecurityAuthority'),ops=require('../services/desktopSecurityOperations');
const activation=require('../services/desktopSecurityActivation'),guard=require('../services/desktopAdminGuard');
const workspace=require('../services/desktopWorkspace'),workspaceStore=require('../services/desktopWorkspaceStore');
const fixture=require('./desktop-bootstrap-fixture');
const signer=crypto.generateKeyPairSync('ed25519'),keyId=fixture.sha256(signer.publicKey.export({type:'spki',format:'der'}));
const admin={id:'overlay-deployment-admin',role:'admin'};
let count=0,a,b,o,nextO;
function test(name,fn){fn();console.log('PASS '+name);count++;}
function reject(fn,code){assert.throws(fn,e=>e.message===code,code);}
function staged(component,version){
 const bytes=fixture.PE(component,auth.DOMAIN+' overlay '+version);
 const approval={keyId,signature:crypto.sign(null,Buffer.from(auth.ReleaseCanonical(component,version,fixture.sha256(bytes))),signer.privateKey).toString('base64')};
 return ops.Stage(component,version,bytes,approval,'TEST');
}
function selected(extra={}){return{aId:a.id,bId:b.id,...extra};}
function activate(extra={}){return ops.ActivatePair({...selected(extra),expectedRevision:ops.Revision(),expectedPolicyRevision:auth.Policy().revision},'TEST');}
function contract(row){return ops.SetContract({expectedRevision:ops.Revision(),artifactId:row.id,contract:{version:1,evidenceVersion:1,minApiSlots:1,maxApiSlots:128,requiredChecks:['ownImage','apiStorage','mitigations']}},'TEST');}
function report(row,outcome='PASS'){
 return {version:1,aSha256:a.sha256,bSha256:b.sha256,...(row?{oSha256:row.sha256}:{}),sourceManifestSha256:'1'.repeat(64),logsSha256:'2'.repeat(64),nativeBuild:'PASS',apiProbe:'PASS',integration:outcome,note:'Synthetic server regression; Windows runtime NOT executed.'};
}
function evidence(row,outcome='PASS'){
 return ops.RecordEvidence({...selected(row?{oId:row.id}:{}),expectedRevision:ops.Revision(),report:report(row,outcome)},'TEST');
}
try {
 test('Legacy policy gains minVersionO zero without a storage write or revision change',()=>{
  const legacy=auth.Defaults();delete legacy.minVersionO;store.Atomic(db=>{db.securityAuthorityPolicy=legacy;});
  const before=JSON.stringify(store.Load());assert.equal(auth.Policy().minVersionO,'0');assert.equal(JSON.stringify(store.Load()),before);
  assert.equal(auth.Policy().revision,legacy.revision);assert.equal(auth.ValidatePolicy(legacy).minVersionO,'0');
 });
 test('Signed O candidates use the same component-bound approval as A and B',()=>{
  auth.SetPolicy({expectedRevision:auth.Policy().revision,trustedReleaseKeys:[{keyId,publicKey:signer.publicKey.export({type:'spki',format:'pem'}).toString()}],requireReleaseSignature:true},'TEST');
  a=staged('A','1.0');b=staged('B','1.0');o=staged('O','1.0');nextO=staged('O','1.1');
  assert.equal(store.Load().artifacts[o.id].component,'O');
  assert.equal(auth.VerifyApproval(store.Load().artifacts[o.id],auth.Policy()),true);
  assert.equal(auth.VerifyApproval({...store.Load().artifacts[o.id],component:'B'},auth.Policy()),false);
 });
 test('Legacy A/B activation remains valid before O is selected',()=>{
  activate();assert.deepEqual(store.Load().active,{A:a.id,B:b.id});
  assert.equal(ops.PreviewPair(selected()).oId,'');
 });
 test('Required build contracts cover O as soon as it is selected',()=>{
  contract(a);contract(b);ops.SetControls({expectedRevision:ops.Revision(),requireBuildContract:true},'TEST');
  assert.ok(ops.PreviewPair(selected({oId:o.id})).reasons.includes('SECURITY_BUILD_CONTRACT_REQUIRED'));
  reject(()=>activate({oId:o.id}),'SECURITY_BUILD_CONTRACT_REQUIRED');contract(o);contract(nextO);
 });
 test('Passing A/B evidence cannot authorize an A/B/O deployment or runtime trio',()=>{
  evidence();ops.SetControls({expectedRevision:ops.Revision(),requireTestEvidence:true},'TEST');
  assert.equal(ops.PreviewPair(selected()).eligible,true);
  reject(()=>activate({oId:o.id}),'SECURITY_TEST_EVIDENCE_REQUIRED');
  reject(()=>ops.RequireRuntimePair(a,b,o),'SECURITY_TEST_EVIDENCE_REQUIRED');
 });
 test('Trio evidence requires both the selected O ID and its exact hash',()=>{
  reject(()=>ops.RecordEvidence({...selected({oId:o.id}),expectedRevision:ops.Revision(),report:report(nextO)},'TEST'),'SECURITY_EVIDENCE_ARTIFACT_MISMATCH');
  reject(()=>ops.RecordEvidence({...selected(),expectedRevision:ops.Revision(),report:report(o)},'TEST'),'SECURITY_EVIDENCE_ARTIFACT_MISMATCH');
  reject(()=>ops.RecordEvidence({...selected({oId:o.id}),expectedRevision:ops.Revision(),report:report()},'TEST'),'SECURITY_EVIDENCE_ARTIFACT_MISMATCH');
  reject(()=>ops.PreviewPair(selected({oId:b.id})),'SECURITY_RELEASE_PAIR_INVALID');
 });
 test('NOT_RUN trio evidence never inherits PASS from a prior pair record',()=>{
  evidence(o,'NOT_RUN');assert.equal(ops.PreviewPair(selected({oId:o.id})).eligible,false);
  evidence(o);assert.equal(Object.keys(ops.State().pairEvidence).length,2);
  assert.notEqual(ops.PairKey(a,b),ops.PairKey(a,b,o));
  assert.equal(ops.RequirePairEvidence(a,b,ops.State(),o).oSha256,o.sha256);
 });
 test('Activation swaps all selected artifact pointers atomically and stores O history',()=>{
  activate({oId:o.id});assert.deepEqual(store.Load().active,{A:a.id,B:b.id,O:o.id});
  assert.equal(ops.State().activations.at(-1).oSha256,o.sha256);
  assert.equal(ops.State().activations.at(-1).previousO,'');
 });
 test('Omitted oId preserves active O in previews and A/B-only update calls',()=>{
  assert.equal(ops.PreviewPair(selected()).oId,o.id);activate();assert.equal(store.Load().active.O,o.id);
  assert.equal(ops.State().activations.at(-1).previousO,o.id);
 });
 test('Replacing O requires new exact trio evidence',()=>{
  reject(()=>activate({oId:nextO.id}),'SECURITY_TEST_EVIDENCE_REQUIRED');evidence(nextO);
  activate({oId:nextO.id});assert.equal(store.Load().active.O,nextO.id);activate({oId:o.id});
 });
 test('O bytes are reread immediately before activation and corrupt data cannot publish',()=>{
  const file=store.ArtifactPath(o.id),original=fs.readFileSync(file),before={...store.Load().active};
  fs.writeFileSync(file,Buffer.alloc(original.length));
  try{reject(()=>activate(),'BOOTSTRAP_ARTIFACT_INVALID');assert.deepEqual(store.Load().active,before);}
  finally{fs.writeFileSync(file,original);}
 });
 test('Active O participates in minimum-version, revocation and signer trust gates',()=>{
  reject(()=>auth.SetPolicy({expectedRevision:auth.Policy().revision,minVersionO:'2'},'TEST'),'SECURITY_RELEASE_VERSION');
  reject(()=>auth.SetPolicy({expectedRevision:auth.Policy().revision,revokedSha256:[o.sha256]},'TEST'),'SECURITY_RELEASE_REVOKED');
  assert.equal(auth.ArtifactReason(store.Load().artifacts[o.id],{...auth.Policy(),trustedReleaseKeys:[]}), 'SECURITY_RELEASE_SIGNATURE');
  assert.equal(auth.Policy().minVersionO,'0');
 });
 test('Build-scoped rollout and approval summaries retain O identity',()=>{
  const rollout={enabled:true,artifactKeys:[ops.BuildKey(o)],patch:{dynamicCode:'prohibit'}};
  ops.SetRollout({expectedRevision:ops.Revision(),expectedPolicyRevision:auth.Policy().revision,rollout},'TEST');
  assert.equal(ops.EffectivePolicy(auth.Policy(),o).dynamicCode,'prohibit');
  assert.equal(ops.EffectivePolicy(auth.Policy(),b).dynamicCode,'observe');
  const summary=guard.Summary('/api/desktop/bootstrap/security-operations/test-evidence',{oId:o.id,minVersionO:'1',report:report(o),rollout});
  assert.equal(summary.oId,o.id);assert.equal(summary.testEvidence.oSha256,o.sha256);assert.deepEqual(summary.rollout.artifactKeys,rollout.artifactKeys);
 });
 test('Enable-all preview binds exact O and rejects omission or substitution',()=>{
  const view=activation.Preview('READY',admin);assert.equal(view.ready,true,JSON.stringify(view.issues));
  assert.equal(view.plan.oId,o.id);assert.equal(view.plan.oSha256,o.sha256);
  reject(()=>activation.CheckRequest({...view.plan,oSha256:nextO.sha256},admin),'SECURITY_ACTIVE_PAIR_CHANGED');
  const legacy={...view.plan};delete legacy.oId;delete legacy.oSha256;
  reject(()=>activation.CheckRequest(legacy,admin),'SECURITY_ACTIVE_PAIR_CHANGED');
  assert.ok(view.pending.some(x=>x.component==='O'&&x.code==='SECURITY_RECENT_OBSERVATION_REQUIRED'));
 });
 test('Enable-all records the selected O hash without fabricating runtime observation',()=>{
  const view=activation.Preview('READY',admin),permit=guard.Authorize(admin,'POST',activation.PATH,view.plan,'');
  assert.equal(permit.ok,true,permit.reason);assert.equal(activation.Apply(view.plan,admin,permit.ticket).activated,true);
  assert.equal(activation.Record().oSha256,o.sha256);
  assert.equal(auth.ActivationObservations(auth.Policy(),[o.id]).length,0);
 });
 test('Release notes bind exact trios and preserve old pair notes independently',()=>{
  workspace.SaveReleaseNote({...selected({oId:''}),note:'A/B only'},'TEST');
  workspace.SaveReleaseNote({...selected(),note:'A/B/O tested together'},'TEST');
  assert.equal(workspace.RefreshSummary().releaseNote,'A/B/O tested together');
  assert.equal(workspaceStore.Load().releaseNotes[a.id+':'+b.id].note,'A/B only');
  assert.equal(workspaceStore.Load().releaseNotes[a.id+':'+b.id+':'+o.id].note,'A/B/O tested together');
  reject(()=>workspace.SaveReleaseNote({...selected({oId:b.id}),note:'Wrong component'},'TEST'),'INPUT_INVALID');
 });
 test('Explicit empty oId deselects O and omitted oId then keeps the A/B release',()=>{
  activate({oId:''});assert.equal(store.Load().active.O,undefined);assert.equal(ops.State().activations.at(-1).previousO,o.id);
  assert.equal(workspace.RefreshSummary().releaseNote,'A/B only');activate();assert.equal(store.Load().active.O,undefined);
  activate({oId:o.id});
 });
 test('Server restarts retain O policy, activation, trio evidence and release notes',()=>{
  const code="const service=name=>require(require('node:path').resolve('services',name));const a=service('desktopSecurityAuthority'),o=service('desktopSecurityOperations'),s=service('desktopBootstrapStore'),w=service('desktopWorkspace');process.stdout.write('RESULT:'+JSON.stringify({minimum:a.Policy().minVersionO,active:s.Load().active.O,count:Object.keys(o.State().pairEvidence).length,note:w.RefreshSummary().releaseNote}));";
  const run=child.spawnSync(process.execPath,['-e',code],{cwd:path.resolve(__dirname,'..'),env:process.env,encoding:'utf8'});
  assert.equal(run.status,0,run.stderr);assert.deepEqual(JSON.parse(run.stdout.split('RESULT:').at(-1)),{minimum:'0',active:o.id,count:3,note:'A/B/O tested together'});
 });
 test('Storage retention includes O flow, session, rollback and evidence references',()=>{
  const space=require('../services/desktopStorageSpace'),candidate=staged('O','1.3');
  store.Atomic(db=>{db.artifacts[candidate.id].createdAt=Date.now()-8*86400000;});
  assert.equal(space.Check(candidate.id,candidate.sha256).id,candidate.id);
  const base=structuredClone(store.Load());base.active={};base.launchers={};base.flows={};base.overlays={};base.securityOperations=ops.Defaults();delete base.securityActivation;
  for(const patch of [
   {flows:{test:{overlayReleaseId:candidate.id}}},
   {overlays:{test:{releaseId:candidate.id,status:'PREPARED'}}},
   {overlays:{test:{releaseId:candidate.id,status:'CLOSED'}}},
   {securityOperations:{activations:[{oId:candidate.id}]}},
   {securityOperations:{activations:[{previousO:candidate.id}]}},
   {securityOperations:{pairEvidence:{test:{oSha256:candidate.sha256}}}}
  ])assert.ok(space.References({...base,...patch},candidate.id).length,JSON.stringify(patch));
  workspace.SaveReleaseNote({...selected({oId:candidate.id}),note:'Retain this O deployment candidate'},'TEST');
  reject(()=>space.DeleteCandidate(candidate.id,candidate.sha256),'WORKSPACE_STORAGE_REFERENCED');
  assert.ok(fs.existsSync(store.ArtifactPath(candidate.id)));
 });
 test('Revoked O signer blocks runtime artifact use and candidate republishing',()=>{
  ops.SetSignerState({expectedRevision:ops.Revision(),keyId,state:'REVOKED'},'TEST');
  reject(()=>auth.RequireArtifact(store.Load().artifacts[o.id]),'SECURITY_RELEASE_SIGNATURE');
  reject(()=>staged('O','1.2'),'SECURITY_SIGNER_NOT_ACTIVE');
 });
 console.log(`Overlay deployment: ${count} passed (server policies and synthetic artifacts; no Windows execution).`);
} finally {fs.rmSync(temp,{recursive:true,force:true});}
