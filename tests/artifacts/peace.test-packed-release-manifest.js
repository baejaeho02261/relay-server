'use strict';
// Pure planning boundaries: no network, executable execution or authority files.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const {createRequire}=require('node:module'),{test}=require('node:test');
const provenance=require('../../services/artifacts/peace.desktop-release-provenance');
const evidence=require('../../services/artifacts/peace.desktop-packing-evidence');
const moduleFile=path.resolve(__dirname,'../../services/artifacts/peace.packed-release-manifest.js');
const source=fs.readFileSync(moduleFile,'utf8'),realRequire=createRequire(moduleFile),ROLES=['A','B','O'];
const hash=value=>crypto.createHash('sha512').update(value).digest('hex');
function Fixture(){
 const policy={revision:4,fixture:'current policy'},state={revision:7,releaseGovernance:provenance.Defaults()},db={artifacts:{},packingEvidence:{}};
 const manifest={version:1,releaseName:'fixture original',securityVersion:4,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:1,sourceManifestSha512:hash('native source declaration'),policySha512:hash('earlier policy'),toolchain:{delphi:'fixture',cpp:'fixture',windowsSdk:'fixture',imgui:'fixture'},artifacts:Object.fromEntries(ROLES.map(role=>[role,hash('input '+role)]))};
 const sourceId=provenance.ManifestId(manifest),at=Date.now(),jobId='a'.repeat(32);
 state.releaseGovernance.manifests[sourceId]={manifest:structuredClone(manifest),recordedAt:at,recordedBy:'fixture',registration:'PLANNED'};
 for(const [index,role]of ROLES.entries()){
  const id=String(index+1).repeat(24);
  db.artifacts[id]={id,component:role,version:'1.0.0',protocol:manifest.protocol,hashVersion:3,handoffVersion:1,sha512:manifest.artifacts[role],deploymentManifestId:sourceId};
  const record={version:1,purpose:evidence.DOMAIN,jobId,component:role,sourceArtifactId:id,inputSha512:manifest.artifacts[role],outputSha512:hash('output '+role),size:4096,toolSha512:hash('tool'),profileSha512:hash('profile'),createdAt:at,actorHash:hash('actor')};
  db.packingEvidence[evidence.ReceiptId(record)]=record;
 }
 const revoked=new Set();let sourceReason='',signerAllowed=true,plans=0;
 const operations={State:()=>structuredClone(state),SignerAllowed:()=>signerAllowed,PlanReleaseManifest(body){
  assert.equal(body.expectedRevision,state.revision);plans++;
  const old=state.releaseGovernance.manifests[body.manifestId];
  if(!old){state.releaseGovernance.manifests[body.manifestId]={manifest:structuredClone(body.manifest),registration:'PLANNED',recordedAt:at,recordedBy:'fixture'};state.revision++;}
  return structuredClone(state);
 }};
 const dependencies={
  '../bootstrap/peace.desktop-bootstrap-store':{Load:()=>db},
  '../security/peace.desktop-security-operations':operations,
  '../security/peace.desktop-security-authority':{Policy:()=>structuredClone(policy),ArtifactReason:()=>sourceReason},
  './peace.desktop-release-safety':{CohortReason:(_,id)=>revoked.has(id)?'SECURITY_RELEASE_COHORT_REVOKED':''}
 };
 const module={exports:{}};
 new Function('require','module','exports',source)(request=>dependencies[request]||realRequire(request),module,module.exports);
 const request=()=>({expectedRevision:state.revision,expectedPolicyRevision:policy.revision,jobId});
 return {service:module.exports,db,state,policy,manifest,sourceId,jobId,revoked,request,
  sourceReason:value=>{sourceReason=value;},signerAllowed:value=>{signerAllowed=value;},plans:()=>plans};
}
function Reject(fn,code){assert.throws(fn,error=>error.message===code,code);}
test('derived plan uses durable output hashes, unchanged native declaration and current policy without mutating original',()=>{
 const f=Fixture(),saved=JSON.stringify(f.state.releaseGovernance.manifests[f.sourceId]),result=f.service.Plan(f.request(),'fixture');
 assert.notEqual(result.manifestId,f.sourceId);assert.equal(result.sourceManifestId,f.sourceId);
 assert.deepEqual(result.manifest.toolchain,f.manifest.toolchain);assert.equal(result.manifest.sourceManifestSha512,f.manifest.sourceManifestSha512);
 assert.equal(result.manifest.policySha512,provenance.PolicyDigest(f.policy));assert.equal(result.manifest.securityVersion,4);
 for(const role of ROLES){const record=Object.values(f.db.packingEvidence).find(r=>r.component===role);assert.equal(result.manifest.artifacts[role],record.outputSha512);assert.equal(result.outputs[role].size,record.size);}
 assert.equal(result.windowsVerified,false);assert.equal(result.activeUnchanged,true);assert.equal(result.registration,'PLANNED');
 assert.equal(JSON.stringify(f.state.releaseGovernance.manifests[f.sourceId]),saved);
 result.manifest.toolchain.delphi='browser mutation';assert.equal(f.service.List().jobs[0].manifest.toolchain.delphi,'fixture');
});
test('exact request rejects client-supplied provenance and stale policy/operations revisions before planning',()=>{
 const f=Fixture();Reject(()=>f.service.Plan({...f.request(),manifest:f.manifest},'fixture'),'PACKED_RELEASE_REQUEST_INVALID');
 Reject(()=>f.service.Plan({...f.request(),expectedRevision:6},'fixture'),'SECURITY_OPERATIONS_CONFLICT');
 Reject(()=>f.service.Plan({...f.request(),expectedPolicyRevision:3},'fixture'),'SECURITY_POLICY_CONFLICT');
 Reject(()=>f.service.Plan({...f.request(),jobId:'b'.repeat(32)},'fixture'),'PACKED_RELEASE_JOB_NOT_FOUND');assert.equal(f.plans(),0);
});
test('missing source or mixed original declarations fail closed and remain visible as unavailable jobs',()=>{
 for(const kind of ['missing','empty','mixed','metadata']){
  const f=Fixture(),row=f.db.artifacts['1'.repeat(24)];let expected;
  if(kind==='missing'){delete f.db.artifacts[row.id];expected='PACKED_RELEASE_SOURCE_MISSING';}
  if(kind==='empty'){delete row.deploymentManifestId;expected='PACKED_RELEASE_SOURCE_MANIFEST_REQUIRED';}
  if(kind==='mixed'){row.deploymentManifestId='f'.repeat(128);expected='PACKED_RELEASE_SOURCE_MANIFEST_MIXED';}
  if(kind==='metadata'){row.handoffVersion=3;expected='PACKED_RELEASE_SOURCE_MANIFEST_MISMATCH';}
  Reject(()=>f.service.Plan(f.request(),'fixture'),expected);const job=f.service.List().jobs[0];assert.equal(job.available,false);assert.equal(job.reason,expected);assert.equal(f.plans(),0);
 }
});
test('retired source cohorts, individual revocation and security floors are never relabeled as eligible',()=>{
 const f=Fixture();f.revoked.add(f.sourceId);Reject(()=>f.service.Plan(f.request(),'fixture'),'SECURITY_RELEASE_COHORT_REVOKED');f.revoked.clear();
 f.sourceReason('SECURITY_RELEASE_REVOKED');Reject(()=>f.service.Plan(f.request(),'fixture'),'SECURITY_RELEASE_REVOKED');f.sourceReason('');
 f.db.artifacts['1'.repeat(24)].releaseApproval={keyId:'f'.repeat(64)};f.signerAllowed(false);Reject(()=>f.service.Plan(f.request(),'fixture'),'SECURITY_SIGNER_REVOKED');f.signerAllowed(true);
 f.state.releaseGovernance.requireManifest=true;f.state.releaseGovernance.minimumSecurityVersion=5;
 Reject(()=>f.service.Plan(f.request(),'fixture'),'SECURITY_RELEASE_DOWNGRADE');assert.equal(f.manifest.securityVersion,4);assert.equal(f.plans(),0);
});
test('same job returns same immutable identity, while a changed policy cannot rewrite its existing tuple',()=>{
 const f=Fixture(),one=f.service.Plan(f.request(),'fixture'),two=f.service.Plan(f.request(),'fixture');assert.equal(one.manifestId,two.manifestId);
 f.policy.revision++;f.policy.fixture='stronger current policy';Reject(()=>f.service.Plan(f.request(),'fixture'),'PACKED_RELEASE_POLICY_CHANGED');
 assert.equal(f.state.releaseGovernance.manifests[one.manifestId].manifest.policySha512,one.manifest.policySha512);
});
test('list is bounded to the latest 100 authenticated jobs without loading transient download buffers',()=>{
 const f=Fixture(),original=Object.values(f.db.packingEvidence),at=original[0].createdAt;
 f.db.packingEvidence={};
 for(let index=0;index<101;index++)for(const record of original){const next={...record,jobId:index.toString(16).padStart(32,'0'),createdAt:at+index};f.db.packingEvidence[evidence.ReceiptId(next)]=next;}
 const listed=f.service.List();assert.equal(listed.jobs.length,100);assert.equal(listed.totalJobs,101);assert.equal(listed.truncated,true);assert.equal(listed.jobs[0].createdAt,at+100);assert.equal(listed.jobs[99].createdAt,at+1);
});
