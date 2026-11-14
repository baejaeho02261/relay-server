'use strict';
// A transformed cohort has a new immutable identity. Derive that identity from
// authenticated packing receipts and the original registered build declaration;
// this does not sign an EXE, approve Windows execution or publish a release.
const provenance=require('./peace.desktop-release-provenance');
const evidence=require('./peace.desktop-packing-evidence');
const ROLES=['A','B','O'],JOB=/^[a-f0-9]{32}$/;
function Fail(code,status=409){const error=Error(code);error.desktopError=true;error.status=status;throw error;}
function Plain(value){return !!value&&Object.getPrototypeOf(value)===Object.prototype;}
function Dependencies(){return {
  store:require('../bootstrap/peace.desktop-bootstrap-store'),
  operations:require('../security/peace.desktop-security-operations'),
  authority:require('../security/peace.desktop-security-authority'),
  safety:require('./peace.desktop-release-safety')
};}
function Context(){
  const dependencies=Dependencies(),db=dependencies.store.Load();
  evidence.ValidateStore(db);
  return {...dependencies,db,state:dependencies.operations.State(),policy:dependencies.authority.Policy()};
}
function Records(context,jobId){
  const records=Object.values(context.db.packingEvidence||{}).filter(record=>record.jobId===jobId);
  if(records.length!==3)Fail('PACKED_RELEASE_JOB_NOT_FOUND',404);
  return ROLES.map(role=>records.find(record=>record.component===role));
}
function Outputs(context,records){
  return Object.fromEntries(records.map(record=>[record.component,{
    sha512:record.outputSha512,size:record.size,sourceArtifactId:record.sourceArtifactId,
    sourceVersion:context.db.artifacts[record.sourceArtifactId]?.version||''
  }]));
}
function Derive(context,jobId){
  const records=Records(context,jobId),sources=records.map(record=>context.db.artifacts[record.sourceArtifactId]);
  if(sources.some(source=>!source))Fail('PACKED_RELEASE_SOURCE_MISSING');
  for(let index=0;index<ROLES.length;index++){
    const source=sources[index],record=records[index];
    if(source.component!==ROLES[index]||source.sha512!==record.inputSha512)Fail('PACKED_RELEASE_SOURCE_MANIFEST_MISMATCH');
  }
  const declarations=sources.map(source=>source.deploymentManifestId||'');
  if(declarations.some(id=>!id))Fail('PACKED_RELEASE_SOURCE_MANIFEST_REQUIRED');
  if(new Set(declarations).size!==1)Fail('PACKED_RELEASE_SOURCE_MANIFEST_MIXED');
  const sourceManifestId=declarations[0],sourceRecord=context.state.releaseGovernance.manifests[sourceManifestId];
  if(!sourceRecord)Fail('PACKED_RELEASE_SOURCE_MANIFEST_REQUIRED');
  const original=provenance.ValidateManifest(sourceRecord.manifest);
  if(provenance.ManifestId(original)!==sourceManifestId)Fail('PACKED_RELEASE_SOURCE_MANIFEST_MISMATCH');
  for(let index=0;index<ROLES.length;index++){
    const role=ROLES[index],source=sources[index];
    if(original.artifacts[role]!==records[index].inputSha512||source.protocol!==original.protocol||source.hashVersion!==original.hashVersion||(source.handoffVersion||1)!==original.handoffVersion)Fail('PACKED_RELEASE_SOURCE_MANIFEST_MISMATCH');
    if(source.releaseApproval?.keyId&&!context.operations.SignerAllowed(source.releaseApproval.keyId))Fail('SECURITY_SIGNER_REVOKED');
    const reason=context.authority.ArtifactReason(source,context.policy);
    if(reason)Fail(reason);
  }
  const retired=context.safety.CohortReason(context.db,sourceManifestId);if(retired)Fail(retired);
  if(original.securityVersion<provenance.PublicationPolicy(context.state.releaseGovernance).minimumSecurityVersion)Fail('SECURITY_RELEASE_DOWNGRADE');
  const manifest={...structuredClone(original),policySha512:provenance.PolicyDigest(context.policy),
    artifacts:Object.fromEntries(records.map(record=>[record.component,record.outputSha512]))};
  const manifestId=provenance.ManifestId(manifest);
  if(manifestId===sourceManifestId)Fail('PACKED_RELEASE_SOURCE_MANIFEST_MISMATCH');
  const existing=Object.entries(context.state.releaseGovernance.manifests).find(([,record])=>provenance.Tuple(record.manifest.artifacts)===provenance.Tuple(manifest.artifacts));
  if(existing&&existing[0]!==manifestId)Fail(existing[1].manifest.policySha512!==manifest.policySha512?'PACKED_RELEASE_POLICY_CHANGED':'PACKED_RELEASE_MANIFEST_CONFLICT');
  const finalRetired=context.safety.CohortReason(context.db,manifestId);if(finalRetired)Fail(finalRetired);
  return {jobId,sourceManifestId,manifestId,manifest,outputs:Outputs(context,records),
    sourceReleaseName:original.releaseName,createdAt:records[0].createdAt,
    registration:existing?(existing[1].registration||'REGISTERED'):'PLANNED'};
}
function List(){
  const context=Context(),groups=new Map();
  for(const record of Object.values(context.db.packingEvidence||{}))groups.set(record.jobId,record.createdAt);
  const jobs=[...groups.entries()].sort((a,b)=>b[1]-a[1]||b[0].localeCompare(a[0])).slice(0,100).map(([jobId,createdAt])=>{
    try{const value=Derive(context,jobId);return {...value,available:true,windowsVerified:false};}
    catch(error){if(!error.desktopError)throw error;return {jobId,createdAt,outputs:Outputs(context,Records(context,jobId)),available:false,reason:error.message,windowsVerified:false};}
  });
  return {jobs,totalJobs:groups.size,truncated:groups.size>jobs.length,expectedRevision:context.state.revision,expectedPolicyRevision:context.policy.revision};
}
function ExportReceipts(jobId){
  if(typeof jobId!=='string'||!JOB.test(jobId))Fail('PACKED_RELEASE_REQUEST_INVALID',400);
  const db=Dependencies().store.Load();evidence.ValidateStore(db);
  // Only the exact validated three-record cohort leaves this read path. Never
  // export authority state, keys, capabilities or client-supplied replacement data.
  return structuredClone(Records({db},jobId));
}
function Plan(body,actor){
  if(!Plain(body)||Object.keys(body).sort().join(',')!=='expectedPolicyRevision,expectedRevision,jobId'||typeof body.jobId!=='string'||!JOB.test(body.jobId)||!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||!Number.isSafeInteger(body.expectedPolicyRevision)||body.expectedPolicyRevision<0)Fail('PACKED_RELEASE_REQUEST_INVALID',400);
  const context=Context();
  if(body.expectedRevision!==context.state.revision)Fail('SECURITY_OPERATIONS_CONFLICT');
  if(body.expectedPolicyRevision!==context.policy.revision)Fail('SECURITY_POLICY_CONFLICT');
  const result=Derive(context,body.jobId),state=context.operations.PlanReleaseManifest({expectedRevision:body.expectedRevision,manifestId:result.manifestId,manifest:result.manifest},actor);
  return {...result,operationsRevision:state.revision,policyRevision:context.policy.revision,
    registration:state.releaseGovernance.manifests[result.manifestId].registration||'REGISTERED',
    windowsVerified:false,activeUnchanged:true};
}
module.exports={List,Plan,ExportReceipts};
