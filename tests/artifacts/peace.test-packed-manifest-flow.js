'use strict';
// Real authenticated authority files, Ed25519 EXE approvals and Cozy slot
// transforms over synthetic PE data. These tests never execute a Windows EXE
// and never manufacture a Windows test or automatic approval.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const child=require('node:child_process');
const ROLES=['A','B','O'];
const sha=value=>crypto.createHash('sha512').update(value).digest('hex');

function Modules(){
  require('../../core/peace.utilities').EnsureDirs();
  return {
    ops:require('../../services/security/peace.desktop-security-operations'),
    auth:require('../../services/security/peace.desktop-security-authority'),
    store:require('../../services/bootstrap/peace.desktop-bootstrap-store'),
    boot:require('../../services/bootstrap/peace.desktop-bootstrap'),
    provenance:require('../../services/artifacts/peace.desktop-release-provenance'),
    packing:require('../../services/artifacts/peace.desktop-packing-evidence'),
    engine:require('../../services/artifacts/peace.cozy-protection-engine'),
    planner:require('../../services/artifacts/peace.packed-release-manifest')
  };
}
function Fixture(m){
  const keys=crypto.generateKeyPairSync('ed25519');
  const publicKey=keys.publicKey.export({type:'spki',format:'pem'}).toString();
  const keyId=m.provenance.KeyId(keys.publicKey);
  m.auth.SetPolicy({expectedRevision:m.auth.Policy().revision,requireReleaseSignature:true,trustedReleaseKeys:[{keyId,publicKey}]},'SYNTHETIC_OPERATOR');
  m.ops.SetProductionGovernance({expectedRevision:m.ops.Revision(),requireManifest:true,minimumSecurityVersion:1},'SYNTHETIC_OPERATOR');
  function approval(role,version,bytes){
    return {keyId,signature:crypto.sign(null,Buffer.from(m.auth.ReleaseCanonical(role,version,sha(bytes))),keys.privateKey).toString('base64')};
  }
  function original(label='first'){
    const version='101.0.0';
    const bytes=Object.fromEntries(ROLES.map(role=>[role,Template(role,label,m.engine)]));
    const manifest={version:1,releaseName:'SYNTHETIC-PACKED-'+label,securityVersion:1,
      protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:1,
      sourceManifestSha512:sha('synthetic private source declaration '+label),
      policySha512:m.provenance.PolicyDigest(m.auth.Policy()),
      toolchain:{delphi:'synthetic declaration',cpp:'synthetic declaration',windowsSdk:'synthetic declaration',imgui:'synthetic declaration'},
      artifacts:Object.fromEntries(ROLES.map(role=>[role,sha(bytes[role])]))};
    const manifestId=m.provenance.ManifestId(manifest),rows={};
    m.ops.PlanReleaseManifest({expectedRevision:m.ops.Revision(),manifestId,manifest},'SYNTHETIC_OPERATOR');
    for(const role of ROLES)rows[role]=m.ops.Stage(role,version,bytes[role],approval(role,version,bytes[role]),'SYNTHETIC_OPERATOR',manifestId);
    m.ops.RecordReleaseManifest({expectedRevision:m.ops.Revision(),manifestId,manifest},'SYNTHETIC_OPERATOR');
    return {version,manifestId,manifest,bytes,rows};
  }
  function transformed(source,overrides={}){
    const jobId=crypto.randomBytes(16).toString('hex'),at=Date.now();
    const inputs=Object.fromEntries(ROLES.map(role=>[role,overrides[role]||source]));
    const outputs=Object.fromEntries(ROLES.map(role=>[role,m.engine.Pack(inputs[role].bytes[role],role)]));
    const records=ROLES.map(role=>({version:1,purpose:m.packing.DOMAIN,jobId,component:role,
      sourceArtifactId:inputs[role].rows[role].id,inputSha512:sha(inputs[role].bytes[role]),
      outputSha512:outputs[role].sha512,size:outputs[role].bytes.length,
      toolSha512:outputs[role].toolSha512,profileSha512:outputs[role].profileSha512,
      createdAt:at,actorHash:sha('SYNTHETIC_OPERATOR')}));
    const receiptIds=m.store.Atomic(db=>m.packing.RecordJob(db,records));
    return {jobId,outputs,records,receiptIds};
  }
  return {approval,original,transformed};
}
function Template(role,label,engine){
  const original=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture').PE(role,'packed manifest '+label+' GAME-MEASUREMENT-PLAN-V1');
  const bytes=Buffer.alloc(original.length+4096);original.copy(bytes);
  const pe=bytes.readUInt32LE(60),optional=pe+24,table=optional+bytes.readUInt16LE(pe+20),slot=table+80;
  bytes.writeUInt16LE(3,pe+6);bytes.writeUInt32LE(0x4000,optional+56);
  bytes.write('.cozy',slot);bytes.writeUInt32LE(4096,slot+8);bytes.writeUInt32LE(0x3000,slot+12);
  bytes.writeUInt32LE(4096,slot+16);bytes.writeUInt32LE(original.length,slot+20);bytes.writeUInt32LE(0xc0000040,slot+36);
  engine.CreateUnsealedSlot().copy(bytes,original.length);
  return bytes;
}
function Request(m,jobId){return {expectedRevision:m.ops.Revision(),expectedPolicyRevision:m.auth.Policy().revision,jobId};}
function Reject(fn,code){assert.throws(fn,error=>error.message===code,code);}
function ReadOnlyFailure(m,fn,code){const before=JSON.stringify(m.store.Load());Reject(fn,code);assert.equal(JSON.stringify(m.store.Load()),before);}
function Select(rows){return {aId:rows.A.id,bId:rows.B.id,oId:rows.O.id};}

function Scenario(name){
  const m=Modules();
  if(name==='resume'){
    const jobId=Object.values(m.store.Load().packingEvidence)[0].jobId;
    const result=m.planner.Plan(Request(m,jobId),'SYNTHETIC_OPERATOR');
    assert.equal(result.registration,'PLANNED');
    assert.equal(result.windowsVerified,false);
    console.log('PACKED_MANIFEST_RESUMED '+JSON.stringify({manifestId:result.manifestId,artifacts:result.manifest.artifacts,jobId}));
    return;
  }
  const f=Fixture(m),original=f.original(),packed=f.transformed(original);
  const originalRecord=JSON.stringify(m.ops.State().releaseGovernance.manifests[original.manifestId]);
  if(name==='publish'){
    for(const role of ROLES){
      const output=packed.outputs[role].bytes;
      ReadOnlyFailure(m,()=>m.ops.Stage(role,original.version,output,f.approval(role,original.version,output),'SYNTHETIC_OPERATOR',original.manifestId),'SECURITY_MANIFEST_ARTIFACT_MISMATCH');
    }
    const plan=m.planner.Plan(Request(m,packed.jobId),'SYNTHETIC_OPERATOR');
    assert.notEqual(plan.manifestId,original.manifestId);
    assert.equal(plan.sourceManifestId,original.manifestId);
    assert.equal(plan.windowsVerified,false);assert.equal(plan.activeUnchanged,true);
    assert.equal(plan.registration,'PLANNED');
    assert.deepEqual(plan.manifest.toolchain,original.manifest.toolchain);
    assert.equal(plan.manifest.sourceManifestSha512,original.manifest.sourceManifestSha512);
    assert.equal(plan.manifest.securityVersion,original.manifest.securityVersion);
    assert.equal(plan.manifest.policySha512,m.provenance.PolicyDigest(m.auth.Policy()));
    assert.equal(JSON.stringify(m.ops.State().releaseGovernance.manifests[original.manifestId]),originalRecord);
    assert.deepEqual(m.store.Load().active,{});
    const revision=m.ops.Revision(),retry=m.planner.Plan(Request(m,packed.jobId),'SYNTHETIC_OPERATOR');
    assert.equal(retry.manifestId,plan.manifestId);assert.equal(m.ops.Revision(),revision);
    for(const role of ROLES)ReadOnlyFailure(m,()=>m.ops.Stage(role,original.version,packed.outputs[role].bytes,f.approval(role,original.version,original.bytes[role]),'SYNTHETIC_OPERATOR',plan.manifestId),'SECURITY_RELEASE_SIGNATURE');
    ReadOnlyFailure(m,()=>m.ops.Stage('A',original.version,packed.outputs.B.bytes,f.approval('A',original.version,packed.outputs.B.bytes),'SYNTHETIC_OPERATOR',plan.manifestId),'COZY_PROTECTION_ROLE_MISMATCH');
    const changed=Buffer.from(packed.outputs.B.bytes);changed[900]^=1;
    ReadOnlyFailure(m,()=>m.ops.Stage('B',original.version,changed,f.approval('B',original.version,changed),'SYNTHETIC_OPERATOR',plan.manifestId),'SECURITY_MANIFEST_ARTIFACT_MISMATCH');
    const rows={};
    for(const role of ROLES){
      const output=packed.outputs[role].bytes;
      rows[role]=m.ops.Stage(role,original.version,output,f.approval(role,original.version,output),'SYNTHETIC_OPERATOR',plan.manifestId);
      assert.equal(rows[role].deploymentManifestId,plan.manifestId);
      assert.equal(rows[role].packingEvidence.jobId,packed.jobId);
      assert.equal(rows[role].ownProtection.state,'SEALED');
    }
    const beforeRegistration=m.ops.PreviewProductionPair(Select(rows));
    assert.equal(beforeRegistration.eligible,false);
    assert.ok(beforeRegistration.reasons.includes('SECURITY_RELEASE_MANIFEST_NOT_REGISTERED'));
    m.ops.RecordReleaseManifest({expectedRevision:m.ops.Revision(),manifestId:plan.manifestId,manifest:plan.manifest},'SYNTHETIC_OPERATOR');
    const preview=m.ops.PreviewProductionPair(Select(rows));
    assert.equal(preview.eligible,false);
    assert.ok(preview.reasons.includes('COZY_VM_V1_EMBEDDED_KEY_RETIRED'),JSON.stringify(preview.reasons));
    assert.equal(preview.packing.windowsVerified,false);
    assert.equal(preview.packing.receiptsVerified,true);
    assert.equal(preview.release.hardwareAttested,false);
    ReadOnlyFailure(m,()=>m.ops.ActivateProductionPair({...Select(rows),expectedRevision:m.ops.Revision(),expectedPolicyRevision:m.auth.Policy().revision},'SYNTHETIC_OPERATOR'),'COZY_VM_V1_EMBEDDED_KEY_RETIRED');
    assert.deepEqual(m.store.Load().active,{});
    assert.equal(m.ops.State().requireCozyProtection,false);
    assert.equal(m.ops.State().requirePackingEvidence,false);
    assert.equal(m.auth.Policy().requireReleaseSignature,true);
    assert.equal(JSON.stringify(m.ops.State().releaseGovernance.manifests[original.manifestId]),originalRecord);
    return;
  }
  if(name==='invalid-request'){
    ReadOnlyFailure(m,()=>m.planner.Plan({...Request(m,packed.jobId),expectedRevision:m.ops.Revision()-1},'SYNTHETIC_OPERATOR'),'SECURITY_OPERATIONS_CONFLICT');
    ReadOnlyFailure(m,()=>m.planner.Plan({...Request(m,packed.jobId),expectedPolicyRevision:m.auth.Policy().revision+1},'SYNTHETIC_OPERATOR'),'SECURITY_POLICY_CONFLICT');
    ReadOnlyFailure(m,()=>m.planner.Plan(Request(m,'0'.repeat(32)),'SYNTHETIC_OPERATOR'),'PACKED_RELEASE_JOB_NOT_FOUND');
    ReadOnlyFailure(m,()=>m.planner.Plan({...Request(m,packed.jobId),artifacts:{A:sha('declared')}} ,'SYNTHETIC_OPERATOR'),'PACKED_RELEASE_REQUEST_INVALID');
    assert.equal(m.planner.List().jobs[0].manifestId,m.provenance.ManifestId({...original.manifest,artifacts:Object.fromEntries(ROLES.map(role=>[role,packed.outputs[role].sha512]))}));
    return;
  }
  if(name==='policy-change'){
    const plan=m.planner.Plan(Request(m,packed.jobId),'SYNTHETIC_OPERATOR');
    m.auth.SetPolicy({expectedRevision:m.auth.Policy().revision,freshnessMs:46000},'SYNTHETIC_OPERATOR');
    ReadOnlyFailure(m,()=>m.planner.Plan(Request(m,packed.jobId),'SYNTHETIC_OPERATOR'),'PACKED_RELEASE_POLICY_CHANGED');
    assert.equal(m.ops.State().releaseGovernance.manifests[plan.manifestId].manifest.policySha512,plan.manifest.policySha512);
    assert.equal(JSON.stringify(m.ops.State().releaseGovernance.manifests[original.manifestId]),originalRecord);
    return;
  }
  if(name==='revoked-source'){
    m.auth.SetPolicy({expectedRevision:m.auth.Policy().revision,revokedSha512:[original.rows.A.sha512]},'SYNTHETIC_OPERATOR');
    ReadOnlyFailure(m,()=>m.planner.Plan(Request(m,packed.jobId),'SYNTHETIC_OPERATOR'),'SECURITY_RELEASE_REVOKED');
    assert.equal(m.planner.List().jobs[0].available,false);
    return;
  }
  if(name==='security-floor'){
    m.ops.SetProductionGovernance({expectedRevision:m.ops.Revision(),minimumSecurityVersion:2},'SYNTHETIC_OPERATOR');
    ReadOnlyFailure(m,()=>m.planner.Plan(Request(m,packed.jobId),'SYNTHETIC_OPERATOR'),'SECURITY_RELEASE_DOWNGRADE');
    assert.equal(m.ops.State().releaseGovernance.minimumSecurityVersion,2);
    return;
  }
  if(name==='source-cohort'){
    const second=f.original('second'),mixed=f.transformed(original,{B:second});
    ReadOnlyFailure(m,()=>m.planner.Plan(Request(m,mixed.jobId),'SYNTHETIC_OPERATOR'),'PACKED_RELEASE_SOURCE_MANIFEST_MIXED');
    m.store.Atomic(db=>{delete db.artifacts[original.rows.A.id];});
    ReadOnlyFailure(m,()=>m.planner.Plan(Request(m,packed.jobId),'SYNTHETIC_OPERATOR'),'PACKED_RELEASE_SOURCE_MISSING');
    return;
  }
  if(name==='restart'){
    const result=child.spawnSync(process.execPath,[__filename,'--scenario','resume'],{env:process.env,encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024});
    assert.equal(result.status,0,result.stderr+'\n'+result.stdout);
    const line=result.stdout.split('\n').find(value=>value.startsWith('PACKED_MANIFEST_RESUMED '));
    assert.ok(line,'second process must load durable source cohort and packing receipts');
    const resumed=JSON.parse(line.slice('PACKED_MANIFEST_RESUMED '.length));
    assert.equal(resumed.jobId,packed.jobId);
    assert.deepEqual(resumed.artifacts,Object.fromEntries(ROLES.map(role=>[role,packed.outputs[role].sha512])));
    assert.notEqual(resumed.manifestId,original.manifestId);
    return;
  }
  throw Error('UNKNOWN_SYNTHETIC_SCENARIO');
}

if(process.argv[2]==='--scenario'){
  Scenario(process.argv[3]);
  process.exit(0);
}else{
  const test=require('node:test');
  const scenarios=[
    ['publish','legacy VM outputs retain exact manifest and signature checks but production publication is retired'],
    ['invalid-request','revision, policy, job and undeclared hash substitution fail without state mutation'],
    ['policy-change','a policy change cannot silently rewrite an already planned output cohort'],
    ['revoked-source','revoked source approvals cannot authorize a new packed declaration'],
    ['security-floor','automatic planning preserves the declared security version and irreversible floor'],
    ['source-cohort','mixed original manifests and collected sources cannot derive a final cohort'],
    ['restart','durable packing receipts and original manifest survive a separate process without download buffers']
  ];
  for(const [scenario,name]of scenarios)test(name,()=>{
    const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-packed-manifest-flow-'));
    try{
      const result=child.spawnSync(process.execPath,[__filename,'--scenario',scenario],{
        env:{...process.env,DATA_DIR:directory,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'},
        encoding:'utf8',timeout:45000,maxBuffer:12*1024*1024
      });
      assert.equal(result.status,0,result.error?.message||result.stderr+'\n'+result.stdout);
    }finally{fs.rmSync(directory,{recursive:true,force:true});}
  });
}
