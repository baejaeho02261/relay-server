'use strict';
// Portable integration of the final-file fixture path. The PE bytes and packing
// job are synthetic test data: no Windows program is executed, and temporary
// fixture signatures are neither production approval nor Windows evidence.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const child=require('node:child_process');
const ROLES=['A','B','O'];
const sha=value=>crypto.createHash('sha512').update(value).digest('hex');
const json=(file,value)=>fs.writeFileSync(file,JSON.stringify(value),{mode:0o600});

function CreateInputs(run,keyless=false){
  const tool=require('../../tools/windows/peace.final-windows-inputs');
  const engine=require('../../services/artifacts/peace.cozy-protection-engine');
  const v2=require('../../services/artifacts/peace.server-policy-protection');
  const evidence=require('../../services/artifacts/peace.desktop-packing-evidence');
  const authority=require('../../services/security/peace.desktop-security-authority');
  const provenance=require('../../services/artifacts/peace.desktop-release-provenance');
  const source=path.join(run,'source'),out=path.join(run,'prepared');
  fs.mkdirSync(path.join(source,'Relay Server','maintenance'),{recursive:true});
  json(path.join(source,'Relay Server','maintenance','source-manifest.json'),
    {version:2,algorithm:'sha512',files:{'synthetic.pas':sha('nonexecutable fixture source')}});
  const jobId=crypto.randomBytes(16).toString('hex'),createdAt=Date.now();
  const records=[],artifacts={},expected={},sourceRows={},serverPolicies=[];
  for(const [index,role]of ROLES.entries()){
    const original=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture')
      .PE(role,'GAME-HANDOFF-V3 GAME-MEASUREMENT-PLAN-V1 FINAL FIXTURE TEST DATA');
    const slot=keyless?v2.CreateUnsealedSlot():engine.CreateUnsealedSlot(),input=Buffer.concat([original,slot]);
    // Extend the last real PE section to include the protection slot.
    const pe=input.readUInt32LE(60),optional=pe+24,table=optional+input.readUInt16LE(pe+20);
    const last=table+(input.readUInt16LE(pe+6)-1)*40,size=input.readUInt32LE(last+16)+slot.length;
    input.writeUInt32LE(size,last+8);input.writeUInt32LE(size,last+16);
    input.writeUInt32LE(Math.ceil((input.readUInt32LE(last+12)+size)/4096)*4096,optional+56);
    try{
      const result=keyless?v2.BindTemplate(input,role):engine.Pack(input,role),id=String(index+1).repeat(24);
      try{
        if(keyless)serverPolicies.push(result.serverPolicy);
        expected[role]={sha512:result.sha512,size:result.bytes.length};
        artifacts[role]=path.join(run,role+'.exe');
        fs.writeFileSync(artifacts[role],result.bytes,{mode:0o600});
        sourceRows[id]={id,component:role,sha512:result.inputSha512};
        records.push({version:1,purpose:evidence.DOMAIN,jobId,component:role,
          sourceArtifactId:id,inputSha512:result.inputSha512,outputSha512:result.sha512,
          size:result.bytes.length,toolSha512:result.toolSha512,profileSha512:result.profileSha512,
          createdAt,actorHash:sha('ISOLATED_SYNTHETIC_PACKING_JOB')});
      }finally{result.bytes.fill(0);}
    }finally{input.fill(0);original.fill(0);slot.fill(0);}
  }
  // Exercise the receipt recorder against actual synthetic input/output hashes,
  // rather than inserting claimed receipt IDs without their production parser.
  const receiptDb={artifacts:sourceRows,packingEvidence:{}};
  const receiptIds=evidence.RecordJob(receiptDb,records);
  assert.equal(Object.keys(receiptDb.packingEvidence).length,3);
  const reviewedPublic=crypto.generateKeyPairSync('ed25519').publicKey;
  const policy={...authority.Defaults(),mode:'enforce',requireReadonlyApi:true,
    requireCompleteCrcLayers:true,requireReleaseSignature:true,
    trustedReleaseKeys:[{keyId:provenance.KeyId(reviewedPublic),
      publicKey:reviewedPublic.export({type:'spki',format:'pem'}).toString()}]};
  const policyFile=path.join(run,'reviewed-policy.json'),packingReceiptsFile=path.join(run,'receipts.json');
  json(policyFile,policy);json(packingReceiptsFile,records);
  const configFile=path.join(run,'inputs.json');
  const config={version:1,releaseVersion:'1.0.0',artifacts,packingReceiptsFile,policyFile};
  if(keyless){config.serverPoliciesFile=path.join(run,'server-policies.json');json(config.serverPoliciesFile,serverPolicies);}
  json(configFile,config);
  const summary=tool.Prepare(configFile,source,out);
  assert.equal(summary.productionApproved,false);assert.equal(summary.windowsExecuted,false);
  assert.equal(summary.buildProvenance,'NOT_ATTESTED');
  assert.equal(summary.receiptAuthenticity,'OPERATOR_SUPPLIED_NOT_INDEPENDENTLY_ATTESTED');
  assert.notEqual(JSON.parse(fs.readFileSync(path.join(out,'policy.json'))).trustedReleaseKeys[0].keyId,
    policy.trustedReleaseKeys[0].keyId,'fixture signer must be newly generated');
  for(const file of fs.readdirSync(out))if(!file.endsWith('.exe'))
    assert.doesNotMatch(fs.readFileSync(path.join(out,file),'utf8'),/-----BEGIN PRIVATE KEY-----/);
  assert.equal(fs.existsSync(path.join(out,'ci-evidence.json')),false);
  return {out,summary,records,receiptIds,expected,jobId,artifacts,serverPolicies};
}

function Scenario(name,run){
  assert.equal(path.resolve(process.env.DATA_DIR),path.join(fs.realpathSync(run),'server-data'));
  assert.equal(fs.readFileSync(path.join(run,'test-owned-marker'),'utf8'),'SYNTHETIC_TEST_ONLY');
  require('../../core/peace.utilities').EnsureDirs();
  const keyless=name.startsWith('v2-'),f=CreateInputs(run,keyless),fixture=require('../../tools/fixtures/peace.fixture-services');
  const store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
  const ops=require('../../services/security/peace.desktop-security-operations');
  const authority=require('../../services/security/peace.desktop-security-authority');
  const evidence=require('../../services/artifacts/peace.desktop-packing-evidence');
  const boot=require('../../services/bootstrap/peace.desktop-bootstrap');
  const empty=()=>{
    const db=store.Load();
    assert.deepEqual(db.active,{});assert.equal(Object.keys(db.artifacts).length,0);
    assert.equal(Object.keys(db.flows).length,0);assert.equal(Object.keys(db.packingEvidence||{}).length,0);
    assert.equal(Object.keys(db.serverPolicies||{}).length,0);
  };
  if(name==='positive'||name==='v2-positive'){
    const selected=fixture.Provision(run,f.out,'1.0.0'),db=store.Load();
    assert.deepEqual(db.active,Object.fromEntries(ROLES.map(role=>[role,selected[role].id])));
    assert.equal(Object.keys(db.artifacts).length,3);assert.equal(Object.keys(db.packingEvidence).length,3);
    assert.equal(Object.keys(db.flows).length,0);assert.equal(Object.keys(db.launchers).length,0);
    for(const role of ROLES){
      const row=db.artifacts[selected[role].id];
      assert.equal(row.sha512,f.expected[role].sha512);assert.equal(row.size,f.expected[role].size);
      assert.equal(row.ownProtection.state,keyless?'BOUND':'SEALED');assert.equal(row.ownProtection.role,role);
      if(keyless){assert.equal(row.ownProtection.engine,'COZY_SERVER_POLICY_V2');assert.deepEqual(db.serverPolicies[row.ownProtection.policyId],f.serverPolicies.find(p=>p.role===role));}
      assert.equal(row.packingReceiptId,f.receiptIds[role]);
      const receipt=evidence.FindReceipt(db,row);assert.equal(receipt.record.jobId,f.jobId);
      assert.deepEqual(receipt.record,f.records.find(record=>record.component===role));
      assert.equal(authority.ArtifactReason(row,authority.Policy()),'');
      const stored=boot.ReadArtifactBytes(row);
      try{assert.equal(sha(stored),f.expected[role].sha512);assert.equal(stored.equals(fs.readFileSync(f.artifacts[role])),true);}
      finally{stored.fill(0);}
    }
    const view=ops.PreviewPair({aId:selected.A.id,bId:selected.B.id,oId:selected.O.id});
    assert.equal(view.eligible,true);assert.equal(view.packing.receiptsVerified,true);
    assert.equal(view.packing.windowsVerified,false);assert.equal(Object.hasOwn(view.release,'ciVerification'),false);
    assert.equal(view.testEvidence,null);assert.equal(ops.State().requirePackingEvidence,true);
    assert.equal(ops.State().requireCozyProtection,true);
    const manifest=JSON.parse(fs.readFileSync(path.join(f.out,'manifest.json')));
    assert.equal(view.release.manifestId,manifest.manifestId);
    assert.deepEqual(manifest.manifest.artifacts,Object.fromEntries(ROLES.map(role=>[role,f.expected[role].sha512])));
    const before=JSON.stringify(store.Load());
    assert.throws(()=>fixture.Provision(run,f.out,'1.0.0'),/WINDOWS_TEST_FIXTURE_MUST_BE_EMPTY/);
    assert.equal(JSON.stringify(store.Load())===before,true,'a retry cannot replace populated fixture state');
    return;
  }
  if(name==='v2-changed-policy'){
    const policies=structuredClone(f.serverPolicies);policies[0].programBase64='AAAA';
    json(path.join(f.out,'server-policies.json'),policies);
    assert.throws(()=>fixture.Provision(run,f.out,'1.0.0'),/COZY_SERVER_POLICY_/);empty();return;
  }
  if(name==='v2-missing-policy'){
    fs.unlinkSync(path.join(f.out,'server-policies.json'));
    assert.throws(()=>fixture.Provision(run,f.out,'1.0.0'));empty();return;
  }
  if(name==='v2-approval-scope'){
    fixture.Provision(run,f.out,'1.0.0');
    Object.assign(process.env,{DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'1',WEB_ADMIN_PORT:'0'});
    const issue=boot.IssueLauncher({requestId:crypto.randomUUID(),label:'Isolated fixture approval scope'},'ISOLATED_WINDOWS_TEST');
    const row=store.Load().launchers[issue.launcherId],keylessService=require('../../services/bootstrap/peace.keyless-bootstrap');
    const saved={ListPending:keylessService.ListPending,Approve:keylessService.Approve};let pending=[],calls=0;
    // This is a callback scope test. The real dual-key proof/approval protocol
    // is tested separately; these stubs never claim a Windows execution PASS.
    keylessService.ListPending=()=>({requests:pending});
    keylessService.Approve=(id,body,actor)=>{calls++;assert.equal(actor,'ISOLATED_WINDOWS_TEST');assert.equal(body.launcherId,row.id);assert.equal(body.persistentKeyId,pending[0].persistentKeyId);assert.equal(body.identityConfirmed,true);return{id,status:'APPROVED'};};
    try{
      const approve=fixture.KeylessApproval(run,f.out,issue);assert.equal(approve(),false);
      const expected={id:'a'.repeat(48),launcherId:row.id,launcherSha512:row.sha512,status:'PENDING_APPROVAL',proof:'PERSISTENT_KEY_POSSESSION',hardwareAttested:false,persistentKeyId:'B'.repeat(64)};
      for(const edit of [p=>p.launcherId='0'.repeat(24),p=>p.launcherSha512='0'.repeat(128),p=>p.proof='UNVERIFIED',p=>p.status='PROOF_REQUIRED',p=>p.hardwareAttested=true]){
        const p=structuredClone(expected);edit(p);pending=[p];assert.throws(approve,/WINDOWS_TEST_KEYLESS_REQUEST_MISMATCH/);assert.equal(calls,0);
      }
      pending=[expected,structuredClone(expected)];assert.throws(approve,/WINDOWS_TEST_KEYLESS_REQUEST_AMBIGUOUS/);assert.equal(calls,0);
      pending=[expected];process.env.DESKTOP_PUBLIC_HOST='example.invalid';assert.throws(approve,/WINDOWS_TEST_KEYLESS_LOOPBACK_FIXTURE_REQUIRED/);process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';
      assert.equal(approve(),true);assert.equal(approve(),true);assert.equal(calls,1);
    }finally{keylessService.ListPending=saved.ListPending;keylessService.Approve=saved.Approve;}
    return;
  }
  if(name==='v2-claim-observer'){
    Object.assign(process.env,{DESKTOP_PUBLIC_HOST:'127.0.0.1',WEB_ADMIN_PORT:'0'});
    const original=boot.Execute,ack=path.join(run,'b-process-observed.signal');let calls=0,ticks=0,barrier;
    boot.Execute=body=>{calls++;if(body.deny)throw Error('REAL_CLAIM_DENIED');return {existingAuthorization:'unchanged'};};
    try{
      barrier=fixture.ClaimObservationBarrier(run,()=>{if(++ticks===3)fs.writeFileSync(ack,'COZY_B_PROCESS_OBSERVED_V1\n',{flag:'wx',mode:0o600});});
      assert.throws(()=>boot.Execute({action:'claim',deny:true}),/REAL_CLAIM_DENIED/);assert.equal(ticks,0);assert.equal(barrier.Used(),false);
      assert.deepEqual(boot.Execute({action:'status'}),{existingAuthorization:'unchanged'});assert.equal(ticks,0);
      assert.deepEqual(boot.Execute({action:'claim'}),{existingAuthorization:'unchanged'});assert.equal(ticks,3);assert.equal(barrier.Used(),true);assert.equal(calls,3);
      barrier.Restore();barrier=null;assert.throws(()=>fixture.ClaimObservationBarrier(run,()=>{}),/NEW_SIGNAL_REQUIRED/);
      fs.unlinkSync(ack);ticks=0;barrier=fixture.ClaimObservationBarrier(run,()=>{if(++ticks===1)fs.writeFileSync(ack,'invalid',{flag:'wx'});});
      assert.throws(()=>boot.Execute({action:'claim'}),/SIGNAL_INVALID/);assert.equal(barrier.Used(),false);
    }finally{barrier?.Restore();boot.Execute=original;}
    return;
  }
  if(name==='mixed-receipts'){
    const records=structuredClone(f.records);records[1].jobId=crypto.randomBytes(16).toString('hex');
    json(path.join(f.out,'packing-receipts.json'),records);
    assert.throws(()=>fixture.Provision(run,f.out,'1.0.0'),/WINDOWS_TEST_FINAL_RECEIPT_COHORT_REQUIRED/);empty();return;
  }
  if(name==='changed-receipt'){
    const records=structuredClone(f.records);records[1].outputSha512=sha('different final B');
    json(path.join(f.out,'packing-receipts.json'),records);
    assert.throws(()=>fixture.Provision(run,f.out,'1.0.0'),/WINDOWS_TEST_FINAL_RECEIPT_FILE_MISMATCH/);empty();return;
  }
  if(name==='changed-file'){
    const file=path.join(f.out,'B.exe'),bytes=fs.readFileSync(file);bytes[900]^=1;
    try{fs.writeFileSync(file,bytes);}finally{bytes.fill(0);}
    assert.throws(()=>fixture.Provision(run,f.out,'1.0.0'),/WINDOWS_TEST_FINAL_ARTIFACT_CHANGED/);empty();return;
  }
  if(name==='wrong-signature'){
    const approval=JSON.parse(fs.readFileSync(path.join(f.out,'A.approval.json')));
    const signature=Buffer.from(approval.signature,'base64');signature[0]^=1;
    approval.signature=signature.toString('base64');signature.fill(0);
    json(path.join(f.out,'A.approval.json'),approval);
    assert.throws(()=>fixture.Provision(run,f.out,'1.0.0'),/SECURITY_RELEASE_SIGNATURE/);
    assert.deepEqual(store.Load().active,{});assert.equal(Object.keys(store.Load().artifacts).length,0);
    assert.equal(Object.keys(store.Load().flows).length,0);
    return;
  }
  throw Error('UNKNOWN_SYNTHETIC_SCENARIO');
}

async function CleanupLoaded(){
  const errors=[],stops=[];
  const stop=(module,method)=>{try{const loaded=require.cache[module]?.exports;if(loaded?.[method])stops.push(Promise.resolve().then(()=>loaded[method]()));}catch(error){errors.push(error);}};
  stop(require.resolve('../../services/bootstrap/peace.desktop-bootstrap'),'Stop');
  const queues=require.cache[require.resolve('../../services/runtime/peace.desktop-work-queue')]?.exports;
  for(const key of ['auth','pe','proof','renewalProof','tpmAttestation'])if(queues?.[key])stops.push(Promise.resolve().then(()=>queues[key].close()));
  for(const result of await Promise.allSettled(stops))if(result.status==='rejected')errors.push(result.reason);
  const stores=[
    [require.resolve('../../services/observability/peace.desktop-performance-metrics'),'Close'],
    [require.resolve('../../storage/sqlite/peace.sqlite-database'),'Close'],
    [require.resolve('../../services/recovery/peace.desktop-recovery-witness'),'Close']
  ];
  for(const [module,method]of stores)try{await require.cache[module]?.exports?.[method]?.();}catch(error){errors.push(error);}
  if(errors.length)throw Error('SYNTHETIC_FIXTURE_CLEANUP_FAILED');
}

if(process.argv[2]==='--scenario'){
  // Audit remains active in the isolated DATA_DIR; avoid dumping its metadata.
  const log=console.log;console.log=(...args)=>{if(!String(args[0]).startsWith('[EVENT]'))log(...args);};
  (async()=>{try{Scenario(process.argv[3],process.argv[4]);}finally{await CleanupLoaded();}})()
    .catch(error=>{console.error(/^[A-Z][A-Z0-9_]+$/.test(error.message)?error.message:'SYNTHETIC_FIXTURE_ASSERTION_FAILED');process.exitCode=1;});
}else{
  const test=require('node:test');
  const scenarios=[
    ['positive','real fixture services approve and activate only the exact sealed synthetic A/B/O cohort'],
    ['v2-positive','real fixture services bind private V2 policies and activate only their exact A/B/O cohort'],
    ['v2-changed-policy','changed V2 private server program cannot stage or activate any final file'],
    ['v2-missing-policy','missing V2 private server policy cannot stage or activate any final file'],
    ['v2-approval-scope','isolated enrollment callback accepts only its one expected already-proven launcher'],
    ['v2-claim-observer','fixture observation barrier retains real claim result and requires a fresh controller signal'],
    ['mixed-receipts','a mixed-job receipt set cannot stage or activate any final file'],
    ['changed-receipt','a receipt naming another final digest cannot stage or activate files'],
    ['changed-file','a changed final executable fails before fixture artifact import'],
    ['wrong-signature','a changed temporary approval is rejected by the real signature gate']
  ];
  for(const [scenario,name]of scenarios)test(name,()=>{
    const run=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-final-windows-provision-'));
    try{
      require('../fixtures/runtime/peace.private-test-directory').Prepare(run);
      const result=child.spawnSync(process.execPath,[__filename,'--scenario',scenario,run],{
        env:{...process.env,DATA_DIR:path.join(run,'server-data'),STORAGE_ENGINE:'json',HA_ENABLED:'0'},
        encoding:'utf8',timeout:30000,maxBuffer:2*1024*1024
      });
      assert.equal(result.signal,null,result.error?.message||'child process must exit after cleanup');
      assert.equal(result.status,0,result.stderr+'\n'+result.stdout);
    }finally{fs.rmSync(run,{recursive:true,force:true});}
    assert.equal(fs.existsSync(run),false);
  });
}
