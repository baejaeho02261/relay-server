'use strict';
// Real publication/runtime validators and Ed25519 approvals over synthetic PE
// fixtures. Server receipt records here are test data, not a native packer or
// evidence of Windows execution.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {Fixture,hash,roles}=require('../fixtures/runtime/peace.next123-fixture');
const packing=require('../../services/artifacts/peace.desktop-packing-evidence');

function ProtectedFixture(){
  const f=Fixture(),source=f.cohort(1,'unpacked'),output=f.cohort(1,'transformed');
  function record(input,target,jobId=crypto.randomBytes(16).toString('hex'),options={}){
    const createdAt=options.createdAt??Date.now(),actorHash=hash('SYNTHETIC PACKING OPERATOR');
    const records=roles.map((component,i)=>({version:1,purpose:'GAME-PACKING-RECEIPT-V1',jobId,component,
      sourceArtifactId:input.rows[i].id,inputSha512:input.rows[i].sha512,
      outputSha512:target.rows[i].sha512,size:target.rows[i].size,
      toolSha512:hash('SYNTHETIC TOOL'),profileSha512:hash('SYNTHETIC PROFILE '+component),createdAt,actorHash}));
    const ids=packing.RecordJob(f.db,records,{now:Math.max(Date.now(),createdAt)});
    if(options.attach!==false)for(const row of target.rows)row.packingReceiptId=ids[row.component];
    return {ids,records};
  }
  return {...f,get db(){return f.db;},source,output,record};
}
function reason(view,code){assert.equal(view.eligible,false);assert.ok(view.reasons.includes(code),JSON.stringify(view.reasons));}

test('legacy cohorts keep their existing publication and runtime behavior before the packing floor',()=>{
  const f=Fixture(),c=f.cohort();const before=JSON.stringify(f.db);
  const view=f.ops.PreviewProductionPair(c.select);
  assert.equal(view.eligible,true);assert.equal(view.packing.status,'NOT_RECORDED');
  assert.equal(view.packing.receiptsVerified,false);assert.equal(view.packing.windowsVerified,false);
  assert.equal(JSON.stringify(f.db),before);
  assert.equal(f.activate(c).eligible,true);assert.equal(f.ops.State().requirePackingEvidence,false);
  assert.doesNotThrow(()=>f.ops.RequireRuntimePair(...c.rows));
});

test('older operations state remains readable while an invalid packing floor is rejected',()=>{
  const f=Fixture();delete f.db.securityOperations.requirePackingEvidence;
  assert.doesNotThrow(()=>f.ops.ValidateState(f.db.securityOperations));
  assert.equal(f.ops.State().requirePackingEvidence,false);
  assert.equal(Object.hasOwn(f.db.securityOperations,'requirePackingEvidence'),false);
  assert.throws(()=>f.ops.ValidateState({...f.db.securityOperations,requirePackingEvidence:'true'}),/STORAGE_INVALID/);
});

test('one complete bound job is accepted without pretending Windows or issued configuration was protected',()=>{
  const f=ProtectedFixture();f.record(f.source,f.output);
  const view=f.ops.PreviewProductionPair(f.output.select);
  assert.equal(view.eligible,true);assert.equal(view.packing.receiptsVerified,true);
  assert.equal(view.packing.proofScope,'TRANSFORMED_TEMPLATES_ONLY');
  assert.equal(view.packing.windowsVerified,false);assert.equal(view.packing.issuedAConfigurationProtected,false);
  assert.equal(f.activate(f.output).eligible,true);
  assert.equal(f.ops.State().requirePackingEvidence,true);
  assert.doesNotThrow(()=>f.ops.RequireRuntimePair(...f.output.rows));
});

test('packing receipt references cannot be swapped between roles',()=>{
  const f=ProtectedFixture(),job=f.record(f.source,f.output);
  f.output.rows[0].packingReceiptId=job.ids.B;
  reason(f.ops.PreviewProductionPair(f.output.select),'PACKING_EVIDENCE_BINDING_MISMATCH');
  assert.throws(()=>f.ops.RequireRuntimePair(...f.output.rows),/PACKING_EVIDENCE_BINDING_MISMATCH/);
  assert.throws(()=>f.activate(f.output),/PACKING_EVIDENCE_BINDING_MISMATCH/);
  assert.deepEqual(f.db.active,{});assert.equal(f.ops.State().requirePackingEvidence,false);
});

test('an existing receipt cannot be replayed onto different output bytes',()=>{
  const f=ProtectedFixture(),job=f.record(f.source,f.output),other=f.cohort(1,'unrelated-output');
  other.rows[0].packingReceiptId=job.ids.A;
  reason(f.ops.PreviewProductionPair(other.select),'PACKING_EVIDENCE_BINDING_MISMATCH');
  assert.throws(()=>f.ops.RequireRuntimePair(...other.rows),/PACKING_EVIDENCE_BINDING_MISMATCH/);
});

test('partial or mixed job output cannot reach runtime even under legacy optional QA controls',()=>{
  const f=ProtectedFixture();f.record(f.source,f.output);
  const source2=f.cohort(1,'second-input'),other=f.cohort(1,'second-output');f.record(source2,other);
  const mixed=[f.output.rows[0],other.rows[1],f.output.rows[2]];
  assert.throws(()=>f.ops.RequireRuntimePair(...mixed),/PACKING_COHORT_MISMATCH/);
  const view=f.ops.PreviewProductionPair({aId:mixed[0].id,bId:mixed[1].id,oId:mixed[2].id});
  reason(view,'PACKING_COHORT_MISMATCH');
  assert.throws(()=>f.ops.RequireRuntimePair(f.output.rows[0],f.source.rows[1],f.output.rows[2]),/PACKING_COHORT_INCOMPLETE/);
});

test('omitting the selected overlay cannot turn receipt-backed A/B into a complete packed cohort',()=>{
  const f=ProtectedFixture();f.record(f.source,f.output);
  reason(f.ops.PreviewProductionPair({...f.output.select,oId:''}),'PACKING_COHORT_INCOMPLETE');
  assert.throws(()=>f.ops.RequireRuntimePair(f.output.rows[0],f.output.rows[1]),/PACKING_COHORT_INCOMPLETE/);
});

test('stripping receipt references does not silently downgrade known transformed outputs to legacy',()=>{
  const f=ProtectedFixture();f.record(f.source,f.output);
  for(const row of f.output.rows)delete row.packingReceiptId;
  const view=f.ops.PreviewProductionPair(f.output.select);
  assert.equal(view.eligible,true);assert.equal(view.packing.receiptsVerified,true);
  f.activate(f.output);assert.equal(f.ops.State().requirePackingEvidence,true);
});

test('activation pins resolved receipts so a repeated deterministic A output cannot change the active job',()=>{
  const f=ProtectedFixture(),first=f.record(f.source,f.output);
  for(const row of f.output.rows)delete row.packingReceiptId;
  f.activate(f.output);
  const active=roles.map(role=>f.db.artifacts[f.db.active[role]]);
  const hashes=active.map(row=>row.sha512);
  const source2=f.cohort(1,'deterministic-input-two'),output2=f.cohort(1,'deterministic-output-two');
  output2.rows[0]=active[0];
  const second=f.record(source2,output2,crypto.randomBytes(16).toString('hex'),{attach:false,createdAt:first.records[0].createdAt+1});
  assert.notEqual(second.ids.A,first.ids.A);
  assert.doesNotThrow(()=>f.ops.RequireRuntimePair(...roles.map(role=>f.db.artifacts[f.db.active[role]])));
  assert.deepEqual(roles.map(role=>f.db.artifacts[f.db.active[role]].sha512),hashes);
  assert.deepEqual(roles.map(role=>f.db.artifacts[f.db.active[role]].packingReceiptId),roles.map(role=>first.ids[role]));
});

test('final activation rechecks receipts inside the same atomic pointer swap',()=>{
  const f=ProtectedFixture(),job=f.record(f.source,f.output);f.active(f.source);
  f.setHook(()=>{delete f.db.packingEvidence[job.ids.O];});
  assert.throws(()=>f.activate(f.output),/PACKING_/);
  assert.deepEqual(f.db.active,Object.fromEntries(f.source.rows.map(row=>[row.component,row.id])));
  assert.equal(f.ops.State().requirePackingEvidence,false);
});

test('a published receipt-backed cohort latches the packing floor and blocks unpacked downgrade and recovery',()=>{
  const f=ProtectedFixture();f.active(f.source);f.pin(f.source);f.record(f.source,f.output);f.activate(f.output);
  assert.equal(f.ops.State().requirePackingEvidence,true);
  reason(f.ops.PreviewProductionPair(f.source.select),'PACKING_EVIDENCE_REQUIRED');
  assert.throws(()=>f.ops.RequireRuntimePair(...f.source.rows),/PACKING_EVIDENCE_REQUIRED/);
  assert.throws(()=>f.activate(f.source),/PACKING_EVIDENCE_REQUIRED/);
  assert.throws(()=>f.ops.PrepareProductionRecovery({expectedRevision:f.ops.Revision(),expectedPolicyRevision:f.auth.Policy().revision,
    requestId:crypto.randomUUID(),...f.source.select,reason:'SYNTHETIC DOWNGRADE ATTEMPT'},'FIXTURE_OPERATOR'),/PACKING_EVIDENCE_REQUIRED/);
  assert.throws(()=>f.ops.SetControls({expectedRevision:f.ops.Revision(),requirePackingEvidence:false},'FIXTURE_OPERATOR'),/SECURITY_OPERATIONS_INVALID/);
  assert.deepEqual(f.db.active,Object.fromEntries(f.output.rows.map(row=>[row.component,row.id])));
});

for(const role of roles)test('packing evidence never overrides revoked or invalid '+role+' executable approval',()=>{
  const f=ProtectedFixture();f.record(f.source,f.output);const row=f.output.rows[roles.indexOf(role)];
  f.db.securityAuthorityPolicy.revokedSha512.push(row.sha512);
  reason(f.ops.PreviewProductionPair(f.output.select),'SECURITY_RELEASE_REVOKED');
  assert.throws(()=>f.activate(f.output),/REVOKED/);
  f.db.securityAuthorityPolicy.revokedSha512=[];row.releaseApproval.signature=Buffer.alloc(64).toString('base64');
  reason(f.ops.PreviewProductionPair(f.output.select),'SECURITY_RELEASE_SIGNATURE');
  assert.throws(()=>f.activate(f.output),/SIGNATURE/);
});

test('a client packed flag cannot create proof or clear a receipt-bound requirement',()=>{
  const f=Fixture(),c=f.cohort();for(const row of c.rows)row.packed=true;
  assert.equal(f.ops.PreviewProductionPair(c.select).packing.receiptsVerified,false);
  assert.throws(()=>f.ops.PreviewProductionPair({...c.select,packed:true}),/SECURITY_OPERATIONS_INVALID/);
  f.db.securityOperations.requirePackingEvidence=true;
  reason(f.ops.PreviewProductionPair(c.select),'PACKING_EVIDENCE_REQUIRED');
});
