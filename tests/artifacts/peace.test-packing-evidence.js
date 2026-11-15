'use strict';
// Synthetic changed bytes/receipts test authority bindings, never a packer,
// Windows execution, virtualization or executable-protection assurance.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const evidence=require('../../services/artifacts/peace.desktop-packing-evidence');
const sha=x=>crypto.createHash('sha512').update(x).digest('hex');
function Fixture(job=1,at=Date.now()){
 const db={artifacts:{}},records=[];
 for(const [i,component]of evidence.ROLES.entries()){
  const sourceArtifactId=String(i+1).repeat(24),inputSha512=sha('source '+component);
  db.artifacts[sourceArtifactId]={id:sourceArtifactId,component,sha512:inputSha512,size:1024};
  records.push({version:1,purpose:evidence.DOMAIN,jobId:job.toString(16).padStart(32,'0'),component,sourceArtifactId,inputSha512,outputSha512:sha('synthetic changed '+job+' '+component),size:1024+i,toolSha512:sha('synthetic tool'),profileSha512:sha('synthetic profile '+component),createdAt:at,actorHash:sha('synthetic session actor')});
 }
 return {db,records,at};
}
function Add(f){return evidence.RecordJob(f.db,f.records,{now:f.at});}
function Rows(f,ids=Add(f)){
 return evidence.ROLES.map((component,i)=>({id:String(i+4).repeat(24),component,sha512:f.records[i].outputSha512,size:f.records[i].size,packingReceiptId:ids[component]}));
}
function Map(records){return Object.fromEntries(records.map(r=>[evidence.ReceiptId(r),structuredClone(r)]));}
function Reject(fn,code){assert.throws(fn,e=>e.message===code,code);}

test('receipt IDs bind every strict field and are independent of object key order',()=>{
 const {records}=Fixture(),r=records[0];assert.equal(evidence.ReceiptId(r),evidence.ReceiptId(Object.fromEntries(Object.entries(r).reverse())));
 for(const patch of [{jobId:'f'.repeat(32)},{component:'B'},{sourceArtifactId:'9'.repeat(24)},{inputSha512:sha('other input')},{outputSha512:sha('other output')},{size:r.size+1},{toolSha512:sha('other tool')},{profileSha512:sha('other profile')},{createdAt:r.createdAt+1},{actorHash:sha('other actor')}])assert.notEqual(evidence.ReceiptId({...r,...patch}),evidence.ReceiptId(r));
});
test('fake claim fields, unchanged bytes, invalid hashes, role and size are rejected',()=>{
 const r=Fixture().records[0];
 for(const patch of [{windowsVerified:true},{protectionVerified:true},{outputSha512:r.inputSha512},{outputSha512:'A'.repeat(128)},{component:'X'},{size:0},{size:64*1024*1024+1},{sourceArtifactId:'../input.exe'},{actorHash:'x'},{jobId:'x'}])Reject(()=>evidence.ReceiptId({...r,...patch}),'PACKING_EVIDENCE_INVALID');
});
test('whole jobs are atomic, complete, role-bound and idempotent',()=>{
 const f=Fixture(),ids=Add(f),before=JSON.stringify(f.db);assert.deepEqual(Add(f),ids);assert.equal(JSON.stringify(f.db),before);assert.equal(Object.keys(f.db.packingEvidence).length,3);
 const bad=Fixture(2);bad.records[2].inputSha512=sha('wrong source');const original=JSON.stringify(bad.db);Reject(()=>Add(bad),'PACKING_SOURCE_CHANGED');assert.equal(JSON.stringify(bad.db),original);
 Reject(()=>evidence.RecordJob(bad.db,bad.records.slice(0,2),{now:bad.at}),'PACKING_EVIDENCE_INVALID');
 const repeated=Fixture(3);repeated.records[2].component='A';Reject(()=>Add(repeated),'PACKING_COHORT_MISMATCH');
});
test('a completed job ID cannot be relabelled or reused for different outputs',()=>{
 const f=Fixture();Add(f);const before=JSON.stringify(f.db);const changed=structuredClone(f.records);changed[0].outputSha512=sha('conflicting output');Reject(()=>evidence.RecordJob(f.db,changed,{now:f.at}),'PACKING_EVIDENCE_CONFLICT');assert.equal(JSON.stringify(f.db),before);
});
test('receipt storage rejects partial jobs, corrupted IDs and cross-role artifact references',()=>{
 const f=Fixture(),ids=Add(f);const partial=structuredClone(f.db);delete partial.packingEvidence[ids.O];Reject(()=>evidence.ValidateStore(partial),'PACKING_EVIDENCE_INVALID');
 const broken=structuredClone(f.db);broken.packingEvidence[ids.A].size++;Reject(()=>evidence.ValidateStore(broken),'PACKING_EVIDENCE_INVALID');
 const row=Rows(f,ids)[0];f.db.artifacts[row.id]={...row,packingReceiptId:ids.B};Reject(()=>evidence.ValidateStore(f.db),'PACKING_EVIDENCE_BINDING_MISMATCH');
});
test('historical source IDs may be collected but existing contradictory sources fail closed',()=>{
 const f=Fixture();Add(f);const id=f.records[0].sourceArtifactId,source=f.db.artifacts[id];delete f.db.artifacts[id];assert.doesNotThrow(()=>evidence.ValidateStore(f.db));f.db.artifacts[id]={...source,sha512:sha('changed source')};Reject(()=>evidence.ValidateStore(f.db),'PACKING_EVIDENCE_BINDING_MISMATCH');
});
test('legacy pairs remain valid until evidence is required, without invented proof',()=>{
 const f=Fixture(),a=f.db.artifacts['1'.repeat(24)],b=f.db.artifacts['2'.repeat(24)];assert.equal(evidence.EvaluatePair(f.db,a,b,null),'');assert.equal(evidence.EvaluatePair(f.db,a,b,null,{required:true}),'PACKING_EVIDENCE_REQUIRED');assert.equal(evidence.Projection(f.db,a),null);
});
test('one-job A/B/O exact output bindings pass, mixed raw or different jobs are rejected',()=>{
 const f=Fixture(),ids=Add(f),rows=Rows(f,ids);assert.equal(evidence.EvaluatePair(f.db,...rows),'');
 assert.equal(evidence.EvaluatePair(f.db,rows[0],rows[1],f.db.artifacts['3'.repeat(24)]),'PACKING_COHORT_INCOMPLETE');
 const other=Fixture(2,f.at);Object.assign(f.db.packingEvidence,Map(other.records));const otherRows=Rows(other, Object.fromEntries(other.records.map(r=>[r.component,evidence.ReceiptId(r)])));assert.equal(evidence.EvaluatePair(f.db,rows[0],rows[1],otherRows[2]),'PACKING_COHORT_MISMATCH');
 assert.equal(evidence.EvaluatePair(f.db,{...rows[0],size:rows[0].size+1},rows[1],rows[2]),'PACKING_EVIDENCE_BINDING_MISMATCH');
});
test('stripping a reference cannot turn known transformed bytes back into an unproven legacy pair',()=>{
 const f=Fixture(),rows=Rows(f);const stripped=rows.map(({packingReceiptId,...row})=>row);assert.equal(evidence.EvaluatePair(f.db,...stripped),'');assert.equal(evidence.EvaluatePair(f.db,stripped[0],f.db.artifacts['2'.repeat(24)],f.db.artifacts['3'.repeat(24)]),'PACKING_COHORT_INCOMPLETE');assert.match(evidence.Projection(f.db,stripped[0]).receiptId,/^[a-f0-9]{128}$/);
});
test('projections expose exact safe transform metadata and explicitly decline runtime assurance',()=>{
 const f=Fixture(),rows=Rows(f),view=evidence.Projection(f.db,rows[0]);assert.equal(view.scope,'TRANSFORMED_TEMPLATE');assert.equal(view.outputSha512,rows[0].sha512);assert.equal(view.windowsVerified,false);assert.equal(view.protectionVerified,false);assert.equal(Object.hasOwn(view,'actorHash'),false);assert.equal(Object.hasOwn(view,'sourceArtifactId'),false);
});
test('old unreferenced whole jobs are pruned on recording, without partial or referenced deletion',()=>{
 const now=Date.now(),f=Fixture(3,now),old=Fixture(1,now-evidence.UNREFERENCED_MS-1),retained=Fixture(2,now-evidence.UNREFERENCED_MS-1);f.db.packingEvidence={...Map(old.records),...Map(retained.records)};
 const row=Rows(retained,Object.fromEntries(retained.records.map(r=>[r.component,evidence.ReceiptId(r)])))[0];delete row.packingReceiptId;f.db.artifacts[row.id]=row;
 Add(f);assert.equal(Object.keys(f.db.packingEvidence).length,6);for(const r of old.records)assert.equal(f.db.packingEvidence[evidence.ReceiptId(r)],undefined);for(const r of retained.records)assert.ok(f.db.packingEvidence[evidence.ReceiptId(r)]);
});
test('bounded recent or referenced storage fails closed without dropping any existing proof',()=>{
 const now=Date.now(),f=Fixture(1000,now);f.db.packingEvidence={};for(let n=1;n<=evidence.MAX_RECEIPTS/3;n++)Object.assign(f.db.packingEvidence,Map(Fixture(n,now).records));const before=JSON.stringify(f.db);Reject(()=>Add(f),'PACKING_EVIDENCE_CAPACITY');assert.equal(JSON.stringify(f.db),before);
});
test('real publisher binds receipts, latches the cohort, rejects direct activation and reloads durable evidence',()=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'packing-evidence-store-')),root=path.resolve(__dirname,'../..');
 const reload=`const assert=require('node:assert/strict'),s=require(${JSON.stringify(require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store'))}),e=require(${JSON.stringify(require.resolve('../../services/artifacts/peace.desktop-packing-evidence'))});const db=s.Load();assert.equal(Object.keys(db.packingEvidence).length,3);const rows=Object.values(db.artifacts).filter(r=>r.packingReceiptId).sort((a,b)=>a.component.localeCompare(b.component));assert.equal(e.EvaluatePair(db,...rows),'');console.log('packing-evidence-reload-pass');`;
 const script=`const assert=require('node:assert/strict'),crypto=require('node:crypto'),child=require('node:child_process');require(${JSON.stringify(require.resolve('../../core/peace.utilities'))}).EnsureDirs();const boot=require(${JSON.stringify(require.resolve('../../services/bootstrap/peace.desktop-bootstrap'))}),store=require(${JSON.stringify(require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store'))}),e=require(${JSON.stringify(require.resolve('../../services/artifacts/peace.desktop-packing-evidence'))}),{PE}=require(${JSON.stringify(require.resolve('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'))});const sha=x=>crypto.createHash('sha512').update(x).digest('hex'),records=[],outputs={},at=Date.now();for(const c of e.ROLES){const input=PE(c,'synthetic original '+c),source=boot.Publish(c,'1.0',input,undefined,{activate:false}),out=PE(c,'synthetic transformed '+c);outputs[c]=out;records.push({version:1,purpose:e.DOMAIN,jobId:'a'.repeat(32),component:c,sourceArtifactId:source.id,inputSha512:sha(input),outputSha512:sha(out),size:out.length,toolSha512:sha('synthetic tool'),profileSha512:sha('synthetic profile '+c),createdAt:at,actorHash:sha('test actor')});}const ids=store.Atomic(db=>e.RecordJob(db,records));for(const c of e.ROLES){const row=boot.Publish(c,'2.0',outputs[c],undefined,{activate:false});assert.equal(row.packingEvidence.receiptId,ids[c]);assert.equal(row.packingEvidence.windowsVerified,false);assert.equal(store.Load().artifacts[row.id].packingReceiptId,ids[c]);}const ops=require(${JSON.stringify(require.resolve('../../services/security/peace.desktop-security-operations'))}),auth=require(${JSON.stringify(require.resolve('../../services/security/peace.desktop-security-authority'))}),pair=Object.values(store.Load().artifacts).filter(r=>r.packingReceiptId).sort((a,b)=>a.component.localeCompare(b.component));ops.ActivatePair({aId:pair[0].id,bId:pair[1].id,oId:pair[2].id,expectedRevision:ops.Revision(),expectedPolicyRevision:auth.Policy().revision},'TEST');assert.equal(store.Load().securityOperations.requirePackingEvidence,true);const active=structuredClone(store.Load().active);assert.throws(()=>boot.Publish('A','3.0',PE('A','new raw candidate')),e=>e.message==='SECURITY_RELEASE_ATOMIC_PUBLICATION_REQUIRED');assert.deepEqual(store.Load().active,active);const staged=boot.Publish('A','3.0',PE('A','new raw candidate'),undefined,{activate:false});assert.equal(staged.packingEvidence,undefined);assert.deepEqual(store.Load().active,active);const reload=${JSON.stringify(reload)};const result=child.execFileSync(process.execPath,['-e',reload],{cwd:process.cwd(),env:process.env,encoding:'utf8',timeout:30000});assert.match(result,/packing-evidence-reload-pass/);console.log('packing-publish-pass');`;
 try{const result=child.spawnSync(process.execPath,['-e',script],{cwd:root,env:{...process.env,DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'},encoding:'utf8',timeout:60000});assert.equal(result.status,0,result.stderr+'\n'+result.stdout);assert.match(result.stdout,/packing-publish-pass/);}finally{fs.rmSync(temp,{recursive:true,force:true});}
});
