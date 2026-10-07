'use strict';
// Production publishing/activation gates with synthetic PE64 fixtures. This
// exercises admission of real parsed CRC baselines, not Windows execution.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-crc-release-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../core/utils').EnsureDirs();
const boot=require('../services/desktopBootstrap'),auth=require('../services/desktopSecurityAuthority'),ops=require('../services/desktopSecurityOperations'),store=require('../services/desktopBootstrapStore');
const integrity=require('../services/desktopIntegrity'),crc=require('../services/desktopCrcPolicy'),{PE}=require('./desktop-bootstrap-fixture');
const actor='CRC-RELEASE-TEST';
let count=0;
function test(name,fn){fn();count++;console.log('PASS '+name);}
function reject(fn,code){assert.throws(fn,error=>error.message===code,code);}
function partialBytes(component){const bytes=PE(component);bytes.fill(0,1024,1040);return bytes;}
function activate(ids){return ops.ActivatePair({...ids,expectedRevision:ops.Revision(),expectedPolicyRevision:auth.Policy().revision},actor);}
const partial=integrity.CodeImage(partialBytes('A')).crcLayers;
assert.equal(crc.Validate(partial),true);assert.equal(crc.Compare(partial,partial).complete,false);
store.Load();
const artifacts={};let ids,receipt,request;
test('A/B/O incomplete candidate uploads cannot persist bytes, artifacts or active pointers',()=>{
 for(const component of ['A','B','O']){
  const before=JSON.stringify(store.Load()),files=fs.readdirSync(path.join(temp,'desktop-bootstrap')).sort();
  reject(()=>boot.Publish(component,'1.0',partialBytes(component)),'CRC_COVERAGE_INCOMPLETE');
  reject(()=>ops.Stage(component,'1.0',partialBytes(component),undefined,actor),'CRC_COVERAGE_INCOMPLETE');
  assert.equal(JSON.stringify(store.Load()),before);
  assert.deepEqual(fs.readdirSync(path.join(temp,'desktop-bootstrap')).sort(),files);
 }
});
test('Provisional metadata checks remain independent; stored artifact checks require a valid baseline',()=>{
 const bytes=PE('A'),metadata=auth.PublishMetadata('A','1.0',bytes);
 const row={component:'A',version:'1.0',...integrity.Digests(bytes),...metadata};
 assert.equal(auth.ArtifactReason(row,auth.Policy()),'CRC_BASELINE_UNAVAILABLE');
 reject(()=>auth.RequireArtifact(row),'CRC_BASELINE_UNAVAILABLE');
});
test('Complete candidates may be staged before their required build contracts are registered',()=>{
 ops.SetControls({expectedRevision:ops.Revision(),requireBuildContract:true},actor);
 for(const component of ['A','B','O']) artifacts[component]=ops.Stage(component,'1.0',PE(component),undefined,actor);
 assert.deepEqual(store.Load().active,{});
 ids={aId:artifacts.A.id,bId:artifacts.B.id,oId:artifacts.O.id};
 assert.ok(ops.PreviewPair(ids).reasons.includes('SECURITY_BUILD_CONTRACT_REQUIRED'));
 ops.SetControls({expectedRevision:ops.Revision(),requireBuildContract:false},actor);
 assert.equal(activate(ids).eligible,true);
 request={requestId:crypto.randomUUID(),label:'retained receipt'};receipt=boot.IssueLauncher(request,actor);
 assert.equal(boot.IssueLauncher(request,actor).launcherId,receipt.launcherId);
});
for(const component of ['A','B','O'])test(component+' historical incomplete baseline blocks preview, activation and new/retried issuance',()=>{
 const id=artifacts[component].id,complete=structuredClone(store.Load().artifacts[id].crcLayers);
 store.Atomic(db=>{db.artifacts[id].crcLayers=structuredClone(partial);});
 try{
  const before=JSON.stringify(store.Load()),view=ops.PreviewPair(ids);
  assert.equal(view.eligible,false);assert.ok(view.reasons.includes('CRC_COVERAGE_INCOMPLETE'));
  const preview=auth.PreviewPolicy({expectedRevision:auth.Policy().revision});
  assert.equal(preview.eligible,false);assert.equal(preview.releases.find(row=>row.id===id).reason,'CRC_COVERAGE_INCOMPLETE');
  reject(()=>activate(ids),'CRC_COVERAGE_INCOMPLETE');
  reject(()=>auth.RequireArtifact(store.Load().artifacts[id]),'CRC_COVERAGE_INCOMPLETE');
  reject(()=>boot.IssueLauncher({requestId:crypto.randomUUID()},actor),'CRC_COVERAGE_INCOMPLETE');
  reject(()=>boot.IssueLauncher(request,actor),'CRC_COVERAGE_INCOMPLETE');
  // Re-staging identical bytes must not silently upgrade old recorded coverage.
  reject(()=>ops.Stage(component,'1.0',PE(component),undefined,actor),'CRC_COVERAGE_INCOMPLETE');
  assert.equal(JSON.stringify(store.Load()),before);
 }finally{store.Atomic(db=>{db.artifacts[id].crcLayers=complete;});}
});
test('Only an explicit coverage policy change permits structurally valid partial baselines',()=>{
 auth.SetPolicy({expectedRevision:auth.Policy().revision,requireCompleteCrcLayers:false},actor);
 for(const component of ['A','B','O']){
  const out=boot.Publish(component,'2.0',partialBytes(component)),row=store.Load().artifacts[out.id];
  assert.equal(out.crcCoverage.matched,true);assert.equal(out.crcCoverage.complete,false);
  assert.equal(auth.ArtifactReason(row,auth.Policy()),'');
  for(const crcLayers of [undefined,null,{}, {...partial,nvme:{...partial.nvme,status:'measured'}}]){
   assert.equal(auth.ArtifactReason({...row,crcLayers},auth.Policy()),'CRC_BASELINE_UNAVAILABLE');
   reject(()=>auth.RequireArtifact({...row,crcLayers}),'CRC_BASELINE_UNAVAILABLE');
  }
 }
 const preview=auth.PreviewPolicy({expectedRevision:auth.Policy().revision,requireCompleteCrcLayers:true});
 assert.equal(preview.eligible,false);
 reject(()=>auth.SetPolicy({expectedRevision:auth.Policy().revision,requireCompleteCrcLayers:true},actor),'CRC_COVERAGE_INCOMPLETE');
});
console.log(`CRC release eligibility: ${count} passed (server services; synthetic PE fixtures; no Windows execution)`);
