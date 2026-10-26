'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-final-v2-inputs-'));
require('../fixtures/runtime/peace.private-ci-test-directory').Prepare(temp);
process.env.DATA_DIR=path.join(temp,'state');process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';
const tool=require('../../ci/pipeline/peace.final-windows-inputs'),v2=require('../../services/artifacts/peace.server-policy-protection'),legacy=require('../../services/artifacts/peace.cozy-protection-engine'),evidence=require('../../services/artifacts/peace.desktop-packing-evidence'),authority=require('../../services/security/peace.desktop-security-authority');
const sha=b=>crypto.createHash('sha512').update(b).digest('hex'),write=(p,v)=>fs.writeFileSync(p,JSON.stringify(v));
const source=path.join(temp,'source'),records=[],policies=[],artifacts={},blobs={},jobId=crypto.randomBytes(16).toString('hex'),createdAt=Date.now();
fs.mkdirSync(path.join(source,'Relay Server','maintenance'),{recursive:true});write(path.join(source,'Relay Server','maintenance','source-manifest.json'),{version:2,algorithm:'sha512',files:{'test.pas':sha('synthetic')}});
function Input(role,slot){const original=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture').PE(role,'GAME-HANDOFF-V3 V2 INPUT TEST DATA'),input=Buffer.concat([original,slot]),pe=input.readUInt32LE(60),opt=pe+24,last=opt+input.readUInt16LE(pe+20)+(input.readUInt16LE(pe+6)-1)*40,size=input.readUInt32LE(last+16)+slot.length;input.writeUInt32LE(size,last+8);input.writeUInt32LE(size,last+16);input.writeUInt32LE(Math.ceil((input.readUInt32LE(last+12)+size)/4096)*4096,opt+56);return input;}
for(const[index,role]of ['A','B','O'].entries()){
 const result=v2.BindTemplate(Input(role,v2.CreateUnsealedSlot()),role);blobs[role]=result.bytes;policies.push(result.serverPolicy);artifacts[role]=path.join(temp,role+'.exe');fs.writeFileSync(artifacts[role],result.bytes);
 records.push({version:1,purpose:evidence.DOMAIN,jobId,component:role,sourceArtifactId:String(index+1).repeat(24),inputSha512:result.inputSha512,outputSha512:result.sha512,size:result.bytes.length,toolSha512:result.toolSha512,profileSha512:result.profileSha512,createdAt,actorHash:sha('synthetic actor')});
}
const publicKey=crypto.generateKeyPairSync('ed25519').publicKey,policyFile=path.join(temp,'policy.json'),packingReceiptsFile=path.join(temp,'receipts.json'),serverPoliciesFile=path.join(temp,'server-policies.json'),configFile=path.join(temp,'selected.json');
write(policyFile,{...authority.Defaults(),mode:'enforce',requireReadonlyApi:true,requireCompleteCrcLayers:true,requireReleaseSignature:true,trustedReleaseKeys:[{keyId:crypto.createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex'),publicKey:publicKey.export({type:'spki',format:'pem'}).toString()}]});
write(packingReceiptsFile,records);write(serverPoliciesFile,policies);const config={version:1,releaseVersion:'1.0.0',artifacts,packingReceiptsFile,policyFile,serverPoliciesFile};write(configFile,config);let next=0;const output=()=>path.join(temp,'out-'+(++next));
test('V2 final inputs copy exact EXEs and keep server programs only in private fixture input',()=>{
 const out=output(),summary=tool.Prepare(configFile,source,out);assert.equal(summary.protectionEngine,v2.ENGINE);assert.equal(summary.fixtureEnrollmentApproval,true);assert.equal(summary.productionApproved,false);assert.equal(summary.windowsExecuted,false);assert.equal(summary.serverPolicyAuthenticity,'OPERATOR_SUPPLIED_NOT_INDEPENDENTLY_ATTESTED');
 assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'server-policies.json'))),policies);assert.deepEqual(tool.Verify(out),summary);
 for(const role of ['A','B','O']){assert.equal(summary.artifacts[role].embeddedClientKeyPresent,false);assert.deepEqual(fs.readFileSync(path.join(out,role+'.exe')),blobs[role]);}
 const text=JSON.stringify(summary);assert.doesNotMatch(text,/programBase64/);for(const p of policies)assert.equal(text.includes(p.programBase64),false);
});
test('V2 preparation requires private server policies and rejects changed/mixed policy commitments',()=>{
 const {serverPoliciesFile:ignored,...without}=config;write(configFile,without);const no=output();assert.throws(()=>tool.Prepare(configFile,source,no),/SERVER_POLICIES_REQUIRED/);assert.equal(fs.existsSync(no),false);write(configFile,config);
 for(const mutate of [p=>p.pop(),p=>p[1]=p[0],p=>p[0].policyId='00'.repeat(32),p=>p[0].functionCount++,p=>p[0].programBase64='AAAA']){
  const p=structuredClone(policies);mutate(p);write(serverPoliciesFile,p);const out=output();assert.throws(()=>tool.Prepare(configFile,source,out),/CI_FINAL_SERVER_POLICY_|COZY_SERVER_POLICY_/);assert.equal(fs.existsSync(out),false);
 }write(serverPoliciesFile,policies);
});
test('verification binds private policy data and refuses omitted or falsified V2 context',()=>{
 const out=output();tool.Prepare(configFile,source,out);const summaryFile=path.join(out,'final-execution-inputs.json'),summary=JSON.parse(fs.readFileSync(summaryFile));
 const changed=structuredClone(summary);delete changed.protectionEngine;write(summaryFile,changed);assert.throws(()=>tool.Verify(out),/PROTECTION_CONTEXT_CHANGED/);write(summaryFile,summary);
 const p=JSON.parse(fs.readFileSync(path.join(out,'server-policies.json')));p[0].programBase64='AAAA';write(path.join(out,'server-policies.json'),p);assert.throws(()=>tool.Verify(out),/COZY_SERVER_POLICY_/);
});
test('V1 and V2 artifacts cannot be mixed under one cohort',()=>{
 const old=legacy.Pack(Input('B',legacy.CreateUnsealedSlot()),'B');fs.writeFileSync(artifacts.B,old.bytes);const out=output();try{assert.throws(()=>tool.Prepare(configFile,source,out),/PROTECTION_COHORT_MIXED/);assert.equal(fs.existsSync(out),false);}finally{fs.writeFileSync(artifacts.B,blobs.B);old.bytes.fill(0);}
});
test('V2 server programs are not copied into an unowned or shared output parent',()=>{
 const parent=path.join(temp,'unowned');fs.mkdirSync(parent,{mode:0o700});const out=path.join(parent,'output');
 assert.throws(()=>tool.Prepare(configFile,source,out),/PRIVATE_SERVER_POLICY_PARENT_REQUIRED/);assert.equal(fs.existsSync(out),false);
 fs.writeFileSync(path.join(parent,'ci-owned-marker'),'SYNTHETIC_TEST_ONLY',{mode:0o600});
 if(process.platform!=='win32'){fs.chmodSync(parent,0o755);assert.throws(()=>tool.Prepare(configFile,source,out),/PRIVATE_SERVER_POLICY_PERMISSIONS_REQUIRED/);assert.equal(fs.existsSync(out),false);}
});
test.after(()=>{for(const b of Object.values(blobs))b.fill(0);fs.rmSync(temp,{recursive:true,force:true});});
