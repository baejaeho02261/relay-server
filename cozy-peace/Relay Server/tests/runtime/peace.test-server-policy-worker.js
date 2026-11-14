'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const policy=require('../../services/artifacts/peace.server-policy-protection');
const {WorkQueue}=require('../../services/runtime/peace.desktop-work-queue');
const {PE}=require('../fixtures/protocol/peace.completion-6-10-fixture');
function Source(role){
 const original=PE(role,Buffer.from('<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><description>SYNTHETIC_WORKER_DATA_ONLY</description></assembly>'));
 const bytes=Buffer.concat([original,policy.CreateUnsealedSlot()]),pe=bytes.readUInt32LE(60),opt=pe+24;
 const last=opt+bytes.readUInt16LE(pe+20)+(bytes.readUInt16LE(pe+6)-1)*40,size=bytes.readUInt32LE(last+16)+policy.SLOT_BYTES;
 bytes.writeUInt32LE(size,last+8);bytes.writeUInt32LE(size,last+16);bytes.writeUInt32LE(Math.ceil((bytes.readUInt32LE(last+12)+size)/4096)*4096,opt+56);return bytes;
}
test('real bounded CPU worker binds public bytes and retains IR only in the internal server result',async()=>{
 const queue=new WorkQueue('keyless-policy-test',1,1,{maxTaskBytes:1024*1024,maxQueuedBytes:2*1024*1024});
 const source=Source('A'),before=Buffer.from(source);let result;
 try{
  const profile={version:1,functions:[{id:2,args:1,body:{op:'xor',left:{op:'arg',index:0},right:{op:'const',value:839117}}}]};
  const pending=queue.run({kind:'server-policy-bind',bytes:source,role:'A',profile},10000,{key:'fixture'});
  profile.functions[0].body.value=0;
  result=await pending;const bytes=Buffer.from(result.bytes);
  assert.deepEqual(source,before);assert.equal(policy.Inspect(bytes).state,'BOUND');
  assert.equal(crypto.createHash('sha512').update(bytes).digest('hex'),result.sha512);
  assert.equal(policy.EvaluateServerPolicy(result.serverPolicy,2,[7]),7^839117);
  assert.equal(bytes.includes(Buffer.from(result.serverPolicy.programBase64,'base64')),false);
  assert.equal(queue.snapshot().completed,1);assert.equal(queue.snapshot().pendingBytes,0);bytes.fill(0);
 }finally{result?.bytes?.fill(0);source.fill(0);before.fill(0);await queue.close();}
 assert.equal(queue.slots.length,0);
});
test('worker validation failures are redacted and leave the CPU lane usable',async()=>{
 const queue=new WorkQueue('keyless-policy-test',1,1,{maxTaskBytes:1024*1024,maxQueuedBytes:2*1024*1024}),source=Source('B');let result;
 try{
  await assert.rejects(queue.run({kind:'server-policy-bind',bytes:source,role:'INVALID',profile:undefined},10000),/^Error: COZY_SERVER_POLICY_ROLE_INVALID$/);
  result=await queue.run({kind:'server-policy-bind',bytes:source,role:'B',profile:undefined},10000);
  assert.equal(policy.Inspect(Buffer.from(result.bytes)).role,'B');assert.equal(queue.snapshot().failed,1);
 }finally{result?.bytes?.fill(0);source.fill(0);await queue.close();}
});
