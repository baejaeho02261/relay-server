 'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const {WorkQueue,pe}=require('../services/desktopWorkQueue');
function task(payload){const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),aad=Buffer.from('GAME-TEST-ONLY-AAD');
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad);const ciphertext=Buffer.concat([cipher.update(Buffer.from(payload)),cipher.final()]);
 const wrappedKey=crypto.publicEncrypt({key:keys.publicKey,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key);
 return {key,work:{kind:'open',privateKey:keys.privateKey,wrappedKey,nonce,aad,ciphertext,tag:cipher.getAuthTag()}};
}
(async()=>{const queue=new WorkQueue('test-auth',1,1),tiny=new WorkQueue('test-capacity',1,0);let count=0;
 try{
 const input=task('{"version":1,"action":"verify"}');const good=await queue.run(input.work,10000);assert.deepEqual(good.payload,{version:1,action:'verify'});assert.deepEqual(Buffer.from(good.key),input.key);good.key.fill(0);input.key.fill(0);count++;
 const altered={...input.work,tag:Buffer.alloc(16)};await assert.rejects(queue.run(altered),/WORK_TASK_FAILED/);count++;
 const ambiguous=task('{"a":1,"a":2}');await assert.rejects(queue.run(ambiguous.work),/WORK_TASK_FAILED/);ambiguous.key.fill(0);count++;
 const running=tiny.run(input.work,10000);await assert.rejects(tiny.run(input.work),/WORK_QUEUE_BUSY/);const returned=await running;returned.key.fill(0);count++;
 const pending=tiny.run(input.work,0.001);await assert.rejects(pending,/WORK_DEADLINE/);assert(tiny.snapshot().timedOut>=1||tiny.snapshot().failed>=1);count++;
 const cache=require('../services/desktopPeCache'),integrity=require('../services/desktopIntegrity');const corpus=require('../contracts/pe-corpus-v1.json');const row=corpus.cases.find(r=>r.accepted),bytes=Buffer.from(row.bytes,'base64');
 const original=await cache.Prepare(bytes);original.digests.sha512='caller-mutated';assert.equal(cache.Get(bytes,'digests').sha512,row.fileSha512);
 const copy=cache.Get(bytes,'code');copy.sha512='mutated';assert.equal(integrity.CodeImage(bytes).sha512,row.codeSha512);bytes[0]^=1;assert.throws(()=>cache.Get(bytes,'code'),/BOOTSTRAP_UPLOAD_CHANGED/);count++;
 await queue.close();await assert.rejects(queue.run(input.work),/WORK_QUEUE_CLOSED/);count++;
 console.log(`PASS ${count} worker groups: real RSA-OAEP/AES-GCM, strict payload, FIFO cap, deadline, cache isolation, stop/drain`);
 }finally{await queue.close();await tiny.close();await pe.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
