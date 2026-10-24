'use strict';
// Portable real TLS/AEAD/RSA test with synthetic PE bytes. No Windows A/B/O is
// executed and no native PASS evidence is produced. The parent owns cleanup
// after worker exit, including Windows files held by the single-writer lock.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os');
const path=require('node:path'),cp=require('node:child_process'),crypto=require('node:crypto');
if(process.argv[2]!=='--worker'){
 assert.equal(process.argv.length,2,'PRODUCT_FAULT_WIRE_ARGUMENT');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'product-fault-wire-'));
 try{
  const run=cp.spawnSync(process.execPath,[__filename,'--worker'],{env:{...process.env,DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'},encoding:'utf8',timeout:30000,maxBuffer:2*1024*1024});
  if(run.error)throw run.error;
  assert.equal(run.status,0,run.stderr||run.stdout);
  const result=JSON.parse(run.stdout);assert.equal(result.status,'PASS');assert.equal(result.nativeExecuted,false);
  process.stdout.write(JSON.stringify(result)+'\n');
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}else{
 // Silence synthetic fixture events; retain exception diagnostics on stderr.
 console.log=()=>{};
 require("../../core/peace.utilities.js").EnsureDirs();
 const f=require("../fixtures/bootstrap/peace.desktop-bootstrap-fixture"),boot=require("../../services/bootstrap/peace.desktop-bootstrap");
 const delegation=require("../../services/bootstrap/peace.desktop-handoff-delegation"),transport=require("../../services/network/peace.desktop-connect");
 const request=require("../fixtures/network/peace.tls-request-fixture").Request;
 let adapter,server;
 (async()=>{try{
  for(const role of ['A','B','O'])boot.Publish(role,'92.0.0',f.PE(role,delegation.MARKER));
  const a=f.Device(),b=f.Device();b.machineId=a.machineId;
  const begin=f.Begin(a,{handoffVersion:3}).begin;f.Download(begin);const finish=f.Finish(a,begin);
  const nonce=crypto.randomBytes(32).toString('hex').toUpperCase();
  const claim={action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,handoffVersion:3,
   childPublicKey:b.publicKey,childKeyId:b.deviceId,childNonce:nonce,
   delegationSignature:f.Sign(a,delegation.Canonical('DELEGATION','B',finish.claimCanonical,b.deviceId,nonce)),
   signature:f.Sign(b,delegation.Canonical('CLAIM','B',finish.claimCanonical,b.deviceId,nonce)),
   binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64};
  adapter=require("../../ci/fixtures/peace.product-fault-adapter").Install({scenario:'response-loss-claim-b'});
  server=transport.CreateServer();adapter.Attach(server);
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  process.env.DESKTOP_PUBLIC_PORT=String(server.address().port);
  const profile=require("../../services/network/peace.connect-transport-key").Profile();
  await assert.rejects(request(profile,'bootstrap',claim),error=>error instanceof SyntaxError||error.code==='ECONNRESET');
  assert.equal(adapter.Status().droppedResponses,1,'actual committed response must be dropped');
  const retry=await request(profile,'bootstrap',claim);assert.equal(retry.ok,true,JSON.stringify(retry));
  const proof=adapter.Status();
  for(const key of ['observed','retryObserved','sameBusinessRequest','sameCommittedResult','noDoubleConsumption','noDuplicateDelegation','distinctChildren'])assert.equal(proof[key],true,key);
  const close=await request(profile,'bootstrap',{action:'close',sessionId:retry.data.sessionId,sessionToken:retry.data.sessionToken});
  assert.equal(close.ok,true,JSON.stringify(close));
  const reuse=adapter.Reuse();assert.equal(reuse.reuseDenied,true);assert.equal(reuse.reuseChecks,2);
  process.stdout.write(JSON.stringify({suite:'PRODUCT_FAULT_REAL_TLS_ADAPTER',status:'PASS',artifacts:'SYNTHETIC_PE',nativeExecuted:false,
   droppedResponses:proof.droppedResponses,retryObserved:proof.retryObserved,sameCommittedResult:proof.sameCommittedResult,
   reuseDenied:reuse.reuseDenied,reuseChecks:reuse.reuseChecks})+'\n');
 }finally{
  adapter?.Dispose();
  if(server?.listening)await new Promise(resolve=>server.close(resolve));
  boot.Stop();
  const queue=require("../../services/runtime/peace.desktop-work-queue");
  await Promise.all(['auth','pe','proof','renewalProof','tpmAttestation'].map(name=>queue[name].close()));
 }} )().catch(error=>{console.error(error);process.exitCode=1;});
}
