'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),tls=require('node:tls'),net=require('node:net'),crypto=require('node:crypto');
const fixture=require("../../../tools/integrity/peace.native-receive-fixture");
function Receive(port,nonce){return new Promise(resolve=>{const chunks=[];let error='';const socket=tls.connect({host:'127.0.0.1',port,servername:'localhost',minVersion:'TLSv1.2',maxVersion:'TLSv1.2',rejectUnauthorized:false},()=>socket.write(JSON.stringify({nonce})+'\n'));const timer=setTimeout(()=>socket.destroy(Error('FIXTURE_TEST_TIMEOUT')),5000);socket.on('data',b=>chunks.push(b));socket.on('error',e=>{error=e.code||e.message;});socket.on('close',()=>{clearTimeout(timer);resolve({bytes:Buffer.concat(chunks),error});});});}
(async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'receive-fixture-test-'));let checks=0;
 try{
  const {identity,pin}=fixture.Certificates(root),cases=fixture.Cases();assert.match(pin,/^[a-f0-9]{64}$/);assert.equal(cases.find(x=>x.id==='line-exact-bound').bytes.length,1025);assert.equal(cases.find(x=>x.id==='line-over-bound').bytes.length,1026);
  for(const row of cases.filter(x=>x.bytes)){
   const nonce=crypto.randomBytes(16).toString('hex'),server=await fixture.Serve(row,identity,nonce);
   try{const received=await Receive(server.port,nonce);assert.equal(server.observation.nonceReceived,true);assert.equal(server.observation.responseSent,true);
    if(row.corruptRecord){assert.equal(server.observation.recordMutated,true);assert.notEqual(received.error,'');assert.equal(received.bytes.length,0);}
    else{assert.equal(received.error,'');assert.deepEqual(received.bytes,row.bytes);}
    checks++;
   }finally{await server.close();}
  }
  for(const row of cases.filter(x=>x.raw)){
   const server=await fixture.Serve(row,identity,'0'.repeat(32));
   try{const output=await new Promise((resolve,reject)=>{const chunks=[],s=net.connect(server.port,'127.0.0.1',()=>s.write(Buffer.from('160303000101','hex')));s.on('error',reject);s.on('data',b=>chunks.push(b));s.on('end',()=>resolve(Buffer.concat(chunks)));});assert.deepEqual(output,row.raw);assert.equal(server.observation.clientHello,true);checks++;}
   finally{await server.close();}
  }
  const row=cases.find(x=>x.corruptRecord),nonce='1'.repeat(32),observed={version:1,caseId:row.id,nonce,nativeReceiveExecuted:true,tlsConnected:true,lineReceived:false,jsonAccepted:false,peAccepted:false,transportClosed:true,elapsedMs:30},wire={connections:1,tlsAccepted:true,nonceReceived:true,responseSent:true,recordMutated:true};
  assert.equal(fixture.Evaluate(row,observed,wire,nonce).outcome,'PASS');
  for(const changed of [{nativeReceiveExecuted:false},{nonce:'2'.repeat(32)},{lineReceived:true},{transportClosed:false},{elapsedMs:7000}]){assert.throws(()=>fixture.Evaluate(row,{...observed,...changed},wire,nonce));checks++;}
  for(const changed of [{connections:0},{nonceReceived:false},{recordMutated:false}]){assert.throws(()=>fixture.Evaluate(row,observed,{...wire,...changed},nonce));checks++;}
  console.log('PASS '+checks+' localhost fixture delivery and evaluator negative checks; native Schannel/product-session/GPU execution NOT_RUN.');
 }finally{fs.rmSync(root,{recursive:true,force:true});}
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
