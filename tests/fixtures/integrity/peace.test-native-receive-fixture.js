'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),tls=require('node:tls'),net=require('node:net'),crypto=require('node:crypto');
const fixture=require('../../../tools/integrity/peace.native-receive-fixture');
// Node/OpenSSL verifies fixture delivery only. The Windows native runner must
// separately verify real Schannel counters and the product certificate pin.
function Receive(port,nonce){return new Promise(resolve=>{const chunks=[];let error='';const socket=tls.connect({host:'127.0.0.1',port,servername:'localhost',minVersion:'TLSv1.2',maxVersion:'TLSv1.2',rejectUnauthorized:false},()=>socket.write(JSON.stringify({nonce})+'\n'));const timer=setTimeout(()=>socket.destroy(Error('FIXTURE_TEST_TIMEOUT')),5000);socket.on('data',b=>chunks.push(b));socket.on('error',e=>{error=e.code||e.message;});socket.on('close',()=>{clearTimeout(timer);resolve({bytes:Buffer.concat(chunks),error});});});}
function NativeReport(row,nonce){return {
 version:1,caseId:row.id,nonce,nativeReceiveExecuted:true,
 tlsConnected:row.connected,lineReceived:row.received&&row.connected,jsonAccepted:row.accepted,peAccepted:row.peAccepted,
 transportClosed:!!(row.closed||!row.connected),elapsedMs:30,
 preAuthenticationReadRejected:true,terminalReadRejected:!!row.terminalRead,
 postFailureReadRejected:!!(row.closed||!row.connected),postFailureWriteRejected:!!(row.closed||!row.connected),
 realProviderCalls:5,providerOverrideCalls:0,handshakeIncomplete:0,readIncomplete:0,readExtra:0,contextExpired:0,
 ...row.minCounters,
};}
function WireReport(row){return {
 connections:1,clientHello:!!row.raw,tlsAccepted:!row.raw&&!row.handshakeTruncate,
 nonceReceived:row.connected,responseSent:!row.wrongPin,recordMutated:!!row.corruptRecord,
 applicationRecords:row.recordMode==='coalesced'?2:1,coalescedRecords:row.recordMode==='coalesced'?2:0,
 recordTruncated:row.recordMode==='truncated',recordFragments:row.recordMode==='fragmented'?2:0,
 handshakeTruncated:!!row.handshakeTruncate,closeNotifyRecord:!!row.closeNotify,
};}
(async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'receive-fixture-test-'));let checks=0;
 try{
  const {identity,pin}=fixture.Certificates(root),cases=fixture.Cases();
  assert.match(pin,/^[a-f0-9]{64}$/);assert.equal(new Set(cases.map(x=>x.id)).size,cases.length);
  assert.equal(cases.find(x=>x.id==='line-exact-bound').bytes.length,1025);assert.equal(cases.find(x=>x.id==='line-over-bound').bytes.length,1026);
  for(const row of cases.filter(x=>x.bytes||x.closeNotify||x.handshakeTruncate)){
   const nonce=crypto.randomBytes(16).toString('hex'),server=await fixture.Serve(row,identity,nonce);
   try{
    const received=await Receive(server.port,nonce),wire=server.observation;
    assert.equal(wire.responseSent,true,row.id);
    if(row.handshakeTruncate){assert.equal(wire.handshakeTruncated,true);assert.equal(wire.nonceReceived,false);assert.notEqual(received.error,'');assert.equal(received.bytes.length,0);}
    else{
     assert.equal(wire.nonceReceived,true,row.id);
     if(row.corruptRecord){assert.equal(wire.recordMutated,true);assert.notEqual(received.error,'');assert.equal(received.bytes.length,0);}
     else if(row.recordMode==='truncated'){
      // OpenSSL may report EOF without an error for this incomplete record.
      // Schannel is checked separately for SEC_E_INCOMPLETE_MESSAGE + rejection.
      assert.equal(wire.recordTruncated,true);assert.equal(received.bytes.length,0);
     }else{assert.equal(received.error,'',row.id);assert.deepEqual(received.bytes,row.bytes||Buffer.alloc(0),row.id);}
     if(row.recordMode==='fragmented')assert.equal(wire.recordFragments,2);
     if(row.recordMode==='coalesced'){assert.equal(wire.coalescedRecords,2);assert.ok(wire.applicationRecords>=2);}
     if(row.closeNotify)assert.equal(wire.closeNotifyRecord,true);
    }
    assert.equal(wire.connections,1);checks++;
   }finally{await server.close();}
  }
  for(const row of cases.filter(x=>x.raw)){
   const server=await fixture.Serve(row,identity,'0'.repeat(32));
   try{const output=await new Promise((resolve,reject)=>{const chunks=[],s=net.connect(server.port,'127.0.0.1',()=>s.write(Buffer.from('160303000101','hex')));s.on('error',reject);s.on('data',b=>chunks.push(b));s.on('end',()=>resolve(Buffer.concat(chunks)));});assert.deepEqual(output,row.raw);assert.equal(server.observation.clientHello,true);checks++;}
   finally{await server.close();}
  }
  // Evaluator input fixtures exercise the validator; they are never stored or
  // represented as executed native evidence by Run().
  const nonce='1'.repeat(32);
  for(const row of cases){
   const observed=NativeReport(row,nonce),wire=WireReport(row);
   assert.equal(fixture.Evaluate(row,observed,wire,nonce).outcome,'PASS');checks++;
   for(const changed of [{nativeReceiveExecuted:false},{nonce:'2'.repeat(32)},{preAuthenticationReadRejected:false},{realProviderCalls:0},{providerOverrideCalls:1},{readIncomplete:-1},{readExtra:0.5},{elapsedMs:7000}]){assert.throws(()=>fixture.Evaluate(row,{...observed,...changed},wire,nonce),row.id);checks++;}
   for(const field of Object.keys(row.minCounters||{})){assert.throws(()=>fixture.Evaluate(row,{...observed,[field]:0},wire,nonce));checks++;}
   if(row.closed||!row.connected)for(const field of ['transportClosed','postFailureReadRejected','postFailureWriteRejected']){assert.throws(()=>fixture.Evaluate(row,{...observed,[field]:false},wire,nonce));checks++;}
   if(row.terminalRead){assert.throws(()=>fixture.Evaluate(row,{...observed,terminalReadRejected:false},wire,nonce));checks++;}
  }
  for(const [id,changed]of [
   ['tls-record-authentication-failure',{recordMutated:false}],
   ['tls-real-handshake-flight-truncated',{handshakeTruncated:false}],
   ['tls-real-handshake-flight-truncated',{nonceReceived:true}],
   ['tls-authenticated-record-truncated',{recordTruncated:false}],
   ['tls-authenticated-record-fragmented',{recordFragments:1}],
   ['tls-authenticated-records-coalesced',{coalescedRecords:1}],
   ['tls-close-notify-before-data',{closeNotifyRecord:false}],
   ['valid-fragmented-json',{connections:0}],
   ['valid-fragmented-json',{nonceReceived:false}],
  ]){const row=cases.find(x=>x.id===id);assert.throws(()=>fixture.Evaluate(row,NativeReport(row,nonce),{...WireReport(row),...changed},nonce));checks++;}
  console.log('PASS '+checks+' localhost fixture delivery and evaluator checks across '+cases.length+' native cases; native Schannel/product-session/GPU execution NOT_RUN.');
 }finally{fs.rmSync(root,{recursive:true,force:true});}
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
