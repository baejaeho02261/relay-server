'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),tls=require('node:tls');
const {Certificates}=require("../../tools/integrity/peace.native-receive-fixture"),{Start}=require("../../ci/fixtures/peace.product-fault-tls-proxy");
function Request(port){return new Promise(resolve=>{let bytes=Buffer.alloc(0),error='';const socket=tls.connect({host:'127.0.0.1',port,servername:'localhost',minVersion:'TLSv1.2',maxVersion:'TLSv1.2',rejectUnauthorized:false},()=>socket.write('owned-request'));const timer=setTimeout(()=>socket.destroy(Error('PROXY_TEST_TIMEOUT')),5000);socket.on('data',b=>{bytes=Buffer.concat([bytes,b]);});socket.on('error',e=>{error=e.code||e.message;});socket.on('close',()=>{clearTimeout(timer);resolve({bytes,error});});});}
(async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'product-proxy-test-'));let upstream,proxy;const sockets=new Set();
 try{
  const {identity}=Certificates(root),events=[];
  upstream=tls.createServer(identity,s=>{sockets.add(s);s.on('error',()=>{});s.on('close',()=>sockets.delete(s));s.once('data',bytes=>{assert.equal(bytes.toString(),'owned-request');s.end('owned-response');});});upstream.on('tlsClientError',()=>{});
  await new Promise(resolve=>upstream.listen(0,'127.0.0.1',resolve));
  proxy=await Start(upstream.address().port,event=>events.push(event));
  const positive=await Request(proxy.port);assert.equal(positive.error,'');assert.equal(positive.bytes.toString(),'owned-response');assert.equal(events.length,0);
  proxy.Arm();assert.throws(()=>proxy.Arm(),/ARM_INVALID/);
  const negative=await Request(proxy.port);assert.notEqual(negative.error,'');assert.equal(negative.bytes.length,0);
  assert.equal(events.filter(e=>e.event==='tls-record-corrupted').length,1);assert.equal(events.find(e=>e.event==='tls-record-corrupted').mutationCount,1);
  const after=await Request(proxy.port);assert.equal(after.error,'');assert.equal(after.bytes.toString(),'owned-response');assert.equal(events.filter(e=>e.event==='tls-record-corrupted').length,1);
  await proxy.Close();assert.throws(()=>proxy.Arm(),/ARM_INVALID/);
  console.log('PASS actual localhost TLS1.2 passthrough, one record authentication failure, one-shot arm and cleanup; native product lease execution NOT_RUN.');
 }finally{if(proxy)await proxy.Close();for(const s of sockets)s.destroy();if(upstream)await new Promise(resolve=>upstream.close(resolve));fs.rmSync(root,{recursive:true,force:true});}
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
