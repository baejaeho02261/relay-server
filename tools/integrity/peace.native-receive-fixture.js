'use strict';
// Test-owned localhost bytes only. No product service, CA store, server policy,
// imported client key, or application trust configuration is changed.
const fs=require('node:fs'),path=require('node:path'),net=require('node:net'),tls=require('node:tls'),crypto=require('node:crypto'),cp=require('node:child_process');
const {crcPeFixture}=require("../../tests/fixtures/artifacts/peace.crc-pe-fixture");
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function Certificates(root,openssl='openssl'){
 const key=path.join(root,'receive-key.pem'),cert=path.join(root,'receive-cert.pem');
 const r=cp.spawnSync(openssl,['req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',key,'-out',cert],{encoding:'utf8',timeout:30000,windowsHide:true});
 if(r.error||r.status!==0)throw Error('RECEIVE_OPENSSL_CERTIFICATE_FAILED');
 const certificate=fs.readFileSync(cert),identity={key:fs.readFileSync(key),cert:certificate,minVersion:'TLSv1.2',maxVersion:'TLSv1.2'};
 return {identity,pin:sha(new crypto.X509Certificate(certificate).raw)};
}
function Cases(){
 const good=Buffer.from('{"value":"'+ 'a'.repeat(1012)+'"}\n'); // 1024 bytes before LF
 const pe=crcPeFixture(),bad=Buffer.from(pe);bad.writeUInt32LE(0xffffffff,0x3c);
 return [
  {id:'valid-fragmented-json',bytes:Buffer.from('{"value":"한글"}\n'),fragment:1,accepted:true},
  {id:'line-exact-bound',bytes:good,accepted:true},
  {id:'line-over-bound',bytes:Buffer.from('{"value":"'+'a'.repeat(1013)+'"}\n'),received:false,closed:true},
  {id:'utf8-overlong',bytes:Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xc0,0xaf,0x22,0x7d,0x0a]),received:false,closed:true},
  {id:'json-duplicate-key',bytes:Buffer.from('{"x":1,"x":2}\n')},
  {id:'json-trailing-object',bytes:Buffer.from('{}{}\n')},
  {id:'json-lone-surrogate',bytes:Buffer.from('{"x":"\\ud800"}\n')},
  {id:'json-depth-over-bound',bytes:Buffer.from('{"x":'+ '['.repeat(33)+'0'+']'.repeat(33)+'}\n')},
  {id:'json-unsafe-integer',bytes:Buffer.from('{"x":9007199254740992}\n')},
  {id:'json-missing-newline',bytes:Buffer.from('{"x":1}'),received:false,closed:true},
  {id:'pe-valid-received-file',bytes:Buffer.from(JSON.stringify({pe:pe.toString('base64')})+'\n'),mode:'pe',limit:8192,accepted:true,peAccepted:true},
  {id:'pe-header-offset-overflow',bytes:Buffer.from(JSON.stringify({pe:bad.toString('base64')})+'\n'),mode:'pe',limit:8192,accepted:true,peAccepted:false},
  {id:'tls-certificate-pin-mismatch',wrongPin:true,connected:false},
  {id:'tls-fatal-handshake-alert',raw:Buffer.from('15030300020228','hex'),connected:false},
  {id:'tls-truncated-handshake-record',raw:Buffer.from('16030300100102','hex'),connected:false},
  {id:'tls-record-authentication-failure',bytes:Buffer.from('{"x":1}\n'),corruptRecord:true,received:false,closed:true},
  {id:'tls-real-handshake-flight-truncated',handshakeTruncate:true,connected:false,received:false,closed:true,minCounters:{handshakeIncomplete:1}},
  {id:'tls-authenticated-record-truncated',bytes:Buffer.from('{"x":1}\n'),recordMode:'truncated',received:false,closed:true,minCounters:{readIncomplete:1}},
  {id:'tls-authenticated-record-fragmented',bytes:Buffer.from('{"x":1}\n'),recordMode:'fragmented',accepted:true,minCounters:{readIncomplete:1}},
  {id:'tls-authenticated-records-coalesced',bytes:Buffer.from('{"x":1}\n'),recordMode:'coalesced',accepted:true,minCounters:{readExtra:1}},
  {id:'tls-close-notify-before-data',closeNotify:true,received:false,closed:true,minCounters:{contextExpired:1}},
  {id:'tls-close-notify-after-data',bytes:Buffer.from('{"x":1}\n'),closeNotify:true,mode:'json-close',accepted:true,closed:true,terminalRead:true,minCounters:{contextExpired:1}},
 ].map(row=>({limit:1024,mode:'json',connected:true,received:true,accepted:false,peAccepted:false,...row}));
}
async function Listen(server){await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});return server.address().port;}
async function Serve(row,identity,nonce){
 const sockets=new Set(),timers=new Set(),observation={connections:0,clientHello:false,tlsAccepted:false,nonceReceived:false,responseSent:false,recordMutated:false,applicationRecords:0,coalescedRecords:0,recordTruncated:false,recordFragments:0,handshakeTruncated:false,closeNotifyRecord:false};
 const track=s=>{sockets.add(s);s.on('error',()=>{});s.once('close',()=>sockets.delete(s));return s;};
 const later=(fn,ms)=>{const timer=setTimeout(()=>{timers.delete(timer);fn();},ms);timers.add(timer);};
 const servers=[];let server;
 async function close(){
  for(const timer of timers)clearTimeout(timer);timers.clear();
  for(const socket of sockets)socket.destroy();
  await Promise.all(servers.map(s=>new Promise(resolve=>s.close(()=>resolve()))));
 }
 try{
 const proxyNeeded=!!(row.corruptRecord||row.recordMode||row.handshakeTruncate||row.closeNotify);
 if(row.raw){server=net.createServer(socket=>{track(socket);observation.connections++;socket.once('data',data=>{observation.clientHello=data.length>=3&&data[0]===22&&data[1]===3;observation.responseSent=true;socket.end(row.raw);});});}
 else{
  const inner=tls.createServer({...identity,handshakeTimeout:4000},socket=>{
   track(socket);observation.tlsAccepted=true;let request='',responded=false;
   socket.on('data',bytes=>{if(responded)return;request+=bytes.toString('utf8');if(request.length>256){socket.destroy();return;}if(!request.endsWith('\n'))return;
    if(request!==JSON.stringify({nonce})+'\n'){socket.destroy();return;}responded=true;observation.nonceReceived=true;
    if(row.closeNotify&&!row.bytes){observation.responseSent=true;socket.end();return;}
    if(!row.bytes)return;
    observation.responseSent=true;
    if(row.fragment){let at=0;const send=()=>{if(socket.destroyed)return;if(at===row.bytes.length){socket.end();return;}socket.write(row.bytes.subarray(at,at+row.fragment));at+=row.fragment;setImmediate(send);};send();}
    else if(row.recordMode==='coalesced'){
     const middle=Math.max(1,Math.floor(row.bytes.length/2));socket.write(row.bytes.subarray(0,middle));
     setImmediate(()=>{if(!socket.destroyed)socket.end(row.bytes.subarray(middle));});
    }else socket.end(row.bytes);
   });
  });
  inner.on('tlsClientError',()=>{});inner.on('connection',socket=>{track(socket);if(!proxyNeeded)observation.connections++;});servers.push(inner);
  if(proxyNeeded){
   const innerPort=await Listen(inner);
   server=net.createServer(client=>{
    track(client);client.setNoDelay(true);observation.connections++;
    const upstream=track(net.connect(innerPort,'127.0.0.1'));client.pipe(upstream);
    let pending=Buffer.alloc(0),held=[],delaying=false,ended=false,terminal=false;
    function finish(){if(ended&&!delaying&&!held.length&&!client.destroyed&&!terminal)client.end(pending);}
    function sendRecord(record){
     if(terminal||client.destroyed)return;
     if(row.handshakeTruncate&&record[0]===22&&!observation.handshakeTruncated){
      // Prefix of a real OpenSSL TLS1.2 server handshake flight, including its
      // original full-length TLS header. Schannel must observe incomplete data.
      observation.handshakeTruncated=true;observation.responseSent=true;terminal=true;
      client.end(record.subarray(0,Math.max(6,Math.floor(record.length/2))));upstream.destroy();return;
     }
     if(record[0]===21&&observation.nonceReceived)observation.closeNotifyRecord=true;
     if(record[0]===23){
      observation.applicationRecords++;
      if(row.corruptRecord&&!observation.recordMutated){record[record.length-1]^=1;observation.recordMutated=true;}
      if(row.recordMode==='truncated'&&!observation.recordTruncated){
       observation.recordTruncated=true;terminal=true;client.end(record.subarray(0,record.length-1));upstream.destroy();return;
      }
      if(row.recordMode==='coalesced'&&observation.coalescedRecords===0){
       held.push(record);if(held.length<2)return;
       observation.coalescedRecords=held.length;client.write(Buffer.concat(held));held=[];return;
      }
      if(row.recordMode==='fragmented'&&observation.recordFragments===0){
       // Delay the remainder so a waiting native receive actually feeds an
       // incomplete record to SSPI, then completes the same authenticated record.
       delaying=true;observation.recordFragments=2;const cut=Math.min(record.length-1,9);
       client.write(record.subarray(0,cut));held.push(record.subarray(cut));
       later(()=>{if(!client.destroyed&&!terminal)for(const bytes of held)client.write(bytes);held=[];delaying=false;finish();},250);return;
      }
     }
     if(delaying)held.push(record);else client.write(record);
    }
    upstream.on('data',chunk=>{if(terminal)return;pending=Buffer.concat([pending,chunk]);while(pending.length>=5){const size=5+pending.readUInt16BE(3);if(pending.length<size)return;const record=Buffer.from(pending.subarray(0,size));pending=pending.subarray(size);sendRecord(record);if(terminal)return;}});
    upstream.on('end',()=>{ended=true;finish();});client.on('close',()=>upstream.destroy());upstream.on('error',()=>client.destroy());
   });
  }else server=inner;
 }
 if(!servers.includes(server))servers.push(server);
 const port=await Listen(server);
 return {port,observation,close};
 }catch(error){await close();throw error;}
}
function Evaluate(row,observed,wire,nonce){
 if(!observed||observed.version!==1||observed.caseId!==row.id||observed.nonce!==nonce||observed.nativeReceiveExecuted!==true)throw Error('RECEIVE_NATIVE_RESULT_BINDING');
 for(const [field,expected]of Object.entries({tlsConnected:row.connected,lineReceived:row.received&&row.connected,jsonAccepted:row.accepted,peAccepted:row.peAccepted}))if(observed[field]!==expected)throw Error('RECEIVE_NATIVE_BOUNDARY_MISMATCH');
 if(observed.preAuthenticationReadRejected!==true)throw Error('RECEIVE_PREAUTH_PLAINTEXT');
 if(!Number.isSafeInteger(observed.realProviderCalls)||observed.realProviderCalls<1||observed.providerOverrideCalls!==0)throw Error('RECEIVE_REAL_PROVIDER_REQUIRED');
 for(const field of ['handshakeIncomplete','readIncomplete','readExtra','contextExpired'])if(!Number.isSafeInteger(observed[field])||observed[field]<0)throw Error('RECEIVE_PROVIDER_COUNTER_INVALID');
 for(const [field,minimum]of Object.entries(row.minCounters||{}))if(observed[field]<minimum)throw Error('RECEIVE_PROVIDER_STATE_NOT_OBSERVED');
 if(row.terminalRead&&observed.terminalReadRejected!==true)throw Error('RECEIVE_CLOSE_NOTIFY_NOT_CONSUMED');
 if((row.closed||!row.connected)&&(observed.transportClosed!==true||observed.postFailureReadRejected!==true||observed.postFailureWriteRejected!==true))throw Error('RECEIVE_FAILED_TRANSPORT_NOT_CLOSED');
 if(!Number.isInteger(observed.elapsedMs)||observed.elapsedMs<0||observed.elapsedMs>6500)throw Error('RECEIVE_NATIVE_DEADLINE');
 if(wire.connections!==1)throw Error('RECEIVE_FIXTURE_CONNECTION_MISMATCH');
 if(row.raw){if(!wire.clientHello||!wire.responseSent)throw Error('RECEIVE_TLS_ALERT_NOT_DELIVERED');}
 else if(row.handshakeTruncate){if(!wire.handshakeTruncated||!wire.responseSent||wire.nonceReceived)throw Error('RECEIVE_REAL_HANDSHAKE_NOT_TRUNCATED');}
 else if(row.wrongPin&&(!wire.tlsAccepted||wire.nonceReceived))throw Error('RECEIVE_PIN_REJECTION_NOT_OBSERVED');
 else if(row.connected&&(!wire.tlsAccepted||!wire.nonceReceived||!wire.responseSent))throw Error('RECEIVE_BYTES_NOT_DELIVERED');
 if(row.corruptRecord&&!wire.recordMutated)throw Error('RECEIVE_RECORD_NOT_MUTATED');
 if(row.recordMode==='truncated'&&!wire.recordTruncated)throw Error('RECEIVE_RECORD_NOT_TRUNCATED');
 if(row.recordMode==='fragmented'&&wire.recordFragments!==2)throw Error('RECEIVE_RECORD_NOT_FRAGMENTED');
 if(row.recordMode==='coalesced'&&(wire.coalescedRecords<2||wire.applicationRecords<2))throw Error('RECEIVE_RECORDS_NOT_COALESCED');
 if(row.closeNotify&&!wire.closeNotifyRecord)throw Error('RECEIVE_CLOSE_NOTIFY_NOT_DELIVERED');
 return {id:row.id,outcome:'PASS',scope:row.recordMode?'REAL_SCHANNEL_RECORD_STATE':row.closeNotify?'REAL_SCHANNEL_CLOSE_NOTIFY':row.corruptRecord?'REAL_SCHANNEL_DECRYPT_REJECTION':(row.raw||row.handshakeTruncate)?'REAL_SCHANNEL_HANDSHAKE_REJECTION':row.mode==='pe'?'RECEIVED_BYTES_TO_PRODUCTION_PE_READER':'REAL_TLS_RECEIVE_BOUNDARY',observed,wire:{...wire}};
}
module.exports={Certificates,Cases,Serve,Evaluate};
