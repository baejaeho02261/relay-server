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
 ].map(row=>({limit:1024,mode:'json',connected:true,received:true,accepted:false,peAccepted:false,...row}));
}
async function Listen(server){await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});return server.address().port;}
async function Serve(row,identity,nonce){
 const sockets=new Set(),observation={connections:0,clientHello:false,tlsAccepted:false,nonceReceived:false,responseSent:false,recordMutated:false};
 const track=s=>{sockets.add(s);s.on('error',()=>{});s.once('close',()=>sockets.delete(s));return s;};
 const servers=[];
 let server;
 if(row.raw){server=net.createServer(socket=>{track(socket);observation.connections++;socket.once('data',data=>{observation.clientHello=data.length>=3&&data[0]===22&&data[1]===3;observation.responseSent=true;socket.end(row.raw);});});}
 else{
  const inner=tls.createServer({...identity,handshakeTimeout:4000},socket=>{
   track(socket);observation.tlsAccepted=true;let request='';
   socket.on('data',bytes=>{request+=bytes.toString('utf8');if(request.length>256){socket.destroy();return;}if(!request.endsWith('\n'))return;
    if(request!==JSON.stringify({nonce})+'\n'){socket.destroy();return;}observation.nonceReceived=true;
    if(!row.bytes)return;
    observation.responseSent=true;
    if(row.fragment){let at=0;const send=()=>{if(socket.destroyed)return;if(at===row.bytes.length){socket.end();return;}socket.write(row.bytes.subarray(at,at+row.fragment));at+=row.fragment;setImmediate(send);};send();}
    else socket.end(row.bytes);
   });
  });
  inner.on('tlsClientError',()=>{});inner.on('connection',socket=>{track(socket);if(!row.corruptRecord)observation.connections++;});servers.push(inner);
  if(row.corruptRecord){
   const innerPort=await Listen(inner);
   server=net.createServer(client=>{
    track(client);observation.connections++;const upstream=track(net.connect(innerPort,'127.0.0.1'));client.pipe(upstream);let pending=Buffer.alloc(0);
    upstream.on('data',chunk=>{pending=Buffer.concat([pending,chunk]);while(pending.length>=5){const size=5+pending.readUInt16BE(3);if(pending.length<size)return;const record=Buffer.from(pending.subarray(0,size));pending=pending.subarray(size);if(record[0]===23&&!observation.recordMutated){record[record.length-1]^=1;observation.recordMutated=true;}client.write(record);}});
    upstream.on('end',()=>client.end(pending));client.on('close',()=>upstream.destroy());upstream.on('error',()=>client.destroy());
   });
  }else server=inner;
 }
 if(!servers.includes(server))servers.push(server);
 const port=await Listen(server);
 return {port,observation,async close(){for(const socket of sockets)socket.destroy();await Promise.all(servers.map(s=>new Promise(resolve=>s.close(resolve))));}};
}
function Evaluate(row,observed,wire,nonce){
 if(!observed||observed.version!==1||observed.caseId!==row.id||observed.nonce!==nonce||observed.nativeReceiveExecuted!==true)throw Error('RECEIVE_NATIVE_RESULT_BINDING');
 for(const [field,expected]of Object.entries({tlsConnected:row.connected,lineReceived:row.received&&row.connected,jsonAccepted:row.accepted,peAccepted:row.peAccepted}))if(observed[field]!==expected)throw Error('RECEIVE_NATIVE_BOUNDARY_MISMATCH');
 if(row.closed&&observed.transportClosed!==true)throw Error('RECEIVE_FAILED_TRANSPORT_NOT_CLOSED');
 if(!Number.isInteger(observed.elapsedMs)||observed.elapsedMs<0||observed.elapsedMs>6500)throw Error('RECEIVE_NATIVE_DEADLINE');
 if(wire.connections!==1)throw Error('RECEIVE_FIXTURE_CONNECTION_MISMATCH');
 if(row.raw){if(!wire.clientHello||!wire.responseSent)throw Error('RECEIVE_TLS_ALERT_NOT_DELIVERED');}
 else if(row.wrongPin&&(!wire.tlsAccepted||wire.nonceReceived))throw Error('RECEIVE_PIN_REJECTION_NOT_OBSERVED');
 else if(row.connected&&(!wire.tlsAccepted||!wire.nonceReceived||!wire.responseSent))throw Error('RECEIVE_BYTES_NOT_DELIVERED');
 if(row.corruptRecord&&!wire.recordMutated)throw Error('RECEIVE_RECORD_NOT_MUTATED');
 return {id:row.id,outcome:'PASS',scope:row.corruptRecord?'REAL_SCHANNEL_DECRYPT_REJECTION':row.raw?'REAL_SCHANNEL_HANDSHAKE_REJECTION':row.mode==='pe'?'RECEIVED_BYTES_TO_PRODUCTION_PE_READER':'REAL_TLS_RECEIVE_BOUNDARY',observed,wire:{...wire}};
}
module.exports={Certificates,Cases,Serve,Evaluate};
