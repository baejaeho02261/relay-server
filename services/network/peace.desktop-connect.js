'use strict';
const tls=require('node:tls'),crypto=require('node:crypto'),{TextDecoder}=require('node:util');
const desktop=require("../licensing/peace.desktop-licenses"),identity=require('./peace.connect-transport-key');
const PROTOCOL='GAME-CONNECT-4',MAX_FRAME=65536,MAX_CLEAR=32768,MAX_RESPONSE_CLEAR=512*1024,MAX_RESPONSE_FRAME=768*1024,DEADLINE_MS=10000;
const REPLAY_MS=10*60*1000,MAX_REPLAYS=12000,seen=new Map(),pendingReplays=new Set();
const work=require("../runtime/peace.desktop-work-queue"),{performance}=require('node:perf_hooks');
const admission=new(require('./peace.desktop-connection-admission').Admission)();
const deviceRate=new(require("../runtime/peace.desktop-request-rate").DeviceRate)();
let lastPrune=0,listener=null;
const rawDeadlines=new Map(),rawSockets=new Set();
function ConnectionKey(socket){return [socket.localAddress,socket.localPort,socket.remoteAddress,socket.remotePort].join('|');}
function Aad(direction,requestId,keyId){return Buffer.from(PROTOCOL+'\n'+direction+'\n'+requestId+'\n'+keyId,'utf8');}
function Plain(value){return !!value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;}
function Prune(){const at=Date.now();if(at-lastPrune<1000)return;lastPrune=at;for(const [id,until]of seen)if(until<=at)seen.delete(id);}
function Base64(value,min,max=min){if(typeof value!=='string'||value.length>Math.ceil(max/3)*4||!/^[A-Za-z0-9+/]*={0,2}$/.test(value))throw Error('CONNECT_FRAME_INVALID');const bytes=Buffer.from(value,'base64');if(bytes.length<min||bytes.length>max||bytes.toString('base64')!==value)throw Error('CONNECT_FRAME_INVALID');return bytes;}
async function Open(frame,budgetMs,peerKey=''){
 if(!Plain(frame)||Object.keys(frame).sort().join(',')!=='ciphertext,keyId,nonce,requestId,tag,v,wrappedKey'||frame.v!==1||!/^([a-f0-9]{64})$/.test(frame.keyId||'')||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(frame.requestId||''))throw Error('CONNECT_FRAME_INVALID');
 const server=identity.Resolve(frame.keyId);
 Prune();const transportId=frame.requestId.toLowerCase();
 if(seen.has(transportId)||pendingReplays.has(transportId))throw Error('CONNECT_REPLAY');
 if(seen.size+pendingReplays.size>=MAX_REPLAYS)throw Error('CONNECT_CAPACITY');
 const wrappedKey=Base64(frame.wrappedKey,256),nonce=Base64(frame.nonce,12),ciphertext=Base64(frame.ciphertext,1,MAX_CLEAR),tag=Base64(frame.tag,16);
 // A reservation blocks concurrent copies but is NOT an authenticated replay.
 // Queue rejection, timeout, bad RSA/GCM and invalid clear JSON all release it.
 pendingReplays.add(transportId);
 let value;
 try{value=await work.auth.run({kind:'open',privateKey:server.privateKey,wrappedKey,nonce,ciphertext,tag,aad:Aad('REQUEST',frame.requestId,server.keyId)},budgetMs,{key:peerKey});
  const opened={key:Buffer.from(value.key),nonce,requestId:frame.requestId,keyId:server.keyId,payload:value.payload};
  // Retain authenticated envelopes even if business authorization later fails.
  // Removing those entries would allow an authenticated request to be replayed.
  seen.set(transportId,Date.now()+REPLAY_MS);
  return opened;
 }finally{pendingReplays.delete(transportId);value?.key?.fill(0);}

}
function Seal(opened,result){
 let nonce;do{nonce=crypto.randomBytes(12);}while(nonce.equals(opened.nonce));
 const cipher=crypto.createCipheriv('aes-256-gcm',opened.key,nonce,{authTagLength:16});cipher.setAAD(Aad('RESPONSE',opened.requestId,opened.keyId));
 const clear=Buffer.from(JSON.stringify(result),'utf8');try{if(clear.length>MAX_RESPONSE_CLEAR)throw Error('CONNECT_RESPONSE_TOO_LARGE');const ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);return {v:1,requestId:opened.requestId,nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};}finally{clear.fill(0);opened.key.fill(0);}
}
async function Dispatch(opened,absoluteDeadline){
 const payload=opened.payload;let devicePrepared;
 try{
  require('../operations/peace.registration-reset').AssertAvailable();
  if(!Plain(payload)||!['body,operation','body,operation,tlsPinVersion'].includes(Object.keys(payload).sort().join(','))||(payload.tlsPinVersion!==undefined&&payload.tlsPinVersion!==1)||!Plain(payload.body)||!['challenge','execute','bootstrap','report','security','device','policy'].includes(payload.operation))desktop.Fail('INPUT_INVALID');
  require("../protocol/peace.desktop-request-protocol").Resolve(payload.operation,payload.body.action);
  const protectedDispatch=require("../authentication/peace.desktop-protected-dispatch"),dispatchTicket=protectedDispatch.Prepare(payload);
  if(typeof payload.body.deviceId==='string')deviceRate.Take(payload.body.deviceId);
  // A retired server certificate must not authorize side effects, including
  // callers that did not request a transition offer. Check again after queued
  // proof work: waiting cannot extend the authenticated certificate window.
  const pinTransition=require('./peace.desktop-tls-pin-transition');pinTransition.Offer();
  if(payload.operation==='device')devicePrepared=await require("../devices/peace.desktop-device-identity").PrepareTpm(payload.body,absoluteDeadline);
  const execute=()=>{require('../operations/peace.registration-reset').AssertAvailable();require('./peace.desktop-transport-rotation').AssertUse(opened.keyId,payload);pinTransition.Offer();return protectedDispatch.Execute(dispatchTicket,payload,{policy:body=>require('../security/peace.server-policy-operations').Execute(body),device:body=>require("../devices/peace.desktop-device-identity").Handle(body,devicePrepared),security:body=>require("../security/peace.desktop-security-authority").Execute(body),report:body=>require("../integrity/peace.desktop-integrity-reports").Execute(body),bootstrap:body=>require("../bootstrap/peace.desktop-bootstrap").Execute(body),challenge:body=>desktop.Challenge(body),execute:body=>desktop.Execute(body)});};
  const proofWork=require("../integrity/peace.desktop-proof-work"),jobs=proofWork.Prepare(payload.operation,payload.body);
  const data=await proofWork.Run(jobs,execute,{deadline:absoluteDeadline,key:String(payload.body.sessionId||payload.body.flowId||payload.body.deviceId||'').slice(0,160),renewal:work.IsRenewal(payload.operation,payload.body.action)||payload.operation==='security'&&payload.body.intent==='verify'});return {ok:true,data};
 }catch(error){const code=error.desktopError?error.message:['CONNECT_RATE_LIMIT','WORK_QUEUE_BUSY'].includes(error.message)?'DESKTOP_RATE_LIMIT':['CONNECT_DEADLINE','WORK_DEADLINE'].includes(error.message)?'CONNECT_DEADLINE':'INPUT_INVALID';require("../runtime/peace.desktop-runtime-diagnostics").Record(payload?.operation,payload?.body,code);return {ok:false,error:code,reason:code,message:desktop.messages[code]||'인증 요청을 처리하지 못했습니다.'};}finally{devicePrepared?.secret?.fill(0);}
}
function Accept(socket){
 let buffer=Buffer.alloc(0),complete=false;
 const absoluteDeadline=rawDeadlines.get(ConnectionKey(socket));
 if(!absoluteDeadline||performance.now()>=absoluteDeadline){socket.destroy();return;}
 socket.setNoDelay(true);socket.disableRenegotiation();
 socket.on('error',()=>{});socket.once('close',()=>buffer.fill(0));
 socket.on('data',async chunk=>{
  if(complete)return socket.destroy();if(buffer.length+chunk.length>MAX_FRAME)return socket.destroy();buffer=Buffer.concat([buffer,chunk]);const end=buffer.indexOf(10);if(end<0)return;
  complete=true;socket.pause();
  // One LF-delimited JSON request is accepted. CRLF from ReadLn clients is
  // supported; a second frame or trailing bytes are never pipelined.
  if(end!==buffer.length-1)return socket.destroy();
  // Monotonic server processing time: a complete frame through response enqueue
  // (or failure). It is neither network round-trip nor client lease latency.
  const requestStarted=performance.now();
  let opened,renewalRecorded=false;try{const raw=buffer.subarray(0,end);opened=await Open(require("../protocol/peace.strict-json").Parse(raw,{maxBytes:MAX_FRAME}),absoluteDeadline-performance.now(),String(socket.remoteAddress||'UNKNOWN'));if(socket.destroyed||performance.now()>=absoluteDeadline)throw Error('CONNECT_DEADLINE');const result=await Dispatch(opened,absoluteDeadline);if(socket.destroyed||performance.now()>=absoluteDeadline)throw Error('CONNECT_DEADLINE');if(opened.payload.tlsPinVersion===1){const plan=require('./peace.desktop-tls-pin-transition').Offer();if(plan)result.tlsPinPlan=plan;}const response=Seal(opened,result),wire=JSON.stringify(response)+'\n';if(Buffer.byteLength(wire)>MAX_RESPONSE_FRAME)throw Error('CONNECT_RESPONSE_TOO_LARGE');if(socket.destroyed||performance.now()>=absoluteDeadline)throw Error('CONNECT_DEADLINE');socket.end(wire);work.RecordRenewal(opened.payload?.operation,opened.payload?.body?.action,result.ok,performance.now()-requestStarted);renewalRecorded=true;}
  catch(_){if(opened&&!renewalRecorded)work.RecordRenewal(opened.payload?.operation,opened.payload?.body?.action,false,performance.now()-requestStarted);opened?.key.fill(0);socket.destroy();}
 });
}
function CreateServer(){
 identity.Load();require("../bootstrap/peace.desktop-bootstrap").Initialize();
 const tlsIdentity=require('./peace.connect-tls').Load();
 const server=tls.createServer({...tlsIdentity.options,handshakeTimeout:DEADLINE_MS},socket=>{
  // Cached certificate validity is rechecked for every accepted TLS connection.
  try{require('./peace.connect-tls').Load();}catch(_){socket.destroy();return;}
  Accept(socket);
 });
 // Count and expire raw sockets before TLS authentication, including peers that
 // never send ClientHello. The same absolute budget covers handshake + request.
 server.on('connection',socket=>{
  rawSockets.add(socket);socket.once('close',()=>rawSockets.delete(socket));
  Prune();socket.on('error',()=>{});
  let ticket;try{ticket=admission.Acquire(String(socket.remoteAddress||''));}catch(_){socket.destroy();return;}
  const connectionKey=ConnectionKey(socket),expires=performance.now()+DEADLINE_MS;
  rawDeadlines.set(connectionKey,expires);work.connections.active=admission.active;
  const deadline=setTimeout(()=>socket.destroy(),DEADLINE_MS);deadline.unref();
  socket.once('close',()=>{clearTimeout(deadline);if(rawDeadlines.get(connectionKey)===expires)rawDeadlines.delete(connectionKey);ticket.release();work.connections.active=admission.active;});
 });
 server.on('tlsClientError',(_error,socket)=>socket.destroy());
 return server;
}
function Start(){
 const config=require("../../config/peace.runtime-configuration"),port=config.CONNECT_TCP_PORT;
 if(!Number.isInteger(port)||port<1||port>65535||port===config.WEB_ADMIN_PORT||port===config.HEALTH_PORT)throw Error('CONNECT_PORT_INVALID');
 const server=CreateServer();server.on('error',error=>{console.error('CONNECT_TCP_START_FAILED', ['EADDRINUSE','EACCES','EADDRNOTAVAIL'].includes(error.code)?error.code:'CONNECT_LISTENER_FAILED');throw error;});
 listener=server;server.listen(port,config.HOST,()=>console.log('CONNECT_TLS_LISTENER_READY'));return server;
}
async function Stop(){const server=listener;listener=null;for(const socket of rawSockets)socket.destroy();rawSockets.clear();rawDeadlines.clear();pendingReplays.clear();seen.clear();if(server?.listening)await new Promise(resolve=>server.close(resolve));}
function IsListening(){if(!listener||!listener.listening)return false;try{require('./peace.connect-tls').Load();return true;}catch(_){return false;}}
module.exports={PROTOCOL,MAX_FRAME,MAX_CLEAR,MAX_RESPONSE_CLEAR,MAX_RESPONSE_FRAME,DEADLINE_MS,Aad,CreateServer,Start,IsListening,Stop};
