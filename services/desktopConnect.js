'use strict';
const tls=require('node:tls'),crypto=require('node:crypto'),{TextDecoder}=require('node:util');
const desktop=require('./desktopLicenses'),identity=require('./connectTransportKey');
const PROTOCOL='GAME-CONNECT-3',MAX_FRAME=24576,MAX_CLEAR=12288,MAX_RESPONSE_CLEAR=512*1024,MAX_RESPONSE_FRAME=768*1024,DEADLINE_MS=10000;
const REPLAY_MS=10*60*1000,MAX_REPLAYS=12000,seen=new Map(),rates=new Map(),activeByIp=new Map();
const decoder=new TextDecoder('utf-8',{fatal:true});
let active=0,lastPrune=0,listener=null;
function Aad(direction,requestId,keyId){return Buffer.from(PROTOCOL+'\n'+direction+'\n'+requestId+'\n'+keyId,'utf8');}
function Plain(value){return !!value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;}
function Prune(){const at=Date.now();if(at-lastPrune<1000)return;lastPrune=at;for(const [id,until]of seen)if(until<=at)seen.delete(id);for(const [id,row]of rates)if(row.until<=at)rates.delete(id);}
function Rate(key,limit){let row=rates.get(key);if(!row||row.until<=Date.now()){row={until:Date.now()+60000,count:0};rates.set(key,row);}if(rates.size>12000||++row.count>limit)throw Error('CONNECT_RATE_LIMIT');}
function Base64(value,min,max=min){if(typeof value!=='string'||value.length>Math.ceil(max/3)*4||!/^[A-Za-z0-9+/]*={0,2}$/.test(value))throw Error('CONNECT_FRAME_INVALID');const bytes=Buffer.from(value,'base64');if(bytes.length<min||bytes.length>max||bytes.toString('base64')!==value)throw Error('CONNECT_FRAME_INVALID');return bytes;}
function Open(frame){
 if(!Plain(frame)||Object.keys(frame).sort().join(',')!=='ciphertext,keyId,nonce,requestId,tag,v,wrappedKey'||frame.v!==1||!/^([a-f0-9]{64})$/.test(frame.keyId||'')||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(frame.requestId||''))throw Error('CONNECT_FRAME_INVALID');
 const server=identity.Load();if(frame.keyId!==server.keyId)throw Error('CONNECT_PIN_MISMATCH');
 const transportId=frame.requestId.toLowerCase();if(seen.has(transportId))throw Error('CONNECT_REPLAY');if(seen.size>=MAX_REPLAYS)throw Error('CONNECT_CAPACITY');
 const wrappedKey=Base64(frame.wrappedKey,256),nonce=Base64(frame.nonce,12),ciphertext=Base64(frame.ciphertext,1,MAX_CLEAR),tag=Base64(frame.tag,16);
 let key;try{key=crypto.privateDecrypt({key:server.privateKey,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},wrappedKey);
  if(key.length!==32)throw Error('CONNECT_KEY_INVALID');
  const decipher=crypto.createDecipheriv('aes-256-gcm',key,nonce,{authTagLength:16});decipher.setAAD(Aad('REQUEST',frame.requestId,server.keyId));decipher.setAuthTag(tag);
  const clear=Buffer.concat([decipher.update(ciphertext),decipher.final()]);
  // Claim the outer nonce before dispatch. Inner idempotent registration uses a
  // separate durable requestId and survives reconnect with a fresh outer ID.
  seen.set(transportId,Date.now()+REPLAY_MS);
  let payload;try{payload=JSON.parse(decoder.decode(clear));}finally{clear.fill(0);}
  return {key,nonce,requestId:frame.requestId,keyId:server.keyId,payload};
 }catch(error){key?.fill(0);throw error;}
}
function Seal(opened,result){
 let nonce;do{nonce=crypto.randomBytes(12);}while(nonce.equals(opened.nonce));
 const cipher=crypto.createCipheriv('aes-256-gcm',opened.key,nonce,{authTagLength:16});cipher.setAAD(Aad('RESPONSE',opened.requestId,opened.keyId));
 const clear=Buffer.from(JSON.stringify(result),'utf8');try{if(clear.length>MAX_RESPONSE_CLEAR)throw Error('CONNECT_RESPONSE_TOO_LARGE');const ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);return {v:1,requestId:opened.requestId,nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};}finally{clear.fill(0);opened.key.fill(0);}
}
function Dispatch(opened){
 const payload=opened.payload;
 try{
  if(!Plain(payload)||Object.keys(payload).sort().join(',')!=='body,operation'||!Plain(payload.body)||!['challenge','execute','bootstrap','report','security','overlay'].includes(payload.operation))desktop.Fail('INPUT_INVALID');
  if(typeof payload.body.deviceId==='string')Rate('DEVICE:'+payload.body.deviceId.slice(0,100),40);
  const data=payload.operation==='overlay'?require('./desktopOverlay').Execute(payload.body):payload.operation==='security'?require('./desktopSecurityAuthority').Execute(payload.body):payload.operation==='report'?require('./desktopIntegrityReports').Execute(payload.body):payload.operation==='bootstrap'?require('./desktopBootstrap').Execute(payload.body):payload.operation==='challenge'?desktop.Challenge(payload.body):desktop.Execute(payload.body);return {ok:true,data};
 }catch(error){const code=error.desktopError?error.message:error.message==='CONNECT_RATE_LIMIT'?'DESKTOP_RATE_LIMIT':'INPUT_INVALID';require('./desktopRuntimeDiagnostics').Record(payload?.operation,payload?.body,code);return {ok:false,error:code,reason:code,message:desktop.messages[code]||'인증 요청을 처리하지 못했습니다.'};}
}
function Accept(socket){
 let buffer=Buffer.alloc(0),complete=false;
 socket.setNoDelay(true);socket.disableRenegotiation();
 socket.on('error',()=>{});socket.once('close',()=>buffer.fill(0));
 socket.on('data',chunk=>{
  if(complete)return socket.destroy();if(buffer.length+chunk.length>MAX_FRAME)return socket.destroy();buffer=Buffer.concat([buffer,chunk]);const end=buffer.indexOf(10);if(end<0)return;
  complete=true;socket.pause();
  // One LF-delimited JSON request is accepted. CRLF from ReadLn clients is
  // supported; a second frame or trailing bytes are never pipelined.
  if(end!==buffer.length-1)return socket.destroy();
  let opened;try{const raw=buffer.subarray(0,end);opened=Open(JSON.parse(decoder.decode(raw)));const response=Seal(opened,Dispatch(opened)),wire=JSON.stringify(response)+'\n';if(Buffer.byteLength(wire)>MAX_RESPONSE_FRAME)throw Error('CONNECT_RESPONSE_TOO_LARGE');socket.end(wire);}
  catch(_){opened?.key.fill(0);socket.destroy();}
 });
}
function CreateServer(){
 identity.Load();require('./desktopBootstrap').Initialize();
 const tlsIdentity=require('./connectTls').Load();
 const server=tls.createServer({...tlsIdentity.options,handshakeTimeout:DEADLINE_MS},socket=>{
  // Cached certificate validity is rechecked for every accepted TLS connection.
  try{require('./connectTls').Load();}catch(_){socket.destroy();return;}
  Accept(socket);
 });
 // Count and expire raw sockets before TLS authentication, including peers that
 // never send ClientHello. The same absolute budget covers handshake + request.
 server.on('connection',socket=>{
  Prune();const ip=String(socket.remoteAddress||'UNKNOWN');
  try{Rate('ALL',1800);Rate('IP:'+ip,1200);if(active>=512||(activeByIp.get(ip)||0)>=32)throw Error('CONNECT_CAPACITY');}catch(_){socket.destroy();return;}
  active++;activeByIp.set(ip,(activeByIp.get(ip)||0)+1);socket.on('error',()=>{});
  const deadline=setTimeout(()=>socket.destroy(),DEADLINE_MS);deadline.unref();
  socket.once('close',()=>{clearTimeout(deadline);active--;const count=(activeByIp.get(ip)||1)-1;if(count)activeByIp.set(ip,count);else activeByIp.delete(ip);});
 });
 server.on('tlsClientError',(_error,socket)=>socket.destroy());
 return server;
}
function Start(){
 const config=require('../config/config'),port=config.CONNECT_TCP_PORT;
 if(!Number.isInteger(port)||port<1||port>65535||port===config.WEB_ADMIN_PORT||port===config.HEALTH_PORT)throw Error('CONNECT_PORT_INVALID');
 const server=CreateServer();server.on('error',error=>{console.error('CONNECT_TCP_START_FAILED:',error.code||error.message);throw error;});
 listener=server;server.listen(port,config.HOST,()=>console.log('GameConnect pinned TLS TCP:',port));return server;
}
function IsListening(){if(!listener||!listener.listening)return false;try{require('./connectTls').Load();return true;}catch(_){return false;}}
module.exports={PROTOCOL,MAX_FRAME,MAX_CLEAR,MAX_RESPONSE_CLEAR,MAX_RESPONSE_FRAME,DEADLINE_MS,Aad,CreateServer,Start,IsListening};
