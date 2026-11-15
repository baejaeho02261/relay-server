"use strict";
// Independent witness host: no authority DB, no license/signing secrets. Only
// compare/prepare/settle existing heads; no online enroll, reset or rewind API.
const fs=require('node:fs'),https=require('node:https');
const tls=require("../../services/network/peace.server-peer-tls"),p=require("../../services/recovery/peace.remote-witness-protocol");
const lifetimes=new WeakMap();
function Config(e=process.env){
 require("../../services/security/peace.service-isolation").Check('witness',e);
 require("../runtime/peace.runtime-pem-files").ProvisionWitness(e);
 if(!require('node:path').isAbsolute(e.WITNESS_DATA_DIR||''))throw Error('RECOVERY_WITNESS_DIRECTORY_REQUIRED');
 const dir=fs.realpathSync(e.WITNESS_DATA_DIR);if(!fs.statSync(dir).isDirectory())throw Error('RECOVERY_WITNESS_DIRECTORY_INVALID');
 tls.Pin(e.WITNESS_CLIENT_SPKI_SHA512);return {dir,clientPin:e.WITNESS_CLIENT_SPKI_SHA512,tls:tls.Server({ca:e.WITNESS_CA_FILE,cert:e.WITNESS_CERT_FILE,key:e.WITNESS_KEY_FILE})};
}
function CreateServer(c,witness){
 // The executable entry point acquires an exclusive OS-backed lock before here.
 let pending=0;
 const server=https.createServer(c.tls,(req,res)=>{
  const send=(status,row)=>{if(res.destroyed)return;res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(row));};
  if(!tls.Peer(req.socket,c.clientPin)){req.resume();return send(403,{ok:false,error:'RECOVERY_WITNESS_CLIENT_DENIED'});}
  if(req.method!=='POST'||req.url!=='/v1/witness'||req.headers['content-type']!=='application/json'||req.headers['content-encoding']&&req.headers['content-encoding']!=='identity'){req.resume();return send(400,{ok:false,error:'RECOVERY_WITNESS_REQUEST_INVALID'});}
  if(pending>=16){req.resume();return send(429,{ok:false,error:'RECOVERY_WITNESS_BUSY'});}
  const declared=req.headers['content-length'];if(!/^\d{1,4}$/.test(declared||'')||Number(declared)<1||Number(declared)>4096){req.resume();return send(413,{ok:false,error:'RECOVERY_WITNESS_SIZE_INVALID'});}
  pending++;let done=false,n=0,chunks=[];
  const finish=(error)=>{if(done)return;done=true;clearTimeout(timer);pending--;if(error){chunks=[];req.resume();return send(400,{ok:false,error});}
   try{if(n!==Number(declared))throw Error('RECOVERY_WITNESS_SIZE_INVALID');const b=require("../../services/protocol/peace.strict-json").Parse(Buffer.concat(chunks,n),{maxBytes:4096,maxDepth:5,maxNodes:64});const result=p.Dispatch(witness,b);send(200,{ok:true,result});}
   catch(e){send(409,{ok:false,error:/^RECOVERY_[A-Z_]+$/.test(e.message)?e.message:'RECOVERY_WITNESS_IO_FAILED'});}finally{chunks=[];}
  };
  const timer=setTimeout(()=>finish('RECOVERY_WITNESS_READ_TIMEOUT'),5000);timer.unref();
  req.on('data',b=>{if(done)return;n+=b.length;if(n>4096||n>Number(declared))return finish('RECOVERY_WITNESS_SIZE_INVALID');chunks.push(b);});
  req.once('end',()=>finish());req.once('aborted',()=>finish('RECOVERY_WITNESS_ABORTED'));req.once('error',()=>finish('RECOVERY_WITNESS_ABORTED'));
 });server.maxConnections=32;server.headersTimeout=5000;server.requestTimeout=6000;
 const sockets=new Set();server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
 lifetimes.set(server,{sockets,closing:null});return server;
}
function CloseServer(server,{timeoutMs=2500}={}){
 if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>10000)throw Error('RECOVERY_WITNESS_SHUTDOWN_TIMEOUT_INVALID');
 const state=lifetimes.get(server);if(!state)throw Error('RECOVERY_WITNESS_SERVER_INVALID');
 if(state.closing)return state.closing;
 state.closing=new Promise((resolve,reject)=>{
  let timer;const finish=error=>{clearTimeout(timer);if(error&&error.code!=='ERR_SERVER_NOT_RUNNING')reject(Error('RECOVERY_WITNESS_SHUTDOWN_FAILED'));else resolve();};
  timer=setTimeout(()=>{for(const socket of state.sockets)socket.destroy();},timeoutMs);timer.unref();
  // Stop accepting first; allow an in-flight durable write to finish. The
  // deadline also closes unauthenticated/partial TLS and idle keepalive sockets.
  server.close(finish);server.closeIdleConnections?.();
 });return state.closing;
}
function InstallShutdown(server,options={}){
 let closing=false;
 const stop=()=>{if(closing)return;closing=true;process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);
  CloseServer(server,options).then(()=>{process.exitCode=0;},()=>{console.error('RECOVERY_WITNESS_SHUTDOWN_FAILED');process.exitCode=1;});
 };
 process.once('SIGINT',stop);process.once('SIGTERM',stop);
 return ()=>{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);};
}
if(require.main===module){try{const listener=require('../../config/peace.runtime-environment').ReadListener('witness');const c=Config();require("../../services/storage/peace.desktop-single-writer").AcquireWitness(c.dir,{haEnabled:false});
 const w=new(require("../../services/recovery/peace.recovery-witness-file").WitnessFile)(c.dir);w.read();for(const name of p.DOMAINS)w.head(name);
 const server=CreateServer(c,w);InstallShutdown(server);server.once('error',()=>{console.error('RECOVERY_WITNESS_LISTEN_FAILED');process.exitCode=1;});server.listen(listener.port,listener.host,()=>console.log('RECOVERY_WITNESS_READY: existing installation, no reset API'));
 }catch(e){console.error(/^(?:RECOVERY_[A-Z_]+|ISOLATION_[A-Z_]+|SERVER_PEER_[A-Z_]+|DESKTOP_WRITER_[A-Z_]+|RUNTIME_CONFIG_[A-Z_]+)$/.test(e.message)?e.message:'RECOVERY_WITNESS_START_FAILED');process.exitCode=1;}}
module.exports={Config,CreateServer,CloseServer,InstallShutdown};
