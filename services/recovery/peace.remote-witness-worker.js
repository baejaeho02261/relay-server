"use strict";
// Network I/O runs in this worker. Existing synchronous journal commits use
// bounded Atomics.wait, not a child shell, curl command or file token cache.
const {parentPort,workerData}=require('node:worker_threads'),https=require('node:https');
const tls=require("../network/peace.server-peer-tls"),strict=require("../protocol/peace.strict-json");
let client,url,error;
try{client=tls.Client(workerData);url=tls.Endpoint(workerData.url);const {agent:_,...secure}=client;client.agent=new https.Agent({...secure,keepAlive:true,maxSockets:1,maxFreeSockets:1,timeout:5000});}catch(_){error='RECOVERY_WITNESS_TLS_CONFIG';}
parentPort.on('message',({request,signal,output})=>{
 const state=new Int32Array(signal),dest=new Uint8Array(output);let complete=false;
 function finish(result){if(complete)return;complete=true;const bytes=Buffer.from(JSON.stringify(result));if(bytes.length>dest.length){return complete=false,finish({ok:false,error:'RECOVERY_WITNESS_RESPONSE_LIMIT'});}dest.set(bytes);Atomics.store(state,1,bytes.length);Atomics.store(state,0,1);Atomics.notify(state,0);}
 if(error)return finish({ok:false,error});
 const body=Buffer.from(JSON.stringify(request));let total=0,chunks=[];
 const req=https.request(url,{...client,path:'/v1/witness',method:'POST',headers:{'Content-Type':'application/json','Content-Length':body.length}},res=>{
  if(res.statusCode!==200&&res.statusCode!==409){res.resume();return finish({ok:false,error:'RECOVERY_WITNESS_UNAVAILABLE'});}
  res.on('data',b=>{total+=b.length;if(total>65536){res.destroy();finish({ok:false,error:'RECOVERY_WITNESS_RESPONSE_LIMIT'});}else chunks.push(b);});
  res.on('error',()=>finish({ok:false,error:'RECOVERY_WITNESS_UNAVAILABLE'}));
  res.on('end',()=>{try{const row=strict.Parse(Buffer.concat(chunks),{maxBytes:65536,maxDepth:12,maxNodes:4096});if(!row||typeof row.ok!=='boolean'||res.statusCode!==200&&row.ok)throw Error();finish(row);}catch(_){finish({ok:false,error:'RECOVERY_WITNESS_RESPONSE_INVALID'});}});
 });
 const timer=setTimeout(()=>{req.destroy();finish({ok:false,error:'RECOVERY_WITNESS_TIMEOUT'});},workerData.timeoutMs-250);timer.unref();req.on('close',()=>clearTimeout(timer));req.on('error',()=>finish({ok:false,error:'RECOVERY_WITNESS_UNAVAILABLE'}));req.end(body);
});
