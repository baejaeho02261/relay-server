"use strict";
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const {Worker}=require('node:worker_threads'),path=require('node:path');
const protocol=require('./peace.remote-witness-protocol'),tls=require("../network/peace.server-peer-tls");
function Config(e=process.env){
 tls.Endpoint(e.DESKTOP_RECOVERY_WITNESS_URL);tls.Pin(e.DESKTOP_RECOVERY_WITNESS_SERVER_SPKI_SHA512);
 if(!protocol.ID.test(e.DESKTOP_RECOVERY_WITNESS_INSTALLATION_ID||''))throw Error('RECOVERY_WITNESS_INSTALLATION_REQUIRED');
 if(e.DESKTOP_RECOVERY_WITNESS_DIR||e.DESKTOP_RECOVERY_WITNESS_REQUIRED!=='1')throw Error('RECOVERY_WITNESS_REMOTE_CONFIGURATION');
 const c={url:e.DESKTOP_RECOVERY_WITNESS_URL,installationId:e.DESKTOP_RECOVERY_WITNESS_INSTALLATION_ID,pin:e.DESKTOP_RECOVERY_WITNESS_SERVER_SPKI_SHA512,
  ca:e.DESKTOP_RECOVERY_WITNESS_CA_FILE,cert:e.DESKTOP_RECOVERY_WITNESS_CERT_FILE,key:e.DESKTOP_RECOVERY_WITNESS_KEY_FILE,timeoutMs:5000};
 // Validate before a worker exists. Do not return key bytes to the main caller.
 for(const k of ['ca','cert','key'])tls.Pem(c[k]).fill(0);return c;
}
class RemoteWitness {
 constructor(c){this.c=c;this.failed=false;this.closing=null;this.worker=new Worker(path.join(MODULE_RESOURCE_ROOT,"recovery/peace.remote-witness-worker.js"),{workerData:c,execArgv:[]});this.worker.unref();this.worker.on('error',()=>{this.close();});this.worker.once('exit',()=>{this.failed=true;});}
 fail(code){this.close();throw Error(code);}
 call(action,name,current,next){
  if(this.failed)throw Error('RECOVERY_WITNESS_RESTART_REQUIRED');
  const request={version:1,installationId:this.c.installationId,action,...(name?{name}:{}),...(current?{current}:{}),...(next?{next}:{})};protocol.Body(request);
  const signal=new SharedArrayBuffer(8),output=new SharedArrayBuffer(65536),state=new Int32Array(signal);
  try{this.worker.postMessage({request,signal,output});}catch(_){this.fail('RECOVERY_WITNESS_UNAVAILABLE');}
  const result=Atomics.wait(state,0,0,this.c.timeoutMs);
  if(result==='timed-out'||Atomics.load(state,0)!==1)this.fail('RECOVERY_WITNESS_TIMEOUT');
  let row;try{row=require("../protocol/peace.strict-json").Parse(Buffer.from(output,0,Atomics.load(state,1)),{maxBytes:65536,maxDepth:12,maxNodes:4096});}catch(_){this.fail('RECOVERY_WITNESS_RESPONSE_INVALID');}
  if(row?.ok!==true)this.fail(/^RECOVERY_[A-Z_]+$/.test(row?.error)?row.error:'RECOVERY_WITNESS_UNAVAILABLE');
  return row.result;
 }
 status(){const s=this.call('status');if(s?.installationId!==this.c.installationId)this.fail('RECOVERY_WITNESS_INSTALLATION_MISMATCH');return {...s,transport:'PINNED_MUTUAL_TLS',storage:'INDEPENDENT_SERVER',remoteAttestation:false};}
 read(){return this.status();}
 head(name){const h=this.call('head',name);if(!require('./peace.recovery-witness-file').ValidHead(h?.current)||h.pending&&!require('./peace.recovery-witness-file').ValidHead(h.pending))this.fail('RECOVERY_WITNESS_RESPONSE_INVALID');return h;}
 open(name,h){return this.call('open',name,h);}
 prepare(name,a,b){return this.call('prepare',name,a,b);}
 settle(name,h){return this.call('settle',name,h);}
 // Termination releases the worker's HTTPS agent, sockets and pending timers.
 // Share one promise so shutdown and a simultaneous network failure can join it.
 close(){this.failed=true;if(!this.closing)this.closing=this.worker.terminate();return this.closing;}
}
module.exports={Config,RemoteWitness};
