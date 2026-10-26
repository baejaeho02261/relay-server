'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Separate CPU lanes keep uploaded PE/CRC work out of the TLS/lease event loop.
// Workers never open a store, consume a licence or publish an authorization.
const {Worker}=require('node:worker_threads'),path=require('node:path');
const {performance}=require('node:perf_hooks');
const MiB=1024*1024;
// Bound structured-clone inputs before enqueueing. KeyObjects carry no readable
// key bytes here; public/private key parsing is still the worker's responsibility.
function TaskBytes(task){
 const seen=new Set();let total=0,nodes=0;
 function walk(v,depth){if(++nodes>8192||depth>24)throw Error('WORK_TASK_SIZE');
  if(v===null||v===undefined)return;if(typeof v==='string'){total+=Buffer.byteLength(v);return;}
  if(['number','boolean'].includes(typeof v)){total+=8;return;}
  if(typeof v!=='object')throw Error('WORK_TASK_INVALID');
  if(ArrayBuffer.isView(v)){if(typeof SharedArrayBuffer!=='undefined'&&v.buffer instanceof SharedArrayBuffer)throw Error('WORK_TASK_INVALID');total+=v.buffer.byteLength;return;}
  if(v instanceof ArrayBuffer){total+=v.byteLength;return;}
  if(v instanceof require('node:crypto').KeyObject){total+=16384;return;}
  if(!Array.isArray(v)&&Object.getPrototypeOf(v)!==Object.prototype)throw Error('WORK_TASK_INVALID');if(seen.has(v))throw Error('WORK_TASK_INVALID');seen.add(v);
  for(const [k,d] of Object.entries(Object.getOwnPropertyDescriptors(v))){if(d.get||d.set)throw Error('WORK_TASK_INVALID');total+=Buffer.byteLength(k)+8;walk(d.value,depth+1);}seen.delete(v);
 }
 walk(task,0);return total;
}
function WipeResult(value){value?.key?.fill(0);value?.bytes?.fill(0);if(value?.serverPolicy)value.serverPolicy.programBase64='';}
class WorkQueue {
 constructor(name,workers,capacity,options={}){this.maxPerKey=options.maxPerKey||workers+capacity;this.lastKey='';this.name=name;this.maxTaskBytes=options.maxTaskBytes||1048576;this.maxQueuedBytes=options.maxQueuedBytes||8*MiB;this.pendingBytes=0;this.heapMb=options.heapMb||64;this.workers=workers;this.capacity=capacity;this.queue=[];this.slots=[];this.serial=0;this.closed=false;this.stats={submitted:0,dispatched:0,completed:0,rejected:0,failed:0,timedOut:0,queueHighWater:0,byteHighWater:0,terminated:0,waitSamples:0,runSamples:0,totalWaitMs:0,totalRunMs:0,maxWaitMs:0,maxRunMs:0};}
 observe(rejected=false){if(!['authentication','pe-analysis','device-proof','renewal-proof','tpm-attestation'].includes(this.name))return;try{require("../observability/peace.desktop-performance-metrics").QueueState(this.name,this.slots.filter(s=>s.job).length,this.queue.filter(j=>!j.settled).length,this.workers,this.capacity,rejected);}catch(_){}}
 run(task,budgetMs=10000,{key=''}={}){
  if(typeof key!=='string'||key.length>160)return Promise.reject(Error('WORK_QUEUE_KEY_INVALID'));
  if(key&&this.queue.filter(j=>!j.settled&&j.key===key).length+this.slots.filter(s=>s.job?.key===key).length>=this.maxPerKey){this.stats.rejected++;this.observe(true);return Promise.reject(Error('WORK_QUEUE_BUSY'));}
  if(this.closed)return Promise.reject(Error('WORK_QUEUE_CLOSED'));
  let taskBytes;try{taskBytes=TaskBytes(task);}catch(e){return Promise.reject(e);}
  if(taskBytes>this.maxTaskBytes||this.pendingBytes>this.maxQueuedBytes-taskBytes){this.stats.rejected++;this.observe(true);return Promise.reject(Error('WORK_QUEUE_BYTES'));}
  if(!Number.isFinite(budgetMs)||budgetMs<=0||budgetMs>120000)return Promise.reject(Error('WORK_DEADLINE'));
  if(this.queue.length+this.slots.filter(s=>s.job).length>=this.capacity+this.workers){this.stats.rejected++;this.observe(true);return Promise.reject(Error('WORK_QUEUE_BUSY'));}
  // Freeze the submitted data by ownership-copy before waiting. Mutating an
  // original queued object must not bypass the byte limit or alter its work.
  try{task=structuredClone(task);}catch(_){return Promise.reject(Error('WORK_TASK_INVALID'));}
  return new Promise((resolve,reject)=>{const now=performance.now(),job={id:++this.serial,key,task,taskBytes,bytesReleased:false,resolve,reject,at:now,deadline:now+budgetMs,settled:false};
   this.pendingBytes+=taskBytes;this.stats.byteHighWater=Math.max(this.stats.byteHighWater,this.pendingBytes);
   job.timer=setTimeout(()=>{if(job.settled)return;const slot=this.slots.find(s=>s.job===job);this.settle(job,Error('WORK_DEADLINE'));this.queue=this.queue.filter(x=>x!==job);
    if(slot){slot.broken=true;this.stats.terminated++;slot.worker.terminate().catch(()=>{});}else this.releaseBytes(job);
    try{require("../security/peace.security-detection").Record('WORKER_TIMEOUT',{subject:this.name,reason:'WORK_DEADLINE'});}catch(_){}
    this.pump();this.observe();},budgetMs);
   this.stats.submitted++;this.queue.push(job);this.stats.queueHighWater=Math.max(this.stats.queueHighWater,this.queue.length);this.observe();this.pump();this.observe();});
 }
 releaseBytes(job){if(!job||job.bytesReleased)return;job.bytesReleased=true;this.pendingBytes=Math.max(0,this.pendingBytes-job.taskBytes);}
 settle(job,error,value){clearTimeout(job.timer);if(job.settled){WipeResult(value);return;}job.settled=true;job.task?.secret?.fill(0);job.task=null;if(error){if(error.message==='WORK_DEADLINE')this.stats.timedOut++;else this.stats.failed++;WipeResult(value);job.reject(error);}else{this.stats.completed++;job.resolve(value);}}
 finishRun(job){
  // Runtime is measured until the worker actually stops using the task, even
  // if the caller's deadline fired earlier. Count the same population in the
  // sum and denominator, including failed work and worker exits exactly once.
  if(!job||!job.dispatched||job.runRecorded)return;
  job.runRecorded=true;this.releaseBytes(job);const run=Math.max(0,performance.now()-job.started);
  this.stats.runSamples++;this.stats.totalRunMs+=run;this.stats.maxRunMs=Math.max(this.stats.maxRunMs,run);
 }
 makeSlot(){
  const worker=new Worker(path.join(MODULE_RESOURCE_ROOT,"runtime/peace.desktop-cpu-worker.js"),{resourceLimits:{maxOldGenerationSizeMb:this.heapMb,maxYoungGenerationSizeMb:16,stackSizeMb:4}}),slot={worker,job:null,exited:false};this.slots.push(slot);worker.unref();
  slot.exitPromise=new Promise(resolve=>worker.once('exit',()=>{slot.exited=true;resolve();}));
  worker.on('message',message=>{const job=slot.job;if(!job||message.id!==job.id){WipeResult(message.value);return;}
   slot.job=null;worker.unref();this.finishRun(job);
   if(performance.now()>=job.deadline)this.settle(job,Error('WORK_DEADLINE'),message.value);
   else this.settle(job,message.error?Error(message.error):null,message.value);
   this.pump();this.observe();});
  worker.on('error',error=>{slot.broken=true;if(slot.job)this.settle(slot.job,Error('WORKER_FAILED'));slot.worker.terminate().catch(()=>{});this.observe();});
  worker.on('exit',()=>{if(slot.job){this.finishRun(slot.job);this.settle(slot.job,Error('WORKER_EXITED'));slot.job=null;}this.slots=this.slots.filter(x=>x!==slot);this.pump();this.observe();});
  return slot;
 }
 pump(){
  if(this.closed)return;
  while(this.queue.length){let slot=this.slots.find(s=>!s.job&&!s.broken);if(!slot&&this.slots.length<this.workers)slot=this.makeSlot();if(!slot)return;
   let index=this.queue.findIndex(j=>!j.settled&&j.key!==this.lastKey);if(index<0)index=0;
   const job=this.queue.splice(index,1)[0];this.lastKey=job.key;if(job.settled)continue;if(performance.now()>=job.deadline){this.settle(job,Error('WORK_DEADLINE'));this.releaseBytes(job);continue;}
   job.started=performance.now();const wait=job.started-job.at;this.stats.waitSamples++;this.stats.totalWaitMs+=wait;this.stats.maxWaitMs=Math.max(this.stats.maxWaitMs,wait);slot.job=job;slot.worker.ref();
   try{slot.worker.postMessage({id:job.id,task:job.task});job.dispatched=true;this.stats.dispatched++;job.task=null;}catch(_){slot.job=null;slot.worker.unref();this.settle(job,Error('WORKER_DISPATCH_FAILED'));this.releaseBytes(job);}
  }
 }
 snapshot(){this.observe();const s=this.stats;return {name:this.name,workers:this.workers,running:this.slots.filter(x=>x.job).length,queued:this.queue.filter(x=>!x.settled).length,capacity:this.capacity,pendingBytes:this.pendingBytes,maxTaskBytes:this.maxTaskBytes,maxQueuedBytes:this.maxQueuedBytes,heapLimitMb:this.heapMb,externalBuffersNotLimitedByV8:true,...s,averageWaitMs:s.waitSamples?s.totalWaitMs/s.waitSamples:0,averageRunMs:s.runSamples?s.totalRunMs/s.runSamples:0,waitPopulation:'DISPATCH_ATTEMPTS',runPopulation:'FINISHED_WORKER_TASKS_INCLUDING_FAILURES_AND_LATE_RESULTS'};}
 // Stop admission. Pure CPU workers drain only until their existing deadline;
 // a deadline terminates that worker. No writer or authority owner runs here.
 async close(){this.closed=true;for(const job of this.queue){this.settle(job,Error('WORK_QUEUE_CLOSED'));this.releaseBytes(job);}this.queue=[];this.observe();
  await Promise.all(this.slots.slice().map(async s=>{while(s.job&&!s.exited)await new Promise(resolve=>setTimeout(resolve,10));
   if(!s.exited){s.worker.ref();s.worker.postMessage({close:true});}await s.exitPromise;}));this.observe();}
}
const auth=new WorkQueue('authentication',2,32,{maxPerKey:8}),pe=new WorkQueue('pe-analysis',1,1,{maxTaskBytes:64*MiB+65536,maxQueuedBytes:128*MiB+131072,heapMb:256}),proof=new WorkQueue('device-proof',1,16,{maxPerKey:2}),renewalProof=new WorkQueue('renewal-proof',1,16,{maxPerKey:2});
const tpmAttestation=new WorkQueue('tpm-attestation',1,4,{maxPerKey:1});
const renewal={attempted:0,failed:0},connections={active:0};
const shutdown={source:'AUTHENTICATED_CLIENT_DIAGNOSTIC',attested:false,received:0,joinBudgetMissed:0,maxJoinElapsedMs:0,durationTruncated:0};
function ValidateShutdown(value){
 if(!value||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!=='durationTruncated,joinBudgetMissed,joinElapsedMs,version'||value.version!==1||!Number.isSafeInteger(value.joinElapsedMs)||value.joinElapsedMs<0||value.joinElapsedMs>86400000||typeof value.joinBudgetMissed!=='boolean'||typeof value.durationTruncated!=='boolean')throw Error('BOOTSTRAP_INPUT_INVALID');
 return value;
}
function RecordShutdown(value,role='UNKNOWN'){ValidateShutdown(value);shutdown.received++;if(value.joinBudgetMissed)shutdown.joinBudgetMissed++;shutdown.maxJoinElapsedMs=Math.max(shutdown.maxJoinElapsedMs,value.joinElapsedMs);if(value.durationTruncated)shutdown.durationTruncated++;try{require("../observability/peace.desktop-performance-metrics").RecordShutdown(role,value);}catch(_){}}

function Renewal(ok){renewal.attempted++;if(!ok)renewal.failed++;}
function IsRenewal(operation,action){return (operation==='execute'&&action==='verify')||
 (operation==='bootstrap'&&action==='overlayVerify');}
function RecordRenewal(operation,action,ok,elapsedMs){
 // A challenge only prepares a renewal. It must not enter its success count.
 if(!IsRenewal(operation,action))return false;
 Renewal(ok===true);try{require("../observability/peace.desktop-performance-metrics").RecordRenewal(operation==='bootstrap'?'O':'B',elapsedMs,ok===true);}catch(_){}return true;
}
function Snapshot(){return {version:1,scope:'PROCESS_LIFETIME',shutdown:{...shutdown},connections:connections.active,authentication:auth.snapshot(),proof:proof.snapshot(),renewalProof:renewalProof.snapshot(),tpmAttestation:tpmAttestation.snapshot(),pe:pe.snapshot(),renewal:{...renewal,failureRatio:renewal.attempted?renewal.failed/renewal.attempted:0}};}
module.exports={IsRenewal,ValidateShutdown,RecordShutdown,WorkQueue,TaskBytes,auth,pe,proof,renewalProof,tpmAttestation,Renewal,RecordRenewal,connections,Snapshot};
