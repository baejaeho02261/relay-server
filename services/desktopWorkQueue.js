'use strict';
// Separate CPU lanes keep uploaded PE/CRC work out of the TLS/lease event loop.
// Workers never open a store, consume a licence or publish an authorization.
const {Worker}=require('node:worker_threads'),path=require('node:path');
const {performance}=require('node:perf_hooks');
class WorkQueue {
 constructor(name,workers,capacity,options={}){this.maxPerKey=options.maxPerKey||workers+capacity;this.lastKey='';this.name=name;this.workers=workers;this.capacity=capacity;this.queue=[];this.slots=[];this.serial=0;this.closed=false;this.stats={submitted:0,dispatched:0,completed:0,rejected:0,failed:0,timedOut:0,queueHighWater:0,waitSamples:0,runSamples:0,totalWaitMs:0,totalRunMs:0,maxWaitMs:0,maxRunMs:0};}
 run(task,budgetMs=10000,{key=''}={}){
  if(typeof key!=='string'||key.length>160)return Promise.reject(Error('WORK_QUEUE_KEY_INVALID'));
  if(key&&this.queue.filter(j=>!j.settled&&j.key===key).length+this.slots.filter(s=>s.job?.key===key).length>=this.maxPerKey){this.stats.rejected++;return Promise.reject(Error('WORK_QUEUE_BUSY'));}
  if(this.closed)return Promise.reject(Error('WORK_QUEUE_CLOSED'));
  if(!Number.isFinite(budgetMs)||budgetMs<=0||budgetMs>120000)return Promise.reject(Error('WORK_DEADLINE'));
  if(this.queue.length+this.slots.filter(s=>s.job).length>=this.capacity+this.workers){this.stats.rejected++;return Promise.reject(Error('WORK_QUEUE_BUSY'));}
  return new Promise((resolve,reject)=>{const now=performance.now(),job={id:++this.serial,key,task,resolve,reject,at:now,deadline:now+budgetMs,settled:false};
   job.timer=setTimeout(()=>{if(job.settled)return;this.settle(job,Error('WORK_DEADLINE'));this.queue=this.queue.filter(x=>x!==job);},budgetMs);
   this.stats.submitted++;this.queue.push(job);this.stats.queueHighWater=Math.max(this.stats.queueHighWater,this.queue.length);this.pump();});
 }
 settle(job,error,value){clearTimeout(job.timer);if(job.settled){if(value?.key)value.key.fill(0);return;}job.settled=true;job.task?.secret?.fill(0);job.task=null;if(error){if(error.message==='WORK_DEADLINE')this.stats.timedOut++;else this.stats.failed++;if(value?.key)value.key.fill(0);job.reject(error);}else{this.stats.completed++;job.resolve(value);}}
 finishRun(job){
  // Runtime is measured until the worker actually stops using the task, even
  // if the caller's deadline fired earlier. Count the same population in the
  // sum and denominator, including failed work and worker exits exactly once.
  if(!job||!job.dispatched||job.runRecorded)return;
  job.runRecorded=true;const run=Math.max(0,performance.now()-job.started);
  this.stats.runSamples++;this.stats.totalRunMs+=run;this.stats.maxRunMs=Math.max(this.stats.maxRunMs,run);
 }
 makeSlot(){
  const worker=new Worker(path.join(__dirname,'desktopCpuWorker.js')),slot={worker,job:null,exited:false};this.slots.push(slot);worker.unref();
  slot.exitPromise=new Promise(resolve=>worker.once('exit',()=>{slot.exited=true;resolve();}));
  worker.on('message',message=>{const job=slot.job;if(!job||message.id!==job.id){if(message.value?.key)message.value.key.fill(0);return;}
   slot.job=null;worker.unref();this.finishRun(job);
   if(performance.now()>=job.deadline)this.settle(job,Error('WORK_DEADLINE'),message.value);
   else this.settle(job,message.error?Error(message.error):null,message.value);
   if(job.settled&&message.value?.key&&performance.now()>=job.deadline)message.value.key.fill(0);
   this.pump();});
  worker.on('error',error=>{slot.broken=true;if(slot.job){this.finishRun(slot.job);this.settle(slot.job,Error('WORKER_FAILED'));slot.job=null;}});
  worker.on('exit',()=>{if(slot.job){this.finishRun(slot.job);this.settle(slot.job,Error('WORKER_EXITED'));slot.job=null;}this.slots=this.slots.filter(x=>x!==slot);this.pump();});
  return slot;
 }
 pump(){
  if(this.closed)return;
  while(this.queue.length){let slot=this.slots.find(s=>!s.job&&!s.broken);if(!slot&&this.slots.length<this.workers)slot=this.makeSlot();if(!slot)return;
   let index=this.queue.findIndex(j=>!j.settled&&j.key!==this.lastKey);if(index<0)index=0;
   const job=this.queue.splice(index,1)[0];this.lastKey=job.key;if(job.settled)continue;if(performance.now()>=job.deadline){this.settle(job,Error('WORK_DEADLINE'));continue;}
   job.started=performance.now();const wait=job.started-job.at;this.stats.waitSamples++;this.stats.totalWaitMs+=wait;this.stats.maxWaitMs=Math.max(this.stats.maxWaitMs,wait);slot.job=job;slot.worker.ref();
   try{slot.worker.postMessage({id:job.id,task:job.task});job.dispatched=true;this.stats.dispatched++;job.task=null;}catch(_){slot.job=null;slot.worker.unref();this.settle(job,Error('WORKER_DISPATCH_FAILED'));}
  }
 }
 snapshot(){const s=this.stats;return {name:this.name,workers:this.workers,running:this.slots.filter(x=>x.job).length,queued:this.queue.filter(x=>!x.settled).length,capacity:this.capacity,...s,averageWaitMs:s.waitSamples?s.totalWaitMs/s.waitSamples:0,averageRunMs:s.runSamples?s.totalRunMs/s.runSamples:0,waitPopulation:'DISPATCH_ATTEMPTS',runPopulation:'FINISHED_WORKER_TASKS_INCLUDING_FAILURES_AND_LATE_RESULTS'};}
 // Stop admitting work. Running tasks drain without terminating a security owner.
 // Thread exit is requested only once its pure CPU task has completed.
 async close(){this.closed=true;for(const job of this.queue)this.settle(job,Error('WORK_QUEUE_CLOSED'));this.queue=[];
  await Promise.all(this.slots.slice().map(async s=>{while(s.job&&!s.exited)await new Promise(resolve=>setTimeout(resolve,10));
   if(!s.exited){s.worker.ref();s.worker.postMessage({close:true});}await s.exitPromise;}));}
}
const auth=new WorkQueue('authentication',2,32,{maxPerKey:8}),pe=new WorkQueue('pe-analysis',1,1),proof=new WorkQueue('device-proof',1,16,{maxPerKey:2}),renewalProof=new WorkQueue('renewal-proof',1,16,{maxPerKey:2});
const tpmAttestation=new WorkQueue('tpm-attestation',1,4,{maxPerKey:1});
const renewal={attempted:0,failed:0},connections={active:0};
const shutdown={source:'AUTHENTICATED_CLIENT_DIAGNOSTIC',attested:false,received:0,joinBudgetMissed:0,maxJoinElapsedMs:0,durationTruncated:0};
function ValidateShutdown(value){
 if(!value||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!=='durationTruncated,joinBudgetMissed,joinElapsedMs,version'||value.version!==1||!Number.isSafeInteger(value.joinElapsedMs)||value.joinElapsedMs<0||value.joinElapsedMs>86400000||typeof value.joinBudgetMissed!=='boolean'||typeof value.durationTruncated!=='boolean')throw Error('BOOTSTRAP_INPUT_INVALID');
 return value;
}
function RecordShutdown(value){ValidateShutdown(value);shutdown.received++;if(value.joinBudgetMissed)shutdown.joinBudgetMissed++;shutdown.maxJoinElapsedMs=Math.max(shutdown.maxJoinElapsedMs,value.joinElapsedMs);if(value.durationTruncated)shutdown.durationTruncated++;}

function Renewal(ok){renewal.attempted++;if(!ok)renewal.failed++;}
function IsRenewal(operation,action){return (operation==='execute'&&action==='verify')||
 (operation==='bootstrap'&&action==='overlayVerify');}
function RecordRenewal(operation,action,ok){
 // A challenge only prepares a renewal. It must not enter its success count.
 if(!IsRenewal(operation,action))return false;
 Renewal(ok===true);return true;
}
function Snapshot(){return {version:1,scope:'PROCESS_LIFETIME',shutdown:{...shutdown},connections:connections.active,authentication:auth.snapshot(),proof:proof.snapshot(),renewalProof:renewalProof.snapshot(),tpmAttestation:tpmAttestation.snapshot(),pe:pe.snapshot(),renewal:{...renewal,failureRatio:renewal.attempted?renewal.failed/renewal.attempted:0}};}
module.exports={IsRenewal,ValidateShutdown,RecordShutdown,WorkQueue,auth,pe,proof,renewalProof,tpmAttestation,Renewal,RecordRenewal,connections,Snapshot};
