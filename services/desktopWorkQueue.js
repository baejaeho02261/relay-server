'use strict';
// Separate CPU lanes keep uploaded PE/CRC work out of the TLS/lease event loop.
// Workers never open a store, consume a licence or publish an authorization.
const {Worker}=require('node:worker_threads'),path=require('node:path');
const {performance}=require('node:perf_hooks');
class WorkQueue {
 constructor(name,workers,capacity){this.name=name;this.workers=workers;this.capacity=capacity;this.queue=[];this.slots=[];this.serial=0;this.closed=false;this.stats={submitted:0,completed:0,rejected:0,failed:0,timedOut:0,queueHighWater:0,totalWaitMs:0,totalRunMs:0,maxWaitMs:0,maxRunMs:0};}
 run(task,budgetMs=10000){
  if(this.closed)return Promise.reject(Error('WORK_QUEUE_CLOSED'));
  if(!Number.isFinite(budgetMs)||budgetMs<=0||budgetMs>120000)return Promise.reject(Error('WORK_DEADLINE'));
  if(this.queue.length+this.slots.filter(s=>s.job).length>=this.capacity+this.workers){this.stats.rejected++;return Promise.reject(Error('WORK_QUEUE_BUSY'));}
  return new Promise((resolve,reject)=>{const now=performance.now(),job={id:++this.serial,task,resolve,reject,at:now,deadline:now+budgetMs,settled:false};
   job.timer=setTimeout(()=>{if(job.settled)return;job.settled=true;this.stats.timedOut++;reject(Error('WORK_DEADLINE'));this.queue=this.queue.filter(x=>x!==job);job.task=null;},budgetMs);
   this.stats.submitted++;this.queue.push(job);this.stats.queueHighWater=Math.max(this.stats.queueHighWater,this.queue.length);this.pump();});
 }
 settle(job,error,value){clearTimeout(job.timer);if(job.settled){if(value?.key)value.key.fill(0);return;}job.settled=true;job.task=null;if(error){this.stats.failed++;job.reject(error);}else{this.stats.completed++;job.resolve(value);}}
 makeSlot(){
  const worker=new Worker(path.join(__dirname,'desktopCpuWorker.js')),slot={worker,job:null,exited:false};this.slots.push(slot);worker.unref();
  slot.exitPromise=new Promise(resolve=>worker.once('exit',()=>{slot.exited=true;resolve();}));
  worker.on('message',message=>{const job=slot.job;if(!job||message.id!==job.id){if(message.value?.key)message.value.key.fill(0);return;}
   slot.job=null;worker.unref();const run=performance.now()-job.started;this.stats.totalRunMs+=run;this.stats.maxRunMs=Math.max(this.stats.maxRunMs,run);
   if(performance.now()>=job.deadline)this.settle(job,Error('WORK_DEADLINE'));
   else this.settle(job,message.error?Error(message.error):null,message.value);
   if(job.settled&&message.value?.key&&performance.now()>=job.deadline)message.value.key.fill(0);
   this.pump();});
  worker.on('error',error=>{if(slot.job){this.settle(slot.job,Error('WORKER_FAILED'));slot.job=null;}slot.broken=true;});
  worker.on('exit',()=>{if(slot.job)this.settle(slot.job,Error('WORKER_EXITED'));this.slots=this.slots.filter(x=>x!==slot);this.pump();});
  return slot;
 }
 pump(){
  if(this.closed)return;
  while(this.queue.length){let slot=this.slots.find(s=>!s.job&&!s.broken);if(!slot&&this.slots.length<this.workers)slot=this.makeSlot();if(!slot)return;
   const job=this.queue.shift();if(job.settled)continue;if(performance.now()>=job.deadline){this.settle(job,Error('WORK_DEADLINE'));continue;}
   job.started=performance.now();const wait=job.started-job.at;this.stats.totalWaitMs+=wait;this.stats.maxWaitMs=Math.max(this.stats.maxWaitMs,wait);slot.job=job;slot.worker.ref();
   try{slot.worker.postMessage({id:job.id,task:job.task});job.task=null;}catch(_){slot.job=null;slot.worker.unref();this.settle(job,Error('WORKER_DISPATCH_FAILED'));}
  }
 }
 snapshot(){const s=this.stats;return {name:this.name,workers:this.workers,running:this.slots.filter(x=>x.job).length,queued:this.queue.filter(x=>!x.settled).length,capacity:this.capacity,...s,averageWaitMs:s.submitted?s.totalWaitMs/s.submitted:0,averageRunMs:s.completed?s.totalRunMs/s.completed:0};}
 // Stop admitting work. Running tasks drain without terminating a security owner.
 // Thread exit is requested only once its pure CPU task has completed.
 async close(){this.closed=true;for(const job of this.queue)this.settle(job,Error('WORK_QUEUE_CLOSED'));this.queue=[];
  await Promise.all(this.slots.slice().map(async s=>{while(s.job&&!s.exited)await new Promise(resolve=>setTimeout(resolve,10));
   if(!s.exited){s.worker.ref();s.worker.postMessage({close:true});}await s.exitPromise;}));}
}
const auth=new WorkQueue('authentication',2,32),pe=new WorkQueue('pe-analysis',1,1);
const renewal={attempted:0,failed:0},connections={active:0};
function Renewal(ok){renewal.attempted++;if(!ok)renewal.failed++;}
function Snapshot(){return {version:1,scope:'PROCESS_LIFETIME',connections:connections.active,authentication:auth.snapshot(),pe:pe.snapshot(),renewal:{...renewal,failureRatio:renewal.attempted?renewal.failed/renewal.attempted:0}};}
module.exports={WorkQueue,auth,pe,Renewal,connections,Snapshot};
