'use strict';
// Admission/backpressure, not an OS sandbox. Never terminates a storage writer,
// alters a licence deadline or deletes audit / revocation data.
const fs=require('node:fs'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const MiB=1024*1024;
const KINDS=new Set(['upload','packing','custom-package','parser-fuzz','artifact-scan']);
function ErrorCode(code,status=429){const e=Error(code);e.desktopError=true;e.status=status;return e;}
function Subject(key){return crypto.createHash('sha512').update(String(key||'SERVER')).digest('hex').slice(0,48);}
function Signal(reason,subject='SERVER'){try{require("../security/peace.security-detection").Record('RESOURCE_REJECTED',{reason,subject});}catch(_) {}}
class Budget {
 constructor({clock=()=>performance.now(),memory=()=>process.memoryUsage().rss,maxBytes=1024*MiB,maxJobs=2,maxPerOwner=1,minFreeBytes=256*MiB,maxRssBytes=0,signal=Signal}={}){
  this.clock=clock;this.memory=memory;this.limits={maxBytes,maxJobs,maxPerOwner,minFreeBytes,maxRssBytes};this.signal=signal;this.jobs=new Map();this.serial=0;this.holdUntil=0;this.holdReason='';this.diskRequired=false;this.disk=null;this.stats={admitted:0,rejected:0,peakReservedBytes:0,completed:0};
 }
 reject(code,key){this.stats.rejected++;this.signal(code,Subject(key));throw ErrorCode(code,code==='RESOURCE_DISK_UNAVAILABLE'?503:429);}
 admit(kind,{key='SERVER',bytes=0,diskBytes=0}={}){
  if(!KINDS.has(kind)||typeof key!=='string'||key.length>160||![bytes,diskBytes].every(x=>Number.isSafeInteger(x)&&x>=0))throw ErrorCode('RESOURCE_REQUEST_INVALID',400);
  const at=this.clock(),l=this.limits;if(this.holdUntil>at)this.reject('RESOURCE_BACKGROUND_HELD',key);
  if([...this.jobs.values()].filter(x=>!x.retained).length>=l.maxJobs||[...this.jobs.values()].filter(x=>!x.retained&&x.owner===Subject(key)).length>=l.maxPerOwner)this.reject('RESOURCE_JOB_LIMIT',key);
  const all=[...this.jobs.values()],reserved=all.reduce((n,j)=>n+j.bytes,0),diskReserved=all.reduce((n,j)=>n+j.diskBytes,0);
  if(bytes>l.maxBytes||reserved>l.maxBytes-bytes)this.reject('RESOURCE_MEMORY_RESERVATION',key);
  if(l.maxRssBytes>0&&this.memory()+bytes>l.maxRssBytes)this.reject('RESOURCE_RSS_PRESSURE',key);
  if(this.diskRequired&&(!this.disk?.ok||at-this.disk.at>20000))this.reject('RESOURCE_DISK_UNAVAILABLE',key);
  if(this.disk?.ok&&this.disk.availableBytes-diskReserved-diskBytes<l.minFreeBytes)this.reject('RESOURCE_DISK_RESERVE',key);
  const id=++this.serial,j={id,kind,owner:Subject(key),bytes,diskBytes,started:at,retained:false};this.jobs.set(id,j);this.stats.admitted++;this.stats.peakReservedBytes=Math.max(this.stats.peakReservedBytes,reserved+bytes);
  let released=false;return Object.freeze({retain:()=>{if(!released)j.retained=true;},release:()=>{if(released)return;released=true;this.jobs.delete(id);this.stats.completed++;},id});
 }
 sampleDisk(availableBytes,ok=true){this.disk={ok:ok===true&&Number.isFinite(availableBytes)&&availableBytes>=0,availableBytes:ok?availableBytes:0,at:this.clock()};}
 hold(reason,ms=300000){if(!/^[A-Z][A-Z0-9_]{1,79}$/.test(reason)||!Number.isInteger(ms)||ms<1000||ms>900000)throw ErrorCode('RESOURCE_HOLD_INVALID',400);this.holdUntil=this.clock()+ms;this.holdReason=reason;}
 releaseHold(){this.holdUntil=0;this.holdReason='';}
 snapshot(){const at=this.clock();return {version:1,scope:'THIS_PROCESS',operatingSystemQuota:'EXTERNAL_CONFIGURATION_REQUIRED',limits:this.limits,active:[...this.jobs.values()].filter(x=>!x.retained).length,retainedResults:[...this.jobs.values()].filter(x=>x.retained).length,reservedBytes:[...this.jobs.values()].reduce((n,j)=>n+j.bytes,0),reservedDiskBytes:[...this.jobs.values()].reduce((n,j)=>n+j.diskBytes,0),rssBytes:this.memory(),disk:this.disk?{ok:this.disk.ok,availableBytes:this.disk.availableBytes,sampleAgeMs:Math.max(0,Math.round(at-this.disk.at))}:null,diskRequired:this.diskRequired,holdRemainingMs:Math.max(0,Math.round(this.holdUntil-at)),holdReason:this.holdUntil>at?this.holdReason:'',lanes:[...KINDS].map(kind=>({kind,active:[...this.jobs.values()].filter(x=>!x.retained&&x.kind===kind).length,retained:[...this.jobs.values()].filter(x=>x.retained&&x.kind===kind).length})),...this.stats};}
}
function NumberEnv(env,name,fallback,min,max){if(!Object.hasOwn(env,name)||env[name]==='')return fallback;if(!/^\d+$/.test(env[name]))throw ErrorCode('RESOURCE_CONFIG_INVALID',503);const n=Number(env[name]);if(!Number.isSafeInteger(n)||n<min||n>max)throw ErrorCode('RESOURCE_CONFIG_INVALID',503);return n;}
function CgroupMemory(){for(const file of ['/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory/memory.limit_in_bytes'])try{const v=fs.readFileSync(file,'utf8').trim();if(/^\d+$/.test(v)){const n=Number(v);if(n>0&&n<Number.MAX_SAFE_INTEGER)return n;}}catch(_){}return 0;}
let budget=new Budget(),timer,started=false;
async function Sample(){try{const dir=require("../../config/peace.runtime-configuration").DATA_DIR,s=await fs.promises.statfs(dir,{bigint:true});const n=s.bavail*s.bsize;budget.sampleDisk(Number(n>BigInt(Number.MAX_SAFE_INTEGER)?BigInt(Number.MAX_SAFE_INTEGER):n));}catch(_){budget.sampleDisk(0,false);Signal('RESOURCE_DISK_UNAVAILABLE');}}
function Start(){if(started)return;started=true;const e=process.env,hard=CgroupMemory(),rss=NumberEnv(e,'GAME_BACKGROUND_MAX_RSS_MIB',0,0,65536)*MiB;
 budget.limits.maxBytes=NumberEnv(e,'GAME_BACKGROUND_RESERVED_MIB',1024,64,8192)*MiB;budget.limits.maxJobs=NumberEnv(e,'GAME_BACKGROUND_CONCURRENCY',2,1,4);budget.limits.minFreeBytes=NumberEnv(e,'GAME_BACKGROUND_DISK_RESERVE_MIB',256,64,16384)*MiB;
 budget.limits.maxRssBytes=rss||(hard?Math.floor(hard*0.85):0);budget.diskRequired=true;Sample();timer=setInterval(Sample,5000);timer.unref();}
function Stop(){clearInterval(timer);timer=null;started=false;}
module.exports={Budget,MiB,KINDS,Subject,ErrorCode,Start,Stop,Sample,Admit:(...a)=>budget.admit(...a),Snapshot:()=>budget.snapshot(),Hold:(...a)=>budget.hold(...a),ReleaseHold:()=>budget.releaseHold()};
