'use strict';
// Workers verify signatures ONLY. The original single-writer handler then
// rechecks current key, challenge, policy, expiry, session and receipt before
// any authorization mutation. An exact per-request transcript cache is not a
// capability and never accepts preverified=true from a network request.
const crypto=require('node:crypto'),{AsyncLocalStorage}=require('node:async_hooks');
const {performance}=require('node:perf_hooks'),context=new AsyncLocalStorage();
function Id(publicKey,canonical,signature){return crypto.createHash('sha512').update(JSON.stringify([publicKey,canonical,signature])).digest('hex');}
function Job(publicKey,canonical,signature){
 if(typeof canonical!=='string'||Buffer.byteLength(canonical)>65536||typeof signature!=='string'||!/^[A-Za-z0-9+/]{342}==$/.test(signature))throw Error('WORK_PROOF_INVALID');
 const bytes=Buffer.from(signature,'base64');if(bytes.length!==256||bytes.toString('base64')!==signature)throw Error('WORK_PROOF_INVALID');
 const parsed=require('./desktopLicenses').ParseKey(publicKey);
 return {id:Id(publicKey,canonical,signature),key:parsed.key,message:Buffer.from(canonical),signature:bytes};
}
function Verify(publicKey,canonical,signature){
 const active=context.getStore();
 if(active){
  // A queued verification cannot extend a request deadline or authenticate a
  // changed transcript/key. Do not fall back to blocking RSA in this context.
  if(performance.now()>=active.deadline)throw Error('CONNECT_DEADLINE');
  return active.results.get(Id(publicKey,canonical,signature))===true;
 }
 // Synchronous internal/CLI calls retain the original full cryptographic check.
 const j=Job(publicKey,canonical,signature);
 try{return crypto.verify('sha256',j.message,{key:j.key,padding:crypto.constants.RSA_PKCS1_PADDING},j.signature);}
 finally{j.message.fill(0);j.signature.fill(0);}
}
async function Run(jobs,execute,{deadline,key='',renewal=false}={}){
 if(!Array.isArray(jobs)||jobs.length>4||!Number.isFinite(deadline))throw Error('WORK_PROOF_INVALID');
 const results=new Map();
 try{
  if(jobs.length){
   const queue=require('./desktopWorkQueue')[renewal?'renewalProof':'proof'];
   const value=await queue.run({kind:'verify',jobs},deadline-performance.now(),{key});
   if(!Array.isArray(value)||value.length!==jobs.length)throw Error('WORK_PROOF_INVALID');
   for(let i=0;i<jobs.length;i++)results.set(jobs[i].id,value[i]===true);
  }
  if(performance.now()>=deadline)throw Error('CONNECT_DEADLINE');
  return context.run({results,deadline},()=>{
   const value=execute();
   // The single-writer commit phase must stay synchronous. A future async
   // handler must explicitly redesign this boundary, not outlive its proof map.
   if(value&&typeof value.then==='function')throw Error('WORK_COMMIT_ASYNC_FORBIDDEN');
   return value;
  });
 }finally{for(const j of jobs){j.message?.fill(0);j.signature?.fill(0);}results.clear();}
}
function Prepare(operation,body){
 try{
 if(operation==='execute')return require('./desktopLicenses').ProofTasks(body);
 if(operation==='bootstrap')return require('./desktopBootstrap').ProofTasks(body);
 if(operation==='security')return require('./desktopSecurityAuthority').ProofTasks(body);
 if(operation==='device')return require('./desktopDeviceIdentity').ProofTasks(body);
 if(operation==='report')return require('./desktopIntegrityReports').ProofTasks(body);
 return [];
 }catch(error){if(error.message==='WORK_PROOF_INVALID')return [];throw error;}
}
module.exports={Job,Verify,Run,Prepare};
