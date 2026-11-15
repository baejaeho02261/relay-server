"use strict";
// Server-only, bounded one-use transaction approvals. No browser flag can mark
// a record approved. Authentication must call approve after validating a new
// password/passkey response for this exact pending action.
const crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Stable(value){
 let nodes=0;
 function walk(v,depth){
  if(++nodes>200000||depth>32)Fail('ADMIN_ACTION_INPUT_LIMIT',400);
  if(v===null||typeof v==='boolean'||typeof v==='string')return JSON.stringify(v);
  if(typeof v==='number'&&Number.isFinite(v)&&(!Number.isInteger(v)||Number.isSafeInteger(v)))return JSON.stringify(v);
  if(Array.isArray(v))return '['+v.map(x=>walk(x,depth+1)).join(',')+']';
  if(v&&Object.getPrototypeOf(v)===Object.prototype)return '{'+Object.keys(v).sort().map(k=>{
   if(['__proto__','constructor','prototype'].includes(k))Fail('ADMIN_ACTION_INPUT_INVALID',400);
   return JSON.stringify(k)+':'+walk(v[k],depth+1);
  }).join(',')+'}';
  Fail('ADMIN_ACTION_INPUT_INVALID',400);
 }
 const out=walk(value,0);if(Buffer.byteLength(out)>4*1024*1024)Fail('ADMIN_ACTION_INPUT_LIMIT',400);return out;
}
const Hash=v=>crypto.createHash('sha512').update(Stable(v)).digest('hex');
function Binding(method,path,body){if(!['POST','PUT','PATCH','DELETE'].includes(method)||typeof path!=='string'||!/^\/api\/[A-Za-z0-9_./-]+$/.test(path)||path.length>1024)Fail('ADMIN_ACTION_INPUT_INVALID',400);return Hash({version:1,method,path,body});}
class ActionStore {
 constructor({active,fence,tick=()=>performance.now(),wall=()=>Date.now(),pendingMs=120000,approvedMs=30000,capacity=2048,perSession=4}){
  if(typeof active!=='function'||typeof fence!=='function')throw Error('ADMIN_ACTION_CONFIG');
  Object.assign(this,{active,fence,tick,wall,pendingMs,approvedMs,capacity,perSession});this.rows=new Map();
 }
 prune(){const t=this.tick(),w=this.wall();for(const [id,r]of this.rows)if(!this.active(r.session)||t<r.start||t>=r.deadline||w<r.created||w>=r.expiresAt)this.rows.delete(id);}
 issue(session,method,path,body,summary){
  this.prune();if(!this.active(session)||session.role!=='admin')Fail('ADMIN_REQUIRED',403);
  const digest=Binding(method,path,body),fence=this.fence(path,body);
  // A repeated preflight reuses the pending record; it cannot extend its TTL.
  for(const r of this.rows.values())if(r.session===session&&r.digest===digest&&r.fence===fence&&r.state==='PENDING')return this.public(r);
  if(this.rows.size>=this.capacity||[...this.rows.values()].filter(r=>r.session===session).length>=this.perSession)Fail('ADMIN_ACTION_CAPACITY',429);
  const id=crypto.randomBytes(24).toString('hex'),t=this.tick(),w=this.wall();
  const r={id,session,sessionId:session.id,method,path,digest,fence,summary:JSON.parse(Stable(summary)),start:t,deadline:t+this.pendingMs,created:w,expiresAt:w+this.pendingMs,state:'PENDING'};
  this.rows.set(id,r);return this.public(r);
 }
 public(r){return {id:r.id,method:r.method,path:r.path,requestSha512:r.digest,policySha512:r.fence,summary:r.summary,expiresAt:r.expiresAt,oneUse:true,storage:'SERVER_MEMORY_ONLY'};}
 pending(session,id){this.prune();const r=this.rows.get(id);if(!r||r.session!==session||r.sessionId!==session.id||!this.active(session))Fail('ADMIN_ACTION_INVALID',403);if(r.state!=='PENDING')Fail('ADMIN_ACTION_ALREADY_APPROVED');return this.public(r);}
 approve(session,id){
  // Called only by the authenticated server password/passkey endpoints, not a
  // generic HTTP approve route. The original request cannot be replaced here.
  this.pending(session,id);const r=this.rows.get(id);r.state='APPROVED';r.deadline=Math.min(r.deadline,this.tick()+this.approvedMs);r.expiresAt=Math.min(r.expiresAt,this.wall()+this.approvedMs);return this.public(r);
 }
 cancel(session,id){const r=this.rows.get(id);if(r?.session===session)this.rows.delete(id);}
 consume(session,id,method,path,body){
  this.prune();const r=this.rows.get(id);
  // A different session cannot consume or destroy the owner's capability.
  if(!r||r.session!==session||r.sessionId!==session.id||!this.active(session))Fail('ADMIN_ACTION_INVALID',403);
  this.rows.delete(id); // Burn before executing, including mismatches/failures.
  if(r.state!=='APPROVED')Fail('ADMIN_ACTION_NOT_APPROVED',403);
  if(r.method!==method||r.path!==path||r.digest!==Binding(method,path,body))Fail('ADMIN_ACTION_CHANGED');
  if(r.fence!==this.fence(path,body))Fail('ADMIN_ACTION_POLICY_CHANGED');
  return {id:r.id,requestSha512:r.digest,policySha512:r.fence};
 }
}
module.exports={ActionStore,Stable,Hash,Binding,Fail};
