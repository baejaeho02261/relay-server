'use strict';
const crypto=require('node:crypto'),protocol=require('./peace.desktop-packing-protocol'),client=require('./peace.desktop-packing-client'),evidence=require('./peace.desktop-packing-evidence');
// One ephemeral in-memory A/B/O job; <=192 MiB retained output. Never stores
// source, profile scripts, private signing keys, user tokens or an active release.
let current,stopped=false,pending;
const PREFIX='/api/desktop/bootstrap/packing/jobs';
function Clear(){if(current?.status==='RUNNING')return false;current?.lease?.release();for(const item of Object.values(current?.outputs||{}))item.bytes.fill(0);current=undefined;return true;}
function Prune(){if(current?.status!=='RUNNING'&&current?.expiresAt<Date.now())Clear();}
const timer=setInterval(Prune,60000);timer.unref();
function Check(session,method='POST'){const r=require("../authentication/peace.desktop-admin-guard").CheckSession(session,PREFIX,method);if(!r.ok)protocol.Fail(r.reason,r.status||403);if(!require("../../web/authentication/peace.web-auth").IsSessionActive(session))protocol.Fail('ADMIN_SESSION_EXPIRED',401);}
function Source(id,c){const b=require("../bootstrap/peace.desktop-bootstrap"),row=b.Initialize().artifacts[id];if(!row||row.component!==c)protocol.Fail('PACKING_SOURCE_INVALID',409);b.AssertSecurityAvailable();return {row,bytes:b.ReadArtifactBytes(row)};}
function View(job){return {id:job.id,status:job.status,createdAt:job.createdAt,expiresAt:job.expiresAt||0,component:job.component||'',error:job.error||'',outputs:Object.fromEntries(Object.entries(job.outputs).map(([c,v])=>[c,{sha512:v.sha512,inputSha512:v.inputSha512,size:v.bytes.length,profileSha512:v.profileSha512,toolSha512:v.toolSha512}])),...(job.receiptIds?{evidence:{scope:'TRANSFORMED_TEMPLATES',receipts:{...job.receiptIds},windowsVerified:false,protectionVerified:false}}:{}),disposition:'UNAPPROVED_CANDIDATE',activeUnchanged:true,windowsVerified:false,allSourceVirtualizationVerified:false};}
function Get(id,session){Prune();if(!current||current.id!==id||current.owner!==session.id)protocol.Fail('PACKING_JOB_NOT_FOUND',404);return current;}
function Output(id,c,session){const j=Get(id,session);if(j.status!=='COMPLETE'||!j.outputs[c])protocol.Fail('PACKING_OUTPUT_NOT_READY',409);return j.outputs[c];}
function ValidateOutput(bytes,source){
 protocol.Pe(bytes);require('./peace.release-exposure').AssertBytes(bytes);const m=require("../integrity/peace.measurement-plan-contract");
 // Never let packing conceal capability markers and silently downgrade the
 // required measurement protocol. Runtime code compatibility still needs tests.
 if(m.ArtifactVersion(bytes)<(source.measurementPlanVersion||0)||m.ArtifactOwnVersion(bytes)<(source.ownMeasurementVersion||0)||m.ArtifactVersion(bytes,'GAME-TLS-PIN-WINDOW-V1')<(source.tlsPinVersion||0))protocol.Fail('PACKING_MEASUREMENT_CONTRACT_LOST',409);
 try{require("../integrity/peace.desktop-integrity").CodeImage(bytes);}catch(_){protocol.Fail('PACKING_BASELINE_UNSUPPORTED',409);}
 for(const marker of ['GAME-CONNECT-4','GAME-AUTHORITY-V2'])if(!bytes.includes(Buffer.from(marker))&&!bytes.includes(Buffer.from(marker,'utf16le')))protocol.Fail('PACKING_PROTOCOL_CONTRACT_LOST',409);
}
function Begin(body,session){
 if(stopped)protocol.Fail('PACKING_STOPPED',503);Check(session);Prune();if(current?.status==='RUNNING')protocol.Fail('PACKING_BUSY',429);
 if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).length!==3||['A','B','O'].some(c=>typeof body[c]!=='string'||!/^[A-F0-9]{24}$/.test(body[c])))protocol.Fail('PACKING_INPUT_INVALID');
 if(!client.Status().configured)protocol.Fail(client.Status().reason,503);
 // Validate the small descriptors now. Read exact source bytes only inside the
 // serial job, then recheck current source/authorization after each await.
 const db=require("../bootstrap/peace.desktop-bootstrap").Initialize();for(const c of ['A','B','O'])if(db.artifacts[body[c]]?.component!==c||!Number.isSafeInteger(db.artifacts[body[c]].size)||db.artifacts[body[c]].size<1||db.artifacts[body[c]].size>64*1024*1024)protocol.Fail('PACKING_SOURCE_INVALID',409);
 Clear();const lease=require("../runtime/peace.server-resource-budget").Admit('packing',{key:session.id,bytes:Math.max(64*1024*1024,Object.values(body).reduce((n,id)=>n+db.artifacts[id].size,0)*5+8*1024*1024)});const job={id:crypto.randomBytes(16).toString('hex'),owner:session.id,controller:new AbortController(),lease,status:'RUNNING',createdAt:Date.now(),outputs:{},sources:{...body}};
 try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_PACKING_STARTED',JSON.stringify({jobId:job.id,artifactIds:body}));}catch(e){lease.release();throw e;}
 current=job;
 pending=Promise.resolve().then(async()=>{
  try{
   for(const c of ['A','B','O']){
    if(stopped||current!==job)protocol.Fail('PACKING_CANCELLED',503);job.component=c;Check(session,'GET');const original=Source(body[c],c);let result;
    try{
     result=await client.Pack(c,original.bytes,crypto.randomBytes(16).toString('hex'),{signal:job.controller.signal});if(stopped||current!==job)protocol.Fail('PACKING_CANCELLED',503);Check(session,'GET');
     const after=Source(body[c],c);try{if(after.row.sha512!==original.row.sha512||protocol.Sha512(after.bytes)!==result.inputSha512)protocol.Fail('PACKING_SOURCE_CHANGED',409);}finally{after.bytes.fill(0);}
     await require('./peace.release-exposure').Prepare(result.bytes,session.id);if(stopped||current!==job)protocol.Fail('PACKING_CANCELLED',503);Check(session,'GET');
     ValidateOutput(result.bytes,original.row);job.outputs[c]=result;result=null;
    }finally{original.bytes.fill(0);result?.bytes?.fill(0);}
   }
   if(stopped||current!==job)protocol.Fail('PACKING_CANCELLED',503);Check(session);
   // A source packed early in the serial job can be revoked while B/O await
   // their worker. Recheck all sources before the single durable receipt commit.
   for(const c of ['A','B','O']){const source=Source(body[c],c);try{if(protocol.Sha512(source.bytes)!==job.outputs[c].inputSha512||protocol.Sha512(job.outputs[c].bytes)!==job.outputs[c].sha512)protocol.Fail('PACKING_SOURCE_CHANGED',409);}finally{source.bytes.fill(0);}}
   const records=['A','B','O'].map(component=>{const out=job.outputs[component];return {version:1,purpose:evidence.DOMAIN,jobId:job.id,component,sourceArtifactId:body[component],inputSha512:out.inputSha512,outputSha512:out.sha512,size:out.bytes.length,toolSha512:out.toolSha512,profileSha512:out.profileSha512,createdAt:job.createdAt,actorHash:protocol.Sha512(Buffer.from(String(session.id),'utf8'))};});
   const receiptIds=require("../storage/peace.desktop-operation-audit").Run('PACKING_EVIDENCE_RECORDED',session.id,{subject:crypto.createHash('sha256').update(job.id).digest('hex'),count:3,bytes:Object.values(job.outputs).reduce((n,out)=>n+out.bytes.length,0),assurance:'TRANSFORMED_TEMPLATES'},db=>{if(stopped||current!==job)protocol.Fail('PACKING_CANCELLED',503);Check(session);return evidence.RecordJob(db,records);});
   job.receiptIds=receiptIds;job.status='COMPLETE';job.lease?.retain();job.expiresAt=Date.now()+600000;
   try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_PACKING_COMPLETED',JSON.stringify({jobId:job.id,sha512:Object.fromEntries(Object.entries(job.outputs).map(([c,v])=>[c,v.sha512])),receiptIds,disposition:'UNAPPROVED_CANDIDATE'}));}catch(_){console.error('PACKING_COMPLETION_AUDIT_PENDING');}
  }catch(e){job.lease?.release();for(const out of Object.values(job.outputs))out.bytes.fill(0);job.outputs={};job.status='FAILED';job.expiresAt=Date.now()+600000;job.error=/^[A-Z][A-Z0-9_]{1,100}$/.test(e.message)?e.message:'PACKING_FAILED';require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_PACKING_FAILED',JSON.stringify({jobId:job.id,component:job.component,reason:job.error}));}
 }).catch(()=>{job.lease?.release();job.status='FAILED';job.error='PACKING_DIAGNOSTICS_FAILED';job.expiresAt=Date.now()+600000;});
 return View(job);
}
async function Stop(){if(stopped)return pending;stopped=true;clearInterval(timer);const job=current;job?.controller?.abort();job?.lease?.release();for(const out of Object.values(job?.outputs||{}))out.bytes.fill(0);if(job)job.outputs={};current=undefined;await pending;}
module.exports={Begin,Get,View,Output,ValidateOutput,Status:client.Status,Stop};
