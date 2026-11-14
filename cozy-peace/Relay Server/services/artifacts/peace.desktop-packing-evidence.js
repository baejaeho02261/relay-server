'use strict';
// A record that the pinned, authenticated worker returned these exact changed
// template bytes. This is NOT proof of virtualization, Windows compatibility,
// plaintext removal, or protection of A's later individualized configuration.
// Pure DB arguments keep validation independent of authority-store loading.
const crypto=require('node:crypto');
const ROLES=['A','B','O'],DOMAIN='GAME-PACKING-RECEIPT-V1';
const MAX_RECEIPTS=384,UNREFERENCED_MS=24*60*60*1000;
const HASH=/^[a-f0-9]{128}$/,ID=/^(?:DA-)?[A-F0-9]{24}$/;
const FIELDS=['version','purpose','jobId','component','sourceArtifactId','inputSha512','outputSha512','size','toolSha512','profileSha512','createdAt','actorHash'];
const plain=x=>!!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
function Fail(code='PACKING_EVIDENCE_INVALID',status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Stable(x){if(Array.isArray(x))return '['+x.map(Stable).join(',')+']';if(plain(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+Stable(x[k])).join(',')+'}';return JSON.stringify(x);}
function ValidateReceipt(r){
 if(!plain(r)||Object.keys(r).length!==FIELDS.length||FIELDS.some(k=>!Object.hasOwn(r,k))||r.version!==1||r.purpose!==DOMAIN||!/^[a-f0-9]{32}$/.test(r.jobId)||!ROLES.includes(r.component)||!ID.test(r.sourceArtifactId)||!['inputSha512','outputSha512','toolSha512','profileSha512','actorHash'].every(k=>typeof r[k]==='string'&&HASH.test(r[k]))||r.inputSha512===r.outputSha512||!Number.isSafeInteger(r.size)||r.size<512||r.size>64*1024*1024||!Number.isSafeInteger(r.createdAt)||r.createdAt<1)Fail();
 return r;
}
function ReceiptId(r){ValidateReceipt(r);return crypto.createHash('sha512').update(DOMAIN+'\n'+Stable(r)).digest('hex');}
function ValidateJob(records){
 if(!Array.isArray(records)||records.length!==3)Fail();
 for(const r of records)ValidateReceipt(r);
 if(new Set(records.map(r=>r.component)).size!==3||new Set(records.map(r=>r.sourceArtifactId)).size!==3||['jobId','createdAt','actorHash','toolSha512'].some(k=>new Set(records.map(r=>r[k])).size!==1))Fail('PACKING_COHORT_MISMATCH');
 return records;
}
function Bound(r,a){return !!a&&a.component===r.component&&a.sha512===r.outputSha512&&a.size===r.size;}
function ValidateStore(db){
 if(!plain(db)||!plain(db.artifacts))Fail();
 const map=db.packingEvidence;
 if(map!==undefined&&(!plain(map)||Object.keys(map).length>MAX_RECEIPTS))Fail();
 const jobs=new Map();
 for(const [id,r]of Object.entries(map||{})){
  if(!HASH.test(id)||ReceiptId(r)!==id)Fail();
  const source=db.artifacts[r.sourceArtifactId];
  // Historical source IDs/hashes remain evidence after an unused source file
  // is collected. A still-existing source may never contradict its record.
  if(source&&(source.component!==r.component||source.sha512!==r.inputSha512))Fail('PACKING_EVIDENCE_BINDING_MISMATCH');
  const list=jobs.get(r.jobId)||[];list.push(r);jobs.set(r.jobId,list);
 }
 for(const records of jobs.values())ValidateJob(records);
 for(const a of Object.values(db.artifacts))if(a&&a.packingReceiptId!==undefined){
  if(typeof a.packingReceiptId!=='string'||!HASH.test(a.packingReceiptId)||!map?.[a.packingReceiptId])Fail();
  if(!Bound(map[a.packingReceiptId],a))Fail('PACKING_EVIDENCE_BINDING_MISMATCH');
 }
 return db;
}
function FindReceipt(db,a){
 if(!a)return null;
 const map=db.packingEvidence||{};
 if(a.packingReceiptId!==undefined){
  const r=map[a.packingReceiptId];
  if(!r||ReceiptId(r)!==a.packingReceiptId)Fail();
  if(!Bound(r,a))Fail('PACKING_EVIDENCE_BINDING_MISMATCH');
  return {id:a.packingReceiptId,record:r};
 }
 // Hash lookup prevents dropping an optional field from making known packed
 // bytes appear to be an untouched legacy artifact. Deterministic latest-job
 // choice also permits repeated deterministic transforms of the same input.
 const matches=Object.entries(map).filter(([,r])=>r.component===a.component&&r.outputSha512===a.sha512);
 if(!matches.length)return null;
 if(matches.some(([,r])=>!Bound(r,a)))Fail('PACKING_EVIDENCE_BINDING_MISMATCH');
 matches.sort((a,b)=>b[1].createdAt-a[1].createdAt||b[1].jobId.localeCompare(a[1].jobId));
 const [id,r]=matches[0];if(ReceiptId(r)!==id)Fail();return {id,record:r};
}
function Projection(db,a){
 const found=FindReceipt(db,a);if(!found)return null;const r=found.record;
 return {receiptId:found.id,jobId:r.jobId,scope:'TRANSFORMED_TEMPLATE',inputSha512:r.inputSha512,outputSha512:r.outputSha512,toolSha512:r.toolSha512,profileSha512:r.profileSha512,createdAt:r.createdAt,windowsVerified:false,protectionVerified:false};
}
function RecordJob(db,records,{now=Date.now()}={}){
 ValidateStore(db);ValidateJob(records);
 if(!Number.isSafeInteger(now)||now<records[0].createdAt||now-records[0].createdAt>30*60*1000)Fail('PACKING_EVIDENCE_TIME_INVALID');
 for(const r of records){const source=db.artifacts[r.sourceArtifactId];if(!source||source.component!==r.component||source.sha512!==r.inputSha512)Fail('PACKING_SOURCE_CHANGED');}
 const ids=Object.fromEntries(records.map(r=>[r.component,ReceiptId(r)]));
 const map={...(db.packingEvidence||{})},old=Object.entries(map).filter(([,r])=>r.jobId===records[0].jobId);
 if(old.length){
  if(old.length!==3||old.some(([id,r])=>ids[r.component]!==id))Fail('PACKING_EVIDENCE_CONFLICT');
  return ids;
 }
 // Opportunistic whole-job cleanup has no timer. Referenced records, including
 // artifacts whose reference field was omitted, may never be pruned.
 const grouped=new Map();for(const [id,r]of Object.entries(map)){const list=grouped.get(r.jobId)||[];list.push([id,r]);grouped.set(r.jobId,list);}
 for(const group of grouped.values())if(group[0][1].createdAt<now-UNREFERENCED_MS&&!group.some(([id,r])=>Object.values(db.artifacts).some(a=>a&&(a.packingReceiptId===id||a.component===r.component&&a.sha512===r.outputSha512))))for(const [id]of group)delete map[id];
 if(Object.keys(map).length+3>MAX_RECEIPTS)Fail('PACKING_EVIDENCE_CAPACITY',503);
 for(const r of records)map[ids[r.component]]=structuredClone(r);
 const next={...db,packingEvidence:map};ValidateStore(next);db.packingEvidence=map;return ids;
}
function EvaluatePair(db,a,b,o,{required=false}={}){
 try{
  ValidateStore(db);const rows=[a,b,o],receipts=rows.map(row=>FindReceipt(db,row)),count=receipts.filter(Boolean).length;
  if(!count)return required?'PACKING_EVIDENCE_REQUIRED':'';
  if(count!==3||rows.some((row,i)=>!row||row.component!==ROLES[i]))return 'PACKING_COHORT_INCOMPLETE';
  if(new Set(receipts.map(r=>r.record.jobId)).size!==1)return 'PACKING_COHORT_MISMATCH';
  ValidateJob(receipts.map(r=>r.record));return '';
 }catch(e){return /^PACKING_(?:EVIDENCE|COHORT)_[A-Z_]+$/.test(e.message)?e.message:'PACKING_EVIDENCE_INVALID';}
}
module.exports={DOMAIN,ROLES,MAX_RECEIPTS,UNREFERENCED_MS,ValidateReceipt,ReceiptId,ValidateStore,RecordJob,FindReceipt,Projection,EvaluatePair};
