'use strict';
// Server-persisted capability belongs to the approved artifact digest, never to
// an untrusted request version. v0 is explicit pre-migration compatibility.
const CONTRACT='GAME-MEASUREMENT-PLAN-V1';
const OWN_CONTRACT='GAME-OWN-MEASUREMENT-BUNDLE-V1';
function ArtifactOwnVersion(bytes){return ArtifactVersion(bytes,OWN_CONTRACT);}
const FIELDS=Object.freeze(['measurementContract','measurementPlanVersion','measurementStartedTick','measurementFinishedTick','moduleGenerationStable','coverage']);
function ArtifactVersion(bytes,marker=CONTRACT){
 if(!Buffer.isBuffer(bytes)||bytes.length<64||bytes.readUInt16LE(0)!==0x5a4d)throw Error('BOOTSTRAP_PE_INVALID');
 const pe=bytes.readUInt32LE(0x3c);
 if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550)throw Error('BOOTSTRAP_PE_INVALID');
 const count=bytes.readUInt16LE(pe+6),table=pe+24+bytes.readUInt16LE(pe+20);
 if(count<1||count>96||table>bytes.length-count*40)throw Error('BOOTSTRAP_PE_INVALID');
 // A capability declaration is part of an approved file, not proof that it ran.
 // Overlays/certificates and zero-fill virtual tails cannot advertise support.
 let supported=false;
 for(let i=0;i<count;i++){
  const p=table+i*40,size=bytes.readUInt32LE(p+16),offset=bytes.readUInt32LE(p+20),flags=bytes.readUInt32LE(p+36);
  if(size>bytes.length||offset>bytes.length-size)throw Error('BOOTSTRAP_PE_INVALID');
  if(!size||!(flags&0x40000000)||!(flags&0x60))continue;
  const section=bytes.subarray(offset,offset+size);
  if(section.includes(Buffer.from(marker))||section.includes(Buffer.from(marker,'utf16le')))supported=true;
 }
 return supported?1:0;
}
function ValidateOwnMetadata(meta,status,layers){
 if(!require('./peace.measurement-status').IsStatus(status))return false;
 const fields=['contract','version','startedTick','finishedTick','coverage','fileStatus','codeStatus','crcStatus','imageStable'];
 if(!meta||Array.isArray(meta)||typeof meta!=='object'||Object.keys(meta).length!==fields.length||fields.some(k=>!Object.hasOwn(meta,k))||meta.contract!==OWN_CONTRACT||meta.version!==1)return false;
 if(!Number.isSafeInteger(meta.startedTick)||!Number.isSafeInteger(meta.finishedTick)||meta.startedTick<0||meta.finishedTick<meta.startedTick||meta.finishedTick-meta.startedTick>60000||typeof meta.imageStable!=='boolean'||!['FULL','PARTIAL'].includes(meta.coverage))return false;
 const statuses=['MEASURED','NOT_MEASURED','FILE_CHANGED','READ_ERROR','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'];
 if(['fileStatus','codeStatus','crcStatus'].some(k=>!statuses.includes(meta[k])))return false;
 const complete=meta.imageStable&&['fileStatus','codeStatus','crcStatus'].every(k=>meta[k]==='MEASURED')&&require("../runtime/peace.desktop-crc-policy").Validate(layers)&&Object.entries(layers).filter(([k])=>k!=='version').every(([,v])=>v.status==='measured');
 return status==='MEASURED'?meta.coverage==='FULL'&&complete:meta.coverage==='PARTIAL';
}
function AssertOwn(payload,artifact){
 if(payload.check!=='OWN_IMAGE')return;
 if(payload.own?.status==='MEASURED'&&artifact?.ownMeasurementVersion===1&&!payload.ownMeasurement)throw Error('INTEGRITY_OWN_MEASUREMENT_REQUIRED');
 if(payload.ownMeasurement!==undefined&&!ValidateOwnMetadata(payload.ownMeasurement,payload.own?.status,payload.crcLayers))throw Error('INTEGRITY_OWN_MEASUREMENT_INVALID');
}
function Required(artifact){return artifact?.measurementPlanVersion===1?1:0;}
function Assert(payload,artifact){
 AssertOwn(payload,artifact);
 if(payload.check!=='MODULE_INVENTORY')return;
 if(Required(artifact)&&!FIELDS.every(k=>Object.hasOwn(payload,k)))throw Error('INTEGRITY_MEASUREMENT_PLAN_REQUIRED');
 if(payload.measurementContract!==undefined&&payload.measurementContract!==CONTRACT)throw Error('INTEGRITY_MEASUREMENT_PLAN_UNSUPPORTED');
 if(Required(artifact)&&(payload.measurementContract!==CONTRACT||payload.measurementPlanVersion!==1))throw Error('INTEGRITY_MEASUREMENT_PLAN_REQUIRED');
}
function Assurance(payload){return payload.measurementPlanVersion===1&&payload.measurementContract===CONTRACT?'COHERENT_PLAN_V1':payload.measurementPlanVersion===1?'PLAN_V1_COMPATIBLE':'LEGACY_UNVERSIONED';}
function Complete(payload){return payload.measurementPlanVersion===1&&payload.measurementContract===CONTRACT&&payload.moduleGenerationStable===true&&payload.coverage==='FULL'&&payload.complete===true&&!payload.truncated;}
module.exports={AssertOwn,ValidateOwnMetadata,CONTRACT,OWN_CONTRACT,ArtifactOwnVersion,FIELDS,ArtifactVersion,Required,Assert,Assurance,Complete};
