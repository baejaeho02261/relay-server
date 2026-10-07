'use strict';
// Role-aware comparison: a missing role cannot borrow another role's digest.
// Unavailable checker ranges remain explicit and do not become a fabricated PASS.
const {isDeepStrictEqual}=require('node:util');
const {registry}=require('./crcLayers');
const roles=Object.keys(registry);
function Plain(value){return value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;}
function Validate(value){
 if(!Plain(value)||value.version!=='CRC-LAYERS-V1'||Object.keys(value).length!==roles.length+1||roles.some(role=>!Plain(value[role])))return false;
 for(const role of roles){const row=value[role];if(row.algorithm!==registry[role].name||typeof row.role!=='string'||!['measured','partial','unavailable'].includes(row.status))return false;
  const fields=row.status==='unavailable'?['algorithm','role','status','reason']:role==='crc32c'?['algorithm','role','status','digest','digestAlgorithm','pageSize','pages','bytes']:row.status==='partial'?['algorithm','role','status','digest','bytes','reason']:['algorithm','role','status','digest','bytes'];
  if(Object.keys(row).length!==fields.length||fields.some(key=>!Object.hasOwn(row,key)))return false;
  if(row.status==='unavailable'){if(!['LINKER_RANGES_REQUIRED','CHECKER_RANGES_REQUIRED'].includes(row.reason))return false;continue;}
  if(row.status==='partial'&&(role!=='nvme'||row.reason!=='CHECKER_RANGES_REQUIRED'))return false;
  const length=role==='crc32c'?128:registry[role].width/4;
  if(typeof row.digest!=='string'||!new RegExp('^[a-fA-F0-9]{'+length+'}$').test(row.digest)||!Number.isSafeInteger(row.bytes)||row.bytes<0)return false;
  if(role==='crc32c'&&(row.digestAlgorithm!=='SHA-512-PAGE-MANIFEST'||row.pageSize!==4096||!Number.isSafeInteger(row.pages)||row.pages<1||row.pages>32768))return false;
 }
 return true;
}
function Compare(observed,expected){
 if(!Validate(expected))return {matched:false,complete:false,reason:'CRC_BASELINE_UNAVAILABLE',signals:[]};
 if(!Validate(observed))return {matched:false,complete:false,reason:'CRC_MEASUREMENT_INVALID',signals:[]};
 const signals=roles.map(role=>({role,status:!isDeepStrictEqual(observed[role],expected[role])?'MISMATCH':expected[role].status==='measured'?'MATCH':expected[role].status==='partial'?'PARTIAL':'UNAVAILABLE'}));
 const matched=signals.every(row=>row.status!=='MISMATCH'),complete=signals.every(row=>row.status==='MATCH');
 return {matched,complete,reason:matched?(complete?'CRC_BASELINE_MATCH':'CRC_PARTIAL_COVERAGE'):'CRC_ROLE_MISMATCH',signals};
}
module.exports={Validate,Compare};
