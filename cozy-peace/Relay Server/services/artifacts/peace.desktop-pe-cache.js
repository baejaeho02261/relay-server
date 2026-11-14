'use strict';
// Only the internally scheduled upload path primes this identity-keyed cache.
// A SHA-512 binding detects accidental mutation before reuse. No disk cache,
// client-supplied baseline, or second storage writer is introduced.
const crypto=require('node:crypto'),cache=new WeakMap();
const UPLOAD_ERRORS={BOOTSTRAP_PE_INVALID:400,BOOTSTRAP_UPLOAD_CHANGED:409,BOOTSTRAP_UPLOAD_BUSY:429,BOOTSTRAP_UPLOAD_TIMEOUT:408,BOOTSTRAP_UPLOAD_ABORTED:400,BOOTSTRAP_PE_ANALYSIS_FAILED:503};
function UploadError(code){const error=Error(code);if(UPLOAD_ERRORS[code]){error.desktopError=true;error.status=UPLOAD_ERRORS[code];}return error;}
function WorkError(error){
 const code=error?.message;
 if(code==='BOOTSTRAP_PE_INVALID')return UploadError(code);
 if(['WORK_QUEUE_BUSY','WORK_QUEUE_BYTES','WORK_TASK_SIZE'].includes(code))return UploadError('BOOTSTRAP_UPLOAD_BUSY');
 if(code==='WORK_DEADLINE')return UploadError('BOOTSTRAP_UPLOAD_TIMEOUT');
 return UploadError('BOOTSTRAP_PE_ANALYSIS_FAILED');
}
function digest(bytes){return crypto.createHash('sha512').update(bytes).digest('hex');}
async function Prepare(bytes,budgetMs=60000){
 if(!Buffer.isBuffer(bytes)||bytes.length>64*1024*1024)throw UploadError('BOOTSTRAP_PE_INVALID');
 const expected=digest(bytes);let value;
 try{value=await require("../runtime/peace.desktop-work-queue").pe.run({kind:'pe',bytes},budgetMs);}
 catch(error){throw WorkError(error);}
 if(value.digests.sha512!==expected||digest(bytes)!==expected)throw UploadError('BOOTSTRAP_UPLOAD_CHANGED');
 require('./peace.release-exposure').Remember(bytes,value.exposure);
 cache.set(bytes,{sha512:expected,value:structuredClone(value)});return value;
}
function Get(bytes,kind){const row=cache.get(bytes);if(!row)return null;if(digest(bytes)!==row.sha512){cache.delete(bytes);throw UploadError('BOOTSTRAP_UPLOAD_CHANGED');}return structuredClone(row.value[kind]);}
module.exports={Prepare,Get,UploadError};
