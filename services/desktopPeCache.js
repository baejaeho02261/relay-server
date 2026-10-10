'use strict';
// Only the internally scheduled upload path primes this identity-keyed cache.
// A SHA-512 binding detects accidental mutation before reuse. No disk cache,
// client-supplied baseline, or second storage writer is introduced.
const crypto=require('node:crypto'),cache=new WeakMap();
function digest(bytes){return crypto.createHash('sha512').update(bytes).digest('hex');}
async function Prepare(bytes,budgetMs=60000){
 if(!Buffer.isBuffer(bytes)||bytes.length>64*1024*1024)throw Error('BOOTSTRAP_PE_INVALID');
 const expected=digest(bytes),value=await require('./desktopWorkQueue').pe.run({kind:'pe',bytes},budgetMs);
 if(value.digests.sha512!==expected||digest(bytes)!==expected)throw Error('BOOTSTRAP_UPLOAD_CHANGED');
 cache.set(bytes,{sha512:expected,value:structuredClone(value)});return value;
}
function Get(bytes,kind){const row=cache.get(bytes);if(!row)return null;if(digest(bytes)!==row.sha512){cache.delete(bytes);throw Error('BOOTSTRAP_UPLOAD_CHANGED');}return structuredClone(row.value[kind]);}
module.exports={Prepare,Get};
