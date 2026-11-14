'use strict';
// Separate JS isolate keeps compression/crypto CPU off the license event loop.
const {parentPort,workerData}=require('node:worker_threads');
const format=require("../../services/artifacts/peace.custom-package-format");
let key,files,box;
try{
 key=Buffer.from(workerData.key);files=workerData.files.map(f=>({name:f.name,bytes:Buffer.from(f.bytes)}));
 workerData.key.fill(0);for(const f of workerData.files)f.bytes.fill(0);
 box=format.Seal(files,key,workerData.metadata);parentPort.postMessage({ok:true,bytes:box});
}catch(e){parentPort.postMessage({ok:false,error:/^CUSTOM_PACKAGE_[A-Z_]+$/.test(e.message)?e.message:'CUSTOM_PACKAGE_FAILED'});}
finally{key?.fill(0);for(const f of files||[])f.bytes.fill(0);box?.fill(0);}
