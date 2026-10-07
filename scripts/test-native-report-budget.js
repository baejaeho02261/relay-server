'use strict';
// Check both valid UTF-8 JSON and escaped Unicode after the signed payload is
// embedded in the encrypted request. All four file/code/EAT digests are carried in every measured module row.
const assert=require('node:assert/strict');
const row={name:'가'.repeat(64),status:'UNVERIFIED_BASELINE',codeStatus:'MATCH_LOCAL_FILE',fileSha512:'f'.repeat(128),fileCrc64:'F'.repeat(16),fileXxh3_128:'f'.repeat(32),fileBlake3:'f'.repeat(64),codeSha512:'a'.repeat(128),codeCrc64:'A'.repeat(16),codeXxh3_128:'a'.repeat(32),codeBlake3:'a'.repeat(64),executableSections:96,exportCount:131072,codeExportCount:131072,forwardedExportCount:131072,exportCoverage:'INVALID_EXPORT_TABLE',exportTableSha512:'b'.repeat(128),exportTableCrc64:'B'.repeat(16),exportTableXxh3_128:'b'.repeat(32),exportTableBlake3:'b'.repeat(64),exportTableStatus:'MEASURED'};
const sample={version:1,hashVersion:3,check:'MODULE_INVENTORY',reason:'BOOTSTRAP',snapshotId:'f'.repeat(36),batchIndex:170,batchCount:171,complete:true,truncated:false,totalModules:1024,measuredModules:1024,scope:'current-process',trust:'client-reported',modules:Array(6).fill(row)};
assert.equal(Math.ceil(1024 / sample.modules.length), 171);
for(const escaped of [false,true]){
 let payload=JSON.stringify(sample);if(escaped)payload=payload.replace(/[^\x00-\x7f]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
 const request={operation:'report',body:{action:'submit',stage:'A',sessionId:'a'.repeat(24),sessionToken:'a'.repeat(43),machineId:'F'.repeat(64),binarySha512:'a'.repeat(128),binaryCrc64:'A'.repeat(16),codeSha512:'a'.repeat(128),codeCrc64:'A'.repeat(16),reportId:'a'.repeat(48),signature:'A'.repeat(344),payload}};
 assert.ok(Buffer.byteLength(payload)<=10240,'Signed payload exceeds its limit');
 assert.ok(Buffer.byteLength(JSON.stringify(request))<=12288,'Escaped encrypted-request body exceeds transport limit');
}
console.log('Native report wire budget PASS: six rows with four file/code/EAT digests, 171 maximum batches, UTF-8 and escaped Unicode, nested JSON');
