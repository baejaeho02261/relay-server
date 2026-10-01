'use strict';
// Check both valid UTF-8 JSON and escaped Unicode after the signed payload is
// embedded in the encrypted request. EAT evidence increases each module row.
const assert=require('node:assert/strict');
const row={name:'가'.repeat(64),status:'UNVERIFIED_BASELINE',codeStatus:'MATCH_LOCAL_FILE',fileSha256:'f'.repeat(64),fileCrc64:'F'.repeat(16),codeSha256:'a'.repeat(64),codeCrc64:'A'.repeat(16),executableSections:96,exportCount:131072,codeExportCount:131072,forwardedExportCount:131072,exportCoverage:'INVALID_EXPORT_TABLE',exportTableSha256:'b'.repeat(64),exportTableCrc64:'B'.repeat(16),exportTableStatus:'MEASURED'};
const sample={version:1,check:'MODULE_INVENTORY',reason:'BOOTSTRAP',snapshotId:'f'.repeat(36),batchIndex:102,batchCount:103,complete:true,truncated:false,totalModules:1024,measuredModules:1024,scope:'current-process',trust:'client-reported',modules:Array(10).fill(row)};
for(const escaped of [false,true]){
 let payload=JSON.stringify(sample);if(escaped)payload=payload.replace(/[^\x00-\x7f]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
 const request={operation:'report',body:{action:'submit',stage:'A',sessionId:'a'.repeat(24),sessionToken:'a'.repeat(43),machineId:'F'.repeat(64),binarySha256:'a'.repeat(64),binaryCrc64:'A'.repeat(16),codeSha256:'a'.repeat(64),codeCrc64:'A'.repeat(16),reportId:'a'.repeat(48),signature:'A'.repeat(344),payload}};
 assert.ok(Buffer.byteLength(payload)<=10240,'Signed payload exceeds its limit');
 assert.ok(Buffer.byteLength(JSON.stringify(request))<=12288,'Escaped encrypted-request body exceeds transport limit');
}
console.log('Native report wire budget PASS: ten EAT rows, UTF-8 and escaped Unicode, nested JSON');
