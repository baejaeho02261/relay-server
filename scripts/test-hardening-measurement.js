 'use strict';
const assert=require('node:assert/strict'),reports=require('../services/desktopIntegrityReports'),{PassThrough}=require('node:stream');
const parse=value=>reports.Payload(JSON.stringify(value));
const base={version:1,hashVersion:3,check:'MODULE_INVENTORY',reason:'PERIODIC',modules:[],snapshotId:'snap1',batchIndex:0,batchCount:1,complete:true,truncated:false,totalModules:0,measuredModules:0,measurementPlanVersion:1,measurementStartedTick:100,measurementFinishedTick:200,moduleGenerationStable:true,coverage:'FULL'};
assert.equal(parse(base).coverage,'FULL');
for(const patch of [{measurementStartedTick:201},{measurementFinishedTick:60101},{measurementPlanVersion:2},{moduleGenerationStable:false},{measuredModules:1},{truncated:true},{measurementStartedTick:1.5},{extraCritical:true}])assert.throws(()=>parse({...base,...patch}),undefined,JSON.stringify(patch));
for(const coverage of ['PARTIAL','SAMPLED']){const p=parse({...base,complete:false,moduleGenerationStable:false,coverage});assert.equal(p.coverage,coverage);assert.equal(p.complete,false);}
const {measurementPlanVersion,measurementStartedTick,measurementFinishedTick,moduleGenerationStable,coverage,...legacy}=base;assert.equal(parse(legacy).complete,true);assert.throws(()=>parse({...legacy,coverage:'FULL'}));
assert.equal(parse({...base,moduleGenerationStatus:'TRACKED_STABLE'}).moduleGenerationStatus,'TRACKED_STABLE');
for(const status of ['TRACKED_CHANGED','UNSUPPORTED','TRACKING_FAILED']){
 assert.throws(()=>parse({...base,moduleGenerationStatus:status}),/INTEGRITY_REPORT_INVALID/);
 assert.equal(parse({...base,complete:false,moduleGenerationStable:false,coverage:'PARTIAL',moduleGenerationStatus:status}).moduleGenerationStatus,status);
}
for(const status of [null,'TRACKED',true,{},''])assert.throws(()=>parse({...base,moduleGenerationStatus:status}),/INTEGRITY_REPORT_INVALID/);
assert.throws(()=>parse({...legacy,moduleGenerationStatus:'TRACKED_STABLE'}),/INTEGRITY_REPORT_INVALID/);
assert.throws(()=>parse({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'CANCELLED'},moduleGenerationStatus:'TRACKED_STABLE'}),/INTEGRITY_REPORT_INVALID/);
const threads={version:1,status:'COMPLETE',enumerated:3,knownImage:2,unknownStart:1,unreadable:0,truncated:false};
assert.deepEqual(parse({...base,threadInventory:threads}).threadInventory,threads);
for(const patch of [{version:2},{status:'SAFE'},{enumerated:4},{unreadable:1},{truncated:true},{knownImage:1025},{threadId:1},{unknownStart:-1}])assert.throws(()=>parse({...base,threadInventory:{...threads,...patch}}),/INTEGRITY_REPORT_INVALID/);
assert.equal(parse({...base,threadInventory:{...threads,status:'PARTIAL',enumerated:4,unreadable:1,truncated:true}}).threadInventory.status,'PARTIAL');
assert.equal(parse({...base,threadInventory:{version:1,status:'UNAVAILABLE',enumerated:0,knownImage:0,unknownStart:0,unreadable:0,truncated:false}}).threadInventory.status,'UNAVAILABLE');
assert.throws(()=>parse({...legacy,threadInventory:threads}),/INTEGRITY_REPORT_INVALID/);
const absentDevice={version:1,status:'NOT_REQUESTED',scope:'',algorithm:'BLAKE3-KEYED-256',diskCount:0,nicCount:0,digest:'',truncated:false};
assert.deepEqual(parse({...base,deviceSignals:absentDevice}).deviceSignals,absentDevice);
const device={...absentDevice,status:'MEASURED',scope:'a'.repeat(128),diskCount:1,nicCount:2,digest:'b'.repeat(64)};
assert.deepEqual(parse({...base,deviceSignals:device}).deviceSignals,device);
for(const patch of [{status:'SAFE'},{version:2},{algorithm:'SHA512'},{scope:'b'.repeat(64)},{diskCount:9},{nicCount:65},{diskCount:-1},{digest:'A'.repeat(64)},{truncated:true},{rawSerial:'PRIVATE'},{diskCount:0,nicCount:0},{status:'NOT_REQUESTED'},{status:'UNAVAILABLE'}])assert.throws(()=>parse({...base,deviceSignals:{...device,...patch}}),/INTEGRITY_REPORT_INVALID/);
assert.equal(parse({...base,deviceSignals:{...device,status:'PARTIAL',truncated:true}}).deviceSignals.status,'PARTIAL');
assert.equal(parse({...base,deviceSignals:{...absentDevice,status:'UNAVAILABLE',scope:'a'.repeat(128)}}).deviceSignals.status,'UNAVAILABLE');
assert.throws(()=>parse({...legacy,deviceSignals:absentDevice}),/INTEGRITY_REPORT_INVALID/);
console.log('PASS report bundle chronology, generation, coverage, strict fields and legacy compatibility');
(async()=>{
 const read=require('../web/routes/desktopBootstrapRoutes').ReadBytes;
 assert.equal(typeof read,'function');
 const request=new PassThrough(),pending=read(request,4);request.write(Buffer.from([1,2]));request.end(Buffer.from([3,4]));assert.deepEqual(await pending,Buffer.from([1,2,3,4]));
 const large=new PassThrough(),rejected=read(large,3);large.write(Buffer.from([1,2]));large.end(Buffer.from([3,4]));await assert.rejects(rejected,/BOOTSTRAP_ARTIFACT_TOO_LARGE/);
 const aborted=new PassThrough(),cancelled=read(aborted,32);aborted.emit('aborted');await assert.rejects(cancelled,/BOOTSTRAP_UPLOAD_ABORTED/);aborted.destroy();
 const failed=new PassThrough(),error=read(failed,32);failed.emit('error',Error('READ_FAULT'));await assert.rejects(error,/READ_FAULT/);failed.destroy();
 console.log('PASS stream-enforced byte cap across chunks, abort and read errors');
})().catch(error=>{console.error(error);process.exitCode=1;});
