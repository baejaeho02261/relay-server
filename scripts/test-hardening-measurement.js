 'use strict';
const assert=require('node:assert/strict'),reports=require('../services/desktopIntegrityReports'),{PassThrough}=require('node:stream');
const parse=value=>reports.Payload(JSON.stringify(value));
const base={version:1,hashVersion:3,check:'MODULE_INVENTORY',reason:'PERIODIC',modules:[],snapshotId:'snap1',batchIndex:0,batchCount:1,complete:true,truncated:false,totalModules:0,measuredModules:0,measurementPlanVersion:1,measurementStartedTick:100,measurementFinishedTick:200,moduleGenerationStable:true,coverage:'FULL'};
assert.equal(parse(base).coverage,'FULL');
for(const patch of [{measurementStartedTick:201},{measurementFinishedTick:60101},{measurementPlanVersion:2},{moduleGenerationStable:false},{measuredModules:1},{truncated:true},{measurementStartedTick:1.5},{extraCritical:true}])assert.throws(()=>parse({...base,...patch}),undefined,JSON.stringify(patch));
for(const coverage of ['PARTIAL','SAMPLED']){const p=parse({...base,complete:false,moduleGenerationStable:false,coverage});assert.equal(p.coverage,coverage);assert.equal(p.complete,false);}
const {measurementPlanVersion,measurementStartedTick,measurementFinishedTick,moduleGenerationStable,coverage,...legacy}=base;assert.equal(parse(legacy).complete,true);assert.throws(()=>parse({...legacy,coverage:'FULL'}));
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
