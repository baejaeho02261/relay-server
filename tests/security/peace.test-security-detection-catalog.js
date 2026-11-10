'use strict';
// Identity/provenance contract; this does not execute native Windows sensors.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const catalog=require('../../services/security/peace.security-detection-catalog');
const native=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW');
const allowedSuccess=new Set(['','POINTER_GRAPH_MATCH','RUNTIME_GRAPH_MATCH','CRC_BASELINE_MATCH','CRC_PARTIAL_COVERAGE']);
function covered(result){if(result?.reason&&!allowedSuccess.has(result.reason))assert.ok(catalog.Get(result.reason),'missing actual outcome '+result.reason);}
test('NHW wire IDs preserve all204 source enum ordinals without alias collapse',()=>{
 const text=fs.readFileSync(path.join(native,'Cozy.NHW.Logging.pas'),'utf8'),match=/TDetectionKind\s*=\s*\((.*?)\);/s.exec(text);assert.ok(match);
 const ids=match[1].match(/\bdk\w+\b/g);assert.equal(ids.length,204);assert.deepEqual(catalog.NHW.map(x=>x.id),ids);
 for(let n=0;n<ids.length;n++){assert.equal(catalog.ResolveNHWOrdinal(n),catalog.Get(ids[n]));assert.equal(catalog.NHW[n].ordinal,n);}
 for(const n of [-1,204,NaN,'1',1.5,Infinity])assert.equal(catalog.ResolveNHWOrdinal(n),null);
});
test('FP1 output taxonomy preserves 197 output states, 194 names and seven internal evidence kinds',()=>{
 assert.deepEqual(catalog.Counts,{nhw:204,cozy:122,nhwStandalone:197,nhwOutputNames:194,nhwInternalEvidence:7});
 assert.deepEqual(catalog.NHW.filter(x=>!x.standaloneOutput).map(x=>x.id),['dkNamespace','dkDeviceMap','dkAllocation','dkCommit','dkMemoryRelease','dkAllocationBurst','dkReadGap']);
 assert.deepEqual(catalog.NHW.filter(x=>x.displayName==='Waring Detect').map(x=>x.id),['dkETWLoss','dkCoverageGap','dkObservationUncertain','dkSensorPressure']);
 for(const row of catalog.COZY){assert.match(row.displayName,/ Detect$/);assert.equal(row.origin,'COZY');}
});
test('Every actual mitigation comparison failure has a classified server mapping',()=>{
 const compare=require('../../services/security/peace.desktop-mitigation-profiles').Check;
 const p={id:'a'.repeat(128),dynamicCode:'prohibit',strictHandles:true,imageLoadMask:3,requireCfg:true};
 const d={version:2,profileId:p.id,requestedMode:'prohibit',strictHandleQueried:true,strictHandleFlags:3,imageLoadQueried:true,imageLoadFlags:3,cfgQueried:true,cfgFlags:1,dynamicQueried:true,dynamicFlags:1};
 const outcomes=[compare(null,d),compare(p,undefined),compare(p,{...d,strictHandleQueried:false}),compare(p,{...d,imageLoadFlags:0}),compare(p,{...d,cfgFlags:0}),compare(p,{...d,dynamicFlags:0})];
 assert.equal(new Set(outcomes).size,6);for(const outcome of outcomes){const row=catalog.Get(outcome);assert.ok(row,outcome);assert.ok(row.sourceUnits.includes('peace.desktop-mitigation-profiles'));assert.equal(row.signalClass,outcome.endsWith('_UNAVAILABLE')?'UNKNOWN':'POLICY_REJECTION');}
 assert.equal(compare(p,d),'');
});
test('Privacy-safe source identity is fixed, immutable and cannot be user supplied free text',()=>{
 for(const row of [...catalog.NHW,...catalog.COZY]){assert.ok(Object.isFrozen(row));assert.ok(Object.isFrozen(row.sourceUnits));assert.ok(row.sourceUnits.length);assert.ok(row.sourceReferences.length);assert.match(row.id,/^(?:dk[A-Za-z0-9]+|[A-Z][A-Z0-9_]+)$/);for(const source of row.sourceUnits)assert.match(source,/^(?:Cozy\.NHW\.[A-Za-z0-9.]+|peace\.[a-z0-9.-]+)$/);}
 for(const id of ['__proto__','constructor','dkProcess\u0000','Process Detect','C:\\Users\\name',null,{},42])assert.equal(catalog.Get(id),null);
 assert.equal(new Set([...catalog.NHW,...catalog.COZY].map(x=>x.id)).size,catalog.NHW.length+catalog.COZY.length);
});
test('Unknown and local policy evidence cannot silently become a strong execution finding',()=>{
 for(const id of ['dkTraceGap','dkReadGap','dkETWLoss','dkCoverageGap','dkObservationUncertain','dkSensorPressure','dkKernelTelemetryGap']){assert.equal(catalog.Get(id).signalClass,'UNKNOWN');assert.equal(catalog.Get(id).strongExecutionCandidate,false);}
 for(const id of ['dkVulnerableDriver','dkKernelMappingEvidence','dkDriverSignerAttestation','dkDriverLoadProvenance','dkDriverServiceTimeline','dkCodeIntegrityPolicy'])assert.equal(catalog.Get(id).localOnlyKernelPolicy,true);
 const strong=catalog.NHW.filter(x=>x.strongExecutionCandidate).map(x=>x.id).sort();assert.deepEqual(strong,['dkInjectionEvidence','dkRemoteThread','dkPrivateThread','dkWriteIntegrity','dkImportRedirect','dkTLSCallbackIntegrity','dkImageCOWIntegrity','dkPECodeIntegrity'].sort());
 assert.equal(catalog.Get('INTEGRITY_SNAPSHOT_STALE').signalClass,'UNKNOWN');assert.equal(catalog.Get('DESKTOP_KEY_USED').signalClass,'POLICY_REJECTION');
});
test('Actual graph and CRC rejection outputs resolve through the registry',()=>{
 const graph=require('../../services/integrity/peace.pointer-graph-contract'),owned=require('../../services/integrity/peace.owned-runtime-graph-contract'),crc=require('../../services/runtime/peace.desktop-crc-policy');
 for(const value of [undefined,null,{},[],{status:'FAILED'},{status:'MEASURED'}])for(const slots of [undefined,0,1,218,269,265])covered(graph.Compare(value,slots));
 for(const value of [undefined,null,{},[],{status:'FAILED'},{status:'MEASURED',profile:'wrong'}])for(const role of ['A','B','O','?'])covered(owned.Compare(value,role));
 for(const a of [undefined,{},null])for(const b of [undefined,{},null])covered(crc.Compare(a,b));
 const status=require('../../services/integrity/peace.measurement-status');for(const state of status.failures)covered({reason:status.FailureReason(state)});
});
test('All catalog producer references resolve to actual source files with the identifier',()=>{
 const server=path.resolve(__dirname,'../..'),railway=path.resolve(server,'../Railway');
 for(const row of catalog.NHW){assert.ok(row.sourceUnits.includes('Cozy.NHW.Engine'));assert.ok(row.sourceUnits.includes('Cozy.NHW.KernelTrust'));for(const ref of row.sourceReferences){const text=fs.readFileSync(path.join(railway,ref.path),'utf8');assert.ok(new RegExp('\\b'+row.id+'\\b').test(text),row.id+' '+ref.path);}}
 for(const row of catalog.COZY){const matches=row.sourceReferences.some(ref=>fs.readFileSync(path.join(server,ref.path),'utf8').includes(row.id));assert.ok(matches||row.id==='MEASUREMENT_GENERATION_UNSUPPORTED'||row.id==='MEASUREMENT_GENERATION_TRACKING_FAILED',row.id);}
});
