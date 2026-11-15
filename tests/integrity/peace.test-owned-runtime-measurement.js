'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const runtime=require('../../services/integrity/peace.owned-runtime-graph-contract');
const plan=require('../../services/integrity/peace.measurement-plan-contract');
const graph=require('../../services/integrity/peace.pointer-graph-contract');
const fixture=require('../fixtures/integrity/peace.owned-runtime-graph-fixture');
const baseline=require('../../services/integrity/peace.desktop-integrity').CodeImage(require('../fixtures/runtime/peace.crc-test-fixture').crcTestFixture());
const schema=require('../../services/protocol/peace.packet-schema');
function Meta(version=3){const m={contract:version===3?plan.OWN_RUNTIME_CONTRACT:plan.OWN_GRAPH_CONTRACT,version,startedTick:1,finishedTick:10,coverage:'FULL',fileStatus:'MEASURED',codeStatus:'MEASURED',crcStatus:'MEASURED',imageStable:true,pointerGraph:graph.Expected(2)};if(version===3)m.ownedGraph=fixture.Graph();return m;}
function Authority(meta){return {version:1,hashVersion:3,measurement:'MEASURED',fileSha512:'a'.repeat(128),fileCrc64:'A'.repeat(16),codeSha512:baseline.sha512,codeCrc64:baseline.crc64,codeXxh3_128:baseline.xxh3_128,codeBlake3:baseline.blake3,crcLayers:baseline.crcLayers,apiSealed:true,apiSlots:2,dynamicCode:'ALLOWED',cfg:'ENABLED',ownMeasurement:meta};}
test('fixed application profiles use independently encoded canonical bytes and remain under authority cap',()=>{
 const expected=fixture.Graph();assert.equal(expected.sha512,'e1d72941e397846f364c44ee668a58f225b8e1bc44e531b7169e64f843b38ac1db4abcfad786710a31e23c096f5808573fe3fcba8e93f69446812a05df8003ed');assert.equal(expected.crc64,'611197839D600374');
 for(const [role,profile]of Object.entries(runtime.PROFILES)){const value=fixture.Graph(profile);assert.equal(runtime.Validate(value),true);assert.equal(runtime.Compare(value,role).matched,true);assert.equal(runtime.Compare(value).matched,false);for(const other of Object.keys(runtime.PROFILES).filter(r=>r!==role))assert.equal(runtime.Compare(value,other).matched,false);}
 const meta=Meta();assert.equal(plan.ValidateOwnMetadata(meta,'MEASURED',baseline.crcLayers),true);schema.ValidateDocument('authorityPayload',Authority(meta));assert.ok(Buffer.byteLength(JSON.stringify(Authority(meta)))<16384);
});
test('canonical snapshots may reorder records but cannot change between before and after',()=>{
 const value=fixture.Graph();value.after.nodes.reverse();value.after.edges.reverse();assert.equal(runtime.Validate(value),true);
 value.after.revision='2';assert.equal(runtime.Validate(value),false);
});
for(const [label,edit]of [
 ['unregistered field',v=>v.address='0x1234'],['node address',v=>v.before.nodes[0].address=1234],['unknown profile',v=>v.profile='CUSTOM'],['wrong root',v=>v.before.rootId=2],['root retired',v=>v.before.nodes[0].alive=false],['child retired',v=>v.before.nodes[2].alive=false],['stale owner generation',v=>v.before.nodes[2].ownerGeneration=2],['wrong borrowed slot kind',v=>v.before.nodes[3].kind=9],['wrong child span',v=>v.before.nodes[3].span=16],['hidden node',v=>v.before.nodes.push({...v.before.nodes[5],id:7})],['bad edge target generation',v=>v.before.edges[0].targetGeneration=2],['missing binding',v=>v.before.edges.pop()],['overlapping cell',v=>v.before.edges[1].offset=0],['offset overflow',v=>v.before.edges[0].offset=0xffffffff],['claimed transition',v=>v.changes.push({nodeId:2,kind:'REBIND'})],['noncanonical revision',v=>v.before.revision='01'],['unsafe revision type',v=>v.before.revision=1],['uint64 overflow',v=>v.before.revision='18446744073709551616'],['changed SHA',v=>v.sha512='0'.repeat(128)],['changed CRC',v=>v.crc64='0'.repeat(16)],['false stable',v=>v.stable=false],['false reason',v=>v.reason='RUNTIME_GRAPH_CHANGED']
])test('rejects '+label,()=>{const value=fixture.Graph();edit(value);assert.equal(runtime.Validate(value),false);});
test('matching hashes do not permit unreviewed shape or ownership',()=>{for(const edit of [v=>v.before.nodes[2].span=16,v=>v.before.nodes[2].kind=10,v=>v.before.nodes[2].ownerId=2]){const v=fixture.Graph();edit(v);v.after=structuredClone(v.before);fixture.Seal(v);assert.equal(runtime.Validate(v),false);}});
test('generation reuse checks remain local to explicit lifecycle and no cross-report replay assertion is made',()=>{const v=fixture.Graph();v.before.nodes[2].generation=2;v.before.edges[1].targetGeneration=2;v.after=structuredClone(v.before);fixture.Seal(v);assert.equal(runtime.Validate(v),true);});
for(const reason of runtime.REASONS.filter(r=>r!=='STABLE'))test('failed '+reason+' has no usable snapshot/hash',()=>{const v=fixture.Failed(reason);assert.equal(runtime.Validate(v),true);assert.equal(runtime.Compare(v,'B').matched,false);for(const edit of [v=>v.before=fixture.Snapshot(),v=>v.after=fixture.Snapshot(),v=>v.sha512='a'.repeat(128),v=>v.crc64='A'.repeat(16),v=>v.stable=true,v=>v.changes=[{nodeId:2,kind:'RETIRE'}]]){const bad=structuredClone(v);edit(bad);assert.equal(runtime.Validate(bad),false);}});
test('artifact V3 requires V3 and expected role profile; legacy V2 unchanged',()=>{
 const payload={own:{status:'MEASURED'},ownMeasurement:Meta()};assert.equal(plan.GraphReason(payload,{component:'B',ownMeasurementVersion:3},2),'');
 assert.equal(plan.GraphReason(payload,{component:'A',ownMeasurementVersion:3},2),'RUNTIME_GRAPH_PROFILE_MISMATCH');
 for(const meta of [undefined,Meta(2),{version:1}])assert.equal(plan.GraphReason({...payload,ownMeasurement:meta},{component:'B',ownMeasurementVersion:3},2),'RUNTIME_GRAPH_REQUIRED');
 const v2=Meta(2);assert.equal(plan.ValidateOwnMetadata(v2,'MEASURED',baseline.crcLayers),true);assert.equal(plan.GraphReason({...payload,ownMeasurement:v2},{ownMeasurementVersion:2},2),'');
 const failed=Meta();failed.ownedGraph=fixture.Failed('CANCELLED');assert.equal(plan.ValidateOwnMetadata(failed,'MEASURED',baseline.crcLayers),false);Object.assign(failed,{coverage:'PARTIAL',codeStatus:'CANCELLED',imageStable:false});assert.equal(plan.ValidateOwnMetadata(failed,'CANCELLED',baseline.crcLayers),true);
 const extra=Meta(2);extra.ownedGraph=fixture.Graph();assert.equal(plan.ValidateOwnMetadata(extra,'MEASURED',baseline.crcLayers),false);
});
test('shared protocol schema accepts failed null snapshots and rejects extra or excessive owned fields',()=>{
 const value=Authority(Meta());value.measurement='CANCELLED';for(const k of ['fileSha512','fileCrc64','codeSha512','codeCrc64','codeXxh3_128','codeBlake3'])value[k]='';value.ownMeasurement.ownedGraph=fixture.Failed('CANCELLED');Object.assign(value.ownMeasurement,{coverage:'PARTIAL',fileStatus:'CANCELLED',imageStable:false});schema.ValidateDocument('authorityPayload',value);
 for(const edit of [v=>v.ownMeasurement.ownedGraph.address=1,v=>v.ownMeasurement.ownedGraph.before=fixture.Snapshot(),v=>v.ownMeasurement.ownedGraph.changes=[{}]]){const bad=structuredClone(value);edit(bad);assert.throws(()=>schema.ValidateDocument('authorityPayload',bad));}
});
test('approved PE capability binds V3 and ignores appended overlay declarations',()=>{const pe=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture').PE('A','plain');assert.equal(plan.ArtifactOwnVersion(Buffer.concat([pe,Buffer.from(plan.OWN_RUNTIME_CONTRACT)])),0);Buffer.from(plan.OWN_RUNTIME_CONTRACT,'utf16le').copy(pe,600);assert.equal(plan.ArtifactOwnVersion(pe),3);});

test('missing registered context is only a failed unavailable profile',()=>{assert.equal(runtime.Validate(fixture.Failed('RUNTIME_GRAPH_REQUIRED','UNAVAILABLE')),true);const measured=fixture.Graph();measured.profile='UNAVAILABLE';assert.equal(runtime.Validate(measured),false);});

test('partial V3 bundle cannot retain a measured runtime snapshot',()=>{for(const status of ['NOT_MEASURED','READ_ERROR','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED']){const meta=Meta();Object.assign(meta,{coverage:'PARTIAL',fileStatus:status,imageStable:false});assert.equal(plan.ValidateOwnMetadata(meta,status,baseline.crcLayers),false);meta.ownedGraph=fixture.Failed('MEASUREMENT_FAILED');assert.equal(plan.ValidateOwnMetadata(meta,status,baseline.crcLayers),true);}});
test('production first dependency binding has revision2 native golden bytes',()=>{const v=fixture.Graph();v.before.revision='2';v.after.revision='2';fixture.Seal(v);assert.equal(v.sha512,'f251551fa1ef4ff100a02bc9961f7d1c5e779173cd7e3841b5d9dac6a4053e69c99341261394d41bb63662f705bb02d53187d00a3a3b3f36a2a0a0fcdea6d893');assert.equal(v.crc64,'5164BB6162E7F72A');assert.equal(runtime.Validate(v),true);});
