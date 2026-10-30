'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const g=require('../../services/integrity/peace.pointer-graph-contract');
const plan=require('../../services/integrity/peace.measurement-plan-contract');
const {Isolated}=require('../fixtures/protocol/peace.completion-6-10-fixture');
test('canonical multi-slot hierarchy has the exact independent Native golden vector',()=>{
 const value=g.Expected(2);assert.equal(value.nodes,7);assert.equal(value.edges,6);assert.equal(value.depth,3);
 assert.equal(value.sha512,'449c0dc31917d686056c206d2d00d5bdeddc2fae66ccd296f2215cfd9f1175cb58014dfbbe2c1f8b4128d46fa714dd323c1c456d4c78b7250a64b4ccb71ec185');
 assert.equal(value.crc64,'BAE913D72444431A');assert.equal(g.Compare(value,2).matched,true);
});
test('single and maximum approved arenas are bounded and distinct',()=>{
 assert.notEqual(g.Expected(1).sha512,g.Expected(1024).sha512);
 for(const n of [0,-1,1025,1.5,NaN,Infinity,'2'])assert.throws(()=>g.Shape(n));
});
for(const [name,change]of [
 ['stale generation',s=>s.nodes[2].generation++],['retired owner',s=>s.nodes[1].alive=false],
 ['wrong ID',s=>s.nodes[1].id=3],['zero span',s=>s.nodes[0].span=0],['oversized span',s=>s.nodes[0].span=1048577],
 ['unknown target',s=>s.edges[0].target=100],['unknown source',s=>s.edges[0].source=0],
 ['overflowing offset',s=>s.edges[0].offset=0xffffffff],['overlap',s=>s.edges[1].offset=4],
 ['wrong width',s=>s.edges[0].width=16],['cycle',s=>s.edges.at(-1).target=1],
 ['unreachable node',s=>s.edges.pop()],['unknown address field',s=>s.nodes[0].address=0x1000],
 ['noncanonical edge order',s=>s.edges.reverse()]
])test('rejects '+name,()=>{const shape=g.Shape(2);change(shape);assert.throws(()=>g.Bytes(shape.nodes,shape.edges),/POINTER_GRAPH_INVALID/);});
test('explicit ordinary/shared pointer DAGs accepted, deep hierarchy denied',()=>{
 const nodes=Array.from({length:4},(_,i)=>({id:i+1,kind:1,span:16,generation:7,alive:true}));
 const edges=[{source:1,target:2,offset:0,width:8},{source:1,target:3,offset:8,width:8},{source:2,target:4,offset:0,width:4},{source:3,target:4,offset:0,width:4}];
 assert.equal(g.Bytes(nodes,edges).depth,2);
 const deep=Array.from({length:18},(_,i)=>({id:i+1,kind:1,span:8,generation:1,alive:true}));
 assert.throws(()=>g.Bytes(deep,deep.slice(1).map((n,i)=>({source:i+1,target:n.id,offset:0,width:8}))),/POINTER_GRAPH_INVALID/);
});
test('approved count, not claimed count, selects expected topology',()=>{
 const valid=g.Expected(2);assert.equal(g.Compare(valid,undefined).matched,false);assert.equal(g.Compare(valid,3).matched,false);
 for(const field of ['sha512','crc64']){const bad={...valid,[field]:valid[field].replace(/^./,valid[field][0]==='A'?'B':'A')};assert.equal(g.Compare(bad,2).matched,false);}
 for(const extra of [{address:'0x1234'},{attested:true},{scope:'ALL_PROCESS_MEMORY'}])assert.equal(g.Validate({...valid,...extra}),false);
});
test('only an exact server build contract permits graph comparison',()=>{
 const artifact={component:'B',sha512:'a'.repeat(128),ownMeasurementVersion:2};
 const db={securityOperations:undefined};
 const operations=Isolated('services/security/peace.desktop-security-operations.js',[],{'../bootstrap/peace.desktop-bootstrap-store':{Load:()=>db}});
 db.securityOperations=operations.Defaults();
 const key=operations.BuildKey(artifact);
 assert.equal(operations.PointerGraphSlots(artifact),0);
 // State validates stored contracts; use the normal full contract shape.
 db.securityOperations.contracts[key]={version:1,evidenceVersion:1,minApiSlots:2,maxApiSlots:2,requiredChecks:['ownImage','apiStorage','mitigations']};
 assert.equal(operations.PointerGraphSlots(artifact),2);
 assert.equal(operations.PointerGraphSlots({...artifact,ownMeasurementVersion:3}),2);
 db.securityOperations.contracts[key].maxApiSlots=3;assert.equal(operations.PointerGraphSlots(artifact),0);
 assert.equal(operations.PointerGraphSlots({...artifact,sha512:'b'.repeat(128)}),0);
 assert.equal(operations.PointerGraphSlots({...artifact,component:'A'}),0);
 assert.equal(operations.PointerGraphSlots({...artifact,ownMeasurementVersion:1}),0);
});
test('capability downgrade and module-inventory own-image bypass are rejected',()=>{
 const artifact={ownMeasurementVersion:2},payload={check:'MODULE_INVENTORY',own:{status:'MEASURED'}};
 assert.equal(plan.GraphReason(payload,artifact,2),'POINTER_GRAPH_REQUIRED');
 payload.ownMeasurement={version:1};assert.equal(plan.GraphReason(payload,artifact,2),'POINTER_GRAPH_REQUIRED');
 payload.ownMeasurement={version:2,pointerGraph:g.Expected(2)};assert.equal(plan.GraphReason(payload,artifact,2),'');
 assert.equal(plan.GraphReason(payload,artifact,3),'POINTER_GRAPH_MISMATCH');
 assert.equal(plan.GraphReason(payload,{ownMeasurementVersion:1},2),'');
});
