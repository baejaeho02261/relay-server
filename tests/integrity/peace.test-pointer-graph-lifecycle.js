'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const v2=require('../../services/integrity/peace.pointer-graph-lifecycle');
const v1=require('../../services/integrity/peace.pointer-graph-contract');
function sample(){return {revision:'1',rootId:10,rootGeneration:1,nodes:[
 {id:10,kind:1,span:16,generation:1,ownerId:0,ownerGeneration:0,alive:true},
 {id:20,kind:2,span:16,generation:1,ownerId:10,ownerGeneration:1,alive:true},
 {id:30,kind:3,span:8,generation:1,ownerId:20,ownerGeneration:1,alive:true}
],edges:[
 {sourceId:10,sourceGeneration:1,targetId:20,targetGeneration:1,offset:0,width:8},
 {sourceId:20,sourceGeneration:1,targetId:30,targetGeneration:1,offset:0,width:8},
 {sourceId:30,sourceGeneration:1,targetId:10,targetGeneration:1,offset:0,width:8}
]};}
const changes=(kind,ids)=>ids.map(nodeId=>({nodeId,kind}));
function retire(s=sample()){
 const n=structuredClone(s);n.revision='2';n.nodes[1].alive=false;n.nodes[2].alive=false;n.edges=[];return n;
}
function revive(s=retire()){
 const n=sample();n.revision='3';n.nodes[1].generation=2;n.nodes[2].generation=2;n.nodes[2].ownerGeneration=2;
 for(const e of n.edges){if(e.sourceId!==10)e.sourceGeneration=2;if(e.targetId!==10)e.targetGeneration=2;}return n;
}
function initial(history){history.accept(sample(),changes('REGISTER',[10,20,30]));}
const retirement=[...changes('RETIRE',[20,30]),...changes('REBIND',[10])];
const revival=[...changes('REREGISTER',[20,30]),...changes('REBIND',[10])];
test('V1 bytes and cycle rejection remain unchanged',()=>{
 assert.equal(v1.Expected(2).sha512,'449c0dc31917d686056c206d2d00d5bdeddc2fae66ccd296f2215cfd9f1175cb58014dfbbe2c1f8b4128d46fa714dd323c1c456d4c78b7250a64b4ccb71ec185');
 const s=v1.Shape(2);s.edges.at(-1).target=1;assert.throws(()=>v1.Bytes(s.nodes,s.edges));
});
test('V2 permits explicit cycle and canonicalizes caller array order',()=>{
 const s=sample(),a=v2.bytes(s);s.nodes.reverse();s.edges.reverse();const b=v2.bytes(s);
 assert.deepEqual(a,b);assert.equal(a.liveNodes,3);assert.equal(a.ownerDepth,2);assert.equal(a.bytes.length,212);
 assert.equal(crypto.createHash('sha512').update(a.bytes).digest('hex'),'791f959e21cb8ce89c48c3bc6adc438ad45e987f7a2e9ef4c08fa74aeb9d799ba85b56cf5c9570342b8a1b8a63c5d809f05349f028656a84fd4348e67c6b4622');
});
test('golden with maximum uint64 revision is deterministic',()=>{
 const s=sample();s.revision='18446744073709551615';assert.equal(v2.bytes(s).bytes.readBigUInt64LE(Buffer.byteLength(v2.CONTRACT)+1),0xffffffffffffffffn);
 const n=structuredClone(s);assert.throws(()=>v2.transition(s,n,[]));
});
for(const [label,change]of [
 ['duplicate stable ID',s=>s.nodes[1].id=10],['unknown address property',s=>s.nodes[0].address=4096],
 ['unknown endpoint',s=>s.edges[0].targetId=99],['stale target generation',s=>s.edges[0].targetGeneration=2],
 ['stale source generation',s=>s.edges[0].sourceGeneration=2],['retired owner',s=>s.nodes[1].alive=false],
 ['stale owner generation',s=>s.nodes[2].ownerGeneration=2],['owner cycle',s=>{s.nodes[0].ownerId=30;s.nodes[0].ownerGeneration=1;}],
 ['unreachable live node',s=>s.edges.splice(1,1)],['overlapping slots',s=>s.edges.push({...s.edges[0],offset:4})],
 ['overflow slot',s=>s.edges[0].offset=0xffffffff],['bad pointer width',s=>s.edges[0].width=16],
 ['invalid revision',s=>s.revision='01'],['unsafe revision number',s=>s.revision=1],
 ['invalid boolean',s=>s.nodes[0].alive=1],['zero root',s=>s.rootId=0]
])test('invalid graph rejected: '+label,()=>{const s=sample();change(s);assert.throws(()=>v2.bytes(s),/OWN_POINTER_GRAPH_INVALID/);});
test('explicit register, retire and generation+1 reregister accepted',()=>{
 const h=new v2.History();initial(h);h.accept(retire(),retirement);h.accept(revive(),revival);
 assert.equal(h.capture().revision,'3');assert.equal(h.capture().nodes[1].generation,2);
});
test('unannounced and redundant events rejected with atomic state retained',()=>{
 const h=new v2.History();assert.throws(()=>h.accept(sample(),[]));initial(h);
 assert.throws(()=>h.accept(retire(),changes('RETIRE',[20,30])));
 assert.equal(h.capture().revision,'1');const noChange=sample();noChange.revision='2';
 assert.throws(()=>h.accept(noChange,changes('REBIND',[10])));h.accept(noChange,[]);assert.equal(h.capture().revision,'2');
});
for(const [label,change,actions]of [
 ['dropped tombstone',s=>s.nodes.pop(),retirement],
 ['live generation increase',s=>{s.nodes[1].generation=2;for(const e of s.edges){if(e.sourceId===20)e.sourceGeneration=2;if(e.targetId===20)e.targetGeneration=2;}s.nodes[2].ownerGeneration=2;},changes('REREGISTER',[20])],
 ['live owner reassignment',s=>{s.nodes[2].ownerId=10;s.nodes[2].ownerGeneration=1;},changes('REBIND',[30])],
 ['revision skip',s=>s.revision='3',[]],
 ['root replacement',s=>{s.rootId=20;s.nodes[0].ownerId=20;s.nodes[0].ownerGeneration=1;s.nodes[1].ownerId=0;s.nodes[1].ownerGeneration=0;},changes('REBIND',[10,20])]
])test('invalid transition rejected: '+label,()=>{
 const h=new v2.History();initial(h);const n=sample();n.revision='2';change(n);assert.throws(()=>h.accept(n,actions));assert.equal(h.capture().revision,'1');
});
test('retired IDs cannot disappear or reuse old generation, even after idle revision',()=>{
 const h=new v2.History();initial(h);h.accept(retire(),retirement);const idle=h.capture();idle.revision='3';h.accept(idle,[]);
 const lost=h.capture();lost.revision='4';lost.nodes=lost.nodes.filter(n=>n.alive);assert.throws(()=>h.accept(lost,[]));
 const stale=sample();stale.revision='4';assert.throws(()=>h.accept(stale,revival));
 const good=revive();good.revision='4';h.accept(good,revival);assert.equal(h.capture().nodes[1].generation,2);
});
test('input and output snapshots cannot mutate retained history',()=>{
 const s=sample(),h=new v2.History();h.accept(s,changes('REGISTER',[10,20,30]));s.nodes[0].generation=50;s.edges.length=0;
 const returned=h.capture();returned.nodes[0].alive=false;returned.edges.length=0;
 assert.equal(h.capture().nodes[0].generation,1);assert.equal(h.capture().nodes[0].alive,true);assert.equal(h.capture().edges.length,3);
});
test('bounded maximum cyclic graph and tombstone history retain cap',()=>{
 const count=4096,s={revision:'1',rootId:1,rootGeneration:1,nodes:[],edges:[]};
 for(let i=1;i<=count;i++){s.nodes.push({id:i,kind:1,span:8,generation:1,ownerId:i===1?0:1,ownerGeneration:i===1?0:1,alive:true});s.edges.push({sourceId:i,sourceGeneration:1,targetId:i===count?1:i+1,targetGeneration:1,offset:0,width:8});}
 assert.equal(v2.bytes(s).liveNodes,count);s.nodes.push({...s.nodes[0],id:4097});assert.throws(()=>v2.bytes(s));
});
test('owner hierarchy cap is separate from permitted reference cycles',()=>{
 const s=sample();s.nodes=[];s.edges=[];s.rootId=1;
 for(let i=1;i<=18;i++){s.nodes.push({id:i,kind:1,span:8,generation:1,ownerId:i-1,ownerGeneration:i===1?0:1,alive:true});if(i>1)s.edges.push({sourceId:i-1,sourceGeneration:1,targetId:i,targetGeneration:1,offset:0,width:8});}
 assert.throws(()=>v2.bytes(s));s.nodes.pop();s.edges.pop();assert.equal(v2.bytes(s).ownerDepth,16);
});
