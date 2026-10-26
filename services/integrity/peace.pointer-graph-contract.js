'use strict';
// Deterministic, address-free topology. The production expectation comes from
// the exact approved build contract; client-supplied counts are never a baseline.
const crypto = require('node:crypto');
const crc = require('../cryptography/peace.crc-layers');
const CONTRACT = 'COZY-POINTER-GRAPH-V1', MAX_NODES = 4096, MAX_EDGES = 4096, MAX_DEPTH = 16;
const plain = v => !!v && Object.getPrototypeOf(v) === Object.prototype;
function Require(ok) { if (!ok) throw Error('INTEGRITY_POINTER_GRAPH_INVALID'); }
function Integer(v, min, max) { return Number.isSafeInteger(v) && v >= min && v <= max; }
function Bytes(nodes, edges) {
 Require(Array.isArray(nodes) && nodes.length > 0 && nodes.length <= MAX_NODES && Array.isArray(edges) && edges.length <= MAX_EDGES);
 for (const [i,n] of nodes.entries()) Require(plain(n) && Object.keys(n).length===5 && n.id===i+1 && Integer(n.kind,1,16) && Integer(n.span,1,1048576) && Integer(n.generation,1,0xffffffff) && n.alive===true);
 const firstEdge=new Int32Array(nodes.length+1);
 for (const [i,e] of edges.entries()) {
  Require(plain(e) && Object.keys(e).length===4 && Integer(e.source,1,nodes.length) && Integer(e.target,1,nodes.length) && Integer(e.offset,0,0xffffffff) && [4,8].includes(e.width));
  firstEdge[e.source]++;
  Require(e.offset+e.width<=nodes[e.source-1].span && nodes[e.source-1].generation===nodes[e.target-1].generation);
  if(i) Require(edges[i-1].source<e.source || edges[i-1].source===e.source && edges[i-1].offset+edges[i-1].width<=e.offset);
 }
 for(let i=1;i<=nodes.length;i++)firstEdge[i]+=firstEdge[i-1];
 const colors=new Uint8Array(nodes.length), heights=new Uint32Array(nodes.length);let visited=0;
 function Visit(index,level) {
  Require(level<=MAX_DEPTH && colors[index]!==1);
  if(colors[index]===2){Require(level+heights[index]<=MAX_DEPTH);return heights[index];}
  colors[index]=1;visited++;let height=0;
  for(let e=firstEdge[index];e<firstEdge[index+1];e++)height=Math.max(height,1+Visit(edges[e].target-1,level+1));
  colors[index]=2;heights[index]=height;return height;
 }
 const depth=Visit(0,0);Require(visited===nodes.length);
 const prefix=Buffer.from(CONTRACT+'\0'),bytes=Buffer.alloc(prefix.length+12+nodes.length*20+edges.length*16);prefix.copy(bytes);let at=prefix.length;
 const put=v=>{bytes.writeUInt32LE(v,at);at+=4;};
 [nodes.length,edges.length,depth].forEach(put);
 for(const n of nodes)[n.id,n.kind,n.span,n.generation,1].forEach(put);
 for(const e of edges)[e.source,e.target,e.offset,e.width].forEach(put);
 return {bytes,depth};
}
function Shape(slots) {
 Require(Integer(slots,1,1024));const nodes=[],edges=[];
 const node=(id,kind,span)=>nodes.push({id,kind,span,generation:1,alive:true});
 const edge=(source,target,offset)=>edges.push({source,target,offset,width:8});
 node(1,1,slots*8);
 for(let i=0;i<slots;i++){node(2+3*i,2,16);node(3+3*i,3,8);node(4+3*i,4,1);edge(1,2+3*i,i*8);}
 for(let i=0;i<slots;i++){edge(2+3*i,3+3*i,0);edge(3+3*i,4+3*i,0);}
 return {nodes,edges};
}
function Expected(slots) {
 const {nodes,edges}=Shape(slots),{bytes,depth}=Bytes(nodes,edges);
 return {version:1,scope:'SEALED_API_ARENA',status:'MEASURED',slots,nodes:nodes.length,edges:edges.length,depth,sha512:crypto.createHash('sha512').update(bytes).digest('hex'),crc64:crc.crcHex('ecma182',bytes)};
}
function Validate(value) {
 if(!plain(value)||Object.keys(value).sort().join(',')!=='crc64,depth,edges,nodes,scope,sha512,slots,status,version'||value.version!==1||value.scope!=='SEALED_API_ARENA')return false;
 if(value.status==='FAILED')return value.slots===0&&value.nodes===0&&value.edges===0&&value.depth===0&&value.sha512===''&&value.crc64==='';
 return value.status==='MEASURED'&&Integer(value.slots,1,1024)&&value.nodes===1+3*value.slots&&value.edges===3*value.slots&&value.depth===3&&typeof value.sha512==='string'&&/^[a-f0-9]{128}$/.test(value.sha512)&&typeof value.crc64==='string'&&/^[A-F0-9]{16}$/.test(value.crc64);
}
function Compare(value, slots) {
 if(!Integer(slots,1,1024))return {matched:false,reason:'POINTER_GRAPH_BUILD_CONTRACT_REQUIRED'};
 if(!Validate(value)||value.status!=='MEASURED')return {matched:false,reason:'POINTER_GRAPH_INCOMPLETE'};
 const expected=Expected(slots),matched=Object.keys(expected).every(k=>value[k]===expected[k]);
 return {matched,reason:matched?'POINTER_GRAPH_MATCH':'POINTER_GRAPH_MISMATCH',scope:'SEALED_API_ARENA',attested:false};
}
module.exports={CONTRACT,MAX_NODES,MAX_EDGES,MAX_DEPTH,Bytes,Shape,Expected,Validate,Compare};
