'use strict';
// Opt-in caller-owned graph V2. No address probing and no implicit wire rollout.
// V1 SEALED_API_ARENA remains in peace.pointer-graph-contract.js unchanged.
const MAX_NODES=4096,MAX_EDGES=4096,MAX_DEPTH=16,MAX_U32=0xffffffff;
const CONTRACT='COZY-OWNED-POINTER-GRAPH-V2';
const nodeKeys=['id','kind','span','generation','ownerId','ownerGeneration','alive'];
const edgeKeys=['sourceId','sourceGeneration','targetId','targetGeneration','offset','width'];
function requireGraph(ok){if(!ok)throw new Error('OWN_POINTER_GRAPH_INVALID');}
function requireTransition(ok){if(!ok)throw new Error('OWN_POINTER_GRAPH_TRANSITION_INVALID');}
function exact(value,keys){requireGraph(value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k)));}
function u32(value,min=0,max=MAX_U32){requireGraph(Number.isInteger(value)&&value>=min&&value<=max);}
function revision(value){requireGraph(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value));const v=BigInt(value);requireGraph(v<=0xffffffffffffffffn);return v;}
function empty(){return {revision:'0',rootId:0,rootGeneration:0,nodes:[],edges:[]};}
function prepare(snapshot){
 exact(snapshot,['revision','rootId','rootGeneration','nodes','edges']);
 const rev=revision(snapshot.revision);requireGraph(rev>0n);u32(snapshot.rootId,1);u32(snapshot.rootGeneration,1);
 requireGraph(Array.isArray(snapshot.nodes)&&snapshot.nodes.length>0&&snapshot.nodes.length<=MAX_NODES&&Array.isArray(snapshot.edges)&&snapshot.edges.length<=MAX_EDGES);
 const nodes=snapshot.nodes.map(n=>{exact(n,nodeKeys);u32(n.id,1);u32(n.kind,1,16);u32(n.span,1,1048576);u32(n.generation,1);u32(n.ownerId);u32(n.ownerGeneration);requireGraph(typeof n.alive==='boolean');return {...n};}).sort((a,b)=>a.id-b.id);
 const edges=snapshot.edges.map(e=>{exact(e,edgeKeys);for(const k of edgeKeys)u32(e[k]);return {...e};}).sort((a,b)=>a.sourceId-b.sourceId||a.offset-b.offset);
 const byId=new Map(nodes.map(n=>[n.id,n]));requireGraph(byId.size===nodes.length);
 const root=byId.get(snapshot.rootId);requireGraph(root?.alive&&root.generation===snapshot.rootGeneration);
 let liveNodes=0,ownerDepth=0;
 for(const n of nodes){
  requireGraph(n.ownerId===0?n.ownerGeneration===0:n.ownerGeneration>0&&byId.has(n.ownerId));
  if(!n.alive)continue;
  liveNodes++;let cur=n,depth=0;
  while(cur.ownerId!==0){const owner=byId.get(cur.ownerId);requireGraph(owner?.alive&&owner.generation===cur.ownerGeneration);requireGraph(++depth<=MAX_DEPTH);cur=owner;}
  requireGraph(cur.id===root.id);ownerDepth=Math.max(ownerDepth,depth);
 }
 const outgoing=new Map();
 for(let i=0;i<edges.length;i++){
  const e=edges[i],source=byId.get(e.sourceId),target=byId.get(e.targetId);
  requireGraph(source?.alive&&target?.alive&&source.generation===e.sourceGeneration&&target.generation===e.targetGeneration);
  requireGraph((e.width===4||e.width===8)&&e.offset+e.width<=source.span);
  if(i&&edges[i-1].sourceId===e.sourceId)requireGraph(edges[i-1].offset+edges[i-1].width<=e.offset);
  if(!outgoing.has(e.sourceId))outgoing.set(e.sourceId,[]);outgoing.get(e.sourceId).push(e);
 }
 const seen=new Set([root.id]),queue=[root.id];
 for(let at=0;at<queue.length;at++)for(const e of outgoing.get(queue[at])||[])if(!seen.has(e.targetId)){seen.add(e.targetId);queue.push(e.targetId);}
 requireGraph(seen.size===liveNodes);
 return {snapshot:{revision:snapshot.revision,rootId:root.id,rootGeneration:root.generation,nodes,edges},rev,byId,outgoing,liveNodes,ownerDepth};
}
function bytes(snapshot){
 const p=prepare(snapshot),s=p.snapshot,prefix=Buffer.from(CONTRACT+'\0','ascii');
 const out=Buffer.alloc(prefix.length+28+s.nodes.length*28+s.edges.length*24);prefix.copy(out);let at=prefix.length;
 const put=v=>{out.writeUInt32LE(v,at);at+=4;};out.writeBigUInt64LE(p.rev,at);at+=8;
 put(s.rootId);put(s.rootGeneration);put(s.nodes.length);put(s.edges.length);put(p.ownerDepth);
 for(const n of s.nodes)for(const k of nodeKeys)put(k==='alive'?Number(n[k]):n[k]);
 for(const e of s.edges)for(const k of edgeKeys)put(e[k]);
 return {bytes:out,liveNodes:p.liveNodes,ownerDepth:p.ownerDepth};
}
function sameShape(a,b){return ['id','kind','span','ownerId','ownerGeneration'].every(k=>a[k]===b[k]);}
function sameOutgoing(a,b){return a.length===b.length&&a.every((e,i)=>edgeKeys.every(k=>e[k]===b[i][k]));}
function transition(previous,next,changes){
 const n=prepare(next);exact(previous,['revision','rootId','rootGeneration','nodes','edges']);const prevRev=revision(previous.revision);
 let p;
 if(prevRev===0n){requireTransition(previous.rootId===0&&previous.rootGeneration===0&&Array.isArray(previous.nodes)&&!previous.nodes.length&&Array.isArray(previous.edges)&&!previous.edges.length);p={rev:0n,byId:new Map(),outgoing:new Map()};}
 else {p=prepare(previous);requireTransition(previous.rootId===next.rootId);}
 requireTransition(n.rev===p.rev+1n);
 requireTransition(Array.isArray(changes)&&changes.length<=MAX_NODES);const actions=new Map(),used=new Set();
 for(const c of changes){exact(c,['nodeId','kind']);u32(c.nodeId,1);requireTransition(['REGISTER','RETIRE','REREGISTER','REBIND'].includes(c.kind)&&!actions.has(c.nodeId)&&n.byId.has(c.nodeId));actions.set(c.nodeId,c.kind);}
 const change=(id,kind)=>{requireTransition(actions.get(id)===kind);used.add(id);};
 for(const id of p.byId.keys())requireTransition(n.byId.has(id));
 for(const node of n.snapshot.nodes){
  const old=p.byId.get(node.id);
  if(!old){requireTransition(node.alive&&node.generation===1);change(node.id,'REGISTER');}
  else if(!old.alive){
   if(node.alive){requireTransition(old.generation<MAX_U32&&node.generation===old.generation+1);change(node.id,'REREGISTER');}
   else requireTransition(sameShape(old,node)&&node.generation===old.generation);
  }else{
   requireTransition(sameShape(old,node)&&node.generation===old.generation);
   if(!node.alive)change(node.id,'RETIRE');
   else if(!sameOutgoing(p.outgoing.get(node.id)||[],n.outgoing.get(node.id)||[]))change(node.id,'REBIND');
  }
 }
 requireTransition(used.size===actions.size);return n.snapshot;
}
class History{
 #snapshot=empty();
 accept(next,changes){const candidate=transition(this.#snapshot,next,changes);const result=bytes(candidate);this.#snapshot=candidate;return result;}
 capture(){return structuredClone(this.#snapshot);}
}
module.exports=Object.freeze({CONTRACT,MAX_NODES,MAX_EDGES,MAX_DEPTH,empty,bytes,transition,History});
