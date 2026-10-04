'use strict';
// Only unreferenced server deployment candidates, never client files, keys or logs.
const fs=require('node:fs');
const store=require('./desktopBootstrapStore');
const KEEP_MS=7*86400000;
let snapshot={asOf:0,pending:false,items:[],bytes:0},running;
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function References(db,id){
 const a=db.artifacts[id],reasons=[];if(!a)return reasons;
 if(Object.values(db.active).includes(id))reasons.push('현재 운영 A/B');
 // Keep even historical references: loader validation expects their artifact rows.
 if(Object.values(db.launchers).some(x=>x.artifactId===id))reasons.push('발급 A 이력');
 if(Object.values(db.flows).some(x=>x.releaseId===id))reasons.push('실행·다운로드 이력');
 const ops=db.securityOperations||{};
 if((ops.activations||[]).some(x=>['aId','bId','previousA','previousB'].some(k=>x[k]===id)))reasons.push('게시·되돌리기 이력');
 if(ops.contracts?.[a.component+':'+a.sha256])reasons.push('빌드 검사 규격');
 if(Object.values(ops.pairEvidence||{}).some(e=>e.aSha256===a.sha256||e.bSha256===a.sha256))reasons.push('시험 근거');
 if((ops.rollout?.artifactKeys||[]).includes(a.component+':'+a.sha256))reasons.push('시험 적용');
 const record=db.securityActivation;
 if(record&&JSON.stringify(record).includes(a.sha256))reasons.push('보호 활성화 기록');
 if(Date.now()-a.createdAt<KEEP_MS)reasons.push('최소 7일 보관');
 return [...new Set(reasons)];
}
async function Scan(){
 if(running)return running;
 snapshot={...snapshot,pending:true};
 running=(async()=>{
  const db=store.Load(),copy=structuredClone(db),items=[];let bytes=0;
  for(const a of Object.values(copy.artifacts)){
   const reasons=References(copy,a.id);let size=0,state='PRESENT';
   try{const st=await fs.promises.lstat(store.ArtifactPath(a.id));if(!st.isFile()||st.isSymbolicLink()){state='UNSAFE_PATH';reasons.push('일반 파일 아님');}else{size=st.size;bytes+=size;}}
   catch(e){state=e.code==='ENOENT'?'MISSING':'READ_ERROR';reasons.push(state==='MISSING'?'실제 파일 없음':'파일 조회 실패');}
   items.push({id:a.id,component:a.component,version:a.version,sha256:a.sha256,size,createdAt:a.createdAt,reasons,eligible:state==='PRESENT'&&!reasons.length,state});
  }
  snapshot={asOf:Date.now(),pending:false,bytes,items,scope:'SERVER_DEPLOYMENT_ARTIFACTS_ONLY',minimumRetentionDays:7};
  return snapshot;
 })().catch(e=>{snapshot={...snapshot,pending:false,error:e.desktopError?e.message:'WORKSPACE_STORAGE_SCAN_FAILED'};throw e;}).finally(()=>{running=undefined;});
 return running;
}
function Snapshot(){return structuredClone(snapshot);}
function Check(id,sha256){
 if(typeof id!=='string'||!/^(?:DA-)?[A-F0-9]{24}$/.test(id)||!/^[a-f0-9]{64}$/.test(sha256||''))Fail('INPUT_INVALID',400);
 const db=store.Load(),a=db.artifacts[id];
 if(!a||a.sha256!==sha256)Fail('WORKSPACE_CONFLICT');
 if(References(db,id).length)Fail('WORKSPACE_STORAGE_REFERENCED');
 return a;
}
function VerifyStored(id,size,sha256){
 let bytes;
 try{bytes=store.ReadBytes(id,size,sha256);}catch(error){if(error.code==='ENOENT')throw error;Fail('WORKSPACE_CONFLICT');}finally{bytes?.fill(0);}
}
function DeleteCandidate(id,sha256){
 const db=store.Load(),pending=db.workspaceGarbage?.[id];
 if(pending?.deletedAt){if(pending.sha256!==sha256)Fail('WORKSPACE_CONFLICT');return{id,deleted:true,bytes:pending.size};}
 if(!pending){
  const a=Check(id,sha256);VerifyStored(id,a.size,sha256);
  // Commit an unreferenced deletion intent before unlink. A restart can finish
  // that same item; it cannot cause an already referenced release to disappear.
  store.Atomic(next=>{if(References(next,id).length||next.artifacts[id]?.sha256!==sha256)Fail('WORKSPACE_STORAGE_REFERENCED');
   next.workspaceGarbage||={};next.workspaceGarbage[id]={sha256,size:a.size,createdAt:Date.now()};delete next.artifacts[id];});
 }
 const intent=store.Load().workspaceGarbage?.[id];if(!intent||intent.sha256!==sha256||store.Load().artifacts[id])Fail('WORKSPACE_CONFLICT');
 const file=store.ArtifactPath(id);
 try{
  VerifyStored(id,intent.size,sha256);
  const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink())Fail('WORKSPACE_CONFLICT');
  fs.unlinkSync(file);
 }catch(e){if(e.code!=='ENOENT')throw e;}
 store.Atomic(next=>{if(next.artifacts[id]||next.workspaceGarbage?.[id]?.sha256!==sha256)Fail('WORKSPACE_CONFLICT');next.workspaceGarbage[id].deletedAt=Date.now();});
 snapshot={...snapshot,asOf:0};return{id,deleted:true,bytes:intent.size};
}
module.exports={Scan,Snapshot,References,Check,DeleteCandidate};
