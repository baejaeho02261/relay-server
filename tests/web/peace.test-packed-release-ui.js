'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'../..'),source=fs.readFileSync(path.join(root,'public/scripts/desktop/peace.admin-desktop-packed-release.js'),'utf8');
const base='/api/desktop/bootstrap/security-operations',jobId='1'.repeat(32),oldId='a'.repeat(128),newId='b'.repeat(128),roles=['A','B','O'];
const sha=value=>crypto.createHash('sha512').update(value).digest('hex'),turn=()=>new Promise(resolve=>setImmediate(resolve));
function Binary(role,changed=false){const bytes=Buffer.alloc(1024,role.charCodeAt(0));if(changed)bytes[511]^=1;return {name:role+'-packed-unapproved.exe',size:bytes.length,arrayBuffer:async()=>Uint8Array.from(bytes).buffer};}
function Approval(role,{version='2.0.1',hash=sha(Buffer.alloc(1024,role.charCodeAt(0))),component=role,privateKey=false}={}){
 const text=privateKey?'-----BEGIN PRIVATE KEY-----':JSON.stringify({component,version,sha512:hash,approval:{keyId:'c'.repeat(64),signature:'A'.repeat(86)+'=='}});
 return {name:role+'.approval.json',size:Buffer.byteLength(text),text:async()=>text};
}
function Job(){return {jobId,createdAt:123,sourceManifestId:oldId,sourceReleaseName:'original',available:true,outputs:Object.fromEntries(roles.map(role=>[role,{sha512:sha(Buffer.alloc(1024,role.charCodeAt(0))),size:1024,sourceArtifactId:role.repeat(24),sourceVersion:'1.0.0'}]))};}
function Fixture(options={}){
 const job=Job(),elements={},calls=[],downloads=[];let close,done,rootNode,modal,invalidations=0,openedPair=null,uploadCount=0;
 const plan={ok:true,jobId,sourceManifestId:oldId,manifestId:options.oldPlan?oldId:newId,manifest:{artifacts:Object.fromEntries(roles.map(role=>[role,job.outputs[role].sha512]))},registration:'PLANNED'};
 if(options.badPlanHash)plan.manifest.artifacts.O='d'.repeat(128);
 let getCount=0;
 const ctx={session:{csrf:'owner'},roleIsAdmin:()=>!!ctx.session,desktopBootstrap:{limits:{maxArtifactBytes:67108864}},crypto:crypto.webcrypto,URLSearchParams,
  esc:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),
  document:{getElementById:()=>rootNode},desktopWorkflowDownload(name,value){downloads.push({name,value:structuredClone(value)});},
  desktopInvalidatePanels(){invalidations++;},showDesktopSecurityOperations:async value=>{openedPair=structuredClone(value);},modalCancel:{click:()=>close()},
  openModal(value){modal=value;for(const match of value.html.matchAll(/id="([^"]+)"/g))elements[match[1]]={value:'',files:[],textContent:'',dataset:{},hidden:value.html.includes('id="'+match[1]+'" hidden'),disabled:false};
   rootNode={isConnected:true,querySelector(selector){return elements[selector.slice(1)];},querySelectorAll(){return Object.values(elements);},replaceChildren(){this.empty=true;}};
   return new Promise(resolve=>{close=()=>{rootNode.isConnected=false;resolve(null);};});},
  api:async(url,opt)=>{
   const record={url,method:opt?.method||'GET',body:opt?.body?structuredClone(opt.body):undefined,rawBody:opt?.rawBody,headers:opt?.headers};calls.push(record);
   if(url===base+'/packed-release-jobs'){getCount++;return {ok:true,jobs:options.noJobs?[]:[structuredClone(job)],expectedRevision:getCount===1?3:5,expectedPolicyRevision:7};}
   if(url===base+'/plan-packed-release')return structuredClone(plan);
   if(url.startsWith('/api/desktop/bootstrap/artifacts?')){
    uploadCount++;const query=new URL(url,'https://example.invalid').searchParams,role=query.get('component');
    if(options.uploadHook)await options.uploadHook(role,ctx);
    if(options.failRole===role)throw new TypeError('connection lost');
    return {ok:true,artifact:{id:role.repeat(24),component:role,sha512:job.outputs[role].sha512,deploymentManifestId:options.wrongCandidate?oldId:newId}};
   }
   if(url===base)return {ok:true,operations:{revision:9}};
   if(url===base+'/release-manifests')return {ok:true};
   throw Error('unexpected request '+url);
  }
 };
 vm.createContext(ctx);vm.runInContext(source+'\nglobalThis.run=showDesktopPackedRelease;globalThis.prepare=desktopPackedReleaseInputs;',ctx);
 function fill(){for(const role of roles){elements['desktop-packed-exe-'+role].files=[Binary(role)];elements['desktop-packed-approval-'+role].files=[Approval(role)];}}
 return {ctx,elements,calls,downloads,job,get modal(){return modal;},get invalidations(){return invalidations;},get openedPair(){return openedPair;},get uploadCount(){return uploadCount;},
  async start(){done=ctx.run(jobId);await turn();fill();},submit(){return elements['desktop-packed-submit'].onclick();},async close(){close();await done;},
  status(){return elements['desktop-packed-status'].textContent;},state(){return elements['desktop-packed-status'].dataset.state;},posts(){return calls.filter(value=>value.method==='POST');}
 };
}
test('main toolbar, generic upload and packing completion expose the dedicated flow',()=>{
 const licenses=fs.readFileSync(path.join(root,'public/scripts/desktop/peace.admin-desktop-licenses.js'),'utf8');
 const workflow=fs.readFileSync(path.join(root,'public/scripts/desktop/peace.admin-desktop-workflow.js'),'utf8');
 assert(licenses.includes('data-desktop-action="packed-release"'));assert(licenses.includes('desktop-artifact-packed-register'));assert(workflow.includes('showDesktopPackedRelease(nextPackedJob)'));
 assert(!/localStorage|sessionStorage|indexedDB/.test(source));assert(!source.includes('releaseManifestId:job.sourceManifestId'));
});
test('dialog explains final approval, preserved Spec and distinct source/final manifests',async()=>{
 const f=Fixture();await f.start();try{assert(f.modal.html.includes('기존 Spec·서명키를 다시 만들 필요가 없습니다'));assert(f.modal.html.includes('재사용할 수 없으므로'));assert(f.modal.html.includes('개인키는 올리지 않습니다'));assert(f.modal.html.includes('Windows 동작 시험이나 운영 게시를 대신하지 않습니다'));assert(f.elements['desktop-packed-source'].textContent.includes(oldId));}finally{await f.close();}
});
test('all three final files are checked before planning and new approval versions are used',async()=>{
 const f=Fixture();await f.start();try{
  await f.submit();assert.equal(f.state(),'success');const posts=f.posts();assert.equal(posts.length,5);
  assert.equal(posts[0].url,base+'/plan-packed-release');assert.deepEqual(posts[0].body,{expectedRevision:5,expectedPolicyRevision:7,jobId});
  const uploads=posts.filter(x=>x.rawBody);assert.equal(uploads.length,3);
  for(let i=0;i<3;i++){const query=new URL(uploads[i].url,'https://example.invalid').searchParams;assert.equal(query.get('component'),roles[i]);assert.equal(query.get('version'),'2.0.1');assert.equal(query.get('releaseManifestId'),newId);assert.notEqual(query.get('releaseManifestId'),oldId);}
  assert.equal(posts.at(-1).url,base+'/release-manifests');assert.equal(posts.at(-1).body.expectedRevision,9);assert.equal(posts.at(-1).body.manifestId,newId);
  assert.equal(f.invalidations,1);assert.equal(f.openedPair,null);assert(f.status().includes('Windows 시험 PASS나 운영 게시를 자동 생성하지 않았습니다'));
 }finally{await f.close();}
});
test('original-byte approvals fail before any planning or upload',async()=>{
 const f=Fixture();await f.start();try{f.elements['desktop-packed-approval-A'].files=[Approval('A',{hash:'f'.repeat(128)})];await f.submit();assert.equal(f.posts().length,0);assert.equal(f.state(),'error');assert(f.status().includes('원본용 승인 대신'));}finally{await f.close();}
});
test('post-packing byte changes, including O normalization, cannot be hidden with a new manifest',async()=>{
 const f=Fixture();await f.start();try{f.elements['desktop-packed-exe-O'].files=[Binary('O',true)];await f.submit();assert.equal(f.posts().length,0);assert(f.status().includes('보호 후 변경'));}finally{await f.close();}
});
test('missing approval, wrong role and private keys fail before server writes',async()=>{
 for(const mode of ['missing','role','private']){const f=Fixture();await f.start();try{f.elements['desktop-packed-approval-B'].files=mode==='missing'?[]:[Approval('B',{component:mode==='role'?'A':'B',privateKey:mode==='private'})];await f.submit();assert.equal(f.posts().length,0);assert.equal(f.state(),'error');}finally{await f.close();}}
});
test('file size mismatch stops before reading or sending file bytes',async()=>{
 const f=Fixture();await f.start();try{f.elements['desktop-packed-exe-B'].files=[{name:'B.exe',size:2048,arrayBuffer:()=>{throw Error('must not read');}}];await f.submit();assert.equal(f.posts().length,0);assert(f.status().includes('같은 작업에서 받은'));}finally{await f.close();}
});
test('server plan must have a new ID and bind all three final hashes',async()=>{
 for(const option of [{oldPlan:true},{badPlanHash:true}]){const f=Fixture(option);await f.start();try{await f.submit();assert.equal(f.uploadCount,0);assert.equal(f.state(),'error');assert(f.status().includes('서버가 반환한 최종 명세'));}finally{await f.close();}}
});
test('failed upload leaves an explicit partial result without automatic retry or fake completion',async()=>{
 const f=Fixture({failRole:'B'});await f.start();try{await f.submit();assert.equal(f.uploadCount,2);assert.equal(f.state(),'error');assert.equal(f.posts().filter(x=>x.url.endsWith('/release-manifests')).length,0);assert(f.status().includes('이미 접수된 후보와 원본 명세는 보존'));assert.equal(f.elements['desktop-packed-publish'].hidden,true);}finally{await f.close();}
});
test('candidate response must confirm the same final manifest before proceeding',async()=>{
 const f=Fixture({wrongCandidate:true});await f.start();try{await f.submit();assert.equal(f.uploadCount,1);assert.equal(f.state(),'error');assert(!f.posts().some(x=>x.url.endsWith('/release-manifests')));}finally{await f.close();}
});
test('session change during hashing prevents all server writes',async()=>{
 const f=Fixture();await f.start();let resolve;f.elements['desktop-packed-exe-A'].files=[{name:'A.exe',size:1024,arrayBuffer:()=>new Promise(r=>{resolve=r;})}];
 const pending=f.submit();await turn();f.ctx.session={csrf:'different-owner'};resolve(Uint8Array.from(Buffer.alloc(1024,65)).buffer);await pending;assert.equal(f.posts().length,0);await f.close();
});
test('closing during a queued upload prevents subsequent roles and manifest completion',async()=>{
 let resume,entered;const ready=new Promise(resolve=>entered=resolve);
 const f=Fixture({uploadHook:async role=>{if(role==='B'){entered();await new Promise(resolve=>resume=resolve);}}});await f.start();const pending=f.submit();await ready;await f.close();resume();await pending;
 assert.equal(f.uploadCount,2);assert(!f.posts().some(x=>x.url.endsWith('/release-manifests')));assert.notEqual(f.state(),'success');
});
test('successful handoff selects exact new A/B/O candidates only after explicit click',async()=>{
 const f=Fixture();await f.start();await f.submit();f.elements['desktop-packed-publish'].onclick();await f.close();assert.deepEqual(f.openedPair,{aId:'A'.repeat(24),bId:'B'.repeat(24),oId:'O'.repeat(24)});
});
test('saved manifest is the final new ID and hashes, never the source manifest',async()=>{
 const f=Fixture();await f.start();try{await f.submit();f.elements['desktop-packed-manifest'].onclick();assert.equal(f.downloads.length,1);assert.equal(f.downloads[0].value.manifestId,newId);assert.deepEqual(f.downloads[0].value.manifest.artifacts,Object.fromEntries(roles.map(role=>[role,f.job.outputs[role].sha512])));}finally{await f.close();}
});
test('missing durable jobs gives recovery guidance and cannot start registration',async()=>{
 const f=Fixture({noJobs:true});await f.start();try{assert(f.status().includes('등록 데이터 초기화는 보호 기록도 삭제'));assert.equal(f.elements['desktop-packed-submit'].disabled,true);assert.equal(f.posts().length,0);}finally{await f.close();}
});
