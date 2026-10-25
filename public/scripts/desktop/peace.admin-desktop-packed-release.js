'use strict';
// Final transformed files and public approvals stay in this modal's memory.
// Planning creates a distinct immutable manifest; it never edits the source one.
const desktopPackedReleaseRoles=['A','B','O'];
async function desktopPackedReleaseHash(file){
 const bytes=await file.arrayBuffer();
 try{return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-512',bytes)),b=>b.toString(16).padStart(2,'0')).join('');}
 finally{new Uint8Array(bytes).fill(0);}
}
function desktopPackedReleaseJob(value){
 return !!value&&/^[a-f0-9]{32}$/.test(value.jobId||'')&&/^[a-f0-9]{128}$/.test(value.sourceManifestId||'')&&
  desktopPackedReleaseRoles.every(role=>{const row=value.outputs?.[role];return !!row&&/^[a-f0-9]{128}$/.test(row.sha512||'')&&Number.isSafeInteger(row.size)&&row.size>=512&&row.size<=67108864;});
}
async function desktopPackedReleaseInputs(job,selections,maxBytes=67108864,alive=()=>true){
 if(!desktopPackedReleaseJob(job)||job.available!==true)throw Error('등록할 수 있는 같은 작업의 A/B/O 보호 기록을 선택하세요.');
 const inputs={};
 for(const role of desktopPackedReleaseRoles){
  const selected=selections[role]||{},file=selected.exe,approvalFile=selected.approval,expected=job.outputs[role];
  if(!file||!/\.exe$/i.test(file.name||'')||!Number.isSafeInteger(file.size)||file.size<512||file.size>maxBytes)throw Error(role+'의 최종 보호 EXE를 선택하세요.');
  if(file.size!==expected.size)throw Error(role+' 파일이 선택한 보호 작업의 결과와 다릅니다. 같은 작업에서 받은 최종 EXE를 선택하세요.');
  const sha512=await desktopPackedReleaseHash(file);if(!alive())return null;
  if(sha512!==expected.sha512)throw Error(role+' 파일이 보호 후 변경되었거나 다른 작업의 파일입니다. 원본 명세 ID를 바꿔도 연결할 수 없습니다. 선택한 작업의 출력 SHA-512를 확인하세요.');
  if(!approvalFile||!Number.isSafeInteger(approvalFile.size)||approvalFile.size<1||approvalFile.size>16384)throw Error(role+'의 최종 EXE용 공개 승인 JSON을 선택하세요.');
  const text=await approvalFile.text();if(!alive())return null;
  if(text.includes('PRIVATE KEY'))throw Error('개인키는 업로드할 수 없습니다. 공개 .approval.json을 선택하세요.');
  let info;try{info=JSON.parse(text.replace(/^\uFEFF/,''));}catch(_){throw Error(role+' 승인 JSON 형식이 올바르지 않습니다.');}
  const approval=info?.approval,version=String(info?.version||'');
  if(typeof info?.version!=='string'||!/^\d+(?:\.\d+){0,3}$/.test(version)||version.length>40||info?.component!==role||info.sha512!==sha512)throw Error(role+' 승인 자료가 최종 보호 EXE·구분·버전과 다릅니다. 원본용 승인 대신 같은 개인키로 최종 보호 EXE에 새 승인을 만드세요.');
  if(!approval||!/^[a-f0-9]{64}$/.test(approval.keyId||'')||!/^[A-Za-z0-9+/]{86}==$/.test(approval.signature||''))throw Error(role+'의 공개 승인 서명 형식을 확인하세요.');
  inputs[role]={file,version,sha512,headers:{'x-game-release-key-id':approval.keyId,'x-game-release-signature':approval.signature}};
 }
 return inputs;
}
function desktopPackedReleaseError(error){
 const messages={
  PACKED_RELEASE_JOB_NOT_FOUND:'서버에 해당 보호 작업 기록이 없습니다. 등록 데이터 초기화 여부와 작업 ID를 확인하세요.',
  PACKED_RELEASE_SOURCE_MISSING:'보호 작업에 연결된 원본 후보가 없습니다. 원본 등록과 초기화 여부를 확인하세요.',
  PACKED_RELEASE_SOURCE_MANIFEST_REQUIRED:'원본 세 파일의 동일한 배포 명세를 확인하지 못했습니다. 원본 등록 명세를 확인하세요.',
  PACKED_RELEASE_SOURCE_MANIFEST_MIXED:'원본 A/B/O의 명세 ID가 서로 다릅니다. 하나의 원본 배포 묶음에서 보호한 세 파일이 필요합니다.',
  PACKED_RELEASE_SOURCE_MANIFEST_MISMATCH:'원본 A/B/O·명세·보호 작업의 연결이 다릅니다. 같은 보호 작업의 세 파일을 선택하세요.',
  PACKED_RELEASE_POLICY_CHANGED:'같은 보호 결과에 다른 정책으로 만든 명세가 있습니다. 현재 정책과 기존 명세를 운영 화면에서 확인하세요.',
  PACKED_RELEASE_MANIFEST_CONFLICT:'같은 보호 결과에 다른 배포 정보의 명세가 있습니다. 기존 최종 명세를 운영 화면에서 확인하세요.',
  SECURITY_MANIFEST_ARTIFACT_MISMATCH:'이 EXE의 해시와 연결한 명세가 다릅니다. 원본 명세 ID는 보호 결과에 사용할 수 없습니다. 이 화면에서 최종 결과용 새 명세를 연결하세요.',
  SECURITY_RELEASE_MANIFEST_CONFLICT:'같은 최종 파일의 명세가 이미 있습니다. 창을 다시 열어 현재 기록으로 이어서 등록하세요.',
  SECURITY_OPERATIONS_CONFLICT:'다른 운영 작업으로 서버 상태가 바뀌었습니다. 이미 등록된 파일은 보존되며, 현재 기록을 다시 확인해 이어서 등록할 수 있습니다.',
  SECURITY_POLICY_CONFLICT:'보안 정책이 바뀌었습니다. 창을 다시 열어 현재 정책으로 명세를 확인하세요.'
 };
 return messages[error.code]||error.serverMessage||error.message||error.code||'보호 결과 등록을 완료하지 못했습니다.';
}
async function showDesktopPackedRelease(preferredJobId=''){
 if(!roleIsAdmin()||!session)throw Error('관리자로 로그인하세요.');
 const owner=session.csrf,base='/api/desktop/bootstrap/security-operations';
 let listing=await api(base+'/packed-release-jobs');
 if(!roleIsAdmin()||session?.csrf!==owner)return;
 let closed=false,busy=false,finished=false,plan=null,selection=null,openPublication=false;
 const jobs=Array.isArray(listing.jobs)?listing.jobs:[];
 const done=openModal({title:'보호 결과 등록',message:'같은 작업에서 받은 최종 A/B/O와 새 공개 승인 JSON을 선택하세요. 원본 명세의 배포 정보를 이어받아 보호 결과용 새 명세를 만들고 세 후보를 연결합니다.',html:`<section id="desktop-packed-release"><p class="small-note">기존 Spec·서명키를 다시 만들 필요가 없습니다. 원본 승인 서명은 파일 해시가 달라 재사용할 수 없으므로, 최종 보호 EXE의 새 .approval.json은 필요합니다. 개인키는 올리지 않습니다.</p><label>서버에 저장된 보호 작업<select id="desktop-packed-job"><option value="">작업 선택</option>${jobs.map(job=>`<option value="${esc(job.jobId||'')}" ${job.available===true&&desktopPackedReleaseJob(job)?'':'disabled'}>${esc(job.sourceReleaseName||job.jobId||'확인되지 않은 작업')} · ${esc(String(job.jobId||'').slice(0,12))}${job.available===true?'':' · 등록 불가: '+esc(desktopPackedReleaseError({code:job.reason||'PACKED_RELEASE_SOURCE_MANIFEST_REQUIRED'}))}</option>`).join('')}</select></label><div id="desktop-packed-source" class="desktop-packed-source" role="status"></div>${desktopPackedReleaseRoles.map(role=>`<fieldset><legend>${role} · ${role==='A'?'실행기':role==='B'?'클라이언트':'오버레이'}</legend><label>최종 보호 EXE<input type="file" id="desktop-packed-exe-${role}" accept=".exe,application/octet-stream"></label><label>최종 EXE용 공개 승인 JSON<input type="file" id="desktop-packed-approval-${role}" accept=".json,application/json"></label><label>최종 승인 버전 (JSON에서 자동 확인)<input type="text" id="desktop-packed-version-${role}" maxlength="40" autocomplete="off" readonly placeholder="승인 JSON 선택 후 표시"></label></fieldset>`).join('')}<p class="small-note">파일의 역할·크기·SHA-512·승인 자료를 먼저 확인합니다. 서버가 서명과 현재 정책을 다시 검사합니다. 이 절차는 Windows 동작 시험이나 운영 게시를 대신하지 않습니다.</p><div class="actions"><button type="button" id="desktop-packed-submit">최종 명세 생성 · A/B/O 후보 등록</button><button type="button" id="desktop-packed-manifest" hidden>최종 배포 명세 JSON 저장</button><button type="button" id="desktop-packed-publish" hidden>선택한 세 후보로 조합 검증 열기</button></div><p id="desktop-packed-status" role="status" aria-live="polite"></p><pre id="desktop-packed-manifest-id" class="desktop-wrap"></pre></section>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-packed-release'),node=id=>root.querySelector('#'+id),alive=()=>!closed&&root.isConnected&&roleIsAdmin()&&session?.csrf===owner;
 function status(message,state='pending'){if(alive()){node('desktop-packed-status').textContent=message;node('desktop-packed-status').dataset.state=state;}}
 function lock(value){busy=value;if(!alive())return;for(const element of root.querySelectorAll('input,select'))element.disabled=value||finished;node('desktop-packed-submit').disabled=value||finished||!node('desktop-packed-job').value;}
 function selectedJob(){return jobs.find(job=>job.jobId===node('desktop-packed-job').value);}
 function showJob(){
  if(busy||!alive())return;const job=selectedJob();plan=null;
  node('desktop-packed-manifest').hidden=true;node('desktop-packed-manifest-id').textContent='';
  node('desktop-packed-source').textContent=job?'원본 명세 ID: '+job.sourceManifestId+'\n보호 결과는 이 ID를 재사용하지 않고, 아래 최종 해시로 새 ID를 만듭니다.\n'+desktopPackedReleaseRoles.map(role=>role+' 출력 SHA-512: '+job.outputs?.[role]?.sha512).join('\n'):'서버에 저장된 같은 보호 작업을 선택하세요. 내려받기 만료 후에도 서버 기록이 남아 있으면 등록할 수 있습니다.';
  for(const role of desktopPackedReleaseRoles)node('desktop-packed-version-'+role).value='';
  lock(false);
 }
 node('desktop-packed-job').onchange=showJob;
 for(const role of desktopPackedReleaseRoles)node('desktop-packed-approval-'+role).onchange=async()=>{
  const field=node('desktop-packed-approval-'+role),file=field.files?.[0];node('desktop-packed-version-'+role).value='';
  if(busy||!alive()||!file||file.size>16384)return;
  try{const value=JSON.parse(await file.text());if(alive()&&field.files?.[0]===file&&value.component===role&&/^\d+(?:\.\d+){0,3}$/.test(value.version||''))node('desktop-packed-version-'+role).value=value.version;}catch(_){}
 };
 node('desktop-packed-manifest').onclick=()=>{if(alive()&&plan)desktopWorkflowDownload('packed-release-manifest.json',{manifestId:plan.manifestId,manifest:plan.manifest});};
 node('desktop-packed-publish').onclick=()=>{if(alive()&&finished&&selection){openPublication=true;modalCancel.click();}};
 node('desktop-packed-submit').onclick=async()=>{
  if(busy||finished||!alive())return;
  const job=selectedJob();const snapshots=Object.fromEntries(desktopPackedReleaseRoles.map(role=>[role,{exe:node('desktop-packed-exe-'+role).files?.[0],approval:node('desktop-packed-approval-'+role).files?.[0],version:node('desktop-packed-version-'+role).value}]));
  lock(true);status('최종 A/B/O의 SHA-512와 공개 승인 자료를 확인하고 있습니다.');
  try{
   const inputs=await desktopPackedReleaseInputs(job,snapshots,desktopBootstrap?.limits?.maxArtifactBytes||67108864,alive);if(!alive()||!inputs)return;
   for(const role of desktopPackedReleaseRoles)node('desktop-packed-version-'+role).value=inputs[role].version;
   // Read current revisions immediately before planning; no stale source ID is
   // accepted from a free-text field or copied into the new upload requests.
   const current=await api(base+'/packed-release-jobs');if(!alive())return;
   const latest=current.jobs?.find(value=>value.jobId===job.jobId);
   if(!desktopPackedReleaseJob(latest)||latest.available!==true||desktopPackedReleaseRoles.some(role=>latest.outputs[role].sha512!==inputs[role].sha512||latest.outputs[role].size!==inputs[role].file.size))throw Error('보호 작업 기록이 바뀌었습니다. 창을 다시 열어 확인하세요.');
   status('보호 결과의 해시로 새 배포 명세를 계획 등록하고 있습니다.');
   const planned=await api(base+'/plan-packed-release',{method:'POST',body:{expectedRevision:current.expectedRevision,expectedPolicyRevision:current.expectedPolicyRevision,jobId:job.jobId}});if(!alive())return;
   if(!/^[a-f0-9]{128}$/.test(planned.manifestId||'')||planned.manifestId===job.sourceManifestId||planned.jobId!==job.jobId||!planned.manifest||desktopPackedReleaseRoles.some(role=>planned.manifest.artifacts?.[role]!==inputs[role].sha512))throw Error('서버가 반환한 최종 명세가 보호 결과와 다릅니다. 파일 등록을 중단했습니다.');
   plan=planned;node('desktop-packed-manifest').hidden=false;
   node('desktop-packed-manifest-id').textContent='원본 명세 ID: '+job.sourceManifestId+'\n최종 보호 결과 명세 ID: '+plan.manifestId;
   const registered={};
   for(const role of desktopPackedReleaseRoles){
    if(!alive())return;status(role+' 보호 결과를 최종 명세에 연결해 후보로 등록하고 있습니다.');
    const input=inputs[role],query=new URLSearchParams({component:role,version:input.version,fileName:input.file.name,releaseManifestId:plan.manifestId});
    const result=await api('/api/desktop/bootstrap/artifacts?'+query,{method:'POST',rawBody:input.file,headers:input.headers});if(!alive())return;
    if(result.artifact?.component!==role||result.artifact.sha512!==input.sha512||result.artifact.deploymentManifestId!==plan.manifestId||typeof result.artifact.id!=='string')throw Error(role+' 후보의 최종 명세 연결을 확인하지 못했습니다. 같은 파일로 현재 상태를 다시 확인하세요.');
    registered[role.toLowerCase()+'Id']=result.artifact.id;
   }
   const state=await api(base);if(!alive())return;
   if(!Number.isSafeInteger(state.operations?.revision))throw Error('명세 등록 완료에 필요한 서버 상태를 확인하지 못했습니다.');
   await api(base+'/release-manifests',{method:'POST',body:{expectedRevision:state.operations.revision,manifestId:plan.manifestId,manifest:plan.manifest}});if(!alive())return;
   selection=registered;finished=true;node('desktop-packed-publish').hidden=false;
   desktopInvalidatePanels();status('보호된 A/B/O 세 후보와 새 배포 명세를 연결했습니다. [선택한 세 후보로 조합 검증 열기]에서 검증 후 운영 게시하세요. Windows 시험 PASS나 운영 게시를 자동 생성하지 않았습니다.','success');
  }catch(error){if(alive())status(desktopPackedReleaseError(error)+' 이미 접수된 후보와 원본 명세는 보존됩니다. 같은 파일을 선택해 이어서 등록할 수 있습니다.','error');}
  finally{if(alive())lock(false);}
 };
 const preferred=jobs.find(job=>job.jobId===preferredJobId&&job.available===true&&desktopPackedReleaseJob(job));
 if(preferred)node('desktop-packed-job').value=preferred.jobId;
 else if(jobs.filter(job=>job.available===true&&desktopPackedReleaseJob(job)).length===1)node('desktop-packed-job').value=jobs.find(job=>job.available===true&&desktopPackedReleaseJob(job)).jobId;
 showJob();
 if(!jobs.length)status('서버에 저장된 보호 작업이 없습니다. 등록 데이터 초기화는 보호 기록도 삭제합니다. 파일을 다시 패킹하기 전에 원본 등록과 서버 기록을 확인하세요.','error');
 try{await done;}finally{closed=true;plan=null;listing=null;for(const role of desktopPackedReleaseRoles){if(node('desktop-packed-exe-'+role))node('desktop-packed-exe-'+role).value='';if(node('desktop-packed-approval-'+role))node('desktop-packed-approval-'+role).value='';}if(root.isConnected)root.replaceChildren();}
 if(openPublication&&selection&&roleIsAdmin()&&session?.csrf===owner)await showDesktopSecurityOperations(selection);
}
