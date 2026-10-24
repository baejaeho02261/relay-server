'use strict';
// Administrator UI only. Drafts, file selections and selection IDs stay in RAM.
const desktopSelectedLicenses=new Set();
let desktopSelectionOwner='';
function desktopWorkflowOwner(){const owner=session?.csrf||'';if(owner!==desktopSelectionOwner){desktopSelectedLicenses.clear();desktopSelectionOwner=owner;}return owner;}
function desktopWorkflowError(node,error,retry){
 const p=error.problem||{title:error.serverMessage||error.message||'요청을 완료하지 못했습니다.',current:'이 작업의 완료를 확인하지 못했습니다.',next:'내용과 현재 서버 상태를 확인한 뒤 다시 시도하세요.',code:error.code||'REQUEST_FAILED',action:'refresh'};
 node.innerHTML=`<div class="desktop-operation-error" role="alert"><strong>${esc(p.title)}</strong><p>현재: ${esc(p.current)}</p><p>다음: ${esc(p.next)}</p><details><summary>상세 코드</summary><code>${esc(error.code||p.code||'REQUEST_FAILED')}</code></details>${retry?'<button type="button" data-workflow-retry>이 항목 다시 확인</button>':''}</div>`;
 if(retry)node.querySelector('[data-workflow-retry]').onclick=retry;
 const names={security:'서버 보안 설정 열기',deploy:'서버 보안 · 배포 운영 열기',licenses:'라이선스 목록으로',jobs:'서버 작업함 열기',storage:'저장공간 확인'};
 if(names[p.action]){const go=document.createElement('button');go.type='button';go.textContent=names[p.action];node.firstElementChild.append(go);go.onclick=async()=>{try{const owner=session?.csrf;if(typeof modalCancel!=='undefined')modalCancel.click();await new Promise(r=>setTimeout(r,0));if(session?.csrf!==owner)return;if(p.action==='security')await showDesktopSecurityOperations();else if(p.action==='deploy')await showDesktopSecurityOperations();else if(p.action==='jobs'||p.action==='storage')await showDesktopWorkspace(p.action);else await renderCurrent();}catch(e){toast(e.message||'화면을 열지 못했습니다.',true);}};}

}
function desktopWorkflowDownload(name,value){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function showDesktopReleaseSafety(){
 if(!roleIsAdmin()||!session)return;const owner=desktopWorkflowOwner();
 let listing=await api('/api/desktop/bootstrap/security-operations');
 if(!roleIsAdmin()||session?.csrf!==owner)return;
 let busy=false,closed=false;
 const promise=openModal({title:'정상본 보존 · 배포 묶음 관리',message:'서버 보안 · 배포 운영에서 현재 운영 정상본을 보존하고 보안상 폐기할 묶음을 관리합니다.',html:`<div id="desktop-release-safety"><p class="small-note">정상본 고정은 운영자가 확인한 기준 보존이며 시험 PASS가 아닙니다. A/B/O 서명·해시·명세·버전·철회·정책 및 관리자 승인 검사는 그대로 수행합니다.</p><div id="desktop-safety-status" role="status"></div><label>정상본 고정 메모<input id="desktop-baseline-note" maxlength="500" placeholder="직접 확인한 환경·동작을 기록하세요"></label><div class="actions"><button type="button" id="desktop-baseline-pin">현재 운영 A/B/O 정상본 고정</button><button type="button" id="desktop-baseline-export">고정 기록 받기</button></div><details><summary>보안상 폐기할 배포 묶음 (되돌릴 수 없음)</summary><label>등록된 묶음<select id="desktop-retire-cohort"></select></label><label>폐기 사유<input id="desktop-retire-reason" maxlength="500"></label><label>영향 확인 후 RETIRE 입력<input id="desktop-retire-confirm" maxlength="6" autocomplete="off"></label><p>현재 또는 실행 중인 묶음을 폐기하면 다음 서버 검사에서 거절됩니다. 단순히 새 버전을 올릴 때 사용하는 버튼이 아닙니다.</p><button type="button" id="desktop-retire-submit">선택 묶음 영구 폐기</button></details><div id="desktop-safety-result" role="status" aria-live="polite"></div></div>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-release-safety'),area=root.querySelector('#desktop-safety-result');
 const live=()=>!closed&&root.isConnected&&roleIsAdmin()&&session?.csrf===owner;
 function lock(value){busy=value;for(const e of root.querySelectorAll('button,input,select,textarea'))e.disabled=value;if(!value&&!listing?.releaseSafety){root.querySelector('#desktop-baseline-pin').disabled=true;root.querySelector('#desktop-retire-submit').disabled=true;}}
 function activeManifest(){
  const tuple=Object.fromEntries(['A','B','O'].map(k=>[k,(listing.candidates||[]).find(a=>a.id===listing.active?.[k]&&a.component===k)?.sha512]));
  const row=Object.entries(listing.operations.releaseGovernance?.manifests||{}).find(([,v])=>v.registration!=='PLANNED'&&['A','B','O'].every(k=>tuple[k]&&v.manifest.artifacts[k]===tuple[k]));
  if(!row)throw Error('현재 운영 A/B/O의 등록 완료된 배포 명세가 필요합니다. 서버 보안 · 배포 운영에서 명세와 운영 조합을 확인하세요.');
  return row[0];
 }
 function render(){
  const v=listing.releaseSafety,status=root.querySelector('#desktop-safety-status'),select=root.querySelector('#desktop-retire-cohort'),previous=select.value;
  if(!v){status.textContent='서버에서 정상본 보존 기능을 사용할 수 없습니다. 서버 상태를 확인하세요.';select.innerHTML='<option value="">폐기 대상 없음</option>';lock(false);return;}
  status.textContent=(v.baseline?'정상본 고정됨: '+v.baseline.manifestId.slice(0,16)+' · '+desktopDate(v.baseline.pinnedAt):'정상본 미고정 · 동작 확인은 운영자 기록으로만 저장됩니다.')+' / 보안 버전 하한 '+listing.operations.releaseGovernance.minimumSecurityVersion;
  select.innerHTML='<option value="">폐기 대상 선택</option>'+Object.entries(listing.operations.releaseGovernance?.manifests||{}).filter(([,r])=>r.registration!=='PLANNED').map(([id,r])=>`<option value="${esc(id)}">${esc(r.manifest.releaseName)} · 보안 ${Number(r.manifest.securityVersion)} · ${esc(id.slice(0,16))}${v.revokedCohorts?.[id]?' · 이미 폐기됨':''}</option>`).join('');
  if([...select.options].some(x=>x.value===previous))select.value=previous;
 }
 async function mutate(action,bodyForRequest){
  if(busy||!live())return false;lock(true);
  try{
   if(!listing.releaseSafety)throw Error('서버에서 정상본 보존 기능을 사용할 수 없습니다.');
   const body=await bodyForRequest();if(!live())return false;
   await api('/api/desktop/bootstrap/security-operations/'+action,{method:'POST',body:{expectedRevision:listing.releaseSafety.revision,...body}});
   if(!live())return false;const next=await api('/api/desktop/bootstrap/security-operations');if(!live())return false;
   listing=next;render();area.textContent='서버에 저장했습니다. 실행 시험이나 운영 게시를 자동 수행하지 않았습니다.';return true;
  }catch(e){if(live())desktopWorkflowError(area,e);return false;}finally{if(live())lock(false);}
 }
 root.querySelector('#desktop-baseline-pin').onclick=()=>mutate('baseline-pin',async()=>{
  const manifestId=activeManifest(),note=root.querySelector('#desktop-baseline-note').value.trim();
  if(!note)throw Error('직접 확인한 정상 동작을 메모에 입력하세요.');
  const policy=await api('/api/desktop/bootstrap/security-authority');
  if(!live())return null;
  return {manifestId,note,expectedOperationsRevision:listing.operations.revision,expectedPolicyRevision:policy.policy.revision};
 });
 root.querySelector('#desktop-baseline-export').onclick=()=>{try{if(busy||!live())return;const baseline=listing.releaseSafety?.baseline;if(!baseline)throw Error('먼저 현재 운영 조합을 고정하세요.');desktopWorkflowDownload('known-good-baseline.json',baseline);}catch(e){if(live())desktopWorkflowError(area,e);}};
 root.querySelector('#desktop-retire-submit').onclick=async()=>{
  const saved=await mutate('retire-cohort',()=>{
   const manifestId=root.querySelector('#desktop-retire-cohort').value,reason=root.querySelector('#desktop-retire-reason').value.trim();
   if(!manifestId||!reason||root.querySelector('#desktop-retire-confirm').value!=='RETIRE')throw Error('폐기 대상·사유·RETIRE 확인이 필요합니다. 현재 묶음을 폐기하면 사용 중 실행도 제한됩니다.');
   return {manifestId,reason};
  });
  if(saved&&live())root.querySelector('#desktop-retire-confirm').value='';
 };
 render();
 try{await promise;}finally{closed=true;listing=null;if(root.isConnected)root.replaceChildren();}
}
async function showDesktopExecutableProtection(){
 if(!roleIsAdmin()||!session)return;const owner=desktopWorkflowOwner();
 let listing=await api('/api/desktop/bootstrap/security-operations');
 if(!roleIsAdmin()||session?.csrf!==owner)return;
 let busy=false,closed=false,waitTimer=null,wakeWait=null;
 const promise=openModal({title:'패킹 · 암호화 · 난독화',message:'서버에 등록된 후보로 보호 작업을 준비합니다. 파일 등록과 일회용 A 발급은 A / B / O 실행 파일 배포에서 진행하세요.',html:`<div id="desktop-protection-modal"><fieldset><legend>보호 작업 대상 · 등록된 A/B/O 후보</legend><p class="small-note">패키지·패킹 작업에는 A/B/O 세 후보가 필요합니다. 결과 파일은 직접 확인한 뒤 새 승인·명세로 등록해야 합니다.</p>${['A','B','O'].map(c=>`<label>${c} 후보<select data-protection-candidate="${c}"></select></label>`).join('')}</fieldset><fieldset><legend>자체 암호화 패키지 (.gcpack)</legend><p class="small-note">VMProtect 없이 이 서버에서 압축·암호화합니다. .gcpack은 보관·전달용 데이터 패키지이며 직접 실행하는 EXE가 아닙니다. 함수 가상화·실행 코드 난독화는 수행하지 않습니다. 복호화 키는 서버에만 설정하고 이 화면에 올리지 않습니다.</p><label>대상<select id="desktop-custom-kind"><option value="artifacts">위에서 선택한 A/B/O 세 파일</option><option value="sources">Railway 전체 매니페스트 파일</option></select></label><button type="button" id="desktop-custom-selected">자체 암호화 패키지 만들기</button><div id="desktop-custom-result" role="status" aria-live="polite"></div></fieldset><fieldset><legend>외부 실행 파일 보호 · 패킹/난독화 도구 연동</legend><p class="small-note">별도 VMProtect 워커와 검토한 프로필이 필요합니다. 실제 보호 범위는 워커와 프로필에 따릅니다. 결과는 미승인 후보이며, 패킹 후 Windows 시험·새 서명·후보 재등록·게시가 필요합니다.</p><button type="button" id="desktop-pack-selected">선택한 A/B/O 패킹 후보 만들기</button><div id="desktop-pack-result" role="status" aria-live="polite"></div></fieldset></div>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-protection-modal');
 const live=()=>!closed&&root.isConnected&&roleIsAdmin()&&session?.csrf===owner;
 function lock(value){busy=value;for(const e of root.querySelectorAll('button,input,select,textarea'))e.disabled=value;}
 function selected(){const body=Object.fromEntries(['A','B','O'].map(c=>[c,root.querySelector(`[data-protection-candidate="${c}"]`).value]));if(Object.values(body).some(x=>!x))throw Error('A, B, O 후보를 모두 선택하세요.');return body;}
 function wait(ms){return new Promise(resolve=>{wakeWait=resolve;waitTimer=setTimeout(()=>{waitTimer=null;wakeWait=null;resolve();},ms);});}
 for(const c of ['A','B','O']){
  const select=root.querySelector(`[data-protection-candidate="${c}"]`);
  select.innerHTML=`<option value="">${c} 후보 선택</option>`+(listing.candidates||[]).filter(x=>x.component===c).map(x=>`<option value="${esc(x.id)}">${esc(x.version)} · ${esc(x.sha512.slice(0,12))}${x.active?' · 현재 운영':''}</option>`).join('');
  if([...select.options].some(x=>x.value===listing.active?.[c]))select.value=listing.active[c];
 }
 root.querySelector('#desktop-custom-selected').onclick=async()=>{
  if(busy||!live())return;lock(true);const area=root.querySelector('#desktop-custom-result');
  try{
   const kind=root.querySelector('#desktop-custom-kind').value,body={kind};if(kind==='artifacts')Object.assign(body,selected());
   const status=await api('/api/desktop/bootstrap/packing/status');if(!live())return;
   if(!status.custom?.configured)throw Error('서버 암호화 키 설정 필요: '+(status.custom?.reason||'CUSTOM_PACKAGE_KEY_NOT_CONFIGURED'));
   if(kind==='sources'&&!status.custom.sourceTreeAvailable)throw Error('서버에 Railway 소스가 없습니다. 서버 전용 배포에서는 A/B/O 보관 패키지를 사용하세요.');
   let response=await api('/api/desktop/bootstrap/packing/custom/jobs',{method:'POST',body});
   const id=encodeURIComponent(response.job.id),stop=Date.now()+100000;
   while(live()&&response.job.status==='RUNNING'&&Date.now()<stop){area.textContent='서버에서 데이터 패키지를 압축·암호화합니다. 실행 파일 보호·운영 게시는 별개입니다.';await wait(1000);if(!live())return;response=await api('/api/desktop/bootstrap/packing/custom/jobs/'+id);}
   if(!live())return;if(response.job.status!=='COMPLETE')throw Error(response.job.error||'암호화 패키지 완료를 확인하지 못했습니다.');
   area.replaceChildren();const note=document.createElement('p');note.textContent=`암호화 완료: ${response.job.fileCount}개 파일 / ${response.job.size}바이트. 내려받기는 10분 후 만료됩니다. 실행 코드 난독화나 운영 게시를 완료했다는 뜻은 아닙니다.`;area.append(note);
   const link=document.createElement('a');link.href='/api/desktop/bootstrap/packing/custom/jobs/'+id+'/download';link.textContent='자체 암호화 패키지 (.gcpack) 받기';link.setAttribute('download','');area.append(link);
   const digest=document.createElement('pre');digest.textContent='SHA-512: '+response.job.sha512;area.append(digest);
  }catch(e){if(live())desktopWorkflowError(area,e);}finally{if(live())lock(false);}
 };
 root.querySelector('#desktop-pack-selected').onclick=async()=>{
  if(busy||!live())return;lock(true);const area=root.querySelector('#desktop-pack-result');
  try{
   const body=selected(),status=await api('/api/desktop/bootstrap/packing/status');if(!live())return;
   if(!status.packing?.configured)throw Error('패킹 워커 설정 필요: '+(status.packing?.reason||'PACKING_WORKER_NOT_CONFIGURED'));
   let response=await api('/api/desktop/bootstrap/packing/jobs',{method:'POST',body});
   const id=encodeURIComponent(response.job.id),stop=Date.now()+600000;
   while(live()&&response.job.status==='RUNNING'&&Date.now()<stop){area.textContent='서버 패킹 진행: '+(response.job.component||'시작')+' · 운영 발급 전 시험·서명 필요';await wait(2000);if(!live())return;response=await api('/api/desktop/bootstrap/packing/jobs/'+id);}
   if(!live())return;if(response.job.status!=='COMPLETE')throw Error(response.job.error||'패킹 완료를 확인하지 못했습니다.');
   area.replaceChildren();const note=document.createElement('p');note.textContent='패킹 후보 생성 완료. 아래 파일로 Windows 시험 및 새 배포 승인을 수행한 뒤 A / B / O 실행 파일 배포에서 후보를 다시 등록하세요. 10분 후 내려받기 만료. 기존 승인 JSON은 재사용할 수 없습니다.';area.append(note);
   for(const c of ['A','B','O','report']){const a=document.createElement('a');a.href='/api/desktop/bootstrap/packing/jobs/'+id+'/'+c;a.textContent=c==='report'?'SHA-512 작업 보고서':c+' 미승인 패킹 EXE';a.setAttribute('download','');const div=document.createElement('div');div.append(a);area.append(div);}
  }catch(e){if(live())desktopWorkflowError(area,e);}finally{if(live())lock(false);}
 };
 try{await promise;}finally{closed=true;if(waitTimer!==null)clearTimeout(waitTimer);waitTimer=null;const wake=wakeWait;wakeWait=null;if(wake)wake();listing=null;if(root.isConnected)root.replaceChildren();}
}
async function showDesktopWorkspace(initialTab='quality'){
 if(!roleIsAdmin())return;const owner=desktopWorkflowOwner();let plan=null,pendingRequest=null,busy=false,tickBusy=false;
 const chosen=[...desktopSelectedLicenses];
 const promise=openModal({title:'서버 운영 작업함',message:'통계·일괄 작업·저장공간 조회는 서버가 처리합니다. 실행한 작업은 이 창을 닫아도 서버에 남고, 다음 접속에서 이어서 조회합니다.',html:`<div id="desktop-workspace-modal"><nav class="actions" aria-label="운영 영역">${[['quality','배포 품질'],['jobs','일괄 작업'],['storage','저장공간']].map(([key,label])=>`<button type="button" data-workspace-tab="${key}">${label}</button>`).join('')}</nav><section data-workspace-section="quality"><div id="desktop-quality-result" role="status">서버 통계를 불러옵니다.</div></section><section data-workspace-section="jobs" hidden><fieldset><legend>새 서버 작업</legend><label>작업<select id="desktop-job-kind"><option value="CREATE">라이선스 일괄 발급</option><option value="METADATA">선택 라이선스 메모·태그</option><option value="EXPORT">선택 라이선스 내보내기</option></select></label><label>발급 개수 (1~100)<input id="desktop-job-count" type="number" min="1" max="100" value="1"></label><label>발급 이름 접두사<input id="desktop-job-prefix" maxlength="100" value="사용자"></label><label>선택 라이선스 ID (쉼표·줄바꿈)<textarea id="desktop-job-ids">${esc(chosen.join('\n'))}</textarea></label><label>관리자 메모<textarea id="desktop-job-note" maxlength="500"></textarea></label><label>태그 (쉼표, 최대 10개)<input id="desktop-job-tags" maxlength="310"></label><div class="actions"><button type="button" id="desktop-job-preview">작업 미리보기</button><button type="button" id="desktop-job-commit" disabled>미리본 작업 실행</button></div></fieldset><div id="desktop-job-plan" role="status"></div><div id="desktop-jobs-list"></div></section><section data-workspace-section="storage" hidden><p>서버 배포 파일만 조회합니다. 키·라이선스 DB·감사 기록·사용자 PC 파일은 정리하지 않습니다. 운영·이력·검사/시험 참조가 없고 7일 지난 후보만 선택할 수 있습니다.</p><div class="actions"><button type="button" id="desktop-storage-scan">서버 용량 다시 조회</button><button type="button" id="desktop-storage-preview">선택 후보 정리 미리보기</button><button type="button" id="desktop-storage-commit" disabled>미리본 후보 정리 실행</button></div><div id="desktop-storage-plan" role="status"></div><div id="desktop-storage-list"></div></section></div>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-workspace-modal'),live=()=>root.isConnected&&session?.csrf===owner;
 function invalidate(){plan=null;pendingRequest=null;root.querySelector('#desktop-job-commit').disabled=true;root.querySelector('#desktop-storage-commit').disabled=true;}
 root.addEventListener('input',invalidate);
 if(['quality','jobs','storage'].includes(initialTab))root.querySelectorAll('[data-workspace-section]').forEach(s=>s.hidden=s.dataset.workspaceSection!==initialTab);
 root.addEventListener('click',e=>{const t=e.target.closest('[data-workspace-tab]');if(t){root.querySelectorAll('[data-workspace-section]').forEach(s=>s.hidden=s.dataset.workspaceSection!==t.dataset.workspaceTab);}});
 async function refresh(){
  if(tickBusy||!live())return;tickBusy=true;
  try{
   const results=await Promise.allSettled(['/summary','/jobs','/storage'].map(p=>api('/api/desktop/workspace'+p)));if(!live())return;
   const [quality,jobs,storage]=results;
   if(quality.status==='fulfilled'){
    const q=quality.value;root.querySelector('#desktop-quality-result').innerHTML=`<p>서버 집계: ${desktopDate(q.asOf)} · 최근 7일에 시작한 흐름 기준. 미완료·사용자 미실행은 실패로 단정하지 않습니다.</p><div class="desktop-stats">${[['A 발급',q.issued],['실행 시작',q.started],['다운로드 완료',q.downloaded],['B 연결',q.claimed],['라이선스 사용',q.authorized]].map(([k,v])=>`<div class="desktop-stat"><span>${esc(k)}</span><strong>${Number(v||0).toLocaleString()}</strong></div>`).join('')}</div><p>시작→B 연결 중앙값 ${q.medianStartToClaimMs===null?'자료 없음':(q.medianStartToClaimMs/1000).toFixed(2)+'초'} · 95백분위 ${q.p95StartToClaimMs===null?'자료 없음':(q.p95StartToClaimMs/1000).toFixed(2)+'초'}</p><div class="table-wrap"><table><thead><tr><th>B 버전</th><th>시작</th><th>다운로드</th><th>B 연결</th><th>라이선스 사용</th><th>종료 / 폐기 / 만료</th></tr></thead><tbody>${(q.versions||[]).map(v=>`<tr><td>${esc(v.version)}</td><td>${v.started}</td><td>${v.downloaded}</td><td>${v.claimed}</td><td>${v.authorized}</td><td>${v.closed} / ${v.revoked} / ${v.expired}</td></tr>`).join('')}</tbody></table></div><p>다운로드 중앙값 ${q.downloadTiming?.medianMs==null?'자료 없음':(q.downloadTiming.medianMs/1000).toFixed(2)+'초'} · 다운로드 완료→B 연결 중앙값 ${q.claimTiming?.medianMs==null?'자료 없음':(q.claimTiming.medianMs/1000).toFixed(2)+'초'}</p><h3>최근 서버 요청 거절</h3><p>최근 서버 이벤트 최대 1,000개 중 관련 기록입니다. 같은 세션·사유는 10초에 한 번 기록하며 전체 사용자 실패율이 아닙니다.</p>${(q.recentRequestFailures||[]).map(f=>`<details><summary>${esc(f.version)} · ${esc(f.problem?.title||f.reason)} · ${f.count}건</summary><p>현재: ${esc(f.problem?.current||'서버에서 요청을 거절했습니다.')}</p><p>다음: ${esc(f.problem?.next||'서버 상태를 확인하세요.')}</p><code>${esc(f.reason)}</code></details>`).join('')||'<p>이 범위에서 기록된 거절이 없습니다.</p>'}${q.releaseNote?`<h3>현재 배포 메모</h3><p class="desktop-wrap">${esc(q.releaseNote)}</p>`:''}`;
   }else desktopWorkflowError(root.querySelector('#desktop-quality-result'),quality.reason,refresh);
   if(jobs.status==='fulfilled'){
    const openJobs=new Set([...root.querySelectorAll('#desktop-jobs-list details[open]')].map(x=>x.dataset.job));
    root.querySelector('#desktop-jobs-list').innerHTML=`<h3>서버 작업 이력</h3>${jobs.value.items.map(j=>`<details data-job="${j.id}" ${openJobs.has(j.id)?'open':''}><summary>${esc(j.kind)} · ${esc(j.status)} · 완료 ${j.done}/${j.total} · 실패 ${j.failed} · ${desktopDate(j.createdAt)}</summary><div class="actions">${j.failed?`<button type="button" data-job-retry="${j.id}">실패 항목만 재시도</button>`:''}${['QUEUED','RUNNING'].includes(j.status)?`<button type="button" data-job-cancel="${j.id}">남은 작업 취소</button>`:''}${j.kind==='EXPORT'&&['DONE','PARTIAL'].includes(j.status)?`<button type="button" data-job-export="${j.id}">결과 JSON 받기</button>`:''}</div><pre>${esc(JSON.stringify(j.items,null,2))}</pre></details>`).join('')||'<p>등록한 작업이 없습니다.</p>'}`;
   }else desktopWorkflowError(root.querySelector('#desktop-jobs-list'),jobs.reason,refresh);
   if(storage.status==='fulfilled'){
    const s=storage.value,selected=new Set([...root.querySelectorAll('[data-storage-id]:checked')].map(x=>x.dataset.storageId));
    root.querySelector('#desktop-storage-list').innerHTML=`<p>${s.pending?'서버 조회 중 · ':''}조회 시각 ${desktopDate(s.asOf)} · 배포 파일 ${Number(s.bytes||0).toLocaleString()} bytes</p>${s.error?`<p role="alert">${esc(s.error)}</p>`:''}<div class="table-wrap"><table><thead><tr><th>선택</th><th>후보</th><th>용량</th><th>보존 이유 / 상태</th></tr></thead><tbody>${(s.items||[]).map(a=>`<tr><td><input type="checkbox" data-storage-id="${esc(a.id)}" ${a.eligible?'':'disabled'} ${selected.has(a.id)&&a.eligible?'checked':''} aria-label="${esc(a.component+' '+a.version)} 선택"></td><td>${esc(a.component+' '+a.version)}<small class="desktop-block code">${esc(a.id)}</small></td><td>${Number(a.size).toLocaleString()}</td><td>${esc(a.reasons.join(' · ')||'미사용 후보 · 정리 가능')}</td></tr>`).join('')}</tbody></table></div>`;
   }else desktopWorkflowError(root.querySelector('#desktop-storage-list'),storage.reason,refresh);
  }finally{tickBusy=false;}
 }
 async function previewJob(body,area){
  if(busy)return;invalidate();busy=true;try{const value=await api('/api/desktop/workspace/jobs/preview',{method:'POST',body});if(!live())return;plan={...value,area};pendingRequest=crypto.randomUUID();root.querySelector('#desktop-'+area+'-plan').innerHTML=`<p>대상 ${value.count}개 · 아직 처리하지 않았습니다. 실행 후 취소는 남은 항목에만 적용됩니다.</p><pre>${esc(JSON.stringify(value.items,null,2))}</pre>`;root.querySelector('#desktop-'+area+'-commit').disabled=false;}catch(e){if(live())desktopWorkflowError(root.querySelector('#desktop-'+area+'-plan'),e);}finally{busy=false;}}
 root.querySelector('#desktop-job-preview').onclick=()=>{const kind=root.querySelector('#desktop-job-kind').value;let body={kind};if(kind==='CREATE'){body.count=Number(root.querySelector('#desktop-job-count').value);body.prefix=root.querySelector('#desktop-job-prefix').value;}else{body.ids=[...new Set(root.querySelector('#desktop-job-ids').value.split(/[,\s]+/).filter(Boolean))];if(kind==='METADATA'){body.note=root.querySelector('#desktop-job-note').value;body.tags=root.querySelector('#desktop-job-tags').value.split(',').map(x=>x.trim()).filter(Boolean);}}return previewJob(body,'job');};
 root.querySelector('#desktop-storage-preview').onclick=()=>previewJob({kind:'CLEANUP',ids:[...root.querySelectorAll('[data-storage-id]:checked')].map(x=>x.dataset.storageId)},'storage');
 async function commit(area){if(busy||!plan||plan.area!==area||!live())return;busy=true;try{const j=await api('/api/desktop/workspace/jobs',{method:'POST',body:{planId:plan.planId,requestId:pendingRequest}});if(live()){root.querySelector('#desktop-'+area+'-plan').textContent='서버 작업 등록: '+j.id+' · 창을 닫아도 서버가 처리합니다.';invalidate();await refresh();}}catch(e){if(live())desktopWorkflowError(root.querySelector('#desktop-'+area+'-plan'),e);}finally{busy=false;}}
 root.querySelector('#desktop-job-commit').onclick=()=>commit('job');root.querySelector('#desktop-storage-commit').onclick=()=>commit('storage');
 root.querySelector('#desktop-storage-scan').onclick=async()=>{try{await api('/api/desktop/workspace/storage/scan',{method:'POST',body:{}});await refresh();}catch(e){if(live())desktopWorkflowError(root.querySelector('#desktop-storage-plan'),e);}};
 root.addEventListener('click',async e=>{const b=e.target.closest('[data-job-retry],[data-job-cancel],[data-job-export]');if(!b||!live()||busy)return;b.disabled=true;try{if(b.dataset.jobExport){const data=await api('/api/desktop/workspace/jobs/'+b.dataset.jobExport+'/export');if(live())desktopWorkflowDownload('licenses-'+b.dataset.jobExport+'.json',data);}else await api('/api/desktop/workspace/jobs/'+(b.dataset.jobRetry||b.dataset.jobCancel)+'/'+(b.dataset.jobRetry?'retry':'cancel'),{method:'POST',body:{}});await refresh();}catch(error){if(live())desktopWorkflowError(root.querySelector('#desktop-job-plan'),error);}finally{if(b.isConnected)b.disabled=false;}});
 const timer=setInterval(()=>{if(live())refresh().catch(()=>{});},2500);refresh().catch(e=>{if(live())desktopWorkflowError(root.querySelector('#desktop-job-plan'),e);});
 try{await promise;}finally{clearInterval(timer);if(root.isConnected)root.replaceChildren();}
}
async function showDesktopUnifiedDetail(id){
 if(!roleIsAdmin())return;const owner=desktopWorkflowOwner();const data=await api('/api/desktop/workspace/licenses/'+encodeURIComponent(id));if(session?.csrf!==owner)return;
 const l=data.license,m=data.metadata;let revision=m.revision,machineAction='';
 const promise=openModal({title:l.label||'사용자 실행 · 라이선스 상세',message:'표시·메모·원인 안내는 관리자 웹 전용입니다. 사용자 EXE에는 이 관리 화면이 없습니다.',html:`<div id="desktop-unified-detail">${desktopMachineSecurityMarkup(l)}<div class="kv"><div>라이선스</div><div class="code">${esc(l.id)}</div><div>상태</div><div>${desktopStatus(l.status)}</div><div>PC</div><div>${esc(l.deviceName||l.machineId||'아직 연결되지 않음')}</div><div>버전</div><div>${esc(l.appVersion||'미확인')}</div></div><label>관리자 메모<textarea id="desktop-meta-note" maxlength="500">${esc(m.note)}</textarea></label><label>태그<input id="desktop-meta-tags" maxlength="310" value="${esc(m.tags.join(', '))}"></label><button type="button" id="desktop-meta-save">서버에 메모 저장</button><div id="desktop-meta-status" role="status"></div><h3>실행 이력</h3><p>영구 실행 시각과 최근 서버 이벤트를 연결한 목록입니다. 기록 없음은 정상 판정을 뜻하지 않습니다. APK 문의 기록은 새로 수집하지 않습니다.</p><ol>${data.timeline.map(t=>`<li>${desktopDate(t.at)} · ${esc(t.label)}${t.reason?' · '+esc(t.reason):''}${t.problem?`<p>현재: ${esc(t.problem.current)}<br>다음: ${esc(t.problem.next)}</p>`:''}${t.flowId?`<small class="code desktop-block">${esc(t.flowId)}</small>`:''}</li>`).join('')}</ol><h3>관련 실행</h3><pre>${esc(JSON.stringify(data.flows,null,2))}</pre></div>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-unified-detail');const machineButton=root.querySelector('#desktop-machine-action');if(machineButton)machineButton.onclick=()=>{if(session?.csrf===owner){machineAction='unblock';modalConfirm.click();}};root.querySelector('#desktop-meta-save').onclick=async e=>{const button=e.target;if(session?.csrf!==owner)return;button.disabled=true;try{const r=await api('/api/desktop/workspace/licenses/'+encodeURIComponent(id)+'/metadata',{method:'POST',body:{expectedRevision:revision,note:root.querySelector('#desktop-meta-note').value,tags:root.querySelector('#desktop-meta-tags').value.split(',').map(t=>t.trim()).filter(Boolean)}});if(root.isConnected){revision=r.revision;root.querySelector('#desktop-meta-status').textContent='서버에 저장했습니다.';}}catch(error){if(root.isConnected)desktopWorkflowError(root.querySelector('#desktop-meta-status'),error);}finally{if(button.isConnected)button.disabled=false;}};
 try{await promise;}finally{if(root.isConnected)root.replaceChildren();}
 if(machineAction&&roleIsAdmin()&&session?.csrf===owner)await showDesktopMachineAction(l,machineAction,owner);
}
content.addEventListener('change',e=>{if(!e.target.matches('[data-license-select]'))return;desktopWorkflowOwner();const id=e.target.dataset.licenseSelect;if(e.target.checked){if(desktopSelectedLicenses.size>=100){e.target.checked=false;toast('최대 100개까지 선택하세요.',true);return;}desktopSelectedLicenses.add(id);}else desktopSelectedLicenses.delete(id);});
