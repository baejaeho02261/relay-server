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
async function showDesktopFirstDeviceApproval(){
 if(!roleIsAdmin()||!session)return;
 const owner=desktopWorkflowOwner(),base='/api/desktop/bootstrap/security-operations/keyless-approvals';
 let initial=await api(base);if(!roleIsAdmin()||session?.csrf!==owner)return;
 let requests=[],closed=false,busy=false;projection(initial);
 const done=openModal({title:'새 A 최초 기기 연결 승인',message:'외부의 신뢰할 수 있는 수단으로 고객·기기를 확인한 뒤 선택한 요청만 승인하세요.',html:'<section id="desktop-first-device-approval"><p class="small-note">새 서버 정책 연결 형식 A가 보낸 키 소유 증명을 조회합니다. 이 기록은 실제 고객 신원이나 TPM 하드웨어 증명이 아닙니다. 요청은 짧은 시간 후 만료되고 서버 재시작 시 사라집니다.</p><button type="button" id="desktop-first-device-refresh">승인 대기 새로고침</button><label>승인 대기 요청<select id="desktop-first-device-request"></select></label><dl id="desktop-first-device-details" class="server-state-artifacts"></dl><label><input type="checkbox" id="desktop-first-device-confirm"> 외부의 신뢰할 수 있는 수단으로 고객·기기를 확인했고, 아래 공개 기기키 지문과 A 발급 ID가 해당 고객의 요청임을 확인했습니다.</label><p class="small-note">확인할 수 없다면 승인하지 마세요. 실행 파일·라이선스·서버 정책의 다른 검사는 계속 적용됩니다.</p><button type="button" id="desktop-first-device-submit" disabled>확인한 기기 연결 승인</button><p id="desktop-first-device-status" role="status" aria-live="polite"></p></section>',confirmLabel:'닫기'});
 const root=document.getElementById('desktop-first-device-approval'),live=()=>!closed&&root.isConnected&&roleIsAdmin()&&session?.csrf===owner,q=id=>root.querySelector('#'+id);
 function projection(value){
  if(value?.ok!==true||!Array.isArray(value.requests)||value.requests.length>256)throw Error('승인 대기 응답을 확인하지 못했습니다.');
  const seen=new Set();return value.requests.map(row=>{
   if(!row||!/^[a-f0-9]{48}$/.test(row.id||'')||seen.has(row.id)||!/^[A-F0-9]{24}$/.test(row.launcherId||'')||!/^[a-f0-9]{128}$/.test(row.launcherSha512||'')||!/^[A-F0-9]{64}$/.test(row.appKeyId||'')||!/^[A-F0-9]{64}$/.test(row.persistentKeyId||'')||!Number.isSafeInteger(row.createdAt)||!Number.isSafeInteger(row.expiresAt)||row.createdAt<1||row.expiresAt<=row.createdAt||row.status!=='PENDING_APPROVAL'||row.proof!=='PERSISTENT_KEY_POSSESSION'||row.hardwareAttested!==false)throw Error('승인 대기 요청의 형식을 확인하지 못했습니다.');
   seen.add(row.id);return {id:row.id,launcherId:row.launcherId,launcherSha512:row.launcherSha512,appKeyId:row.appKeyId,persistentKeyId:row.persistentKeyId,createdAt:row.createdAt,expiresAt:row.expiresAt};
  });
 }
 const selected=()=>requests.find(row=>row.id===q('desktop-first-device-request').value);
 function controls(){if(!live())return;for(const el of root.querySelectorAll('button,input,select'))el.disabled=busy;q('desktop-first-device-submit').disabled=busy||!selected()||!q('desktop-first-device-confirm').checked;}
 function details(){
  q('desktop-first-device-confirm').checked=false;const row=selected(),area=q('desktop-first-device-details');area.replaceChildren();
  if(row)for(const [label,value]of [['요청 ID',row.id],['A 발급 ID',row.launcherId],['발급 A SHA-512',row.launcherSha512],['공개 기기키 지문',row.persistentKeyId],['현재 앱 키 지문',row.appKeyId],['승인 만료 (한국 시간)',new Date(row.expiresAt).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'})]]){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;area.append(dt,dd);}
  controls();
 }
 function render(value){requests=projection(value);const select=q('desktop-first-device-request');select.replaceChildren();const blank=document.createElement('option');blank.value='';blank.textContent=requests.length?'요청 선택':'현재 승인 대기 없음';select.append(blank);for(const row of requests){const option=document.createElement('option');option.value=row.id;option.textContent=row.launcherId+' · '+row.persistentKeyId.slice(0,12)+'…';select.append(option);}details();}
 function status(message){if(live())q('desktop-first-device-status').textContent=message;}
 function failure(error){
  const messages={KEYLESS_REQUEST_EXPIRED:'요청이 만료되었습니다. 현재 대기 목록을 새로고침하세요.',KEYLESS_APPROVAL_MISMATCH:'선택한 기기키 또는 A 발급 정보가 현재 요청과 다릅니다. 다시 조회하고 외부에서 확인하세요.',KEYLESS_RATE_LIMIT:'요청이 많아 잠시 후 다시 조회해야 합니다.',KEYLESS_PROOF_INVALID:'서버가 키 소유 증명을 확인하지 못했습니다.',KEYLESS_REQUEST_INVALID:'서버가 요청을 확인하지 못했습니다. 대기 목록을 다시 조회하세요.'};
  status(messages[error.code]||'처리 완료를 확인하지 못했습니다. 현재 대기 목록을 다시 조회하세요.');
 }
 q('desktop-first-device-request').onchange=()=>{if(!busy&&live())details();};
 q('desktop-first-device-confirm').onchange=controls;
 q('desktop-first-device-refresh').onclick=async()=>{if(busy||!live())return;busy=true;controls();try{const value=await api(base);if(live()){render(value);status('현재 승인 대기를 조회했습니다. 승인할 기기를 다시 확인하세요.');}}catch(error){if(live())failure(error);}finally{busy=false;controls();}};
 q('desktop-first-device-submit').onclick=async()=>{
  if(busy||!live()||!q('desktop-first-device-confirm').checked)return;const row=selected();if(!row)return;
  const snapshot={...row};busy=true;controls();
  try{
   const response=await api(base+'/'+encodeURIComponent(snapshot.id)+'/approve',{method:'POST',body:{identityConfirmed:true,persistentKeyId:snapshot.persistentKeyId,launcherId:snapshot.launcherId}});
   if(!live())return;
   if(response?.version!==1||response.id!==snapshot.id||response.status!=='APPROVED'||response.hardwareAttested!==false||!Number.isSafeInteger(response.expiresAt))throw Error('승인 응답을 확인하지 못했습니다.');
   requests=requests.filter(item=>item.id!==snapshot.id);render({ok:true,requests:requests.map(item=>({...item,status:'PENDING_APPROVAL',proof:'PERSISTENT_KEY_POSSESSION',hardwareAttested:false}))});
   status('선택한 기기 연결 승인을 서버에 기록했습니다. A의 실행 완료를 확인한 것은 아닙니다.');
  }catch(error){if(live()){q('desktop-first-device-confirm').checked=false;failure(error);}}finally{busy=false;controls();}
 };
 try{render(initial);initial=null;await done;}finally{closed=true;requests=[];initial=null;if(root.isConnected)root.replaceChildren();}
}
// Only an operation nonce is retained in this tab while the server restarts.
// No registration data, keys or reset approval is persisted in the browser.
let desktopPendingRegistrationReset=null;
async function showDesktopRegistrationReset(){
 if(!roleIsAdmin()||!session)return;
 const owner=desktopWorkflowOwner(),base='/api/desktop/bootstrap/security-operations/registration-reset',scope='ABO_LICENSES_ISSUANCE_OPERATIONS_V1';
 let operationId=desktopPendingRegistrationReset?.id||'',closed=false,busy=false,completed=false,submitted=!!operationId,pollTimer=null,wakePoll=null,controller=null;
 let state=await api(base+(operationId?'?requestId='+encodeURIComponent(operationId):''));
 if(!roleIsAdmin()||session?.csrf!==owner)return;
 if(state.scope!==scope||state.confirmation!=='전체 초기화'||!Number.isSafeInteger(state.epoch))throw Error('초기화 범위와 서버 상태를 확인하지 못했습니다. 새로고침하세요.');
 if(!operationId&&['QUEUED','RUNNING'].includes(state.operation?.status)&&/^[a-f0-9]{64}$/.test(state.operation.id||'')){
  operationId=state.operation.id;submitted=true;desktopPendingRegistrationReset={id:operationId};
 }
 const done=openModal({title:'등록 데이터 전체 초기화',message:'등록한 A/B/O 파일·라이선스·발급 내역과 관련 운영 데이터를 모두 지웁니다. 초기화 후 파일과 라이선스를 다시 등록해야 합니다.',html:`<section id="desktop-registration-reset"><p class="desktop-reset-warning"><strong>이 작업은 되돌릴 수 없습니다.</strong> 사용 중인 A/B/O의 서버 인증도 종료됩니다.</p><h4>지울 데이터 · 조회 시점 수량</h4><div id="desktop-reset-counts" class="kv"></div><p class="small-note">배포 명세·패킹 기록·실행 세션·기기 연결·무결성 기준·운영 메모와 작업 내역도 초기화합니다. 처리 시점에 등록된 데이터 전체에 적용됩니다.</p><p class="small-note">서버 키·관리자 로그인 수단·보안 정책·철회 기록·보안 감사 기록은 유지합니다. PC에 저장된 EXE 파일은 바뀌지 않습니다.</p><label>삭제 범위를 확인했다면 <strong>전체 초기화</strong> 입력<input id="desktop-reset-confirmation" type="text" maxlength="6" autocomplete="off" spellcheck="false"></label><div class="actions"><button type="button" id="desktop-reset-submit" class="danger" disabled>등록 데이터 전체 초기화</button><button type="button" id="desktop-reset-check">서버에서 결과 확인</button><button type="button" id="desktop-reset-login" hidden>다시 로그인</button></div><p id="desktop-reset-status" role="status" aria-live="polite"></p><p class="small-note">실행 시 관리자 비밀번호 또는 패스키를 다시 확인합니다. 초기화 중 서버가 잠시 연결을 끊을 수 있으며, 재로그인 후 이 버튼에서 결과를 확인할 수 있습니다.</p></section>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-registration-reset'),q=id=>root.querySelector('#'+id),live=()=>!closed&&root.isConnected&&roleIsAdmin()&&session?.csrf===owner;
 const countNames={artifacts:'등록 A/B/O 파일',activeArtifacts:'운영 중 A/B/O',licenses:'라이선스',issuedLaunchers:'일회용 A 발급',flows:'A/B 실행 세션',overlays:'O 실행 세션',issueReceipts:'발급 처리 내역',packingEvidence:'패킹 기록',releaseManifests:'배포 명세'};
 function renderCounts(){
  const number=value=>Number.isSafeInteger(value)&&value>=0?value.toLocaleString()+'건':'확인되지 않음';
  const counts=state.counts||{},related=state.relatedCounts||{};
  q('desktop-reset-counts').innerHTML=Object.entries(countNames).map(([key,label])=>`<div>${esc(label)}</div><div>${esc(number(counts[key]))}</div>`).join('')+[['기기 연결',related.machine?.bindings],['무결성 기준',related.integrity?.baselines],['운영 작업',related.workspace?.jobs]].map(([label,value])=>`<div>${esc(label)}</div><div>${esc(number(value))}</div>`).join('');
 }
 function status(message,kind='pending'){if(live()){q('desktop-reset-status').textContent=message;q('desktop-reset-status').dataset.state=kind;}}
 function controls(){if(!live())return;q('desktop-reset-confirmation').disabled=busy||submitted||completed;q('desktop-reset-submit').disabled=busy||submitted||completed||q('desktop-reset-confirmation').value!=='전체 초기화';q('desktop-reset-check').disabled=busy;}
 function remember(id){operationId=id;submitted=true;desktopPendingRegistrationReset={id};controls();}
 function wait(){return new Promise(resolve=>{wakePoll=resolve;pollTimer=setTimeout(()=>{pollTimer=null;wakePoll=null;resolve();},2000);});}
 function friendly(error){
  const messages={REGISTRATION_RESET_REQUEST_INVALID:'초기화 확인 문구와 요청 범위를 확인하세요.',REGISTRATION_RESET_EPOCH_CONFLICT:'다른 초기화 작업으로 서버 상태가 바뀌었습니다. 창을 닫고 다시 열어 현재 범위를 확인하세요.',REGISTRATION_RESET_IN_PROGRESS:'다른 초기화 작업이 진행 중입니다. 서버에서 결과를 확인하세요.',REGISTRATION_RESET_CONFLICT:'초기화 준비 중 서버 상태가 변경되었습니다. 창을 다시 열어 현재 상태를 확인하세요.',REGISTRATION_RESET_AUTHORIZATION_CONFLICT:'서버 유지보수 초기화가 이미 예약되어 있습니다. 해당 작업의 완료 후 다시 확인하세요.',REGISTRATION_RESET_SERVICE_UNAVAILABLE:'서버가 현재 초기화 요청을 받을 수 없습니다. 서버 상태를 확인한 뒤 다시 시도하세요.',REGISTRATION_RESET_RECEIPT_CAPACITY:'보존된 초기화 기록의 한도에 도달했습니다. 서버 운영 점검이 필요합니다.',REGISTRATION_RESET_NOT_AUTHORIZED:'이 초기화 요청의 관리자 승인을 확인하지 못했습니다. 다시 승인하세요.',REGISTRATION_RESET_MAINTENANCE:'서버가 초기화 중입니다. 재로그인 후 결과를 확인하세요.'};
  return messages[error.code]||error.message||'초기화 요청 결과를 확인하지 못했습니다.';
 }
 async function readStatus(){
  controller=new AbortController();const timeout=setTimeout(()=>controller?.abort(),8000);
  try{
   const response=await fetch(base+'?requestId='+encodeURIComponent(operationId),{method:'GET',headers:{Accept:'application/json'},credentials:'same-origin',cache:'no-store',signal:controller.signal});
   if(response.status===401){const error=Error('로그인이 만료되었습니다.');error.status=401;throw error;}
   const value=await response.json();
   if(!response.ok||value?.ok!==true){const error=Error(value?.message||'서버의 초기화 결과를 확인하지 못했습니다.');error.code=value?.error;error.status=response.status;throw error;}
   if(value.scope!==scope)throw Error('초기화 결과의 범위가 요청과 다릅니다.');return value;
  }finally{clearTimeout(timeout);controller=null;}
 }
 async function observe(){
  if(busy||!live()||!operationId)return;busy=true;controls();const expected=operationId,until=Date.now()+120000;
  try{
   while(live()&&operationId===expected&&Date.now()<until){
    try{
     const value=await readStatus();if(!live()||operationId!==expected)return;
     const operation=value.operation;
     if(operation&&operation.id!==expected)throw Error('다른 초기화 작업의 응답입니다. 완료로 확인할 수 없습니다.');
     if(operation?.status==='COMPLETE'&&Number.isSafeInteger(operation.completedAt)&&operation.completedAt>0){
      state=value;completed=true;renderCounts();q('desktop-reset-confirmation').value='';
      if(desktopPendingRegistrationReset?.id===expected)desktopPendingRegistrationReset=null;
      desktopSelectedLicenses.clear();
      if(typeof desktopPendingIssue!=='undefined')desktopPendingIssue=null;
      if(typeof desktopPendingRevoke!=='undefined')desktopPendingRevoke=null;
      if(typeof desktopPendingLauncher!=='undefined')desktopPendingLauncher=null;
      if(typeof desktopInvalidatePanels==='function')desktopInvalidatePanels();
      status('등록 데이터 전체 초기화가 완료되었습니다. A/B/O 파일과 라이선스를 새로 등록할 수 있습니다.','success');return;
     }
     if(operation&&!['QUEUED','RUNNING'].includes(operation.status))throw Error('서버의 초기화 진행 상태를 확인하지 못했습니다.');
     status(operation?'초기화 요청을 저장했습니다. 서버 처리와 재접속 후 완료 결과를 확인하고 있습니다.':'이 요청의 접수·완료 여부를 아직 확인하지 못했습니다. 같은 요청의 상태만 조회하고 있습니다.');
    }catch(error){
     if(!live())return;
     if(error.status===401){q('desktop-reset-login').hidden=false;status('서버 연결이 복구되면 다시 로그인한 뒤 [초기화 결과 확인]을 누르세요. 아직 완료로 확인하지 않았습니다.','pending');return;}
     status('서버 연결 또는 처리 결과를 아직 확인하지 못했습니다. 재접속을 기다리고 있습니다.','pending');
    }
    await wait();
   }
   if(live())status('완료 여부를 아직 확인하지 못했습니다. [서버에서 결과 확인]으로 같은 요청을 확인하세요. 초기화를 다시 실행하지 않습니다.','pending');
  }finally{busy=false;controls();}
 }
 q('desktop-reset-confirmation').oninput=controls;
 q('desktop-reset-submit').onclick=async()=>{
  if(busy||submitted||completed||!live())return;
  if(q('desktop-reset-confirmation').value!=='전체 초기화'){status('확인 문구를 정확히 입력하세요: 전체 초기화','error');return;}
  const requestId=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
  remember(requestId);busy=true;controls();status('확인한 초기화 요청에 대한 관리자 재인증을 진행합니다.');
  try{
   const result=await api(base,{method:'POST',body:{requestId,scope,confirmation:'전체 초기화',expectedEpoch:state.epoch}});
   if(!live())return;
   if(result.operation?.id!==requestId||!['QUEUED','RUNNING','COMPLETE'].includes(result.operation.status))throw Error('요청한 초기화 작업의 접수 결과를 확인하지 못했습니다.');
   remember(requestId);status('초기화 요청을 저장했습니다. 서버 처리 결과를 확인합니다.');
  }catch(error){
   // Never resend a destructive POST after losing a response. Retain the
   // nonce even if restart/SSE has already closed this modal for login.
   const rejected=error.status>=400&&error.status<500||/재인증을 취소|작업 화면 또는 로그인 상태가 변경|작업 화면 또는 로그인 상태가 변경되어/.test(error.message||'');
   if(rejected){if(desktopPendingRegistrationReset?.id===requestId)desktopPendingRegistrationReset=null;operationId='';submitted=false;}
   if(!live())return;
   status(friendly(error)+(operationId?' 서버에서 같은 요청의 결과를 확인합니다.':''),'error');
  }finally{busy=false;controls();}
  if(live()&&operationId)await observe();
 };
 q('desktop-reset-check').onclick=async()=>{
  if(busy||!live())return;
  if(operationId)return observe();
  busy=true;controls();
  try{const value=await api(base);if(!live())return;if(value.scope!==scope||!Number.isSafeInteger(value.epoch))throw Error('초기화 범위를 확인하지 못했습니다.');state=value;renderCounts();status('서버에서 현재 등록 수량을 확인했습니다.');}
  catch(error){if(live())status(friendly(error),'error');}finally{busy=false;controls();}
 };
 q('desktop-reset-login').onclick=()=>{if(live())showLogin();};
 renderCounts();controls();
 if(operationId)void observe();
 else if(state.operation?.status==='COMPLETE')status('이전 초기화 완료 기록이 있습니다. 위 수량은 현재 서버의 등록 데이터입니다.');
 try{await done;}finally{
  closed=true;controller?.abort();if(pollTimer!==null)clearTimeout(pollTimer);const wake=wakePoll;wakePoll=null;if(wake)wake();
  q('desktop-reset-confirmation').oninput=null;q('desktop-reset-submit').onclick=null;q('desktop-reset-check').onclick=null;q('desktop-reset-login').onclick=null;
  state=null;if(root.isConnected)root.replaceChildren();
 }
}
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
 let busy=false,closed=false,waitTimer=null,wakeWait=null,ownProfileFile=null,nextPackedJob='';
 const promise=openModal({title:'패킹 · 암호화 · 난독화',message:'실제 실행 파일 변환과 암호화 보관을 구분합니다. 파일 등록과 일회용 A 발급은 A / B / O 실행 파일 배포에서 진행하세요.',html:`<div id="desktop-protection-modal"><fieldset><legend>조회 시점 운영 A/B/O · 서버 패킹 기록</legend><p class="small-note">기록은 서버 자체 엔진 또는 신뢰한 외부 워커가 반환한 EXE 템플릿의 해시를 연결합니다. 기록만으로 모든 함수 보호나 Windows 실행 검증이 확인되지는 않습니다.</p><div id="desktop-protection-active" role="status"></div><p class="small-note" id="desktop-protection-issued-config">A의 발급 설정 형식은 게시된 템플릿에 따라 다릅니다. 새 서버 정책 연결 형식은 공개 연결 정보와 최초 기기 승인을 사용합니다. 기존 발급 파일은 자동으로 전환되지 않습니다.</p></fieldset><fieldset><legend>변환·보관 작업 대상 · 등록된 A/B/O 후보</legend><p class="small-note">작업에는 A/B/O 세 후보가 필요합니다. 실제 변환 결과는 Windows 시험과 새 승인·명세로 등록한 뒤 게시해야 발급·다운로드 경로에 연결됩니다.</p>${['A','B','O'].map(c=>`<label>${c} 후보<select data-protection-candidate="${c}"></select></label>`).join('')}</fieldset><fieldset><legend>암호화 보관 파일 (.gcpack)</legend><p class="small-note">선택한 파일의 복사본을 압축·암호화해 보관합니다. A 발급·B/O 배포에는 적용되지 않습니다. 직접 실행하는 EXE가 아니며 함수 가상화·실행 코드 난독화도 수행하지 않습니다. 복호화 키는 서버에만 설정하고 이 화면에 올리지 않습니다.</p><label>보관 대상<select id="desktop-custom-kind"><option value="artifacts">위에서 선택한 A/B/O 파일 복사본</option><option value="sources">매니페스트에 등록된 Railway 폴더 소스</option></select></label><button type="button" id="desktop-custom-selected">암호화 보관 파일 만들기</button><div id="desktop-custom-result" role="status" aria-live="polite"></div></fieldset><fieldset><legend>서버 정책 연결 · Cozy v2</legend><p class="small-note">정책 코드를 서버에 보관하고 실행 권한 조건을 서버에서 검사합니다. 추가 함수는 새 A/B/O 클라이언트의 인증된 서버 연산 호출로 실행합니다. 등록한 함수 ID와 인수를 제품의 호출 지점에 연결해야 하며, 정책 등록만으로 기존 코드가 자동 변경되지는 않습니다. 새 A/B/O에는 공개 정책 식별자·해시를 연결하며 복호화 키와 정책 바이트코드를 넣지 않습니다. 임의의 Delphi 소스 자동 변환이나 EXE 전체 암호화는 지원하지 않습니다.</p><p class="small-note">새 v2 슬롯으로 다시 빌드한 A/B/O가 필요하며 서버 정책 연결 전에는 실행되지 않습니다. 기존 VM v1 파일의 내장 키는 이 작업으로 제거되지 않습니다. 새 A의 최초 기기 연결은 별도 관리자 승인이 필요하고 Windows 실행 시험도 별도입니다.</p><label>서버 정책 JSON (선택, 최대 64 KiB)<input type="file" id="desktop-own-profile-file" accept=".json,application/json"></label><button type="button" id="desktop-own-profile-clear">선택한 정책 지우기</button><p class="small-note" id="desktop-own-profile-status">기본 정책: 필수 서버 시작 함수 1만 포함합니다.</p><details><summary>서버 정책 JSON 형식</summary><p class="small-note">version: 1, functions: 최대 15개, 각 함수의 id: 2~65535, args: 0~8, body: 정수식 IR입니다. 필수 함수 1은 바꿀 수 없습니다. 지원 연산은 arg(index), const(value: Int32), not(value), eq/and/or/add/xor(left, right), if(condition, then, else)입니다. JavaScript·네이티브 함수·실행 파일은 정책으로 올리지 않습니다. 정책 내용은 서버에 저장하며 결과 화면과 EXE에 포함하지 않습니다.</p></details><button type="button" id="desktop-own-pack-selected">선택한 A/B/O 서버 정책 연결 후보 만들기</button><div id="desktop-own-pack-result" role="status" aria-live="polite"></div></fieldset><fieldset><legend>외부 실행 파일 보호 · VMProtect 워커 연동</legend><p class="small-note">별도 VMProtect 워커와 검토한 프로필이 필요합니다. 실제 보호 범위는 도구와 프로필에 따릅니다. 결과와 서버 기록은 미승인 후보이며 Windows 시험·새 EXE 승인·후보 등록·게시가 필요합니다. 기존 형식 A의 발급 평문은 외부 템플릿 변환만으로 없어지지 않습니다.</p><button type="button" id="desktop-pack-selected">선택한 A/B/O EXE 변환 후보 만들기</button><div id="desktop-pack-result" role="status" aria-live="polite"></div></fieldset></div>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-protection-modal');
 const live=()=>!closed&&root.isConnected&&roleIsAdmin()&&session?.csrf===owner;
 function lock(value){busy=value;for(const e of root.querySelectorAll('button,input,select,textarea'))e.disabled=value;}
 function selected(){const body=Object.fromEntries(['A','B','O'].map(c=>[c,root.querySelector(`[data-protection-candidate="${c}"]`).value]));if(Object.values(body).some(x=>!x))throw Error('A, B, O 후보를 모두 선택하세요.');return body;}
 function wait(ms){return new Promise(resolve=>{wakeWait=resolve;waitTimer=setTimeout(()=>{waitTimer=null;wakeWait=null;resolve();},ms);});}
 function boundServerTemplate(artifact,role){const p=artifact?.ownProtection;return p?.engine==='COZY_SERVER_POLICY_V2'&&p.state==='BOUND'&&p.version===2&&p.role===role&&p.slotBytes===4096&&Number.isSafeInteger(p.functionCount)&&p.functionCount>0&&p.functionCount<=16&&/^[a-f0-9]{64}$/.test(p.policyId||'')&&/^[a-f0-9]{128}$/.test(p.policySha512||'')&&p.execution==='SERVER_ONLY'&&p.authenticationRequired===true&&p.slotContainsSecret===false&&p.clientBytecode===false&&p.windowsVerified===false&&p.arbitraryDelphiTranslation===false;}
 function linkedRecord(artifact){const e=artifact?.packingEvidence;return !!artifact&&e?.scope==='TRANSFORMED_TEMPLATE'&&/^[a-f0-9]{128}$/.test(e.receiptId||'')&&/^[a-f0-9]{32}$/.test(e.jobId||'')&&e.outputSha512===artifact.sha512&&e.windowsVerified===false&&e.protectionVerified===false;}
 const ownProfileInput=root.querySelector('#desktop-own-profile-file'),ownProfileStatus=root.querySelector('#desktop-own-profile-status');
 ownProfileInput.onchange=()=>{if(busy||!live())return;ownProfileFile=ownProfileInput.files?.[0]||null;ownProfileStatus.textContent=ownProfileFile?'선택됨: '+ownProfileFile.name+' · 서버 정책 연결 시 읽고 검사합니다.':'기본 정책: 필수 서버 시작 함수 1만 포함합니다.';};
 root.querySelector('#desktop-own-profile-clear').onclick=()=>{if(busy||!live())return;ownProfileFile=null;ownProfileInput.value='';ownProfileStatus.textContent='기본 정책: 필수 서버 시작 함수 1만 포함합니다.';};
 async function readOwnProfile(file){
  if(!/\.json$/i.test(file.name||''))throw Error('사용자 함수 프로필은 .json 파일을 선택하세요.');
  if(!Number.isSafeInteger(file.size)||file.size<1||file.size>65536)throw Error('사용자 함수 프로필은 64 KiB 이하의 JSON 파일이어야 합니다.');
  const text=await file.text();if(!live())return null;
  if(typeof text!=='string'||new Blob([text]).size>65536)throw Error('사용자 함수 프로필 JSON은 UTF-8 기준 64 KiB 이하여야 합니다.');
  let profile;try{profile=JSON.parse(text.replace(/^\uFEFF/,''));}catch(_){throw Error('사용자 함수 프로필 JSON 형식이 올바르지 않습니다.');}
  const shape=(x,keys)=>!!x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
  if(!shape(profile,['version','functions'])||profile.version!==1||!Array.isArray(profile.functions)||profile.functions.length>15||profile.functions.some(fn=>!shape(fn,['id','args','body'])||!Number.isInteger(fn.id)||fn.id<2||fn.id>65535||!Number.isInteger(fn.args)||fn.args<0||fn.args>8||!fn.body||typeof fn.body!=='object'||Array.isArray(fn.body)||!['arg','const','not','eq','and','or','add','xor','if'].includes(fn.body.op)))throw Error('프로필은 version: 1과 functions의 id·args·body 정수식 IR만 지원합니다. 스크립트나 네이티브 함수는 사용할 수 없습니다.');
  return profile;
 }

 const activeArea=root.querySelector('#desktop-protection-active');activeArea.className='table-wrap';
 const activeTable=document.createElement('table'),tableHead=document.createElement('thead'),tableBody=document.createElement('tbody');
 tableHead.innerHTML='<tr><th>실행 파일</th><th>운영 SHA-512</th><th>서버 템플릿 변환 기록</th></tr>';activeTable.append(tableHead,tableBody);
 for(const c of ['A','B','O']){
  const artifact=(listing.candidates||[]).find(a=>a.component===c&&a.id===listing.active?.[c]),evidence=artifact?.packingEvidence;
  const linked=linkedRecord(artifact),own=boundServerTemplate(artifact,c);
  const row=document.createElement('tr');row.dataset.activePacking=c;
  for(const value of [c,artifact?artifact.sha512:'등록된 운영 파일 없음',artifact?.ownProtection?.engine==='COZY_VM_V1'?(artifact.ownProtection.state==='SEALED'?'기존 VM v1 · 내장 키 남음 · 새 형식으로 재빌드 필요':'기존 VM v1 템플릿 · 새 형식으로 재빌드 필요'):linked?(own?'서버 정책 연결 기록 확인 · 정책 정의 '+artifact.ownProtection.functionCount+'개 · Windows 시험 별도':artifact.ownProtection?.engine==='COZY_SERVER_POLICY_V2'?'서버 기록 연결됨 · 정책 연결 형식 확인 필요':'외부 워커 변환 기록 연결됨 · 시험·보호 범위 별도 확인'):'연결된 서버 패킹 기록 없음']){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}
  if(linked){const receipt=document.createElement('code');receipt.textContent='기록 ID: '+evidence.receiptId;row.lastElementChild.append(document.createElement('br'),receipt);}
  tableBody.append(row);
 }
 activeArea.append(activeTable);
 const activeArtifacts=['A','B','O'].map(c=>(listing.candidates||[]).find(a=>a.component===c&&a.id===listing.active?.[c]));
 const ownCohort=activeArtifacts.every((a,i)=>boundServerTemplate(a,['A','B','O'][i])&&linkedRecord(a))&&new Set(activeArtifacts.map(a=>a.packingEvidence.jobId)).size===1;
 if(ownCohort)root.querySelector('#desktop-protection-issued-config').textContent='조회 시점 운영 A/B/O는 같은 작업의 서버 정책 연결 v2 묶음입니다. 정책은 인증된 서버에서 실행하며 새 형식의 슬롯에는 복호화 키·바이트코드가 없습니다. A의 공개 발급 설정은 암호화 비밀이 아니며 최초 기기 승인이 필요합니다. Windows 실행 시험은 별도 확인해야 합니다.';
 else if(activeArtifacts.some(a=>a?.ownProtection?.engine==='COZY_VM_V1'&&a.ownProtection.state==='SEALED'))root.querySelector('#desktop-protection-issued-config').textContent='기존 VM v1 내장 키 남음: 운영 파일에 복호화 키가 포함된 기존 형식입니다. 새 v2로 다시 빌드·서버 정책 연결·시험·승인·게시해야 전환됩니다. 기존 파일을 키 제거 완료로 간주하지 마세요.';
 else if(activeArtifacts.some(a=>a?.ownProtection?.engine==='COZY_SERVER_POLICY_V2'))root.querySelector('#desktop-protection-issued-config').textContent='운영 A/B/O의 정책 연결 상태·역할·같은 작업의 기록을 확인하지 못했습니다. 새 후보의 서버 정책 연결·Windows 시험·승인·게시 상태를 확인하세요.';
 for(const c of ['A','B','O']){
  const select=root.querySelector(`[data-protection-candidate="${c}"]`);
  select.innerHTML=`<option value="">${c} 후보 선택</option>`+(listing.candidates||[]).filter(x=>x.component===c).map(x=>`<option value="${esc(x.id)}">${esc(x.version)} · ${esc(x.sha512.slice(0,12))}${x.active?' · 현재 운영':''}${boundServerTemplate(x,c)?' · 서버 정책 연결됨':x.ownProtection?.engine==='COZY_SERVER_POLICY_V2'&&x.ownProtection.state==='UNSEALED'?' · 서버 정책 연결 전 템플릿':x.ownProtection?.engine==='COZY_VM_V1'?(x.ownProtection.state==='SEALED'?' · 기존 VM v1 내장 키 남음':' · 기존 VM v1 템플릿'):''}</option>`).join('');
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
   while(live()&&response.job.status==='RUNNING'&&Date.now()<stop){area.textContent='서버에서 보관용 복사본을 압축·암호화합니다. A 발급·B/O 배포에는 적용되지 않습니다.';await wait(1000);if(!live())return;response=await api('/api/desktop/bootstrap/packing/custom/jobs/'+id);}
   if(!live())return;if(response.job.status!=='COMPLETE')throw Error(response.job.error||'암호화 보관 파일 완료를 확인하지 못했습니다.');
   area.replaceChildren();const note=document.createElement('p');note.textContent=`보관 파일 암호화 완료: ${response.job.fileCount}개 파일 / ${response.job.size}바이트. 내려받기는 10분 후 만료됩니다. A 발급·B/O 배포에는 적용되지 않습니다.`;area.append(note);
   const link=document.createElement('a');link.href='/api/desktop/bootstrap/packing/custom/jobs/'+id+'/download';link.textContent='암호화 보관 파일 (.gcpack) 받기';link.setAttribute('download','');area.append(link);
   const digest=document.createElement('pre');digest.textContent='SHA-512: '+response.job.sha512;area.append(digest);
  }catch(e){if(live())desktopWorkflowError(area,e);}finally{if(live())lock(false);}
 };
 async function createPackingCandidates(mode){
  if(busy||!live())return;lock(true);const own=mode==='COZY_SERVER_POLICY_V2',area=root.querySelector(own?'#desktop-own-pack-result':'#desktop-pack-result');
  try{
   const body=selected();if(own){body.mode='COZY_SERVER_POLICY_V2';const file=ownProfileFile;if(file){const profile=await readOwnProfile(file);if(!live())return;body.profile=profile;}}
   const status=await api('/api/desktop/bootstrap/packing/status');if(!live())return;
   if(own){if(!status.ownEngine?.configured||status.ownEngine.engine!=='COZY_SERVER_POLICY_V2'||status.ownEngine.scope!=='SERVER_POLICY_BINDING')throw Error('서버 정책 연결 엔진을 사용할 수 없습니다. 새 v2 슬롯과 서버 정책 형식을 지원하는지 확인하세요.');}
   else if(!status.packing?.configured)throw Error('패킹 워커 설정 필요: '+(status.packing?.reason||'PACKING_WORKER_NOT_CONFIGURED'));
   let response=await api('/api/desktop/bootstrap/packing/jobs',{method:'POST',body});
   const id=encodeURIComponent(response.job.id),stop=Date.now()+600000;
   while(live()&&response.job.status==='RUNNING'&&Date.now()<stop){area.textContent=(own?'서버 정책 연결 진행: ':'외부 패킹 진행: ')+(response.job.component||'시작')+' · 운영 발급 전 Windows 시험·새 승인 필요';await wait(2000);if(!live())return;response=await api('/api/desktop/bootstrap/packing/jobs/'+id);}
   if(!live())return;if(response.job.status!=='COMPLETE'){const failure=response.job.error||'변환 완료를 확인하지 못했습니다.',error=Error(failure);if(/^[A-Z][A-Z0-9_]{1,119}$/.test(failure))error.code=failure;throw error;}
   if(own&&(response.job.engine!=='COZY_SERVER_POLICY_V2'||response.job.protectionScope!=='SERVER_POLICY_BINDING'))throw Error('요청한 서버 정책 연결 엔진으로 생성한 결과인지 확인하지 못했습니다.');
   area.replaceChildren();const note=document.createElement('p');note.textContent=own?'서버 정책 연결 v2 미승인 후보 생성 완료. 정책 내용과 연산은 서버에 두고 EXE에는 공개 정책 식별자·해시만 연결했습니다. EXE 전체 암호화·함수 자동 변환이나 Windows 실행 성공을 뜻하지 않습니다. 최종 EXE에 새 공개 승인을 만든 뒤 [보호 결과 등록]에서 새 명세 생성과 세 후보 등록을 진행하세요. 운영 게시 전 실제 Windows 시험과 최초 기기 승인이 필요합니다.':'미승인 외부 EXE 템플릿 변환 후보 생성 완료. 아래 정확한 출력 해시로 Windows 시험 및 새 EXE 승인을 수행한 뒤 A / B / O 실행 파일 배포에서 후보를 등록하고 게시해야 합니다. 기존 형식 A의 새 평문 JSON 보호는 완료되지 않았습니다.';area.append(note);
   const expiry=document.createElement('p');expiry.textContent='10분 후 내려받기 만료. 기존 승인 JSON은 재사용할 수 없습니다. 이 작업은 현재 운영 파일을 게시하거나 A를 발급하지 않습니다.';area.append(expiry);
   const receipts=response.job.evidence?.scope==='TRANSFORMED_TEMPLATES'?response.job.evidence.receipts:null;
   const record=document.createElement('p');record.textContent=receipts&&['A','B','O'].every(c=>/^[a-f0-9]{128}$/.test(receipts[c]||''))?(own?'A/B/O 서버 정책 연결 기록 저장됨 · 실제 Windows 실행 검증은 별도 확인':'A/B/O 워커 변환 기록 저장됨 · 함수 가상화·Windows 실행 검증은 별도 확인'):'연결할 A/B/O 서버 변환 기록을 확인하지 못했습니다. 보호 적용 완료로 간주하지 마세요.';area.append(record);
   for(const c of ['A','B','O']){const output=response.job.outputs?.[c];if(!output||!/^[a-f0-9]{128}$/.test(output.sha512||''))continue;const digest=document.createElement('pre');digest.textContent=c+' 출력 SHA-512: '+output.sha512+(/^[a-f0-9]{128}$/.test(receipts?.[c]||'')?'\n서버 변환 기록 ID: '+receipts[c]:'');area.append(digest);}
   const register=document.createElement('button');register.type='button';register.textContent='보호 결과 등록';register.onclick=()=>{if(live()&&!busy){nextPackedJob=response.job.id;modalCancel.click();}};area.append(register);
   for(const c of ['A','B','O','report']){const a=document.createElement('a');a.href='/api/desktop/bootstrap/packing/jobs/'+id+'/'+c;a.textContent=c==='report'?'SHA-512 작업 보고서':c+(own?' 미승인 서버 정책 연결 EXE':' 미승인 외부 패킹 EXE');a.setAttribute('download','');const div=document.createElement('div');div.append(a);area.append(div);}
  }catch(e){if(live())desktopWorkflowError(area,e);}finally{if(live())lock(false);}
 }
 root.querySelector('#desktop-own-pack-selected').onclick=()=>createPackingCandidates('COZY_SERVER_POLICY_V2');
 root.querySelector('#desktop-pack-selected').onclick=()=>createPackingCandidates('EXTERNAL');
 try{await promise;}finally{closed=true;if(waitTimer!==null)clearTimeout(waitTimer);waitTimer=null;const wake=wakeWait;wakeWait=null;if(wake)wake();ownProfileFile=null;listing=null;if(root.isConnected)root.replaceChildren();}
 if(nextPackedJob&&roleIsAdmin()&&session?.csrf===owner)await showDesktopPackedRelease(nextPackedJob);
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
