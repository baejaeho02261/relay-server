'use strict';
async function showDesktopOverlay(){
 if(!roleIsAdmin())return;
 const owner=desktopWorkflowOwner(),endpoint='/api/desktop/bootstrap/overlay',pluginEndpoint=endpoint+'/plugins';
 let [model,plugins]=await Promise.all([api(endpoint),api(pluginEndpoint)]),busy=false,stopped=false,timer=null;
 const controllers=new Set();
 if(session?.csrf!==owner)return;
 const pending=openModal({title:'오버레이 발급 · 표시 설정',message:'B는 라이선스 인증을 마친 뒤 인증 세션과 콘솔을 닫습니다. 유지된 B 프로세스가 서버에서 받은 GameOverlayPlugin.bin을 검증하고 로드합니다.',html:`<div id="desktop-overlay-editor"><fieldset><legend>오버레이 플러그인 · GameOverlayPlugin.bin</legend><p class="small-note">A의 실행 흐름은 유지됩니다. RAD Studio 명령 프롬프트에서 <code>Build_Win64.cmd</code>를 실행한 뒤 <code>build/Win64/Release/overlay/GameOverlayPlugin.bin</code>을 아래에서 선택하세요. IDE에서는 GameOverlayPlugin 프로젝트를 Win64 / Release로 빌드하면 같은 .bin 파일이 생성됩니다.</p><p class="small-note">파일 확인 · 후보 등록 → 선택 플러그인 운영 게시 순서로 적용합니다. 서버에서 게시한 파일을 인증 후 B가 내려받으므로 B 옆에 DLL을 복사할 필요는 없습니다.</p><label>플러그인 파일 (최대 16MB)<input id="overlay-plugin-file" type="file" accept=".bin"></label><label>버전<input id="overlay-plugin-version" maxlength="40" value="1.0.0"></label><div id="overlay-plugin-policy" role="status"></div><label><span id="overlay-plugin-approval-label">공개 승인 JSON</span><input id="overlay-plugin-approval" type="file" accept=".json"></label><p class="small-note">개인키는 업로드하지 않습니다. 표시 데이터(.dat)는 실행 플러그인이 아닙니다.</p><button type="button" id="overlay-plugin-upload">파일 확인 · 후보 등록</button><label>플러그인 후보<select id="overlay-plugin-candidate"></select></label><div class="actions"><button type="button" id="overlay-plugin-publish">선택 플러그인 운영 게시</button><button type="button" id="overlay-plugin-reload">플러그인 상태 다시 읽기</button></div><div id="overlay-plugin-result" role="status" aria-live="polite"></div><div id="overlay-plugin-state"></div></fieldset><label><input id="overlay-enabled" type="checkbox"> 오버레이 발급 및 갱신 허용</label><label>제목<input id="overlay-title" maxlength="120"></label><label>내용 (최대 8줄, 한 줄 240자)<textarea id="overlay-lines" rows="8" maxlength="1927"></textarea></label><label>화면 테마<select id="overlay-theme"><option value="dark">다크</option><option value="light">라이트</option></select></label><div class="actions"><button type="button" id="overlay-save">서버에 저장</button><button type="button" id="overlay-reload">서버 내용 다시 읽기</button><a href="/api/desktop/bootstrap/overlay/module.dat" download="overlay.dat">표시 데이터 내려받기</a></div><p id="overlay-status" role="status" aria-live="polite"></p><p id="overlay-version" class="small-note"></p><h4>오버레이 실행 권한</h4><p class="small-note">권한 회수와 발급 중지는 다음 서버 확인 시 적용됩니다. 연결이 끊기면 최대 30초의 유효기간 후 화면이 닫힙니다.</p><p id="overlay-session-status" class="small-note" role="status">권한 목록은 4초마다 자동 갱신됩니다.</p><div id="overlay-sessions"></div></div>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-overlay-editor'),status=root.querySelector('#overlay-status'),sessionStatus=root.querySelector('#overlay-session-status');
 const pluginResult=root.querySelector('#overlay-plugin-result'),candidate=root.querySelector('#overlay-plugin-candidate');
 const live=()=>!stopped&&root.isConnected&&session?.csrf===owner;
 function stop(){stopped=true;if(timer!==null){clearInterval(timer);timer=null;}for(const controller of controllers)controller.abort();controllers.clear();}
 async function request(url,options={},timeout=10000){
  const controller=new AbortController();controllers.add(controller);
  const deadline=setTimeout(()=>controller.abort(),timeout);
  try{return await api(url,{...options,signal:controller.signal});}
  finally{clearTimeout(deadline);controllers.delete(controller);}
 }
 async function readState(){
  const results=await Promise.allSettled([request(endpoint),request(pluginEndpoint)]);
  for(const result of results)if(result.status==='rejected')throw result.reason;
  return results.map(result=>result.value);
 }
 function pluginPhase(row){
  if(!row.pluginId)return '플러그인 미지정';
  const phase={PENDING:'플러그인 설치 대기',INSTALLING:'플러그인 · 무결성 확인 중',READY:'서버 무결성 확인됨'}[row.pluginPhase]||'플러그인 상태 미확인';
  return phase+(row.pluginPhase==='READY'&&row.pluginVerifiedAt>0?' · '+desktopDate(row.pluginVerifiedAt):'');
 }
 function showSessions(rows){
  root.querySelector('#overlay-sessions').innerHTML=(rows||[]).length?`<div class="table-wrap"><table><thead><tr><th>실행 권한</th><th>라이선스</th><th>상태</th><th>최근 확인</th><th>관리</th></tr></thead><tbody>${rows.map(row=>`<tr><td class="code">${esc(row.id)}</td><td class="code">${esc(row.licenseId)}</td><td>${esc(row.status)}<br><span class="small-note">${pluginPhase(row)}</span></td><td>${desktopDate(row.lastSeenAt)}</td><td>${row.status==='ACTIVE'?`<button type="button" class="danger" data-overlay-revoke="${esc(row.id)}">권한 회수</button>`:'—'}</td></tr>`).join('')}</tbody></table></div>`:'<p>발급된 오버레이 실행 권한이 없습니다. B의 라이선스 완료 요청이 서버에 도착해야 발급됩니다. A의 실행 흐름은 유지하고, B 갱신과 GameOverlayPlugin.bin 운영 게시를 확인하세요.</p>';
 }
 function pluginActions(){
  const selected=(plugins.artifacts||[]).find(row=>row.id===candidate.value);
  root.querySelector('#overlay-plugin-publish').disabled=busy||!selected?.eligible||selected.active;
 }
 function approvalPolicy(){
  const value=plugins.approval;
  return value&&typeof value.required==='boolean'&&value.component==='O'&&Array.isArray(value.trustedSignerKeyIds)&&value.trustedSignerKeyIds.every(key=>/^[a-f0-9]{64}$/.test(key))?value:null;
 }
 function pluginInputError(code,title,current,next,action='refresh'){
  const error=Error(title);error.problem={code,title,current,next,action};throw error;
 }
 function showApprovalPolicy(){
  const policy=approvalPolicy(),node=root.querySelector('#overlay-plugin-policy');
  root.querySelector('#overlay-plugin-approval').required=policy?.required===true;
  root.querySelector('#overlay-plugin-approval-label').textContent=!policy?'공개 승인 JSON · 서버 정책 확인 필요':policy.required?'공개 승인 JSON · 필수 (O / 같은 버전 / 같은 파일)':'공개 승인 JSON · 선택 (제출 시 서버 검증)';
  if(!policy){node.textContent='서버의 오버레이 승인 정책을 확인하지 못했습니다. 이번 GameWeb 소스를 적용한 뒤 상태를 다시 읽으세요.';return;}
  const keyText=policy.trustedSignerKeyIds.length?`<details><summary>현재 등록된 배포 서명 키 ${policy.trustedSignerKeyIds.length}개</summary>${policy.trustedSignerKeyIds.map(key=>`<div><code>${esc(key)}</code></div>`).join('')}</details>`:'<p>등록된 배포 서명 키가 없습니다. 서버 보안 설정에서 기존 승인 개인키에 대응하는 공개키를 확인하세요.</p>';
  node.innerHTML=`<p>${policy.required?'현재 서버 정책: O 배포 승인 서명 필수. 같은 .bin 파일과 입력 버전으로 생성한 공개 승인 JSON을 함께 선택하세요.':'현재 서버 정책: 승인 JSON 없이 후보 등록할 수 있습니다. JSON을 제출하면 구분·버전·파일·등록된 서명 키를 모두 확인합니다.'}</p>${policy.required||policy.trustedSignerKeyIds.length?keyText:''}`;
 }
 async function readPluginApproval(file,version,digest,policy){
  if(!file.size||file.size>65536)pluginInputError('OVERLAY_PLUGIN_APPROVAL_INVALID','공개 승인 JSON을 읽을 수 없습니다.','승인 파일 크기는 1바이트 이상 64KB 이하여야 합니다.','개인키가 아닌 GameOverlayPlugin.bin의 공개 승인 JSON을 선택하세요.');
  let value;try{value=JSON.parse(await file.text());}catch(_){pluginInputError('OVERLAY_PLUGIN_APPROVAL_INVALID','공개 승인 JSON 형식이 올바르지 않습니다.','선택한 파일을 JSON으로 읽지 못했습니다.','개인키가 아닌 GameOverlayPlugin.bin의 공개 승인 JSON을 선택하세요.');}
  const plain=value&&typeof value==='object'&&!Array.isArray(value),approved=plain&&(value.approval||value);
  if(!plain||value.component!=='O')pluginInputError('OVERLAY_PLUGIN_APPROVAL_COMPONENT_MISMATCH','오버레이용 O 승인 JSON이 필요합니다.','선택한 승인 JSON은 오버레이 구분 O가 아닙니다.','승인 생성 도구에서 O를 선택하고 같은 GameOverlayPlugin.bin으로 승인 JSON을 생성하세요.');
  if(value.version!==version)pluginInputError('OVERLAY_PLUGIN_APPROVAL_VERSION_MISMATCH','입력 버전과 승인 버전이 다릅니다.',`입력 버전: ${version} / 승인 버전: ${typeof value.version==='string'?value.version:'없음'}`,'같은 배포 버전을 입력하거나 해당 버전의 공개 승인 JSON을 선택하세요.');
  if(value.sha256!==digest)pluginInputError('OVERLAY_PLUGIN_APPROVAL_HASH_MISMATCH','선택한 .bin과 승인 JSON의 파일 해시가 다릅니다.','승인 JSON은 현재 선택한 파일 내용에 대한 승인이 아닙니다.','같은 빌드의 GameOverlayPlugin.bin과 공개 승인 JSON을 선택하세요. 재빌드했다면 승인을 다시 생성하세요.');
  if(!approved||typeof approved!=='object'||Array.isArray(approved)||!/^[a-f0-9]{64}$/.test(approved.keyId||'')||typeof approved.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(approved.signature))pluginInputError('OVERLAY_PLUGIN_APPROVAL_INVALID','공개 승인 서명 형식이 올바르지 않습니다.','승인 JSON의 keyId 또는 Ed25519 서명이 없거나 형식이 다릅니다.','승인 생성 도구가 만든 공개 승인 JSON을 그대로 선택하세요.');
  if(!policy.trustedSignerKeyIds.includes(approved.keyId))pluginInputError('OVERLAY_PLUGIN_SIGNER_UNTRUSTED','이 승인 키는 서버에 등록되어 있지 않습니다.',`선택한 승인 키: ${approved.keyId}`,'서버 보안 설정에서 기존 승인 개인키에 대응하는 공개키 등록·사용 가능 상태를 확인하세요.','security');
  return {...value,approval:approved};
 }
 function showPlugins(next,preferred=''){
  plugins=next;showApprovalPolicy();const selected=preferred||candidate.value||plugins.activeId,rows=plugins.artifacts||[];
  candidate.innerHTML=rows.length?rows.map(row=>`<option value="${esc(row.id)}"${row.eligible?'':' disabled'}>${esc(row.version)} · ${esc(row.sha256.slice(0,12))}${row.active?' · 현재 운영':''}${row.eligible?'':' · 게시 불가'}</option>`).join(''):'<option value="">등록된 플러그인 없음</option>';
  if(rows.some(row=>row.id===selected))candidate.value=selected;
  const active=rows.find(row=>row.id===plugins.activeId&&row.active);
  const current=active?`운영 버전 ${esc(active.version)} · ${plugins.ready&&active.eligible?'서버 사용 가능':'사용 불가'}`:'운영 게시된 플러그인이 없습니다.';
  const details=rows.map(row=>`<details><summary>${esc(row.version)}${row.active?' · 현재 운영':' · 후보'} · ${Math.ceil(row.size/1024)}KB</summary><p>${row.eligible?'서버 검사 통과':'서버 검사 보류: '+esc(row.reason||'상태 확인 필요')} · ${row.signaturePresent?(row.signatureValid?'승인 서명 확인됨':'승인 서명 확인 실패'):'승인 서명 없음'}</p><p class="small-note">파일 SHA-256: <code>${esc(row.sha256)}</code><br>코드 SHA-256: <code>${esc(row.codeSha256||'확인되지 않음')}</code><br>모듈 내보내기 SHA-256: <code>${esc(row.exportTableSha256||'확인되지 않음')}</code></p></details>`).join('');
  root.querySelector('#overlay-plugin-state').innerHTML=`<p>등록할 배포 파일: <code>${esc(plugins.fileName||'GameOverlayPlugin.bin')}</code></p><p>${current}</p>${details}`;
  pluginActions();
 }
 function show(){
  root.querySelector('#overlay-enabled').checked=model.enabled;
  root.querySelector('#overlay-title').value=model.document.title;
  root.querySelector('#overlay-lines').value=model.document.lines.join('\n');
  root.querySelector('#overlay-theme').value=model.document.theme;
  root.querySelector('#overlay-version').textContent='표시 버전 '+model.version+' · SHA-256 '+model.documentSha256;
  showSessions(model.sessions);
 }
 function lock(value,freezeForm=true){busy=value;for(const el of root.querySelectorAll('button'))el.disabled=value;if(freezeForm)for(const el of root.querySelectorAll('input,select,textarea'))el.disabled=value;pluginActions();}
 async function refreshSessions(){
  if(!live()){stop();return;}
  if(busy||document.hidden)return;
  lock(true,false);
  try{
   const [next,nextPlugins]=await readState();
   // Automatic reads preserve display drafts, version input and selected files.
   if(live()){showSessions(next.sessions);showPlugins(nextPlugins);sessionStatus.textContent='권한 목록은 4초마다 자동 갱신됩니다.';}
  }catch(_){if(live())sessionStatus.textContent='권한 목록을 갱신하지 못했습니다. 다음 확인에서 다시 시도합니다.';}
  finally{if(live())lock(false);else stop();}
 }
 show();showPlugins(plugins);
 candidate.onchange=pluginActions;
 root.querySelector('#overlay-plugin-upload').onclick=async()=>{
  if(busy||!live())return;
  const file=root.querySelector('#overlay-plugin-file').files[0],version=root.querySelector('#overlay-plugin-version').value.trim(),approvalFile=root.querySelector('#overlay-plugin-approval').files[0];
  if(!file||!file.size||file.size>Math.min(plugins.maxBytes||16777216,16777216)||!file.name.toLowerCase().endsWith('.bin')||!/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(version)){pluginResult.textContent='16MB 이하의 .bin 파일과 올바른 버전을 선택하세요.';return;}
  lock(true);
  try{
   const policy=approvalPolicy();
   if(!policy)pluginInputError('OVERLAY_PLUGIN_POLICY_UNAVAILABLE','서버의 오버레이 승인 정책을 확인하지 못했습니다.','필수 서명 여부와 등록된 배포 서명 키를 확인할 수 없습니다.','이번 GameWeb 소스를 적용한 뒤 플러그인 상태를 다시 읽으세요.');
   if(policy.required&&!approvalFile)pluginInputError('OVERLAY_PLUGIN_APPROVAL_REQUIRED','현재 서버 정책에서는 O 승인 JSON이 필수입니다.','GameOverlayPlugin.bin만 선택되어 있습니다.','같은 .bin 파일과 입력 버전으로 생성한 O 공개 승인 JSON을 함께 선택하세요.');
   pluginResult.textContent='선택한 파일을 확인하고 있습니다.';
   const digest=await desktopFileHash(file);if(!live())return;
   const headers={};
   if(approvalFile){const approved=await readPluginApproval(approvalFile,version,digest,policy);if(!live())return;headers['x-game-release-key-id']=approved.approval.keyId;headers['x-game-release-signature']=approved.approval.signature;headers['x-game-release-component']=approved.component;headers['x-game-release-version']=approved.version;headers['x-game-release-sha256']=approved.sha256;}
   pluginResult.textContent='서버에서 플러그인과 무결성을 검증하고 있습니다.';
   const saved=await request(pluginEndpoint+'?'+new URLSearchParams({version,fileName:file.name}),{method:'POST',rawBody:file,headers},120000);
   if(!live())return;
   if(!saved.artifact||saved.artifact.sha256!==digest)throw Error('서버에서 확인한 파일 해시가 다릅니다. 운영 게시하지 말고 파일을 다시 확인하세요.');
   const next=await request(pluginEndpoint);if(live()){showPlugins(next,saved.artifact.id);pluginResult.textContent='후보 등록 완료. 선택한 플러그인을 운영 게시해야 새 인증에서 사용할 수 있습니다.';}
  }catch(error){if(live())desktopWorkflowError(pluginResult,error);}
  finally{if(live())lock(false);else stop();}
 };
 root.querySelector('#overlay-plugin-publish').onclick=async()=>{
  if(busy||!live())return;
  const selected=(plugins.artifacts||[]).find(row=>row.id===candidate.value);if(!selected?.eligible||selected.active)return;
  lock(true);
  try{const next=await request(pluginEndpoint+'/activate',{method:'POST',body:{id:selected.id,expectedRevision:plugins.revision}});if(live()){showPlugins(next,selected.id);pluginResult.textContent=next.ready&&next.activeId===selected.id?'선택한 플러그인을 운영 게시했습니다. B의 다음 라이선스 인증에서 적용됩니다.':'서버 응답에서 운영 사용 가능 상태를 확인하지 못했습니다. 플러그인 상태를 다시 읽으세요.';}}
  catch(error){if(live())desktopWorkflowError(pluginResult,error);}
  finally{if(live())lock(false);else stop();}
 };
 root.querySelector('#overlay-plugin-reload').onclick=async()=>{
  if(busy||!live())return;lock(true);
  try{const next=await request(pluginEndpoint);if(live()){showPlugins(next);pluginResult.textContent='서버의 플러그인 상태를 읽었습니다.';}}
  catch(error){if(live())desktopWorkflowError(pluginResult,error);}
  finally{if(live())lock(false);else stop();}
 };
 root.querySelector('#overlay-save').onclick=async()=>{
  if(busy||!live())return;
  const title=root.querySelector('#overlay-title').value.trim(),text=root.querySelector('#overlay-lines').value;
  const lines=text===''?[]:text.split(/\r?\n/);
  if(!title||title.length>120||lines.length>8||lines.some(line=>line.length>240)){status.textContent='제목과 내용의 길이를 확인하세요.';return;}
  lock(true);
  try{
   const next=await request(endpoint,{method:'POST',body:{expectedVersion:model.version,enabled:root.querySelector('#overlay-enabled').checked,document:{schema:1,format:'GAME-OVERLAY-DATA-1',title,lines,theme:root.querySelector('#overlay-theme').value}}});
   if(live()){model=next;show();status.textContent='서버에 저장했습니다. 실행 중인 오버레이는 다음 확인에서 새 내용을 받습니다.';}
  }catch(error){if(live())status.textContent=(error.message||'저장하지 못했습니다.')+' 입력 내용은 유지됩니다. 버전이 변경됐다면 서버 내용을 다시 읽고 수정하세요.';}
  finally{if(live())lock(false);else stop();}
 };
 root.querySelector('#overlay-reload').onclick=async()=>{
  if(busy||!live())return;lock(true);
  try{const [next,nextPlugins]=await readState();if(live()){model=next;show();showPlugins(nextPlugins);status.textContent='서버의 최신 내용을 읽었습니다.';}}
  catch(error){if(live())status.textContent=error.message||'조회하지 못했습니다.';}
  finally{if(live())lock(false);else stop();}
 };
 root.querySelector('#overlay-sessions').onclick=async event=>{
  const button=event.target.closest('[data-overlay-revoke]');if(!button||busy||!live())return;
  lock(true);
  try{await request(endpoint+'/sessions/'+encodeURIComponent(button.dataset.overlayRevoke)+'/revoke',{method:'POST',body:{reason:'관리자 웹에서 오버레이 권한 회수'}});if(!live())return;const next=await request(endpoint);if(live()){showSessions(next.sessions);status.textContent='선택한 오버레이 권한을 회수했습니다.';}}
  catch(error){if(live())status.textContent=error.message||'회수하지 못했습니다.';}
  finally{if(live())lock(false);else stop();}
 };
 timer=setInterval(refreshSessions,4000);
 try{await pending;}finally{stop();if(root.isConnected)root.replaceChildren();}
}
// Administrator UI only. Drafts, file selections and selection IDs stay in RAM.
const desktopSelectedLicenses=new Set();
let desktopSelectionOwner='';
function desktopWorkflowOwner(){const owner=session?.csrf||'';if(owner!==desktopSelectionOwner){desktopSelectedLicenses.clear();desktopSelectionOwner=owner;}return owner;}
function desktopWorkflowError(node,error,retry){
 const p=error.problem||{title:error.serverMessage||error.message||'요청을 완료하지 못했습니다.',current:'이 작업의 완료를 확인하지 못했습니다.',next:'내용과 현재 서버 상태를 확인한 뒤 다시 시도하세요.',code:error.code||'REQUEST_FAILED',action:'refresh'};
 node.innerHTML=`<div class="desktop-operation-error" role="alert"><strong>${esc(p.title)}</strong><p>현재: ${esc(p.current)}</p><p>다음: ${esc(p.next)}</p><details><summary>상세 코드</summary><code>${esc(p.code)}</code></details>${retry?'<button type="button" data-workflow-retry>이 항목 다시 확인</button>':''}</div>`;
 if(retry)node.querySelector('[data-workflow-retry]').onclick=retry;
 const names={security:'서버 보안 설정 열기',deploy:'새 버전 배포 열기',licenses:'라이선스 목록으로',jobs:'서버 작업함 열기',storage:'저장공간 확인'};
 if(names[p.action]){const go=document.createElement('button');go.type='button';go.textContent=names[p.action];node.firstElementChild.append(go);go.onclick=async()=>{try{const owner=session?.csrf;if(typeof modalCancel!=='undefined')modalCancel.click();await new Promise(r=>setTimeout(r,0));if(session?.csrf!==owner)return;if(p.action==='security')await showDesktopSecurityOperations();else if(p.action==='deploy')await showDesktopDeploymentWizard();else if(p.action==='jobs'||p.action==='storage')await showDesktopWorkspace(p.action);else await renderCurrent();}catch(e){toast(e.message||'화면을 열지 못했습니다.',true);}};}

}
function desktopWorkflowDownload(name,value){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function desktopApprovalRead(file,component){
 if(!file||file.size>65536)throw Error('64KB 이하의 공개 approval.json을 선택하세요.');
 const value=JSON.parse(await file.text()),a=value.approval||value;
 if(value.component!==component||typeof value.version!=='string'||!/^\d+(?:\.\d+){0,3}$/.test(value.version)||!/^[a-f0-9]{64}$/.test(value.sha256||'')||!/^[a-f0-9]{64}$/.test(a.keyId||'')||typeof a.signature!=='string')throw Error(component+'의 구분·버전·해시·공개 서명 자료를 확인하세요. 개인키는 선택하지 마세요.');
 return {...value,approval:a};
}
async function desktopFileHash(file){if(!crypto.subtle)throw Error('파일 사전 확인은 HTTPS 관리자 주소에서 사용하세요.');return [...new Uint8Array(await crypto.subtle.digest('SHA-256',await file.arrayBuffer()))].map(x=>x.toString(16).padStart(2,'0')).join('');}
async function showDesktopDeploymentWizard(){
 if(!roleIsAdmin())return;const owner=desktopWorkflowOwner();const initial=await api('/api/desktop/bootstrap/security-operations');if(session?.csrf!==owner)return;
 let listing=initial,preview=null,busy=false;const staged=new Map();
 const promise=openModal({title:'새 버전 배포',message:'사용자 A/B에는 관리자 화면이 없습니다. 파일 확인 → 후보 등록 → 조합 검증 → 게시를 이 창에서 진행합니다. 개인키는 업로드하지 않습니다.',html:`<div id="desktop-deploy-wizard">${['A','B'].map(c=>`<fieldset><legend>${c==='A'?'A · 사용자 실행기':'B · 사용자 프로그램'}</legend><p class="small-note">변경하지 않는 구성 요소는 파일을 비워 두고 현재 운영 후보를 유지하세요.</p><label>실행 파일<input data-file="${c}" type="file" accept=".exe"></label><label>공개 승인 JSON<input data-approval="${c}" type="file" accept=".json"></label><label>버전<input data-version="${c}" maxlength="40" value="1.0.0"></label><p data-file-status="${c}" role="status"></p><label>게시할 후보<select data-candidate="${c}"></select></label></fieldset>`).join('')}<label>이번 변경 내용 (서버에 보관)<textarea id="desktop-release-notes" maxlength="1000"></textarea></label><div class="actions"><button type="button" id="desktop-stage-selected">선택 파일 확인 · 후보 등록</button><button type="button" id="desktop-pair-preview">선택 A/B 조합 검증</button><button type="button" id="desktop-pair-publish" disabled>검증한 조합 운영 게시</button></div><div id="desktop-deploy-result" role="status" aria-live="polite"></div></div>`,confirmLabel:'닫기'});
 const root=document.getElementById('desktop-deploy-wizard'),result=root.querySelector('#desktop-deploy-result'),publish=root.querySelector('#desktop-pair-publish');
 const live=()=>root.isConnected&&session?.csrf===owner;
 function selects(preferred={}){for(const c of ['A','B']){const select=root.querySelector(`[data-candidate="${c}"]`),id=preferred[c]||select.value||listing.active[c];select.innerHTML=(listing.candidates||[]).filter(x=>x.component===c).map(x=>`<option value="${esc(x.id)}">${esc(x.version)} · ${esc(x.sha256.slice(0,12))}${x.active?' · 현재 운영':''}</option>`).join('');if([...select.options].some(x=>x.value===id))select.value=id;}}
 function invalidate(){preview=null;publish.disabled=true;}
 function lock(value){busy=value;for(const e of root.querySelectorAll('button,input,select,textarea'))e.disabled=value;if(!value)publish.disabled=!preview?.eligible;}
 selects();root.addEventListener('change',()=>{invalidate();});
 for(const c of ['A','B'])root.querySelector(`[data-approval="${c}"]`).onchange=async()=>{try{const v=await desktopApprovalRead(root.querySelector(`[data-approval="${c}"]`).files[0],c);if(!live())return;root.querySelector(`[data-version="${c}"]`).value=v.version;root.querySelector(`[data-file-status="${c}"]`).textContent=`${c} / ${v.version} / 서명 키 ${v.approval.keyId.slice(0,12)} · 공개키 신뢰 등록은 별도입니다.`;}catch(e){if(live())desktopWorkflowError(result,e);} };
 root.querySelector('#desktop-stage-selected').onclick=async()=>{
  if(busy||!live())return;invalidate();lock(true);let any=false;const preferred={};
  try{
   for(const c of ['A','B']){
    const file=root.querySelector(`[data-file="${c}"]`).files[0];if(!file)continue;any=true;
    const version=root.querySelector(`[data-version="${c}"]`).value.trim(),af=root.querySelector(`[data-approval="${c}"]`).files[0];
    if(!file.size||file.size>67108864||!file.name.toLowerCase().endsWith('.exe')||!/^\d+(?:\.\d+){0,3}$/.test(version))throw Error('64MB 이하의 EXE와 올바른 버전을 선택하세요.');
    const headers={};const digest=await desktopFileHash(file);if(!live())return;
    if(af){const approval=await desktopApprovalRead(af,c);if(approval.version!==version)throw Error(`${c} 승인 버전 ${approval.version} / 입력 버전 ${version}: 서로 일치시켜 주세요.`);if(approval.sha256!==digest)throw Error(c+' EXE 내용이 승인 파일의 해시와 다릅니다. 같은 빌드의 파일을 선택하세요.');headers['x-game-release-key-id']=approval.approval.keyId;headers['x-game-release-signature']=approval.approval.signature;}
    const key=[c,version,digest,headers['x-game-release-signature']||''].join(':');let artifact=staged.get(key);
    result.textContent=c+' 파일을 서버에서 검증하고 후보로 등록합니다.';
    if(!artifact){const r=await api('/api/desktop/bootstrap/artifacts?'+new URLSearchParams({component:c,version,fileName:file.name}),{method:'POST',rawBody:file,headers});artifact=r.artifact;staged.set(key,artifact);}
    preferred[c]=artifact.id;if(live())root.querySelector(`[data-file-status="${c}"]`).textContent='후보 등록됨 · 운영 게시는 아직 하지 않았습니다.';
   }
   if(!any)throw Error('등록할 파일을 선택하세요. 파일을 바꾸지 않는 경우 아래 조합 검증으로 진행하세요.');
   listing=await api('/api/desktop/bootstrap/security-operations');if(live()){selects(preferred);result.textContent='후보 등록 완료. 아래 선택 A/B를 검증한 뒤 별도로 게시하세요.';}
  }catch(e){if(live()){desktopWorkflowError(result,e);try{listing=await api('/api/desktop/bootstrap/security-operations');if(live())selects(preferred);}catch(_){} }}finally{if(live())lock(false);}
 };
 root.querySelector('#desktop-pair-preview').onclick=async()=>{
  if(busy||!live())return;lock(true);try{const aId=root.querySelector('[data-candidate="A"]').value,bId=root.querySelector('[data-candidate="B"]').value;if(!aId||!bId)throw Error('A와 B 후보를 각각 선택하세요.');const r=await api('/api/desktop/bootstrap/security-operations/preview-pair',{method:'POST',body:{aId,bId}});if(live()){preview=r.preview;result.textContent=preview.eligible?'조합 검증 통과. 아직 운영 파일은 변경하지 않았습니다.':'조합 검증 보류: '+preview.reasons.join(', ');}}catch(e){if(live())desktopWorkflowError(result,e);}finally{if(live())lock(false);}
 };
 publish.onclick=async()=>{
  if(busy||!live()||!preview?.eligible)return;const selected=preview;lock(true);
  try{
   const note=root.querySelector('#desktop-release-notes').value.trim();
   if(note)await api('/api/desktop/workspace/deployment-note',{method:'POST',body:{aId:selected.aId,bId:selected.bId,note}});
   await api('/api/desktop/bootstrap/security-operations/activate',{method:'POST',body:{expectedRevision:selected.operationsRevision,expectedPolicyRevision:selected.policyRevision,aId:selected.aId,bId:selected.bId}});
   if(live()){result.textContent='선택 A/B를 운영 게시했습니다. 사용자에게 새 A를 발급하세요.';listing=await api('/api/desktop/bootstrap/security-operations');if(live())selects();}invalidate();
  }catch(e){invalidate();if(live())desktopWorkflowError(result,e);}finally{if(live())lock(false);}
 };
 try{await promise;}finally{if(root.isConnected)root.replaceChildren();if(session?.csrf===owner&&currentView==='desktop-licenses')await renderCurrent();}
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
