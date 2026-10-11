'use strict';
// Server-owned state only; no browser database/storage or persisted drafts.
async function showDesktopServerState(){
 if(!roleIsAdmin()||!session)throw Error('관리자 로그인이 필요합니다.');
 const owner=session.csrf,base='/api/desktop/bootstrap/server-state';
 let status=await api(base),devices=await api(base+'/devices'),quarantine=await api(base+'/quarantine'),identity=await api(base+'/device-identity'),candidates=[],nextAfter=null,closed=false,busy=false;
 let recoveryRequestId=crypto.randomUUID(),checkpointRequestId=crypto.randomUUID(),replacementRequestId=crypto.randomUUID(),storageRequestId=crypto.randomUUID(),identityPolicyRequestId=crypto.randomUUID(),identityRevokeRequestId=crypto.randomUUID();
 if(session?.csrf!==owner||!roleIsAdmin())return;
 const done=openModal({title:'서버 복구 · 장치 · 저장소',html:'<section id="desktop-server-state-root" class="desktop-security"></section>',confirmLabel:'닫기'});
 const root=document.getElementById('desktop-server-state-root'),alive=()=>!closed&&root.isConnected&&session?.csrf===owner&&roleIsAdmin(),el=id=>root.querySelector('#'+id);
 const button=(action,label,disabled=false)=>`<button type="button" data-server-state-action="${action}" ${disabled?'disabled':''}>${label}</button>`;
 const message=(text,error=false)=>{if(alive()){el('server-state-status').textContent=text;el('server-state-status').dataset.state=error?'error':'success';}};
 function render(){
  if(!alive())return;
  root.innerHTML=`<p class="small-note">인증·복구 세대·소비/폐기 이력은 서버가 판단합니다. 클라이언트 실행·렌더링·TLS 확인·측정과 짧은 수명의 메모리 키는 남습니다. 영속 장치키와 TPM 증명의 요구 수준은 아래 서버 정책으로 결정합니다. 원격 다중 서버 합의는 지원하지 않습니다.</p>
   <div class="actions">${button('refresh','서버 상태 새로고침')}</div><p id="server-state-status" role="status" aria-live="polite"></p>
   <details open><summary>복구 세대 · 외부 최신 상태 증거</summary><div class="kv"><div>복구 세대</div><div>${status.epoch}</div><div>외부 증거</div><div>${esc(status.witness.status)}</div><div>미보충 감사</div><div>${status.auditPending}</div><div>오프라인 무기한 승인</div><div>허용하지 않음</div></div>
   <p class="small-note">NOT_CONFIGURED이면 전체 과거 DATA_DIR 복원을 탐지한다고 볼 수 없습니다. 별도 백업 범위·저장장치에 증거를 일회 등록하고 서버의 REQUIRED 설정을 켜야 합니다. 증거까지 함께 복원하면 이 보장이 없어집니다.</p>
   <label>복구 사유<select id="server-recovery-reason"><option value="BACKUP_RESTORE">백업 복원</option><option value="SECURITY_INCIDENT">침해 대응</option><option value="CREDENTIAL_ROTATION">자격증명 변경</option><option value="RECOVERY_DRILL">복구 훈련</option></select></label>
   <label><input id="server-recovery-confirm" type="checkbox"> 현재 A/B/O 및 관리자 세션 폐기를 확인합니다. 이미 사용한 라이선스를 복원하지 않습니다.</label>${button('recover','복구 세대 증가 · 구 세션 폐기')}
   <p class="small-note">이 작업 후 관리자는 다시 로그인해야 합니다. 기존 PC의 메모리 lease는 다음 서버 검사 또는 만료에서 거절되며, 원격 화면을 즉시 강제 종료했다고 표시하지 않습니다.</p></details>
   <details><summary>라이선스 checkpoint · 분할 보관</summary><pre class="desktop-security-result">${esc(JSON.stringify(status.journal,null,2))}</pre>
   <p class="small-note">사용·폐기 라이선스, 서명 비밀값, 기존 요청 결과를 모두 보존합니다. 활성 저널을 줄여도 서버 보관 segment는 자동 삭제하지 않습니다. 큰 파일 작업은 점검 시간에 실행하세요. 활성 A/B/O 실행이 남아 있으면 거절됩니다.</p>${button('checkpoint','서버 checkpoint 생성')}</details>
   <details><summary>PC 정책 · 감사 보존 · 발신함 checkpoint</summary><pre class="desktop-security-result">${esc(JSON.stringify(status.storage||{},null,2))}</pre>
   <p class="small-note">활성 실행을 종료한 점검 시간에 사용하세요. PC 차단 세대와 요청 지문은 유지합니다. 감사 보존은 기간이 지난 상세 기록만 삭제하고 중복 요청 방지 지문과 체인 기준점을 보존합니다. 미전송 감사 이벤트는 압축하지 않습니다.</p>
   <label>작업<select id="server-storage-action"><option value="MACHINE_CHECKPOINT">PC 정책 checkpoint</option><option value="MACHINE_ARCHIVE_RETENTION">PC 정책 이전 segment 보존 기간 적용</option><option value="OUTBOX_COMPACT">전송 완료 감사 발신함 압축</option><option value="AUDIT_RETENTION">감사 상세 기록 보존 기간 적용</option></select></label>
   <label>보존 일수 (PC segment 최소 7일)<input id="server-storage-days" type="number" min="1" max="3650" value="90"></label>${button('storage','서버 저장소 유지관리')}</details>
   <details><summary>장치 식별 · 앱 키 소유 증명</summary><p class="small-note">LEGACY_PC_HASH_V1 식별은 유지합니다. APP_KEY_POSSESSION은 현재 앱 키의 서명 증명이며 TPM 증명이 아닙니다. 상세 키 증명은 30일 후 정리하지만 폐기 tombstone은 유지합니다.</p>
   <pre class="desktop-security-result">${esc(JSON.stringify(devices,null,2))}</pre>
   <label>폐기할 기존 장치<select id="server-device-old"><option value="">장치 선택</option>${devices.items.filter(x=>x.status==='REGISTERED').map(x=>`<option value="${esc(x.id)}">${esc(x.id)}</option>`).join('')}</select></label>
   <label>새 PC 식별 해시 (64자리)<input id="server-device-new" maxlength="64" autocomplete="off" spellcheck="false"></label>
   <label>교체 사유<select id="server-device-reason"><option value="MAINBOARD_REPLACED">메인보드 교체</option><option value="TPM_RESET">TPM 초기화</option><option value="WINDOWS_REINSTALLED">Windows 재설치</option><option value="ADMIN_RECOVERY">관리자 복구</option></select></label>
   <label><input id="server-device-confirm" type="checkbox"> 기존 장치를 폐기하고 새 장치는 별도 인증합니다. 라이선스는 자동 이월하지 않습니다.</label>${button('replace','서버 장치 교체 등록')}</details>
   <details><summary>영속 장치키 · TPM 서버 정책</summary><p class="small-note">앱 키 소유와 TPM 하드웨어 키 증명을 별도로 검증합니다. TPM 모드는 제조사 EK 신뢰 체인·폐기 목록·유효기한과 실제 장치 시험이 준비된 환경에서 적용하세요. 정책 변경은 기존 증명을 무효화하며 새 A 실행이 필요합니다.</p>
   <pre class="desktop-security-result">${esc(JSON.stringify({mode:identity.mode,revision:identity.revision,trustConfigured:identity.trustConfigured,workQueue:identity.workQueue,items:identity.items},null,2))}</pre>
   <label>최소 요구 수준<select id="server-identity-mode">${[['COMPATIBLE','기존 실행 호환'],['PERSISTENT','영속 앱 키 필수'],['TPM_ATTESTED','TPM 2.0 키 증명 필수']].map(([v,n])=>`<option value="${v}" ${identity.mode===v?'selected':''}>${n}</option>`).join('')}</select></label>
   <label><input id="server-identity-enrolled" type="checkbox" ${identity.requireForEnrolled?'checked':''}> 한번 등록한 장치의 증명 생략을 거절합니다.</label>
   <label>TPM 신뢰 설정 JSON<textarea id="server-identity-trust" rows="7" spellcheck="false" autocomplete="off">${esc(identity.trust?JSON.stringify(identity.trust,null,2):'')}</textarea></label><p class="small-note">roots / intermediates: 공개 PEM 인증서 배열 · revokedCertificateSha256: 폐기 인증서 SHA-256 배열 · validUntil: 신뢰 목록 갱신 기한(UTC 밀리초). 테스트용 인증서는 운영 신뢰 목록에 넣지 마세요.</p>
   ${button('identity-policy','서버 장치 정책 저장')}
   <label>폐기·복구할 장치키<select id="server-identity-key"><option value="">장치키 선택</option>${(identity.items||[]).map(x=>`<option value="${esc(x.id)}">${esc(x.status+' · '+x.id)}</option>`).join('')}</select></label>
   <label>사유<select id="server-identity-reason"><option value="KEY_COMPROMISED">키 침해</option><option value="WINDOWS_REINSTALLED">Windows 재설치</option><option value="TPM_RESET">TPM 초기화</option><option value="MAINBOARD_REPLACED">메인보드 교체</option><option value="ADMIN_RECOVERY">관리자 복구</option></select></label>
   <label><input id="server-identity-recover" type="checkbox"> 기존 실행을 폐기하고 새 A의 새 키 등록을 15분간 1회 허용합니다. 사용된 라이선스는 복원하지 않습니다.</label>
   ${button('identity-revoke','기존 장치키 폐기 · 선택한 복구 적용')}</details>
   <details><summary>참조 없는 서버 파일 · 격리</summary><p class="small-note">활성 A/B/O를 종료한 뒤 서버의 배포 파일만 확인합니다. 참조·해시가 일치하는 파일을 격리하며 삭제는 별도 승인과 격리 후 7일 경과가 필요합니다. PC 파일이나 임의 경로는 처리하지 않습니다.</p>
   <div class="actions">${button('scan','고아 파일 검사')}${button('scan-next','다음 검사 구간',!nextAfter)}</div>
   ${candidates.map((x,i)=>`<div><code>${esc(x.name)}</code> ${x.eligible?button('quarantine-'+i,'격리'):'읽기/경로 검사 실패'}</div>`).join('')}
   <h4>격리 기록</h4>${quarantine.items.map((x,i)=>`<div><code>${esc(x.name)}</code> ${esc(x.status)} ${button('delete-'+i,'유예 완료 파일 삭제',!x.deleteEligible)}</div>`).join('')||'<p>격리된 파일이 없습니다.</p>'}</details>`;
 }
 async function reload(){const values=await Promise.all([api(base),api(base+'/devices'),api(base+'/quarantine'),api(base+'/device-identity')]);if(alive()){[status,devices,quarantine,identity]=values;render();}}
 root.addEventListener('change',e=>{if(e.target.id.startsWith('server-identity-')){identityPolicyRequestId=crypto.randomUUID();identityRevokeRequestId=crypto.randomUUID();}if(e.target.id.startsWith('server-device-'))replacementRequestId=crypto.randomUUID();if(e.target.id==='server-recovery-reason')recoveryRequestId=crypto.randomUUID();if(e.target.id.startsWith('server-storage-'))storageRequestId=crypto.randomUUID();});
 root.addEventListener('click',async event=>{
  const target=event.target.closest('[data-server-state-action]');if(!target||!alive()||busy)return;const action=target.dataset.serverStateAction;busy=true;target.disabled=true;
  try{
   if(action==='refresh'){await reload();return;}
   if(action==='scan'||action==='scan-next'){const scan=await api(base+'/orphans'+(action==='scan-next'?'?after='+encodeURIComponent(nextAfter||''):''));if(alive()){candidates=scan.items;nextAfter=scan.nextAfter;render();message('서버 파일 검사 결과입니다. 자동 격리·삭제는 하지 않았습니다.');}return;}
   if(action==='recover'){
    if(!el('server-recovery-confirm').checked)throw Error('세션 폐기 확인란을 선택하세요.');
    const result=await api(base+'/recover-sessions',{method:'POST',body:{requestId:recoveryRequestId,expectedEpoch:status.epoch,reasonCode:el('server-recovery-reason').value}});
    if(alive()){message('서버 복구 세대 '+result.epoch+' 적용 완료. 창을 닫고 다시 로그인하세요.');root.querySelectorAll('button,input,select').forEach(n=>{n.disabled=true;});closed=true;}return;
   }
   if(action==='checkpoint'){
    const result=await api(base+'/journal-checkpoint',{method:'POST',body:{requestId:checkpointRequestId,expectedRevision:status.licenseRevision}});checkpointRequestId=crypto.randomUUID();
    if(result.compacted===false&&result.checkpointRequired===true){
     if(alive()){await reload();message('이전 checkpoint 기록은 확정됐지만 이후 변경이 있어 분할 보관은 완료되지 않았습니다. 활성 A/B/O를 종료한 뒤 새로 고친 현재 상태에서 checkpoint를 다시 생성하세요.',true);}return;
    }
   }
   else if(action==='storage'){
    const selected=el('server-storage-action').value,body={requestId:storageRequestId,action:selected};if(['AUDIT_RETENTION','MACHINE_ARCHIVE_RETENTION'].includes(selected))body.days=Number(el('server-storage-days').value);
    await api(base+'/storage-maintenance',{method:'POST',body});storageRequestId=crypto.randomUUID();
   }
   else if(action==='identity-policy'){
    const body={requestId:identityPolicyRequestId,expectedRevision:identity.revision,mode:el('server-identity-mode').value,requireForEnrolled:el('server-identity-enrolled').checked},raw=el('server-identity-trust').value.trim();if(raw)body.trust=JSON.parse(raw);
    await api(base+'/device-identity-policy',{method:'POST',body});identityPolicyRequestId=crypto.randomUUID();
   }
   else if(action==='identity-revoke'){
    await api(base+'/device-key-revoke',{method:'POST',body:{requestId:identityRevokeRequestId,expectedRevision:identity.revision,enrollmentId:el('server-identity-key').value,reasonCode:el('server-identity-reason').value,allowReenrollment:el('server-identity-recover').checked}});identityRevokeRequestId=crypto.randomUUID();
   }
   else if(action==='replace'){
    if(!el('server-device-confirm').checked)throw Error('장치 폐기·별도 인증 확인란을 선택하세요.');
    await api(base+'/device-replacement',{method:'POST',body:{requestId:replacementRequestId,expectedRevision:devices.revision,oldBindingId:el('server-device-old').value,newMachineId:el('server-device-new').value.trim().toUpperCase(),reasonCode:el('server-device-reason').value}});replacementRequestId=crypto.randomUUID();
   }else if(action.startsWith('quarantine-')){const row=candidates[Number(action.slice(11))];if(!row?.eligible)throw Error('검사 결과를 다시 확인하세요.');await api(base+'/orphan-quarantine',{method:'POST',body:{name:row.name,sha512:row.sha512}});candidates=candidates.filter(x=>x!==row);}
   else if(action.startsWith('delete-')){const row=quarantine.items[Number(action.slice(7))];if(!row?.deleteEligible)throw Error('삭제 유예 기간을 확인하세요.');const yes=await openModal({isolated:true,title:'격리 파일 삭제',message:row.name+' 파일을 서버에서 삭제합니다. 참조·해시·유예 기간을 다시 검사합니다.',confirmLabel:'삭제'});if(!yes||!alive())return;await api(base+'/orphan-delete',{method:'POST',body:{id:row.id,sha512:row.sha512}});}
   else return;
   if(alive()){await reload();message('서버에서 처리를 확정했습니다.');}
  }catch(e){message(e.message+(e.code?' · '+e.code:''),true);}
  finally{busy=false;if(alive()&&target.isConnected)target.disabled=false;}
 });
 render();try{await done;}finally{closed=true;status=null;devices=null;quarantine=null;identity=null;candidates=[];nextAfter=null;recoveryRequestId='';checkpointRequestId='';replacementRequestId='';storageRequestId='';identityPolicyRequestId='';identityRevokeRequestId='';if(root.isConnected)root.replaceChildren();}
}
