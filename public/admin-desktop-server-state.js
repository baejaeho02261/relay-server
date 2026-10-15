'use strict';
// Server-owned state only; no browser database/storage or persisted drafts.
async function showDesktopServerState(){
 if(!roleIsAdmin()||!session)throw Error('관리자 로그인이 필요합니다.');
 const owner=session.csrf,base='/api/desktop/bootstrap/server-state';
 let [status,devices,quarantine,identity]=await Promise.all([api(base),api(base+'/devices'),api(base+'/quarantine'),api(base+'/device-identity')]);
 let candidates=[],nextAfter=null,closed=false,busy=false,selectedBuild='',selectedReport='',selectedFlow='',lifecycle=null,lifecycleError='',lifecycleLoading=false,lifecycleRequest=0;
 let recoveryRequestId=crypto.randomUUID(),checkpointRequestId=crypto.randomUUID(),replacementRequestId=crypto.randomUUID(),storageRequestId=crypto.randomUUID(),identityPolicyRequestId=crypto.randomUUID(),identityRevokeRequestId=crypto.randomUUID();
 if(session?.csrf!==owner||!roleIsAdmin())return;
 const done=openModal({title:'구현 · 검증 · 실행 종료 상태',html:'<section id="desktop-server-state-root" class="desktop-security"></section>',confirmLabel:'닫기'});
 const root=document.getElementById('desktop-server-state-root'),alive=()=>!closed&&root.isConnected&&session?.csrf===owner&&roleIsAdmin(),el=id=>root.querySelector('#'+id);
 const button=(action,label,disabled=false)=>`<button type="button" data-server-state-action="${action}" ${disabled?'disabled':''}>${label}</button>`;
 const message=(text,error=false)=>{if(alive()){el('server-state-status').textContent=text;el('server-state-status').dataset.state=error?'error':'success';}};
 const labels={IMPLEMENTED:'구현',PARTIAL:'부분 구현',NOT_IMPLEMENTED:'미구현',NOT_RECORDED:'기록 없음',NOT_RUN:'미실행',PASS:'통과 보고',PASS_REPORTED:'통과 보고',FAIL:'실패 보고',INCOMPLETE:'불완전',OPERATOR_RECORDED:'관리자 등록',CURRENT:'현재 정책 일치',STALE:'정책 변경됨',UNBOUND:'정책 연결 없음',MIXED:'정책 연결 혼재',CLIENT_REPORTED:'클라이언트 보고',SERVER_CONFIRMED:'서버 확인',NOT_REPORTED:'보고 없음',OBSERVED:'관측 보고',FAILED:'실패',SCHEDULED:'정리 예약',TIMEOUT:'대기 만료',REMOVED:'파일 제거 관측 보고',NOT_ATTEMPTED:'정리 시도 안 함',UNKNOWN:'미확인',ACKNOWLEDGED:'응답 수신 보고',REQUESTED:'요청됨',PENDING:'정리 대기',ACTIVE:'활성',CLOSED:'종료',EXPIRED:'만료',REJECTED:'거절',REVOKED:'폐기',HANDED_OFF:'인수인계 완료',NOT_STARTED:'시작 전',AUTHORITY_ENDED:'서버 권한 종료',TRANSFER_COMMITTED:'인계 확정'};
 const scopeLabels={ISOLATED_SERVICE:'격리 서버 시험',DEPLOYMENT_SERVER:'대상 서버 시험',WINDOWS_PROBE:'Windows 보조 프로브',SELECTED_FINAL_ABO:'선택한 최종 A/B/O 실행',DEDICATED_PRODUCT_TESTBUILD:'장애 주입 전용 제품 빌드',PHYSICAL_ENVIRONMENT:'물리 환경 시험',SERVICE_EXECUTED:'서버 시험 실행 보고',WINDOWS_EXECUTED:'Windows 실행 보고',PHYSICAL_EXECUTED:'물리 환경 실행 보고',NOT_EXECUTED:'실행하지 않음'};
 const eventLabels={FLOW_STARTED:'실행 흐름 시작',HANDOFF_COMPLETED:'인수인계 완료',SESSION_CLAIMED:'세션 인수 완료',LEASE_EXPIRED:'서버 lease 만료',AUTHORITY_ENDED:'서버 권한 종료',TRANSFER_COMMITTED:'인계 확정',CLOSE_REQUEST:'종료 요청',CLOSE_RESPONSE_PREPARED:'종료 응답 준비',CLOSE_ACK:'종료 응답 수신 보고',CLOSE_RESPONSE:'종료 응답 결과',CLOSE_REQUEST_ACCEPTED:'종료 요청 수락',SHUTDOWN_BEGIN:'종료 시작',UI_HIDDEN:'오버레이 비표시',PROCESS_EXIT:'프로세스 종료 관측',FILE_CLEANUP:'파일 정리 결과',WINDOW_HIDDEN:'오버레이 비표시',SHUTDOWN_REQUESTED:'종료 시작'};
 const textLabel=value=>labels[value]||String(value??'확인되지 않음');
 const short=value=>typeof value==='string'&&value.length>28?value.slice(0,12)+'…'+value.slice(-10):String(value??'없음');
 const date=value=>{const d=new Date(value);return value&&Number.isFinite(d.getTime())?d.toLocaleString('ko-KR'):'기록 없음';};
 const badge=(value,implementation=false)=>`<span class="server-state-badge" data-outcome="${esc(value||'NOT_RECORDED')}">${esc(value==='PARTIAL'?(implementation?'부분 구현':'부분 결과'):textLabel(value))}</span>`;
 const manual=()=>status.capabilities?.manualVerification||{};
 const builds=()=>Array.isArray(manual().builds)?manual().builds:[];
 const build=()=>builds().find(row=>row.buildKey===selectedBuild)||null;
 const histories=()=>{const selected=build(),rows=Array.isArray(manual().history)?manual().history:[];return selected?rows.filter(row=>selected.history?.includes(row.id)||row.manifestId===selected.manifestId&&['A','B','O'].every(role=>(row.artifacts?.[role]?.sha512||row.artifacts?.[role])===selected.artifacts?.[role])):[];};
 function selectInitialBuild(){if(!build()){selectedBuild=(builds().find(row=>row.active)||builds()[0])?.buildKey||'';selectedReport='';}if(selectedReport&&!histories().some(row=>row.id===selectedReport))selectedReport='';}
 function configured(value){
  if(value===null||value===undefined)return '<span class="small-note">값 없음</span>';
  if(typeof value==='object')return `<dl class="server-state-values">${Object.entries(value).map(([key,item])=>`<div><dt>${esc(key)}</dt><dd>${configured(item)}</dd></div>`).join('')}</dl>`;
  return esc(typeof value==='boolean'?(value?'예':'아니요'):value);
 }
 function checksMarkup(domain){
  const checks=Array.isArray(domain?.checks)?domain.checks:[];
  if(!checks.length)return '<p class="small-note">이 분야의 시험 기록이 없습니다.</p>';
  return `<div class="table-wrap"><table class="server-state-checks"><thead><tr><th>시험 항목</th><th>결과</th><th>실행 범위 · 실행 환경</th><th>정책 · 시각</th></tr></thead><tbody>${checks.map(check=>`<tr><td><code>${esc(check.id)}</code>${check.reasonCode?`<p class="small-note">${esc(check.reasonCode)}</p>`:''}</td><td>${badge(check.outcome)}</td><td>${esc(scopeLabels[check.scope]||check.scope||'범위 미기록')}<br><span class="small-note">${esc(scopeLabels[check.execution]||check.execution||'실행 정보 없음')}</span>${check.evidenceSha512?`<details class="server-state-inline"><summary>증거 파일 SHA-512</summary><code class="server-state-digest">${esc(check.evidenceSha512)}</code></details>`:''}</td><td>${badge(check.policyStatus||'NOT_RECORDED')}<br><time>${esc(date(check.recordedAt))}</time></td></tr>`).join('')}</tbody></table></div>`;
 }
 function capabilityRows(){
  const rows=status.capabilities?.features;
  if(!Array.isArray(rows))return '<p class="small-note">기능 상태를 제공하지 않는 서버입니다. 검증 완료로 판단하지 않습니다.</p>';
  const selected=build(),record=histories().find(row=>row.id===selectedReport),domains=record?.domains||selected?.domains||manual().domains||[];
  return `<p class="small-note">구현, 현재 설정, 실기 검증을 별도로 표시합니다. 결과는 선택한 명세와 정확히 같은 A/B/O에만 연결됩니다. 관리자 보고는 CI 서명·하드웨어 증명·운영 게시 승인이 아닙니다.</p>
  <div class="server-state-build-bar"><label>대상 A/B/O 배포 조합<select id="server-verification-build"><option value="">등록된 배포 조합 ${builds().length?'선택':'없음'}</option>${builds().map(row=>`<option value="${esc(row.buildKey)}" ${row.buildKey===selectedBuild?'selected':''}>${row.active?'현재 운영 · ':row.registration&&row.registration!=='REGISTERED'?'현재 미등록 · ':''}${esc(short(row.manifestId))} · 기록 ${Number(row.recordCount)||0}개</option>`).join('')}</select></label>${button('verification-context','선택 조합의 시험 입력 JSON 저장',!selected||selected.registration&&selected.registration!=='REGISTERED')}</div>
  ${selected?`<details class="server-state-inline"><summary>선택한 명세 · 최종 A/B/O 해시 확인</summary><dl class="server-state-artifacts"><dt>배포 명세</dt><dd><code>${esc(selected.manifestId)}</code></dd>${['A','B','O'].map(role=>`<dt>${role} SHA-512</dt><dd><code>${esc(selected.artifacts?.[role]||'없음')}</code></dd>`).join('')}<dt>소스 명세</dt><dd><code>${esc(selected.sourceManifestSha512||'없음')}</code></dd></dl></details>`:'<p class="small-note">등록된 명세와 A/B/O가 있어야 대상 빌드의 시험 입력을 저장할 수 있습니다.</p>'}
  <label>선택 조합의 검증 이력<select id="server-verification-history"><option value="">분야별 최신 기록 합쳐 보기</option>${histories().map(row=>`<option value="${esc(row.id)}" ${row.id===selectedReport?'selected':''}>${esc(date(row.finishedAt||row.recordedAt))} · ${esc(textLabel(row.outcome))} · ${esc(row.runId||short(row.id))}</option>`).join('')}</select></label>
  <p class="small-note">${record?'선택한 한 실행의 결과입니다.':'각 시험의 가장 최근 기록을 표시합니다. 새 미실행·실패 기록이 이전 통과를 대체합니다.'} 정책 변경·미연결 결과와 미기록 항목은 통과로 간주하지 않습니다.</p>
  ${record?`<div class="server-state-report-meta">${badge(record.outcome)} ${badge(record.policyStatus||'UNBOUND')}<span>등록 ${esc(date(record.recordedAt))}</span><span>실행 ${esc(record.runId)}</span><span>하드웨어 증명 없음 · 게시 승인 아님</span></div>`:''}
  <div class="table-wrap"><table id="server-capabilities-table"><thead><tr><th>영역</th><th>구현</th><th>현재 서버 설정</th><th>선택 빌드의 실기 검증</th></tr></thead><tbody>${rows.map(row=>{const domain=domains.find(item=>String(item.id)===String(row.id)),hasChecks=domain?.checks?.some(check=>check.outcome!=='NOT_RECORDED'),legacy=row.verification?.status==='OPERATOR_RECORDED';return `<tr><td><strong>${esc(row.id)} · ${esc(row.name)}</strong></td><td>${badge(row.implementation,true)}</td><td><details class="server-state-inline"><summary>현재 설정 ${Object.keys(row.configured||{}).length}개</summary>${configured(row.configured)}</details></td><td>${badge(domain?.outcome||'NOT_RECORDED')}${domain?`<p>${badge(domain.policyStatus||'NOT_RECORDED')}</p><details class="server-state-inline"><summary>시험 ${Number(domain.checks?.length)||0}개 · ${Number(domain.missingChecks?.length)||0}개 미기록 상세</summary>${checksMarkup(domain)}</details>`:`<p class="small-note">${legacy?'기존 관리자 기록은 있으나 분야별 상세가 없습니다.':'검증 기록 없음'}</p>`}${hasChecks?'<p class="small-note">기록된 시험 범위 한정 · 하드웨어 증명 없음</p>':''}${row.limitations?.length?`<details class="server-state-inline"><summary>적용 한계</summary><ul>${row.limitations.map(limit=>`<li>${esc(limit)}</li>`).join('')}</ul></details>`:''}</td></tr>`;}).join('')}</tbody></table></div>
  <p class="small-note">저장된 검증 기록 ${Number(manual().recordCount)||0}개. CI는 선택 사항입니다. 검증 이력은 운영 게시 승인 조건을 변경하지 않습니다.</p>`;
 }
 function refreshCapabilities(){if(alive()){selectInitialBuild();el('server-capabilities-panel').innerHTML=capabilityRows();}}
 function lifecycleMarkup(){
  const items=Array.isArray(lifecycle?.items)?lifecycle.items:[],flow=items.find(row=>row.flowId===selectedFlow)||items[0];
  const events=Array.isArray(flow?.events)?flow.events:[];
  return `<p class="small-note">서버 권한 종료와 PC의 프로세스·파일 정리는 서로 다른 상태입니다. 종료·파일 삭제는 인증된 클라이언트 관측 보고이며, 보고가 없으면 PC에 남아 있는지 판단하지 않습니다.</p>
   <div class="server-state-build-bar"><label>실행 ID로 조회<input id="server-lifecycle-query" maxlength="128" autocomplete="off" spellcheck="false" placeholder="비워 두면 최근 실행" value="${esc(el('server-lifecycle-query')?.value||'')}"></label>${button('lifecycle-load',lifecycleLoading?'조회 중…':'종료 추적 새로고침',lifecycleLoading)}</div>
   ${lifecycleError?`<p class="server-state-alert" role="alert">${esc(lifecycleError)}</p>`:''}
   <label>실행 선택<select id="server-lifecycle-flow">${!items.length?'<option value="">조회된 실행 없음</option>':items.map(row=>`<option value="${esc(row.flowId)}" ${row.flowId===flow?.flowId?'selected':''}>${esc(date(row.createdAt))} · ${esc(row.flowId)}</option>`).join('')}</select></label>
   ${flow?`<div class="server-state-residual" data-confirmed="${flow.bResidual?.confirmed===true}"><strong>B 잔류 원인 · ${esc(flow.bResidual?.code||'상태 미확인')}</strong><p>${esc(flow.bResidual?.summary||'B의 종료 관측이 없습니다.')}</p><span class="small-note">${flow.bResidual?.confirmed===true?'해당 사유에 대한 서버 기록이 있습니다. PC의 실제 프로세스 부재를 증명하지는 않습니다.':'미확인 상태입니다. 잔류 또는 정상 정리를 단정하지 않습니다.'}</span></div>
   <div class="table-wrap"><table id="server-lifecycle-roles"><thead><tr><th>역할</th><th>서버 권한</th><th>프로세스 종료</th><th>파일 정리</th><th>최근 기록</th></tr></thead><tbody>${['A','B','O'].map(role=>{const row=flow.roles?.[role]||{};return `<tr><th>${role}<br><code class="small-note">${esc(row.sessionId||'세션 없음')}</code></th><td>${esc(textLabel(row.status||'상태 미기록'))}<br><span class="small-note">${row.authorityEnded===true?'서버 권한 종료':row.authorityEnded===false?'서버 권한 종료 미확인':'권한 상태 미확인'}</span></td><td>${badge(row.processExit||'NOT_REPORTED')}</td><td>${badge(row.fileCleanup||'NOT_REPORTED')}</td><td>${esc(date(row.lastAt))}</td></tr>`;}).join('')}</tbody></table></div>
   <ol class="server-state-timeline" id="server-lifecycle-events">${events.map(item=>`<li><time>${esc(date(item.at))}</time><div><strong>${esc(item.role||'서버')} · ${esc(eventLabels[item.event]||item.event)}</strong> ${badge(item.source)}${item.targetSessionId?`<p class="small-note">대상 세션 <code>${esc(item.targetSessionId)}</code>${item.reporterSessionId?' · 보고 세션 <code>'+esc(item.reporterSessionId)+'</code>':''}</p>`:''}<p>${esc(textLabel(item.status||''))}${item.reporterRole?' · 보고 '+esc(item.reporterRole):''}${Number.isInteger(item.pid)?' · PID '+item.pid:''}${Number.isInteger(item.exitCode)?' · 종료 코드 '+item.exitCode:''}${Number.isInteger(item.win32Error)&&item.win32Error?' · Windows 오류 '+item.win32Error:''}${Number.isFinite(item.elapsedMs)?' · '+item.elapsedMs+' ms':''}</p></div></li>`).join('')||'<li>연결된 종료 이벤트가 없습니다.</li>'}</ol>`:'<p class="small-note">실행 기록이 없어 종료·정리 여부를 판단할 수 없습니다.</p>'}`;
 }
 function refreshLifecycle(){if(alive())el('server-lifecycle-panel').innerHTML=lifecycleMarkup();}
 async function loadLifecycle(){
  const request=++lifecycleRequest,query=(el('server-lifecycle-query')?.value||'').trim();lifecycleLoading=true;lifecycleError='';refreshLifecycle();
  try{const value=await api(base+'/lifecycle?limit=20'+(query?'&flowId='+encodeURIComponent(query):''));if(alive()&&request===lifecycleRequest){lifecycle=value;if(!value.items?.some(row=>row.flowId===selectedFlow))selectedFlow=value.items?.[0]?.flowId||'';}}
  catch(error){if(alive()&&request===lifecycleRequest){lifecycle=null;lifecycleError=error.message+(error.code?' · '+error.code:'');}}
  finally{if(alive()&&request===lifecycleRequest){lifecycleLoading=false;refreshLifecycle();}}
 }
 async function saveVerificationContext(){
  const selected=build();if(!selected)throw Error('대상 배포 조합을 선택하세요.');if(selected.registration&&selected.registration!=='REGISTERED')throw Error('현재 등록된 배포 명세를 선택하세요.');
  const expected=selected.buildKey,value=await api(base+'/verification-context?manifestId='+encodeURIComponent(selected.manifestId));
  if(!alive()||build()?.buildKey!==expected)return;
  // The API envelope is not part of the strict on-disk context contract.
  const context=Object.fromEntries(Object.entries(value).filter(([key])=>key!=='ok'));
  const blob=new Blob([JSON.stringify(context,null,2)+'\n'],{type:'application/json'}),url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download='verification-context-'+selected.manifestId.slice(0,16)+'.json';root.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  message('선택한 명세·A/B/O·현재 정책의 시험 입력을 저장했습니다. 실기 보고 생성 시 이 파일을 사용하세요.');
 }
 function render(){
  if(!alive())return;
  selectInitialBuild();
  root.innerHTML=`<p class="small-note">인증·복구 세대·소비/폐기 이력은 서버가 판단합니다. 클라이언트 실행·렌더링·TLS 확인·측정과 짧은 수명의 메모리 키는 남습니다. 영속 장치키와 TPM 증명의 요구 수준은 아래 서버 정책으로 결정합니다. 원격 다중 서버 합의는 지원하지 않습니다.</p>
   <div class="actions">${button('refresh','서버 상태 새로고침')}</div><p id="server-state-status" role="status" aria-live="polite"></p>
   <details open><summary>1~14 기능 · 설정 · 검증 상태</summary><div id="server-capabilities-panel">${capabilityRows()}</div></details>
   <details><summary>분야별 실기 보고 등록 · 기존 Windows 시험 기록</summary><p class="small-note">1·2·4·8·11·12를 포함한 분야별 실기 보고와 기존 manual-…-results-verification.json을 등록합니다. 시험 도구가 생성한 실제 결과를 선택하세요. 서버가 등록된 명세·최종 A/B/O·현재 정책과 연결하며 실패·부분·미실행도 그대로 보존합니다.</p>
   <input id="server-manual-verification" type="file" accept=".json,application/json" aria-label="분야별 실기 또는 수동 Windows 시험 JSON">${button('manual-verification','시험 기록 등록')}
   <p class="small-note">최대 64KiB. 검증 이력에서 대상을 선택하여 결과를 확인하세요. CI 서명이나 게시 승인을 만들지 않습니다.</p></details>
   <details open><summary>A/B/O 종료 · 파일 정리 추적</summary><div id="server-lifecycle-panel">${lifecycleMarkup()}</div></details>
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
 root.addEventListener('change',e=>{if(!alive())return;if(e.target.id==='server-verification-build'){selectedBuild=e.target.value;selectedReport='';refreshCapabilities();return;}if(e.target.id==='server-verification-history'){selectedReport=e.target.value;refreshCapabilities();return;}if(e.target.id==='server-lifecycle-flow'){selectedFlow=e.target.value;refreshLifecycle();return;}if(e.target.id.startsWith('server-identity-')){identityPolicyRequestId=crypto.randomUUID();identityRevokeRequestId=crypto.randomUUID();}if(e.target.id.startsWith('server-device-'))replacementRequestId=crypto.randomUUID();if(e.target.id==='server-recovery-reason')recoveryRequestId=crypto.randomUUID();if(e.target.id.startsWith('server-storage-'))storageRequestId=crypto.randomUUID();});
 root.addEventListener('click',async event=>{
  const target=event.target.closest('[data-server-state-action]');if(!target||!alive()||busy)return;const action=target.dataset.serverStateAction;busy=true;target.disabled=true;
  try{
   if(action==='refresh'){await reload();await loadLifecycle();return;}
   if(action==='verification-context'){await saveVerificationContext();return;}
   if(action==='lifecycle-load'){await loadLifecycle();return;}
   if(action==='scan'||action==='scan-next'){const scan=await api(base+'/orphans'+(action==='scan-next'?'?after='+encodeURIComponent(nextAfter||''):''));if(alive()){candidates=scan.items;nextAfter=scan.nextAfter;render();message('서버 파일 검사 결과입니다. 자동 격리·삭제는 하지 않았습니다.');}return;}
   if(action==='recover'){
    if(!el('server-recovery-confirm').checked)throw Error('세션 폐기 확인란을 선택하세요.');
    const result=await api(base+'/recover-sessions',{method:'POST',body:{requestId:recoveryRequestId,expectedEpoch:status.epoch,reasonCode:el('server-recovery-reason').value}});
    if(alive()){message('서버 복구 세대 '+result.epoch+' 적용 완료. 창을 닫고 다시 로그인하세요.');root.querySelectorAll('button,input,select').forEach(n=>{n.disabled=true;});closed=true;}return;
   }
   if(action==='manual-verification'){
    const file=el('server-manual-verification').files?.[0];if(!file||file.size>65536)throw Error('64KiB 이하의 시험 보고 JSON을 선택하세요.');
    const reportText=await file.text();if(!alive())return;
    const imported=await api(base+'/manual-verification',{method:'POST',body:{reportText}});
    if(alive()){await reload();const importedBuild=builds().find(row=>row.manifestId===imported.record?.manifestId&&row.history?.includes(imported.record?.id));if(importedBuild){selectedBuild=importedBuild.buildKey;selectedReport=imported.record.id;refreshCapabilities();}message('시험 기록을 등록했습니다. 해당 명세·A/B/O의 검증 이력에서 확인하세요. 게시 승인 조건은 바꾸지 않습니다.');}return;
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
 render();void loadLifecycle();try{await done;}finally{closed=true;++lifecycleRequest;lifecycle=null;selectedBuild='';selectedReport='';selectedFlow='';status=null;devices=null;quarantine=null;identity=null;candidates=[];nextAfter=null;recoveryRequestId='';checkpointRequestId='';replacementRequestId='';storageRequestId='';identityPolicyRequestId='';identityRevokeRequestId='';if(root.isConnected)root.replaceChildren();}
}
