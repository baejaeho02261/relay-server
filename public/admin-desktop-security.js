'use strict';
// Modal state is ephemeral: no localStorage, sessionStorage, IndexedDB or policy
// cache. Closing / logging out drops the policy draft and public approval file.
async function showDesktopSecurityOperations() {
  if(!roleIsAdmin()||!session)throw Error('관리자 로그인을 확인해주세요.');
  const owner=session.csrf,base='/api/desktop/bootstrap/security-operations';
  let data=await api('/api/desktop/bootstrap/security-authority'),policyPreview='',pairPreview=null,rolloutPreview='',busy=false,closed=false;
  let recoveryPreview=null,recoveryDraft='',recoveryRequestId='';
  let activationState=(await api(base+'/activation')).status,activationPreview=null;
  if(!roleIsAdmin()||session?.csrf!==owner)return;
  const done=openModal({title:'서버 보안 · 배포 운영',html:'<section id="desktop-security-root" class="desktop-security"></section>',confirmLabel:'닫기'});
  const root=document.getElementById('desktop-security-root');
  const alive=()=>!closed&&root.isConnected&&session?.csrf===owner&&roleIsAdmin();
  const node=id=>root.querySelector('#'+id);
  const select=(id,items,value)=>`<select id="${id}">${items.map(([v,label])=>`<option value="${esc(v)}" ${v===value?'selected':''}>${esc(label)}</option>`).join('')}</select>`;
  const checkbox=(id,label,value,locked=false)=>`<label><input type="checkbox" id="${id}" ${value?'checked':''} ${locked?'disabled aria-disabled="true"':''}> ${esc(label)}</label>`;
  const input=(id,label,value,type='text')=>`<label>${esc(label)}<input id="${id}" type="${type}" value="${esc(value??'')}" autocomplete="off"></label>`;
  const button=(action,label)=>`<button type="button" data-security-action="${action}">${label}</button>`;
  const sections=()=>Array.from(root.children).filter(x=>x.tagName==='DETAILS');
  const reasonText=reason=>({
    INTEGRITY_MEASUREMENT_BUILD_UPGRADE_REQUIRED:'A/B/O를 새 측정 규격으로 모두 다시 빌드·검증해 등록하세요.',
    TLS_PIN_ACTIVE_BUILD_UPGRADE_REQUIRED:'현재 운영 A/B/O 모두 새 pin 전환 규격을 지원해야 합니다.',
    TLS_PIN_GENERATION_CONFLICT:'pin 전환 세대가 바뀌었습니다. 새로고침 후 확인하세요.',
    TLS_PIN_TRANSITION_NOT_FINISHED:'이전 전환이 종료되고 새 인증서가 활성화된 뒤 다음 전환을 등록하세요.',
    SECURITY_RELEASE_MIXED_MANIFEST:'선택한 A/B/O의 명세 ID가 다르거나 누락되었습니다. 같은 명세로 등록한 세 후보를 선택하세요.',
    SECURITY_RELEASE_MANIFEST_NOT_REGISTERED:'계획 등록만 완료된 명세입니다. 아래 명세 영역에서 같은 JSON으로 [세 파일 확인 후 명세 등록 완료]를 실행하세요.',
    SECURITY_RELEASE_MANIFEST_REQUIRED:'선택한 후보에 등록된 배포 명세가 필요합니다.',
    SECURITY_CI_EVIDENCE_REQUIRED:'기존 실행에 저장된 CI 요구가 남아 있습니다. 배포 명세 영역에서 현재 조합에 수동 배포 정책을 적용하거나, 승인한 최종 A/B/O와 명세로 새 조합을 검증·게시하세요. CI 시험 PASS는 생성하지 않습니다.',
    SECURITY_PUBLICATION_REQUIREMENTS_REQUIRED:'운영 게시에는 최종 A/B/O의 유효한 EXE 승인 서명, 등록 완료된 동일 명세와 보안 버전 1 이상이 필요합니다. 아래 수동 배포 순서로 준비하세요. CI 증거 JSON은 요구하지 않습니다.',
    SECURITY_RELEASE_MANIFEST_INVALID:'명세 내용 또는 ID가 유효하지 않습니다. 생성 도구의 원본 JSON을 확인하세요.',
    SECURITY_MANIFEST_ARTIFACT_MISMATCH:'명세의 파일과 선택한 후보가 다릅니다. 승인 처리까지 끝난 최종 EXE와 명세를 확인하세요.'
  }[reason]||reason);
  function compatibilityMatrix(){
    const matrix=data.mitigationCompatibility||{records:[]};
    if(!matrix.records.length)return '<p class="small-note">아직 등록한 Windows·GPU·드라이버 관측 결과가 없습니다. NOT_RUN · 기존 정책 유지.</p>';
    const judgement={NOT_RUN:'미실행',INPUT_OR_RELEASE_CHANGED:'파일·명세 변경: 다시 검사',STALE_RETEST_REQUIRED:'30일 경과: 다시 검사',DO_NOT_APPLY:'미지원·실패: 적용 근거 없음',PROBE_PASS_PRODUCT_VALIDATION_REQUIRED:'probe 통과 · 실제 A/B/O 흐름 시험 필요'};
    return matrix.records.map(record=>`<article class="desktop-compatibility-record"><p><strong>${esc(record.runId)}</strong> · ${esc(record.finishedAt)}<br><small>명세 ${esc(record.manifestId.slice(0,20))}… · ${record.activeArtifacts?'현재 운영 파일':'다른 후보 파일'} · 운영자 기록</small></p>
      <table><thead><tr><th>Windows 빌드</th><th>범위 / 정책</th><th>결과</th><th>GPU·드라이버 식별</th><th>적용 판단</th></tr></thead><tbody>${record.rows.map(row=>`<tr><td>${esc(row.environment?.windowsBuild??'미수집')}</td><td>${esc(row.componentScope)} / ${esc(row.mode)}</td><td>${esc(row.status)}</td><td>${row.componentScope==='O'?esc(row.environment?.gpuIdentitySha512?.slice(0,20)||'미수집')+'…':'그래픽 시험 아님'}</td><td>${esc(judgement[row.judgement]||row.judgement)}</td></tr>`).join('')}</tbody></table>
      <details><summary>정책 조회값·오류 코드 / 전체 GPU·드라이버 fingerprint</summary><pre>${esc(JSON.stringify(record.rows,null,2))}</pre></details></article>`).join('');
  }
  function publishReady(){return !!pairPreview&&pairPreview.policyRevision===data.policy.revision&&pairPreview.operationsRevision===data.operations.operations.revision&&pairPreview.selection===JSON.stringify(pairBody());}
  function reportStatus(message,state='success',sectionIndex=-1){
    for(const el of [node('security-status'),sections()[sectionIndex]?.querySelector(':scope > .security-section-status')])if(el){el.hidden=false;el.textContent=message;el.dataset.state=state;}
  }
  function updatePairStatus(message){
    const ready=publishReady(),view=node('sec-pair-status');
    node('sec-activate').disabled=busy||!ready;
    if(view){view.dataset.state=ready?'ready':'pending';view.textContent=message||(ready?'조합 검증을 통과했습니다. 선택한 A/B/O를 운영 게시할 수 있습니다.':'선택한 A/B/O 조합을 먼저 검증해주세요.');}
    const release=pairPreview?.result?.release,ciVerified=release?.evidenceType==='CI_SIGNED_VERIFIED'&&release?.ciVerification==='SIGNATURE_VERIFIED';
    node('sec-ci-status').textContent=ciVerified?'CI 서명 증거 확인됨 · 하드웨어 실행 증명이 아닙니다.':'CI 미실행/미검증 · 수동 배포의 서명·명세 확인은 Windows 시험 PASS가 아닙니다.';
    const rows=data.operations.candidates,governance=data.operations.operations.releaseGovernance||{};
    const selected=Object.entries(pairBody()).map(([key,id])=>({component:key[0].toUpperCase(),candidate:rows.find(row=>row.id===id)}));
    node('sec-candidate-summary').innerHTML=selected.map(({component,candidate})=>`<div><strong>${component}</strong> ${candidate?`<span>${esc(candidate.id)}</span><small>명세 ${esc(candidate.deploymentManifestId?candidate.deploymentManifestId.slice(0,20)+'…':'미연결')}</small>`:'<span>선택 안 함</span>'}</div>`).join('');
    const ids=selected.filter(x=>x.candidate).map(x=>x.candidate.deploymentManifestId||''),stage=node('sec-release-stage');
    const common=ids.length&&ids[0]&&ids.every(id=>id===ids[0])?ids[0]:'';
    const record=common&&governance.manifests?.[common];
    if(record){const registered=(record.registration||'REGISTERED')==='REGISTERED';stage.dataset.state=registered?'REGISTERED':'PLANNED';stage.textContent=registered?'명세 등록 완료 · REGISTERED — 다음 단계: 조합 검증':'명세 계획 등록 · PLANNED — 다음 단계: 같은 JSON으로 세 파일 확인 후 명세 등록 완료';}
    else{stage.dataset.state='pending';stage.textContent=ids.some(Boolean)?'선택한 후보의 명세 연결을 확인하세요. 조합 검증에서 서버가 최종 판정합니다.':'명세 미연결 — 현재 서버의 명세 요구 조건은 조합 검증에서 확인합니다.';}
  }
  function render(){
    if(!alive())return;
    const p=data.policy,box=data.operations,s=box.operations,active=box.active,rows=box.candidates;
    const previous=node('sec-a')?pairBody():null,opened=sections().map(x=>x.open);
    const selected=component=>{const id=previous?previous[component.toLowerCase()+'Id']:active[component]||'';return rows.some(x=>x.component===component&&x.id===id)?id:'';};
    const g=s.releaseGovernance||{requireManifest:false,requireCiEvidence:false,minimumSecurityVersion:0,manifests:{},ciKeys:{},ciEvidence:{}};
    const publication=box.productionPublication;
    const pinState=data.tlsPinTransition||{enabled:false,generation:0};
    const publicationFloor=Math.max(1,publication?.requirements?.minimumSecurityVersion||g.minimumSecurityVersion||0);
    const legacyRuntime=publication?.legacyRuntimePolicy??(!g.requireManifest||g.requireCiEvidence||g.minimumSecurityVersion<1);
    const choices=component=>rows.filter(x=>!component||x.component===component).map(a=>[a.id,`${a.component} · ${a.version} · 후보 ${a.id} · 명세 ${a.deploymentManifestId?a.deploymentManifestId.slice(0,12)+'…':'미연결'}${a.active?' · 운영 중':''}`]);
    policyPreview='';rolloutPreview='';activationPreview=null;recoveryPreview=null;
    if(pairPreview&&(pairPreview.policyRevision!==p.revision||pairPreview.operationsRevision!==s.revision))pairPreview=null;
    root.innerHTML=`<p class="small-note">정책·검사 기준·승인·배포 이력은 서버에 저장합니다. 이 화면은 메모리에서만 초안을 유지합니다. 시험 기록은 운영자 확인 자료이며 하드웨어 실행 증명이 아닙니다.</p>
      <div class="actions">${button('refresh','새로고침')}</div>
      <p id="security-status" role="status" aria-live="polite"></p>
      <div class="kv"><div>정책 / 운영 revision</div><div>${p.revision} / ${s.revision}</div><div>관리자 보호</div><div>${box.adminProtection?.recentReauthenticationRequired?'1인 운영 · 중요 변경 시 최근 재인증 필요':'1인 운영 · 기존 관리자 로그인 사용'}</div><div>감사 저장</div><div>${esc(box.auditHealth.status)} · 프로세스 시작 후 실패 ${box.auditHealth.failedWrites}건</div></div>
      <details open><summary>1인 운영 · 현재 가능한 보호 적용</summary>
      <p><strong>${activationState.allEnabled?'1인 운영 · 서버 및 Windows 강제 설정 켜짐':activationState.serverEnabled?'1인 운영 · 서버 검사 규격/시험 요구까지 켜짐':activationState.baselineEnabled?'1인 운영 · 기본 서버 보호 적용됨 · 추가 검증은 별도':'1인 운영 · 기본 서버 보호 적용 전'}</strong></p>
      <p class="small-note">현재 서버 저장값을 표시합니다. 관리자 혼자 적용합니다. 서버에서 최근 재인증을 요구하면 현재 관리자 인증을 한 번 더 확인합니다. 추가 운영자 승인은 요구하지 않습니다. 보호 설정과 실제 PC 실행 검증은 구분합니다.</p>
      <label>활성화 범위${select('sec-enable-profile',[['READY','현재 가능한 서버 보호: 1인 운영 / Windows 설정 유지']],'READY')}</label>
      <div class="actions">${button('check-enable-all','적용 내용 확인')}<button type="button" id="sec-enable-all-button" data-security-action="enable-all" disabled>확인한 보호 설정 적용</button></div>
      <div id="sec-enable-issues" class="desktop-security-result" role="status" aria-live="polite"></div><pre id="sec-enable-preview" class="desktop-security-result"></pre>
      <p class="small-note">서명·실제 파일·감사 저장 오류는 적용을 막습니다. 아직 없는 검사 규격·시험 기록·최근 관측은 별도 준비 항목으로 표시합니다. 이미 켜진 요구는 자동 해제하지 않습니다. 시험 PASS 생성이나 CFG 플래그 변경은 하지 않으며, 기존 시험 적용은 종료합니다.</p></details>
      <details><summary>정책 편집 · 적용 전 영향 미리보기</summary><div class="desktop-security-grid">
      <label>검사 결과 정책${select('sec-mode',[['enforce','검사 실패 시 작업 보류'],['observe','관찰만']],p.mode)}</label>
      <label>동적 코드${select('sec-dynamic',[['observe','상태 조회만'],['prohibit','생성·수정 제한 요구']],p.dynamicCode)}</label>
      ${input('sec-fresh','판정 유효기간 (ms)',p.freshnessMs,'number')}${input('sec-challenge','challenge 유효기간 (ms)',p.challengeMs,'number')}
      ${input('sec-min-a','최소 A 버전',p.minVersionA)}${input('sec-min-b','최소 B 버전',p.minVersionB)}${input('sec-min-o','최소 O 버전',p.minVersionO??'0')}
      ${checkbox('sec-legacy','구버전 금지',p.enforceLegacy)}${checkbox('sec-readonly','읽기 전용 API 저장 요구',p.requireReadonlyApi)}${checkbox('sec-cfg','CFG 요구',p.requireCfg)}${checkbox('sec-signature','배포 서명 강제',p.requireReleaseSignature)}${checkbox('sec-device-signals','선택적 장치 관측 요청 (원본 식별자 미전송)',p.deviceSignalsRequested===true)}
      </div><label>신뢰 서명자 공개키 목록 (서명 도구의 trustedKey 배열 · 개인키 금지)<textarea id="sec-keys" rows="5" spellcheck="false">${esc(JSON.stringify(p.trustedReleaseKeys,null,2))}</textarea></label>
      <label>철회할 파일 SHA-512 (한 줄에 하나)<textarea id="sec-revoked" rows="3">${esc(p.revokedSha512.join('\n'))}</textarea></label>
      <div class="actions">${button('preview-policy','영향 미리보기')}${button('save-policy','미리본 정책 적용')}</div><pre id="sec-policy-preview" class="desktop-security-result"></pre>
      <p class="small-note">선택적 장치 관측은 지원하는 새 클라이언트에만 요청하며 기본값은 꺼짐입니다. 세션·Challenge 범위의 해시만 진단용으로 받고 기존 장치 Binding이나 실행 승인 기준을 바꾸지 않습니다. 전역 정책 적용은 진행 중인 빌드별 시험 적용을 종료합니다. 연결되지 않은 PC의 호환성은 판정하지 않습니다.</p></details>
      <details><summary>Windows · GPU 호환성별 완화 정책</summary>
      <p class="small-note">CI는 선택 사항입니다. IDE에서 ProcessMitigationProfileProbe와 OverlayMitigationProbe를 빌드한 뒤 Run_Mitigation_Compatibility.bat으로 관측 JSON을 만드세요. 같은 최종 A/B/O·등록 명세·소스 기록과 연결하며, O의 GPU fingerprint에는 실제 DXGI 어댑터와 UMD 드라이버 버전이 포함됩니다.</p>
      <label>수동 호환성 관측 JSON<input id="sec-compatibility-report" type="file" accept=".json,application/json"></label>
      ${button('import-mitigation-compatibility','호환성 관측 기록 등록')}
      <p class="small-note">읽어 온 정책 값과 오류 코드를 표시합니다. probe 통과는 실제 A/B/O 전체 흐름 통과·하드웨어 증명으로 바뀌지 않습니다. 미실행·미지원·변경·만료는 별도로 표시하며 이 기록으로 정책을 자동 적용하거나 완화하지 않습니다.</p>
      ${compatibilityMatrix()}
      <details><summary>선택적 CI 서명 프로필 적용</summary><p class="small-note">아래 프로필 기능만 실제 Windows 시험과 전용 CI 서명·동일 빌드·OS·GPU 결속이 필요합니다. 일반 게시나 위 수동 관측 등록의 필수 조건은 아닙니다. CFG 메타데이터만으로 전체 호출부 보호를 인정하지 않습니다.</p>
      <label>서명된 호환성 시험 증빙 JSON<input id="sec-mitigation-evidence" type="file" accept=".json,application/json"></label>
      ${checkbox('sec-mitigation-enabled','검증된 조합에 프로필 사용',true)}
      ${button('save-mitigation-profile','서명 증빙 확인 후 프로필 저장')}
      <pre>${esc(JSON.stringify(data.mitigationProfiles||{profiles:[]},null,2))}</pre></details></details>
      <details><summary>빌드별 검사 규격 · 단계적 적용</summary><label>검사 규격 대상${select('sec-contract-artifact',choices(),rows[0]?.id||'')}</label>
      <div class="desktop-security-grid">${input('sec-min-slots','최소 API 슬롯 수 (실제 probe 결과 기준)','','number')}${input('sec-max-slots','최대 API 슬롯 수','','number')}</div>
      ${button('save-contract','이 빌드 규격 저장')}<p class="small-note">V1의 자기 이미지·API 저장·완화 정책 3개 검사와 기존 10필드 응답을 사용합니다. 슬롯 수를 추정값으로 자동 등록하지 않습니다.</p>
      <div class="desktop-security-grid">${checkbox('sec-contract-required','모든 승인 빌드에 검사 규격 요구',s.requireBuildContract)}${checkbox('sec-tests-required','A/B/O 게시 전 시험 PASS 기록 요구',s.requireTestEvidence)}</div>${button('save-controls','운영 요구 조건 저장')}
      <label>시험 적용 대상 (서버 승인 빌드만 선택)<select id="sec-rollout-builds" multiple size="5">${rows.map(a=>{const key=a.component+':'+a.sha512;return `<option value="${esc(key)}" ${s.rollout.artifactKeys.includes(key)?'selected':''}>${esc(a.component+' '+a.version+' · '+a.sha512.slice(0,12))}</option>`;}).join('')}</select></label>
      ${checkbox('sec-rollout-enabled','선택 빌드에만 시험 정책 적용',s.rollout.enabled)}
      <label>시험 정책 (4개 필드만 허용)<textarea id="sec-rollout-patch" rows="4">${esc(JSON.stringify(Object.keys(s.rollout.patch).length?s.rollout.patch:{mode:p.mode,requireReadonlyApi:p.requireReadonlyApi,dynamicCode:p.dynamicCode,requireCfg:p.requireCfg},null,2))}</textarea></label><div class="actions">${button('preview-rollout','시험 적용 영향 미리보기')}${button('save-rollout','미리본 시험 적용 / 종료')}</div><pre id="sec-rollout-preview" class="desktop-security-result"></pre></details>
      <details><summary>배포 후보 · A/B/O 동시 게시 · 검증된 이전 조합으로 전환</summary>
      <p class="small-note">기존 A/B/O 파일 등록 버튼은 후보만 등록합니다. 이 화면에서 조합을 선택해 운영 게시합니다. 이전 조합도 현재 서명·철회·시험 정책을 통과해야 합니다.</p>
      <div class="desktop-security-grid"><label>A${select('sec-a',[['','A 후보 선택'],...choices('A')],selected('A'))}</label><label>B${select('sec-b',[['','B 후보 선택'],...choices('B')],selected('B'))}</label><label>O${select('sec-o',[['','오버레이 사용 안 함'],...choices('O')],selected('O'))}</label></div>
      <div id="sec-candidate-summary" class="security-candidate-summary"></div><p id="sec-release-stage" class="security-release-stage"></p>
      <div class="actions">${button('preview-pair','조합 검증')}<button type="button" id="sec-activate" data-security-action="activate" disabled>검증한 A/B/O 조합 운영 게시</button></div><p id="sec-pair-status" class="security-pair-status" role="status" aria-live="polite"></p><pre id="sec-pair-preview" class="desktop-security-result"></pre>
      <p id="sec-ci-status" class="small-note">CI 미실행/미검증 · 수동 배포의 서명·명세 확인은 Windows 시험 PASS가 아닙니다.</p>
      <details><summary>선택 사항 · 운영자 시험 기록</summary><label>시험 결과 JSON (Windows 수집 도구 결과 또는 운영자 확인 자료)<input type="file" id="sec-evidence-file" accept=".json,application/json"></label>${button('record-evidence','선택 A/B/O에 시험 결과 기록')}
      <p class="small-note">nativeBuild · apiProbe · integration은 PASS / FAIL / NOT_RUN을 구분합니다. 실제 실행하지 않은 항목을 PASS로 표시하지 마세요. 이 기록은 CI 서명을 대신하지 않습니다.</p></details>
      <pre class="desktop-security-result">${esc(JSON.stringify(s.activations.slice(-10).reverse(),null,2))}</pre></details>
      <details><summary>배포 명세 · 수동 배포 · 최소 보안 버전</summary>
      <p class="small-note">수동 빌드한 최종 A/B/O의 EXE 승인 서명, 하나의 등록 완료된 배포 명세, 보안 버전 1 이상을 서버가 확인합니다. CI 증거 JSON은 요구하지 않습니다. 서명·명세 확인만으로 실제 Windows 시험을 통과했다고 표시하지 않습니다.</p>
      <div class="desktop-security-grid">${checkbox('sec-manifest-required','하나의 A/B/O 배포 명세 필수',true,true)}${input('sec-security-floor','최소 보안 배포 버전 (1 이상 · 낮출 수 없음)',publicationFloor,'number')}</div>
      <p id="sec-ci-requirement" class="small-note">신규 운영 게시: CI 증거 요구 안 함 · EXE 승인 서명 및 명세 검사 유지</p>
      ${button('save-release-governance','현재 조합에 수동 배포 정책 적용')}
      <p id="sec-runtime-governance" class="small-note">${legacyRuntime?'기존 실행: 과거 저장 정책 유지. 현재 조합에 수동 배포 정책을 적용하거나 새 조합을 게시하면 CI 요구를 해제하고 명세·보안 버전 조건을 저장합니다.':'기존 실행에도 수동 배포의 명세·최소 보안 버전 정책이 적용되어 있습니다.'}${g.requireCiEvidence?' 현재 저장된 기존 실행 정책: CI 증거 요구 켜짐.':''}</p>
      <p class="small-note">현재 운영 조합도 서명·명세 검증을 통과해야 이 조건을 저장할 수 있습니다. 명세가 없는 기존 조합은 승인한 최종 A/B/O로 명세를 준비해 새로 게시하세요. 실패하면 기존 운영 조합과 정책을 바꾸지 않습니다.</p>
      <div class="actions">${button('download-policy','명세 생성용 현재 정책 JSON 저장')}</div><p class="small-note">내려받은 deployment-policy.json을 BAT가 있는 GameWeb/tools 폴더에 저장하세요. 현재 정책 SHA-512: <code>${esc(box.policySha512||'현재 정책을 새로고침하세요.')}</code></p>
      <div class="small-note" id="sec-manual-workflow"><strong>IDE 수동 빌드부터 운영 게시까지</strong>
      <ol><li>필요할 때 <code>Prepare_ImGui.bat</code>으로 ImGui 브리지를 준비하고, IDE에서 A/B/O를 Win64 Release로 빌드합니다. 최종 EXE는 <code>GameConnect_Win64/Win64/Release</code>에 모입니다.</li>
      <li><code>Create_Spec.bat</code>으로 실제 버전의 <code>tools/spec.json</code>을 준비하고, 위 버튼으로 현재 서버 정책을 <code>tools/deployment-policy.json</code>에 저장합니다. 사용할 EXE 승인 공개키가 이 정책의 신뢰 서명자에 있어야 합니다.</li>
      <li>같은 최종 A/B/O 각각에 <code>Create_Approval.bat</code> → <code>Check_Approval.bat</code>을 실행합니다. 승인 도구 처리가 끝난 최종 파일과 승인 JSON을 보관합니다.</li>
      <li>그 세 파일로 <code>Create_Release_Manifest.bat</code> → <code>Check_Release_Manifest.bat</code>을 실행해 <code>tools/release-manifest.json</code>을 준비합니다.</li>
      <li>아래에서 명세를 계획 등록하고, 최종 A/B/O와 각 승인 JSON을 같은 명세 ID로 후보 등록합니다. 같은 명세 JSON으로 등록을 완료한 뒤 <strong>조합 검증 → 운영 게시</strong>를 진행합니다.</li></ol>
      <p>승인이나 명세 생성 후 EXE를 다시 빌드·변경했다면 새 최종 파일로 승인·명세를 다시 준비하세요. CI 키 생성과 Windows CI 실행은 이 수동 배포 순서에 포함되지 않습니다.</p></div>
      <label>배포 명세 JSON (tools/release-manifest.json)<input type="file" id="sec-manifest-file" accept=".json,application/json"></label>${button('plan-manifest','파일 업로드 전 명세 계획 등록')}${button('record-manifest','세 파일 확인 후 명세 등록 완료')}
      <div class="security-manifest-list">${Object.entries(g.manifests).map(([id,r])=>`<article class="security-manifest-card"><div><strong>${esc(r.manifest.releaseName)}</strong><span class="security-manifest-state" data-state="${esc(r.registration||'REGISTERED')}">${(r.registration||'REGISTERED')==='REGISTERED'?'등록 완료 · REGISTERED':'계획 등록 · PLANNED'}</span></div><code>${esc(id)}</code><p>${(r.registration||'REGISTERED')==='REGISTERED'?'후보를 선택하고 조합 검증을 진행하세요.':'A/B/O 후보 등록 후 같은 JSON으로 [세 파일 확인 후 명세 등록 완료]를 실행하세요.'}</p></article>`).join('')||'<p class="empty">등록된 배포 명세가 없습니다.</p>'}</div>
      <pre class="desktop-security-result">${esc(JSON.stringify(Object.entries(g.manifests).map(([id,r])=>({manifestId:id,releaseName:r.manifest.releaseName,securityVersion:r.manifest.securityVersion,handoffVersion:r.manifest.handoffVersion,recordedAt:r.recordedAt,registration:r.registration||'REGISTERED'})),null,2))}</pre><p class="small-note">위 목록은 저장 기록입니다. 현재 유효성은 [조합 검증]에서 키 상태와 정책을 다시 검사합니다.</p></details>
      <details><summary>긴급 복구 · 승인한 조합으로 전환</summary><p class="small-note">위 A/B/O 선택을 대상으로 복구 내용을 준비한 뒤 명시적으로 승인·적용합니다. 보안 버전 하한·EXE 승인 서명·명세·실제 파일 검증을 그대로 적용하며 낮은 버전 예외 통과는 없습니다. 계획은 현재 정책/운영 revision에 결속되고 5분 후 만료됩니다.</p>
      ${input('sec-recovery-reason','복구 사유','')}<div class="actions">${button('prepare-recovery','선택 조합의 복구 내용 준비')}<button type="button" id="sec-recovery-apply" data-security-action="apply-recovery" disabled>준비한 복구 승인·적용</button></div><pre id="sec-recovery-preview" class="desktop-security-result"></pre>
      <pre class="desktop-security-result">${esc(JSON.stringify(Object.entries(g.recoveryPlans||{}).map(([recoveryId,r])=>({recoveryId,reason:r.reason,status:r.status,createdAt:r.createdAt,appliedAt:r.appliedAt,manifestId:r.manifestId})),null,2))}</pre></details>
      <details id="sec-optional-ci"><summary>선택 사항 · 기존 CI 공개키와 시험 이력</summary>
      <label>CI 공개키 JSON (Export_CI_Public_Key.bat의 ci-public-key.json · 개인키 금지)<input type="file" id="sec-ci-key-file" accept=".json,application/json"></label>${button('record-ci-key','CI 전용 공개키 등록')}
      <p class="small-note">수동 운영 게시에는 CI 키가 필요하지 않습니다. 기존 키와 시험 기록은 보존합니다. ACTIVE는 선택적인 새 CI 증거를 허용합니다. RETIRING은 기존 증거만 유지하며 REVOKED는 기존 증거도 무효화합니다. 키 철회는 복원할 수 없으며 현재 실행에도 영향을 줍니다. 키 유효기간은 발급 후 변경하지 않습니다.</p>
      ${Object.values(g.ciKeys).map(k=>`<div class="desktop-security-signer"><code>${esc(k.keyId)}</code>${select('ci-signer-'+k.keyId,[['ACTIVE','정상 사용'],['RETIRING','전환 중'],['REVOKED','긴급 철회']],k.state)}<button type="button" data-security-action="ci-signer" data-key="${esc(k.keyId)}">CI 키 상태 저장</button></div>`).join('')||'<p>등록된 CI 키가 없습니다.</p>'}
      <pre class="desktop-security-result">${esc(JSON.stringify(g.ciEvidence||{},null,2))}</pre><p class="small-note">저장된 시험 기록만 표시합니다. 키 등록이나 이력 보존으로 CI PASS를 새로 만들지 않습니다.</p></details>
      <details><summary>서버·승인·CI 키 용도 분리</summary><p class="small-note">서버 통신/TLS/EXE 승인/CI 키의 정규화한 공개키 지문으로 중복 용도를 거절합니다. 저장하는 정보는 공개 지문과 용도뿐이며 이 화면에서 서버 개인키를 내보내지 않습니다.</p><pre class="desktop-security-result">${esc(JSON.stringify(box.keyPurposes||{},null,2))}</pre></details>
      <details><summary>서명 키 전환 · 철회</summary><p class="small-note">ACTIVE: 신규 서명 배포 허용. RETIRING: 기존 배포 검증만 허용. REVOKED: 기존 배포도 거절하며 복원 불가. 현재 운영 키 철회는 세션 작업을 막을 수 있습니다.</p>
      ${p.trustedReleaseKeys.map(k=>`<div class="desktop-security-signer"><code>${esc(k.keyId)}</code>${select('signer-'+k.keyId,[['ACTIVE','정상 사용'],['RETIRING','전환 중'],['REVOKED','긴급 철회']],s.signerStates[k.keyId]?.state||'ACTIVE')}<button type="button" data-security-action="signer" data-key="${esc(k.keyId)}">상태 저장</button></div>`).join('')||'<p>등록된 신뢰 서명자가 없습니다.</p>'}</details>
      <details><summary>최근 빌드별 관측 슬롯 수 · 보안 진단</summary><p class="small-note">최근 10분 클라이언트 보고값입니다. 서버가 실행 상태의 정직성을 증명하거나 정상 기준으로 자동 등록하지 않습니다.</p><pre class="desktop-security-result">${esc(JSON.stringify(data.recentBuildObservations,null,2))}</pre><pre class="desktop-security-result">${esc(JSON.stringify(data.events.slice(0,40),null,2))}</pre></details>
      <details><summary>인증서 pin 전환 · 사전 공지</summary>
      <p class="small-note">서버를 중지하고 Prepare_TLS_Pin.bat로 새 인증서를 준비한 뒤 서버를 다시 시작하세요. 현재 A/B/O 모두 새 pin 규격을 지원해야 합니다. 계획은 최근 재인증 후 등록하며, 공지된 기간은 취소·연장할 수 없습니다.</p>
      <pre class="desktop-security-result">${esc(JSON.stringify(pinState,null,2))}</pre>
      <div class="desktop-security-grid">${input('sec-pin-generation','준비된 stagedGeneration (48자리 소문자 hex)','')}${input('sec-pin-start','전환 시작 · UTC ISO 시각',new Date(Date.now()+600000).toISOString())}${input('sec-pin-end','구 pin 종료 · UTC ISO 시각',new Date(Date.now()+4200000).toISOString())}</div>
      ${checkbox('sec-pin-confirm','전환 기간 안에 Activate_TLS_Pin.bat를 실행하고, 계획을 받지 못한 기존 A는 새로 발급해야 함을 확인했습니다.',false)}
      <div class="actions">${button('schedule-pin','확인한 pin 전환 계획 등록')}</div>
      <p class="small-note">클라이언트 신뢰 상태는 메모리와 인증된 Handoff에만 유지합니다. 이 버튼은 서버 인증서를 즉시 바꾸지 않으며, 로컬의 모든 재시작에 대한 영구 복귀 방지를 보장하지 않습니다.</p></details>
      <details><summary>통신·측정 작업 부하</summary><p class="small-note">새로고침 시점의 프로세스 누적 지표입니다. 봉투 복호화·일반 서명·갱신 서명·PE 작업은 별도 제한 대기열을 사용합니다. 서명 검증 뒤 현재 세션과 기한을 재검사합니다. shutdown은 서버가 받은 클라이언트 진단이며 실제 종료 완료 증명이 아닙니다. 갱신 실패율은 서버에 도달해 처리한 verify 요청 기준이며 끊긴 클라이언트 전체를 포함하지 않습니다.</p><pre class="desktop-security-result">${esc(JSON.stringify(data.runtimeLoad||{status:'UNAVAILABLE'},null,2))}</pre></details>`;
    sections().forEach((section,index)=>{if(index<opened.length)section.open=opened[index];const status=document.createElement('p');status.className='security-section-status';status.hidden=true;status.setAttribute('role','status');status.setAttribute('aria-live','polite');section.append(status);});
    node('sec-security-floor').min=String(publicationFloor);
    fillContract();
    if(!publishReady())pairPreview=null;
    if(pairPreview)node('sec-pair-preview').textContent=JSON.stringify(pairPreview.result,null,2);
    updatePairStatus();
  }
  function fillContract(){const id=node('sec-contract-artifact')?.value,c=data.operations.candidates.find(x=>x.id===id)?.contract;node('sec-min-slots').value=c?.minApiSlots??'';node('sec-max-slots').value=c?.maxApiSlots??'';}
  function policyBody(){return{expectedRevision:data.policy.revision,expectedOperationsRevision:data.operations.operations.revision,mode:node('sec-mode').value,dynamicCode:node('sec-dynamic').value,freshnessMs:Number(node('sec-fresh').value),challengeMs:Number(node('sec-challenge').value),minVersionA:node('sec-min-a').value.trim(),minVersionB:node('sec-min-b').value.trim(),minVersionO:node('sec-min-o').value.trim(),enforceLegacy:node('sec-legacy').checked,requireReadonlyApi:node('sec-readonly').checked,requireCfg:node('sec-cfg').checked,requireReleaseSignature:node('sec-signature').checked,deviceSignalsRequested:node('sec-device-signals').checked,trustedReleaseKeys:JSON.parse(node('sec-keys').value),revokedSha512:node('sec-revoked').value.split(/\s+/).filter(Boolean)};}
  function pairBody(){return{aId:node('sec-a').value,bId:node('sec-b').value,oId:node('sec-o').value};}
  async function reload(){const next=await api('/api/desktop/bootstrap/security-authority'),activation=await api(base+'/activation');if(alive()){data=next;activationState=activation.status;render();}}
  root.addEventListener('change',event=>{if(['sec-a','sec-b','sec-o'].includes(event.target.id)){pairPreview=null;recoveryPreview=null;node('sec-recovery-apply').disabled=true;node('sec-pair-preview').textContent='';updatePairStatus('선택이 변경되었습니다. 이 A/B/O 조합을 다시 검증해주세요.');}if(event.target.id==='sec-contract-artifact')fillContract();if(event.target.id==='sec-enable-profile'){activationPreview=null;node('sec-enable-all-button').disabled=true;node('sec-enable-issues').textContent='범위가 변경되었습니다. 사전 점검을 다시 실행하세요.';node('sec-enable-preview').textContent='';}});
  root.addEventListener('click',async event=>{
    const target=event.target.closest('[data-security-action]');if(!target||busy||!alive())return;
    const action=target.dataset.securityAction,revision=data.operations.operations.revision;
    const sectionIndex=sections().indexOf(target.closest('details'));
    busy=true;target.disabled=true;reportStatus('서버에서 처리하고 있습니다.','busy',sectionIndex);updatePairStatus(node('sec-pair-status').textContent);
    try{
      let changed=false,successMessage='',statusState='success';
      if(action==='refresh')await reload();
      else if(action==='check-enable-all'){
        const profile=node('sec-enable-profile').value;
        const out=await api(base+'/preview-enable-all',{method:'POST',body:{profile}});
        if(alive()&&node('sec-enable-profile').value===profile){
          activationPreview=out.preview;
          node('sec-enable-all-button').disabled=!out.preview.ready;
          node('sec-enable-issues').textContent=(out.preview.ready?'적용 가능합니다. 현재 관리자 혼자 [확인한 보호 설정 적용]을 누르세요.':out.preview.issues.map(x=>(x.component?x.component+' · ':'')+x.code+' — '+x.detail).join('\n'))+((out.preview.pending||[]).length?'\n\n별도 준비 항목 (기존 필수가 아닌 항목은 이번 적용을 막지 않음):\n'+out.preview.pending.map(x=>(x.component?x.component+' · ':'')+x.detail).join('\n'):'');
          node('sec-enable-preview').textContent=JSON.stringify({target:out.preview.target,activePair:out.preview.plan,recentObservations:out.preview.recentObservations,pending:out.preview.pending,warning:out.preview.warning},null,2);
        }
      }else if(action==='enable-all'){
        if(!activationPreview?.ready||activationPreview.profile!==node('sec-enable-profile').value)throw Error('현재 범위의 사전 점검을 먼저 통과해야 합니다.');
        await api(base+'/enable-all',{method:'POST',body:activationPreview.plan});changed=true;
      }else if(action==='preview-policy'){
        const body=policyBody(),out=await api('/api/desktop/bootstrap/security-authority/preview',{method:'POST',body});
        if(alive()){policyPreview=JSON.stringify(body);node('sec-policy-preview').textContent=JSON.stringify(out.preview,null,2);}
      }else if(action==='save-policy'){
        const body=policyBody();if(JSON.stringify(body)!==policyPreview)throw Error('현재 편집 내용으로 영향 미리보기를 먼저 실행해주세요.');
        await api('/api/desktop/bootstrap/security-authority',{method:'POST',body});changed=true;
      }else if(action==='import-mitigation-compatibility'){
        const file=node('sec-compatibility-report').files[0];if(!file||file.size>32768)throw Error('32KiB 이하의 호환성 관측 JSON을 선택하세요.');
        const reportText=await file.text();if(!alive())return;
        await api(base+'/mitigation-compatibility',{method:'POST',body:{reportText}});changed=true;
      }else if(action==='save-mitigation-profile'){
        const file=node('sec-mitigation-evidence').files[0];if(!file||file.size>65536)throw Error('서명된 호환성 증빙 JSON을 선택하세요.');
        const envelope=JSON.parse(await file.text());if(!alive())return;
        await api(base+'/mitigation-profiles',{method:'POST',body:{requestId:crypto.randomUUID(),envelope,enabled:node('sec-mitigation-enabled').checked,expectedOperationsRevision:data.operations.operations.revision}});changed=true;
      }else if(action==='save-controls'){
        await api(base+'/controls',{method:'POST',body:{expectedRevision:revision,requireBuildContract:node('sec-contract-required').checked,requireTestEvidence:node('sec-tests-required').checked}});changed=true;
      }else if(action==='save-contract'){
        await api(base+'/contracts',{method:'POST',body:{expectedRevision:revision,artifactId:node('sec-contract-artifact').value,contract:{version:1,evidenceVersion:1,minApiSlots:Number(node('sec-min-slots').value),maxApiSlots:Number(node('sec-max-slots').value),requiredChecks:['ownImage','apiStorage','mitigations']}}});changed=true;
      }else if(action==='preview-rollout'||action==='save-rollout'){
        const rollout={enabled:node('sec-rollout-enabled').checked,artifactKeys:Array.from(node('sec-rollout-builds').selectedOptions).map(x=>x.value),patch:JSON.parse(node('sec-rollout-patch').value)};
        const body={expectedRevision:revision,expectedPolicyRevision:data.policy.revision,rollout};
        if(action==='preview-rollout'){
          const out=await api(base+'/preview-rollout',{method:'POST',body});
          if(alive()){rolloutPreview=JSON.stringify(body);node('sec-rollout-preview').textContent=JSON.stringify(out.preview,null,2);}
        }else{
          if(rolloutPreview!==JSON.stringify(body))throw Error('현재 내용을 먼저 시험 적용 미리보기로 확인해주세요.');
          await api(base+'/rollout',{method:'POST',body});changed=true;
        }
      }else if(action==='preview-pair'){
        const body=pairBody(),out=await api(base+'/preview-pair',{method:'POST',body});
        if(alive()){
          const current=JSON.stringify(body)===JSON.stringify(pairBody())&&out.preview.policyRevision===data.policy.revision&&out.preview.operationsRevision===data.operations.operations.revision;
          pairPreview=current&&out.preview.eligible?{selection:JSON.stringify(body),policyRevision:out.preview.policyRevision,operationsRevision:out.preview.operationsRevision,result:out.preview}:null;
          if(current){statusState=out.preview.eligible?'success':'error';node('sec-pair-preview').textContent=JSON.stringify(out.preview,null,2);successMessage=out.preview.eligible?'조합 검증을 통과했습니다. 이제 운영 게시할 수 있습니다.':(out.preview.reasons||[]).map(reasonText).join('\n')||'서버에서 조합을 승인하지 않았습니다.';updatePairStatus(successMessage);node('sec-pair-status').dataset.state=out.preview.eligible?'ready':'blocked';}
          else {statusState='error';successMessage='검사 중 선택 또는 서버 revision이 변경되었습니다. 현재 조합을 다시 검증해주세요.';updatePairStatus(successMessage);}
        }
      }else if(action==='activate'){
        const pair=pairBody();if(!publishReady())throw Error('선택한 A/B/O 조합을 먼저 검증해주세요.');
        await api(base+'/activate',{method:'POST',body:{expectedRevision:revision,expectedPolicyRevision:data.policy.revision,...pair}});changed=true;successMessage='서버에 반영했습니다. 선택한 A/B/O 조합이 운영 게시되었습니다.';
      }else if(action==='record-evidence'){
        const file=node('sec-evidence-file').files?.[0];if(!file||file.size>65536)throw Error('64KiB 이하의 시험 결과 JSON을 선택해주세요.');
        const report=JSON.parse(await file.text());if(!alive())return;
        await api(base+'/test-evidence',{method:'POST',body:{expectedRevision:revision,...pairBody(),report}});changed=true;
      }else if(action==='schedule-pin'){
        const stagedGeneration=node('sec-pin-generation').value.trim(),start=node('sec-pin-start').value.trim(),end=node('sec-pin-end').value.trim();
        if(!node('sec-pin-confirm').checked)throw Error('전환 운영 조건을 확인해주세요.');
        if(!/^[a-f0-9]{48}$/.test(stagedGeneration)||![start,end].every(t=>/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(t)&&Number.isSafeInteger(Date.parse(t))))throw Error('준비한 세대와 UTC ISO 시각을 확인해주세요.');
        await api(base+'/tls-pin-transition',{method:'POST',body:{expectedGeneration:data.tlsPinTransition?.generation||0,stagedGeneration,notBefore:Date.parse(start),oldNotAfter:Date.parse(end)}});changed=true;
        successMessage='pin 전환 계획을 등록했습니다. 공지한 기간 안에 서버를 중지하고 Activate_TLS_Pin.bat를 실행해야 합니다.';
      }else if(action==='save-release-governance'){
        await api(base+'/release-governance',{method:'POST',body:{expectedRevision:revision,requireManifest:true,requireCiEvidence:false,minimumSecurityVersion:Number(node('sec-security-floor').value)}});changed=true;
      }else if(action==='plan-manifest'||action==='record-manifest'||action==='record-ci-key'){
        const inputId=(action==='record-manifest'||action==='plan-manifest')?'sec-manifest-file':'sec-ci-key-file';
        const file=node(inputId).files?.[0];if(!file||file.size>65536)throw Error('64KiB 이하의 공개 JSON 파일을 선택해주세요.');
        const value=JSON.parse(await file.text());if(!alive())return;
        if(action==='record-manifest'||action==='plan-manifest'){
          if(!value||!value.manifest||typeof value.manifestId!=='string'||Object.keys(value).sort().join(',')!=='manifest,manifestId')throw Error('명세 생성 도구의 원본 JSON을 선택해주세요.');
          await api(base+(action==='plan-manifest'?'/plan-release':'/release-manifests'),{method:'POST',body:{expectedRevision:revision,manifestId:value.manifestId,manifest:value.manifest}});
          successMessage=action==='plan-manifest'?'명세 계획 등록(PLANNED)을 완료했습니다. 같은 명세 ID로 A/B/O 후보를 등록한 뒤 [세 파일 확인 후 명세 등록 완료]를 진행하세요.':'명세 등록 완료(REGISTERED). 같은 명세의 A/B/O 후보를 선택해 조합 검증·운영 게시하세요. CI 증거 JSON은 필요하지 않습니다.';
        }else {
          if(!value||Object.keys(value).sort().join(',')!=='keyId,notAfter,notBefore,publicKey,state')throw Error('CI 공개키 도구의 원본 JSON을 선택해주세요. 개인키는 등록하지 않습니다.');
          await api(base+'/ci-signers',{method:'POST',body:{expectedRevision:revision,...value}});
          successMessage='선택적인 CI 전용 공개키를 등록했습니다. 수동 운영 게시에는 CI 증거가 필요하지 않습니다.';
        }
        changed=true;
      }else if(action==='prepare-recovery'){
        const selection=pairBody(),reason=node('sec-recovery-reason').value.trim();if(!reason||reason.length>500)throw Error('500자 이하의 복구 사유를 입력해주세요.');
        const draft=JSON.stringify({selection,reason,policyRevision:data.policy.revision});if(draft!==recoveryDraft){recoveryRequestId=crypto.randomUUID();recoveryDraft=draft;}
        const out=await api(base+'/recovery/prepare',{method:'POST',body:{expectedRevision:revision,expectedPolicyRevision:data.policy.revision,requestId:recoveryRequestId,...selection,reason}});
        if(alive()){await reload();if(alive()){recoveryPreview=out.result;node('sec-a').value=selection.aId;node('sec-b').value=selection.bId;node('sec-o').value=selection.oId;node('sec-recovery-reason').value=reason;node('sec-recovery-preview').textContent=JSON.stringify(recoveryPreview,null,2);node('sec-recovery-apply').disabled=recoveryPreview.status!=='PREPARED';}}
      }else if(action==='apply-recovery'){
        if(!recoveryPreview||recoveryPreview.status!=='PREPARED'||JSON.stringify(pairBody())!==JSON.stringify(recoveryPreview.selection)||node('sec-recovery-reason').value.trim()!==recoveryPreview.reason)throw Error('현재 선택과 사유로 복구 내용을 먼저 준비해주세요.');
        await api(base+'/recovery/apply',{method:'POST',body:{expectedRevision:recoveryPreview.preparedRevision,expectedPolicyRevision:recoveryPreview.policyRevision,recoveryId:recoveryPreview.recoveryId}});changed=true;
      }else if(action==='ci-signer'){
        await api(base+'/ci-signers',{method:'POST',body:{expectedRevision:revision,keyId:target.dataset.key,state:node('ci-signer-'+target.dataset.key).value}});changed=true;
      }else if(action==='download-policy'){
        const url=URL.createObjectURL(new Blob([JSON.stringify(data.policy,null,2)+'\n'],{type:'application/json'}));
        const link=document.createElement('a');link.href=url;link.download='deployment-policy.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
      }else if(action==='signer'){
        await api(base+'/signers',{method:'POST',body:{expectedRevision:revision,keyId:target.dataset.key,state:node('signer-'+target.dataset.key).value}});changed=true;
      }
      if(changed&&alive())await reload();
      if(alive())reportStatus(successMessage||(changed?'서버에 반영했습니다. 이전 임시 판정은 새 검사를 요구합니다.':'처리했습니다.'),statusState,sectionIndex);
    }catch(error){
      if(/SECURITY_.*(?:CONFLICT|PAIR_CHANGED|PREVIEW_CHANGED)/.test(error.code||error.message||'')){activationPreview=null;pairPreview=null;}
      if(alive())reportStatus((error.code&&reasonText(error.code)!==error.code?reasonText(error.code):error.message||'처리하지 못했습니다.')+(error.code?' · 오류 코드: '+error.code:''),'error',sectionIndex);
    }finally{
      busy=false;if(target.isConnected)target.disabled=false;
      if(alive()){node('sec-enable-all-button').disabled=!activationPreview?.ready;node('sec-activate').disabled=!publishReady();}
    }
  });
  render();
  try{await done;}finally{closed=true;recoveryPreview=null;recoveryDraft='';recoveryRequestId='';data=null;activationState=null;activationPreview=null;policyPreview='';pairPreview=null;rolloutPreview='';if(root.isConnected)root.replaceChildren();}
}
