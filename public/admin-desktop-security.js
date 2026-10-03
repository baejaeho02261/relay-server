'use strict';
// Modal state is ephemeral: no localStorage, sessionStorage, IndexedDB or policy
// cache. Closing / logging out drops the policy draft and public approval file.
async function showDesktopSecurityOperations() {
  if(!roleIsAdmin()||!session)throw Error('관리자 로그인을 확인해주세요.');
  const owner=session.csrf,base='/api/desktop/bootstrap/security-operations';
  let data=await api('/api/desktop/bootstrap/security-authority'),policyPreview='',pairPreview='',rolloutPreview='',busy=false,closed=false;
  let activationState=(await api(base+'/activation')).status,activationPreview=null;
  if(!roleIsAdmin()||session?.csrf!==owner)return;
  const done=openModal({title:'서버 보안 · 배포 운영',html:'<section id="desktop-security-root" class="desktop-security"></section>',confirmLabel:'닫기'});
  const root=document.getElementById('desktop-security-root');
  const alive=()=>!closed&&root.isConnected&&session?.csrf===owner&&roleIsAdmin();
  const node=id=>root.querySelector('#'+id);
  const select=(id,items,value)=>`<select id="${id}">${items.map(([v,label])=>`<option value="${esc(v)}" ${v===value?'selected':''}>${esc(label)}</option>`).join('')}</select>`;
  const checkbox=(id,label,value)=>`<label><input type="checkbox" id="${id}" ${value?'checked':''}> ${esc(label)}</label>`;
  const input=(id,label,value,type='text')=>`<label>${esc(label)}<input id="${id}" type="${type}" value="${esc(value??'')}" autocomplete="off"></label>`;
  const button=(action,label)=>`<button type="button" data-security-action="${action}">${label}</button>`;
  function render(){
    if(!alive())return;
    const p=data.policy,box=data.operations,s=box.operations,active=box.active,rows=box.candidates;
    const choices=component=>rows.filter(x=>!component||x.component===component).map(a=>[a.id,`${a.component} ${a.version} · ${a.sha256.slice(0,12)}${a.active?' · 운영 중':' · 후보'}`]);
    policyPreview='';pairPreview='';rolloutPreview='';activationPreview=null;
    root.innerHTML=`<p class="small-note">정책·검사 기준·승인·배포 이력은 서버에 저장합니다. 이 화면은 메모리에서만 초안을 유지합니다. 시험 기록은 운영자 확인 자료이며 하드웨어 실행 증명이 아닙니다.</p>
      <div class="actions">${button('refresh','새로고침')}${button('step-up','관리자 패스키 재인증')}</div>
      <p id="security-status" role="status" aria-live="polite"></p>
      <div class="kv"><div>정책 / 운영 revision</div><div>${p.revision} / ${s.revision}</div><div>관리자 보호</div><div>${box.adminProtection.dualApprovalRequired?'2인 승인 요구':'추가 승인 비활성'} · ${box.adminProtection.stepUpRequired?'최근 재인증 요구':'재인증 강제 비활성'} · 매핑된 운영자 ${box.adminProtection.provisionedPrincipalCount}명</div><div>감사 저장</div><div>${esc(box.auditHealth.status)} · 프로세스 시작 후 실패 ${box.auditHealth.failedWrites}건</div></div>
      <details open><summary>보호 기능 일괄 활성화</summary>
      <p><strong>${activationState.allEnabled?'Windows 강제 포함 전체 설정 켜짐':activationState.serverEnabled?'7개 서버 운영 항목 설정 켜짐 · Windows 강제는 별도':'전체 강제 설정 미완료'}</strong></p>
      <p class="small-note">현재 서버 저장값을 표시합니다. 설정이 켜졌다는 뜻이지 모든 PC의 실행 검증이 끝났다는 뜻은 아닙니다. 첫 활성화에도 등록된 서로 다른 운영자 2명의 승인이 필요합니다.</p>
      <label>활성화 범위${select('sec-enable-profile',[['ALL','전부: 서버 7개 항목 + Windows 동적 코드 제한·CFG'],['SERVER','서버 7개 항목만: Windows 설정은 현재값 유지']],'ALL')}</label>
      <div class="actions">${button('check-enable-all','활성화 사전 점검')}<button type="button" id="sec-enable-all-button" data-security-action="enable-all" disabled>점검한 설정 일괄 활성화</button></div>
      <div id="sec-enable-issues" class="desktop-security-result" role="status" aria-live="polite"></div><pre id="sec-enable-preview" class="desktop-security-result"></pre>
      <p class="small-note">조건 미충족 시 기존 정책은 유지됩니다. 키 자동 신뢰, 슬롯 수 추정 등록, 시험 PASS 자동 생성, CFG 플래그 위조는 하지 않습니다. 준비 후 다시 점검하세요. 활성화는 기존 시험 적용을 종료하고 새 측정을 요구합니다.</p></details>
      <details><summary>정책 편집 · 적용 전 영향 미리보기</summary><div class="desktop-security-grid">
      <label>검사 결과 정책${select('sec-mode',[['enforce','검사 실패 시 작업 보류'],['observe','관찰만']],p.mode)}</label>
      <label>동적 코드${select('sec-dynamic',[['observe','상태 조회만'],['prohibit','생성·수정 제한 요구']],p.dynamicCode)}</label>
      ${input('sec-fresh','판정 유효기간 (ms)',p.freshnessMs,'number')}${input('sec-challenge','challenge 유효기간 (ms)',p.challengeMs,'number')}
      ${input('sec-min-a','최소 A 버전',p.minVersionA)}${input('sec-min-b','최소 B 버전',p.minVersionB)}
      ${checkbox('sec-legacy','구버전 금지',p.enforceLegacy)}${checkbox('sec-readonly','읽기 전용 API 저장 요구',p.requireReadonlyApi)}${checkbox('sec-cfg','CFG 요구',p.requireCfg)}${checkbox('sec-signature','배포 서명 강제',p.requireReleaseSignature)}
      </div><label>신뢰 서명자 공개키 목록 (서명 도구의 trustedKey 배열 · 개인키 금지)<textarea id="sec-keys" rows="5" spellcheck="false">${esc(JSON.stringify(p.trustedReleaseKeys,null,2))}</textarea></label>
      <label>철회할 파일 SHA-256 (한 줄에 하나)<textarea id="sec-revoked" rows="3">${esc(p.revokedSha256.join('\n'))}</textarea></label>
      <div class="actions">${button('preview-policy','영향 미리보기')}${button('save-policy','미리본 정책 적용')}</div><pre id="sec-policy-preview" class="desktop-security-result"></pre>
      <p class="small-note">전역 정책 적용은 진행 중인 빌드별 시험 적용을 종료합니다. 연결되지 않은 PC의 호환성은 판정하지 않습니다.</p></details>
      <details><summary>빌드별 검사 규격 · 단계적 적용</summary><label>검사 규격 대상${select('sec-contract-artifact',choices(),rows[0]?.id||'')}</label>
      <div class="desktop-security-grid">${input('sec-min-slots','최소 API 슬롯 수 (실제 probe 결과 기준)','','number')}${input('sec-max-slots','최대 API 슬롯 수','','number')}</div>
      ${button('save-contract','이 빌드 규격 저장')}<p class="small-note">V1의 자기 이미지·API 저장·완화 정책 3개 검사와 기존 10필드 응답을 사용합니다. 슬롯 수를 추정값으로 자동 등록하지 않습니다.</p>
      <div class="desktop-security-grid">${checkbox('sec-contract-required','모든 승인 빌드에 검사 규격 요구',s.requireBuildContract)}${checkbox('sec-tests-required','A/B 게시 전 시험 PASS 기록 요구',s.requireTestEvidence)}</div>${button('save-controls','운영 요구 조건 저장')}
      <label>시험 적용 대상 (서버 승인 빌드만 선택)<select id="sec-rollout-builds" multiple size="5">${rows.map(a=>{const key=a.component+':'+a.sha256;return `<option value="${esc(key)}" ${s.rollout.artifactKeys.includes(key)?'selected':''}>${esc(a.component+' '+a.version+' · '+a.sha256.slice(0,12))}</option>`;}).join('')}</select></label>
      ${checkbox('sec-rollout-enabled','선택 빌드에만 시험 정책 적용',s.rollout.enabled)}
      <label>시험 정책 (4개 필드만 허용)<textarea id="sec-rollout-patch" rows="4">${esc(JSON.stringify(Object.keys(s.rollout.patch).length?s.rollout.patch:{mode:p.mode,requireReadonlyApi:p.requireReadonlyApi,dynamicCode:p.dynamicCode,requireCfg:p.requireCfg},null,2))}</textarea></label><div class="actions">${button('preview-rollout','시험 적용 영향 미리보기')}${button('save-rollout','미리본 시험 적용 / 종료')}</div><pre id="sec-rollout-preview" class="desktop-security-result"></pre></details>
      <details><summary>배포 후보 · A/B 동시 게시 · 검증된 이전 조합으로 전환</summary>
      <p class="small-note">기존 A/B 파일 등록 버튼은 후보만 등록합니다. 이 화면에서 조합을 선택해 운영 게시합니다. 이전 조합도 현재 서명·철회·시험 정책을 통과해야 합니다.</p>
      <div class="desktop-security-grid"><label>A${select('sec-a',choices('A'),active.A||'')}</label><label>B${select('sec-b',choices('B'),active.B||'')}</label></div>
      <div class="actions">${button('preview-pair','조합 검증')}${button('activate','검증한 A/B 조합 운영 게시')}</div><pre id="sec-pair-preview" class="desktop-security-result"></pre>
      <label>시험 결과 JSON (Windows 수집 도구 결과 또는 운영자 확인 자료)<input type="file" id="sec-evidence-file" accept=".json,application/json"></label>${button('record-evidence','선택 A/B에 시험 결과 기록')}
      <p class="small-note">nativeBuild · apiProbe · integration은 PASS / FAIL / NOT_RUN을 구분합니다. 실제 실행하지 않은 항목을 PASS로 표시하지 마세요.</p>
      <pre class="desktop-security-result">${esc(JSON.stringify(s.activations.slice(-10).reverse(),null,2))}</pre></details>
      <details><summary>서명 키 전환 · 철회</summary><p class="small-note">ACTIVE: 신규 서명 배포 허용. RETIRING: 기존 배포 검증만 허용. REVOKED: 기존 배포도 거절하며 복원 불가. 현재 운영 키 철회는 세션 작업을 막을 수 있습니다.</p>
      ${p.trustedReleaseKeys.map(k=>`<div class="desktop-security-signer"><code>${esc(k.keyId)}</code>${select('signer-'+k.keyId,[['ACTIVE','정상 사용'],['RETIRING','전환 중'],['REVOKED','긴급 철회']],s.signerStates[k.keyId]?.state||'ACTIVE')}<button type="button" data-security-action="signer" data-key="${esc(k.keyId)}">상태 저장</button></div>`).join('')||'<p>등록된 신뢰 서명자가 없습니다.</p>'}</details>
      <details><summary>관리자 추가 승인</summary>${button('approvals','요청 목록 새로고침')}<div id="sec-approval-list"></div><p class="small-note">서버에 매핑된 서로 다른 운영자 신원과 최근 패스키 확인을 요구합니다. 브라우저 세션 두 개는 2인 승인이 아닙니다. 승인 후 요청자가 같은 내용을 다시 실행해야 합니다.</p></details>
      <details><summary>최근 빌드별 관측 슬롯 수 · 보안 진단</summary><p class="small-note">최근 10분 클라이언트 보고값입니다. 서버가 실행 상태의 정직성을 증명하거나 정상 기준으로 자동 등록하지 않습니다.</p><pre class="desktop-security-result">${esc(JSON.stringify(data.recentBuildObservations,null,2))}</pre><pre class="desktop-security-result">${esc(JSON.stringify(data.events.slice(0,40),null,2))}</pre></details>`;
    fillContract();
  }
  function fillContract(){const id=node('sec-contract-artifact')?.value,c=data.operations.candidates.find(x=>x.id===id)?.contract;node('sec-min-slots').value=c?.minApiSlots??'';node('sec-max-slots').value=c?.maxApiSlots??'';}
  function policyBody(){return{expectedRevision:data.policy.revision,expectedOperationsRevision:data.operations.operations.revision,mode:node('sec-mode').value,dynamicCode:node('sec-dynamic').value,freshnessMs:Number(node('sec-fresh').value),challengeMs:Number(node('sec-challenge').value),minVersionA:node('sec-min-a').value.trim(),minVersionB:node('sec-min-b').value.trim(),enforceLegacy:node('sec-legacy').checked,requireReadonlyApi:node('sec-readonly').checked,requireCfg:node('sec-cfg').checked,requireReleaseSignature:node('sec-signature').checked,trustedReleaseKeys:JSON.parse(node('sec-keys').value),revokedSha256:node('sec-revoked').value.split(/\s+/).filter(Boolean)};}
  function pairBody(){return{aId:node('sec-a').value,bId:node('sec-b').value};}
  async function reload(){const next=await api('/api/desktop/bootstrap/security-authority'),activation=await api(base+'/activation');if(alive()){data=next;activationState=activation.status;render();}}
  function b64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
  function bytes(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
  async function stepUp(){
    if(!navigator.credentials)throw Error('이 브라우저에서 패스키를 사용할 수 없습니다. HTTPS와 등록된 패스키를 확인해주세요.');
    const begin=await api(base+'/step-up/begin',{method:'POST',body:{}});if(!alive())return;
    const publicKey={...begin.publicKey,challenge:bytes(begin.publicKey.challenge),allowCredentials:begin.publicKey.allowCredentials.map(c=>({...c,id:bytes(c.id)}))};
    const credential=await navigator.credentials.get({publicKey});if(!credential||!alive())return;
    await api(base+'/step-up/finish',{method:'POST',body:{challengeId:begin.challengeId,credentialId:credential.id,clientDataJSON:b64(credential.response.clientDataJSON),authenticatorData:b64(credential.response.authenticatorData),signature:b64(credential.response.signature)}});
  }
  root.addEventListener('change',event=>{if(event.target.id==='sec-contract-artifact')fillContract();if(event.target.id==='sec-enable-profile'){activationPreview=null;node('sec-enable-all-button').disabled=true;node('sec-enable-issues').textContent='범위가 변경되었습니다. 사전 점검을 다시 실행하세요.';node('sec-enable-preview').textContent='';}});
  root.addEventListener('click',async event=>{
    const target=event.target.closest('[data-security-action]');if(!target||busy||!alive())return;
    const action=target.dataset.securityAction,revision=data.operations.operations.revision;
    busy=true;target.disabled=true;node('security-status').textContent='서버에서 처리하고 있습니다.';
    try{
      let changed=false;
      if(action==='refresh')await reload();
      else if(action==='step-up')await stepUp();
      else if(action==='check-enable-all'){
        const profile=node('sec-enable-profile').value;
        const out=await api(base+'/preview-enable-all',{method:'POST',body:{profile}});
        if(alive()&&node('sec-enable-profile').value===profile){
          activationPreview=out.preview;
          node('sec-enable-all-button').disabled=!out.preview.ready;
          node('sec-enable-issues').textContent=out.preview.ready?'사전 점검 통과. 일괄 활성화를 요청하면 다른 운영자의 승인이 필요합니다.':out.preview.issues.map(x=>(x.component?x.component+' · ':'')+x.code+' — '+x.detail).join('\n');
          node('sec-enable-preview').textContent=JSON.stringify({target:out.preview.target,activePair:out.preview.plan,recentObservations:out.preview.recentObservations,warning:out.preview.warning},null,2);
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
        if(alive()){pairPreview=out.preview.eligible?JSON.stringify(body):'';node('sec-pair-preview').textContent=JSON.stringify(out.preview,null,2);}
      }else if(action==='activate'){
        const pair=pairBody();if(JSON.stringify(pair)!==pairPreview)throw Error('선택한 A/B 조합을 먼저 검증해주세요.');
        await api(base+'/activate',{method:'POST',body:{expectedRevision:revision,expectedPolicyRevision:data.policy.revision,...pair}});changed=true;
      }else if(action==='record-evidence'){
        const file=node('sec-evidence-file').files?.[0];if(!file||file.size>65536)throw Error('64KiB 이하의 시험 결과 JSON을 선택해주세요.');
        const report=JSON.parse(await file.text());if(!alive())return;
        await api(base+'/test-evidence',{method:'POST',body:{expectedRevision:revision,...pairBody(),report}});changed=true;
      }else if(action==='signer'){
        await api(base+'/signers',{method:'POST',body:{expectedRevision:revision,keyId:target.dataset.key,state:node('signer-'+target.dataset.key).value}});changed=true;
      }else if(action==='approvals'){
        const out=await api(base+'/approvals');if(alive())node('sec-approval-list').innerHTML=out.tickets.map(t=>`<details><summary>${esc(t.ticketId)} · ${esc(t.status)}</summary><pre class="desktop-security-result">${esc(JSON.stringify(t.summary||{path:t.pathname,payloadHash:t.payloadHash},null,2))}</pre><p>요청자 ${esc(t.requestedPrincipal||'미확인')} · 만료 ${desktopDate(t.expiresAt)}</p>${t.status==='PENDING'?`<button type="button" data-security-action="approve-ticket" data-ticket="${esc(t.ticketId)}">이 내용 승인</button>`:''}</details>`).join('')||'<p>승인 요청이 없습니다.</p>';
      }else if(action==='approve-ticket'){
        await api(base+'/approve',{method:'POST',body:{ticketId:target.dataset.ticket}});
      }
      if(changed&&alive())await reload();
      if(alive())node('security-status').textContent=changed?'서버에 반영했습니다. 이전 임시 판정은 새 검사를 요구합니다.':'처리했습니다.';
    }catch(error){if(alive())node('security-status').textContent=(error.message||'처리하지 못했습니다.')+' · 재인증/추가 승인 요구 시 먼저 완료한 뒤 같은 내용을 다시 실행하세요. 충돌이면 새로고침 후 다시 미리보세요.';}
    finally{busy=false;if(target.isConnected)target.disabled=false;if(alive())node('sec-enable-all-button').disabled=!activationPreview?.ready;}
  });
  render();
  try{await done;}finally{closed=true;data=null;activationState=null;activationPreview=null;policyPreview='';pairPreview='';rolloutPreview='';if(root.isConnected)root.replaceChildren();}
}
