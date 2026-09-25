'use strict';
let memberOauthDetail='',memberProviderFilter='',memberGrantBusy=false;
const memberGrantDraftKey='moaplay.admin.walletGrant.pending.v1';
const memberOauthStates={checking:'연결 확인 중',active:'연결 정상',degraded:'확인 지연',revoked:'연결 해제됨',reauth_required:'재인증 필요',unlinked:'미연결'};
function memberOauthState(value){return memberOauthStates[value]||'미확인';}
function memberProviderName(value){return {google:'Google',kakao:'카카오'}[value]||'미연결';}
function memberProviderFilterField(){return `<select id="member-provider-filter" aria-label="계정 제공자"><option value="">모든 제공자</option>${[['google','Google'],['kakao','카카오']].map(([value,label])=>`<option value="${value}" ${memberProviderFilter===value?'selected':''}>${label}</option>`).join('')}</select>`;}
function memberCredentialFacts(credentials){return memberFacts(Object.entries(credentials||{}).map(([key,value])=>[key,value?'설정됨 · 값 비공개':'미설정']));}
function memberIntegrationPanel(result){
 const oauth=result.oauth||{},payment=result.payments||{};
 let html='<section class="member-panel"><h3>계정·결제 연결 설정</h3><p class="small-note">운영 서버의 환경 변수로 설정합니다. 값을 변경한 후 서버를 재시작하고 상태를 새로 확인하세요. 비밀 키는 이 화면에 입력하거나 표시하지 않습니다.</p>'+memberButton('refresh','','설정 상태 새로 확인')+'</section>';
 html+='<section class="member-panel"><h3>카카오·Google 계정 연결</h3><p class="small-note">'+esc(oauth.publicUrlField||'MEMBER_OAUTH_PUBLIC_URL')+'에 HTTPS 공개 주소를 지정하세요. 각 개발자 콘솔의 웹 OAuth 앱에 아래 콜백 주소를 정확히 등록하고 OpenID Connect를 사용하세요. 브라우저에서 계정을 확인한 뒤 앱에서 연결을 완료합니다.</p><p class="small-note">MEMBER_OAUTH_TOKEN_KEY는 서버에서 토큰을 암호화하는 키입니다. 운영 서버에서 <code>openssl rand -base64 32</code>로 생성하고 환경 변수에 저장하세요. 기존 키를 보관해야 저장된 계정 인증을 계속 확인할 수 있습니다.</p>';
 for(const provider of oauth.providers||[]){
  html+='<article class="member-record"><h4>'+esc(provider.name)+'</h4><span class="member-badge">'+(provider.configured?'설정 완료':'설정 필요')+'</span>'+memberCredentialFacts(provider.credentials)+memberFacts([['공개 주소',provider.origin||'HTTPS 주소 설정 필요'],['OAuth 콜백',provider.callbackUri||'공개 주소 설정 후 표시']]);
  if(provider.missing?.length)html+='<p role="status">필요한 설정: '+esc(provider.missing.join(', '))+'</p>';
  if(provider.id==='google')html+='<p class="small-note">Google OAuth 웹 애플리케이션의 클라이언트 ID와 비밀 키를 사용하고, 동의 화면의 게시 상태와 테스트 사용자를 확인하세요.</p>';
  if(provider.id==='kakao')html+='<p class="small-note">카카오 로그인과 OpenID Connect를 활성화하고 REST API 키를 클라이언트 ID로 사용하세요.</p>'+memberFacts([['연결 해제 콜백',provider.unlinkCallback||'공개 주소 설정 후 표시'],['연결 해제 알림',provider.unlinkNotificationsConfigured?'설정됨':'미설정'],['알림 환경 변수',(provider.unlinkFields||[]).join(', ')]]);
  html+='</article>';
 }
 html+='</section><section class="member-panel"><h3>카카오페이·토스페이</h3>'+memberFacts([['결제 공개 주소',payment.origin||'HTTPS 주소 설정 필요'],['최근 설정 확인',fmtTime(payment.checkedAt)]]);
 for(const provider of payment.providers||[]){
  html+='<article class="member-record"><h4>'+esc(provider.name)+'</h4><span class="member-badge">'+(provider.enabled?'결제 연결 가능':'설정 필요')+'</span>'+memberFacts([['상태',provider.message],['환경',provider.mode==='live'?'운영':provider.mode==='test'?'테스트':'미확인']])+memberCredentialFacts(provider.credentials);
  if(provider.missing?.length)html+='<p>필요한 설정: '+esc(provider.missing.join(', '))+'</p>';
  for(const issue of provider.issues||[])html+='<p class="small-note">'+esc(issue.message)+(issue.fields?.length?' ('+esc(issue.fields.join(', '))+')':'')+'</p>';
  html+='</article>';
 }
 return html+'<p class="small-note">'+esc(payment.note||'설정 완료는 키 형식과 필수 설정 확인 결과입니다. 실제 운영 결제는 계약 및 제공자 승인 상태까지 확인해야 합니다.')+'</p></section>';
}
function memberOauthFacts(identity){return '<section class="member-panel"><h3>계정 연결 상태</h3>'+memberFacts([['제공자',memberProviderName(identity.provider)],['연결 계정',identity.accountLabel],['상태',memberOauthState(identity.status)],['연결',identity.linkedAt?fmtTime(identity.linkedAt):''],['최종 인증',identity.verifiedAt?fmtTime(identity.verifiedAt):''],['최근 확인',identity.lastCheckedAt?fmtTime(identity.lastCheckedAt):''],['연결 해제',identity.revokedAt?fmtTime(identity.revokedAt):''],['상태 코드',identity.reason||identity.lastError]])+'</section>';}
async function renderMemberOauth(automatic=false){
 const accountId=memberOauthDetail,serial=++memberRenderSerial;
 const result=await api('/api/member?'+new URLSearchParams({view:'oauthAccounts',accountId}));
 if(serial!==memberRenderSerial||memberView!=='oauthAccounts'||accountId!==memberOauthDetail||(automatic&&!memberCanAutoRefresh()))return;
 memberLastRefresh=Date.now();const fingerprint=JSON.stringify(result);if(automatic&&memberFingerprint===fingerprint)return;memberFingerprint=fingerprint;
 const p=result.profile,i=p.identity||{},position=automatic?captureScrollState(currentView):null;memberRows=new Map([[p.id,p]]);
 content.innerHTML='<div class="member-shell">'+memberButton('oauth.back','','연결 계정 목록')+'<section class="member-panel"><h3>@'+esc(p.handle)+' · '+esc(p.nickname)+'</h3><div class="actions">'+memberButton('profile.lookup',p.id,'회원 조회')+memberButton('oauth.recheck',p.id,'제공자 연결 재확인')+(i.provider?memberButton('oauth.reauth',p.id,'앱 계정 재인증 요구',true):'')+'</div><p class="small-note">재인증 요구는 이 앱의 인증을 즉시 해제합니다. 계정 소유 연결과 잔액·구매 내역은 유지되며 같은 계정으로 다시 인증해야 합니다.</p></section>'+memberOauthFacts(i)+'<section class="member-panel"><h3>계정 연결 기록</h3>'+(i.events||[]).slice().reverse().map(event=>'<article class="member-record">'+memberFacts([['시간',fmtTime(event.at)],['작업',event.type],['상태 코드',event.reason],['처리자',event.actor],['사유',event.detail]])+'</article>').join('')+(!(i.events||[]).length?'<p class="member-empty">기록이 없습니다.</p>':'')+'</section></div>';
 if(position)restoreScrollState(position);
}
function memberPendingGrant(){try{const value=JSON.parse(localStorage.getItem(memberGrantDraftKey)||'null');return value?.action==='wallet.grant'?value:null;}catch(_){return null;}}
function memberGrantRecovery(){return memberPendingGrant()?memberButton('wallet.retry','','미확인 지급 결과 확인'):'';}
async function grantMemberBalance(row,retry=false){
 if(memberGrantBusy)return;memberGrantBusy=true;
 try{
  let body=memberPendingGrant();
  if(body){
   const choice=await openModal({title:'미확인 지급 결과 확인',message:'이전에 전송한 지급 요청을 같은 요청 번호로 확인합니다. 이미 지급되었다면 추가 지급하지 않습니다.',html:memberFacts([['회원',body.accountId],['금액',memberMoney(body.amount)],['사유',body.reason],['요청 번호',body.requestId]]),confirmLabel:'같은 요청으로 확인'});if(!choice)return;
  }else{
   if(retry){toast('미확인 지급 요청이 없습니다.');return;}
   if(!row.id){const target=await openModal({title:'지급할 회원 선택',fields:[{name:'handle',label:'회원 @아이디 또는 회원 번호'}],confirmLabel:'회원 확인'});if(!target)return;const found=await api('/api/member?'+new URLSearchParams({view:'lookup',handle:target.handle.trim()}));row=found.profile;}
   const values=await openModal({title:'관리자 잔액 지급',message:'@'+row.handle+' · '+row.nickname+' · 현재 잔액 '+memberMoney(row.balance),fields:[{name:'amount',label:'지급할 금액 (원 · 양의 정수)',placeholder:'직접 금액 입력'},{name:'reason',label:'지급 사유 (3~500자)',type:'textarea'}],confirmLabel:'지급 내용 확인'});if(!values)return;
   const raw=values.amount.trim(),amount=Number(raw),reason=values.reason.trim();if(!/^[1-9][0-9]*$/.test(raw)||!Number.isSafeInteger(amount))throw Error('지급할 금액을 정확한 양의 정수로 입력해주세요.');if(reason.length<3||reason.length>500)throw Error('지급 사유를 3~500자로 입력해주세요.');
   const confirmed=await openModal({title:'잔액 지급 최종 확인',message:'아래 회원 한 명에게 충전 잔액을 지급합니다.',html:memberFacts([['회원','@'+row.handle+' · '+row.nickname],['회원 번호',row.id],['지급 금액',memberMoney(amount)],['지급 사유',reason]]),confirmLabel:memberMoney(amount)+' 지급'});if(!confirmed)return;
   body={action:'wallet.grant',accountId:row.id,confirmedAccountId:row.id,confirmed:true,amount,reason,requestId:'grant_'+crypto.randomUUID()};
   localStorage.setItem(memberGrantDraftKey,JSON.stringify(body));
  }
  const result=await api('/api/member/action',{method:'POST',body});localStorage.removeItem(memberGrantDraftKey);
  toast(memberMoney(result.result.amount)+' 지급 완료 · 거래 '+result.result.id);await renderMember();
 }catch(error){
  if(['AMOUNT_INVALID','ADMIN_REASON_REQUIRED','ADMIN_CONFIRM_REQUIRED','REQUEST_ID_INVALID','BALANCE_INVALID','ACCOUNT_BLOCKED','MEMBER_NOT_FOUND'].includes(error.code))localStorage.removeItem(memberGrantDraftKey);
  if(memberPendingGrant()){toast(error.message+' 같은 요청 번호를 보관했습니다. 지급 버튼에서 결과를 다시 확인하세요.',true);await renderMember();}else throw error;
 }
 finally{memberGrantBusy=false;}
}
async function handleMemberAccountsAction(action,button,row){
 if(['wallet.grant','wallet.new','wallet.retry'].includes(action)){await grantMemberBalance(row,action==='wallet.retry');return true;}
 if(action==='oauth.detail'){if(memberView!=='oauthAccounts')switchView('member-oauthAccounts');memberOauthDetail=row.id||button.dataset.id;await renderMemberOauth();return true;}
 if(action==='oauth.back'){memberOauthDetail='';await renderMember();return true;}
 if(!['oauth.recheck','oauth.reauth'].includes(action))return false;
 if(button.disabled)return true;button.disabled=true;
 try{
  let body={action,accountId:row.id};
  if(action==='oauth.reauth'){
   const values=await openModal({title:'앱 계정 재인증 요구',message:'@'+row.handle+' 회원의 앱 인증을 해제합니다. 연결된 계정의 소유권과 보유 잔액은 유지됩니다.',fields:[{name:'reason',label:'처리 사유 (3~240자)',type:'textarea'}],danger:true,confirmLabel:'재인증 요구'});if(!values)return true;const reason=values.reason.trim();if(reason.length<3||reason.length>240)throw Error('처리 사유를 3~240자로 입력해주세요.');body={...body,confirmed:true,confirmedAccountId:row.id,reason};
  }
  await api('/api/member/action',{method:'POST',body});toast(action==='oauth.recheck'?'계정 연결 상태를 확인했습니다.':'앱 계정 재인증이 필요하도록 변경했습니다.');await renderMemberOauth();
 }finally{if(button.isConnected)button.disabled=false;}
 return true;
}
