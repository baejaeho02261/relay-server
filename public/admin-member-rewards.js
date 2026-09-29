'use strict';
let memberRewardRules=null;
function memberRewardsPanel(result){
 memberRewardRules=result.rules;const r=result.rules;
 const points=n=>Number(n||0).toLocaleString('ko-KR')+' P',exchange=r.pointExchange||{enabled:false,cashUnit:0,pointUnit:0};
 const kinds={ATTENDANCE:'출석 보상',POINT_RECHARGE:'이전 포인트 충전',POINT_EXCHANGE:'포인트 교환',POINT_EXCHANGE_REVERSE:'포인트 교환 회수',SHOP_PURCHASE:'상점 구매'};
 return `<section class="member-panel"><div class="member-toolbar"><h3>출석 · 포인트</h3>${memberButton('rewards.edit','','보상 기준 수정')}</div><div class="member-metrics"><article><span>연속 출석 보상</span><strong>${r.attendanceDays}일 · ${points(r.attendancePoints)}</strong></article><article><span>포인트 → 충전 잔액 교환</span><strong>${exchange.enabled?points(exchange.pointUnit)+' → '+memberMoney(exchange.cashUnit):'준비 중'}</strong></article></div></section><section class="member-panel"><h3>포인트 내역</h3>${result.items?.length?`<div class="table-wrap"><table><thead><tr><th>회원</th><th>구분</th><th>포인트</th><th>처리 후</th><th>시각</th></tr></thead><tbody>${result.items.map(x=>`<tr><td>${esc(x.member?.nickname||'회원')}<div class="small-note">${esc(x.member?.accountLabel||x.member?.handle||'')}</div></td><td>${kinds[x.kind]||'포인트 기록'}</td><td>${x.amount>0?'+':''}${points(x.amount)}</td><td>${points(x.balance)}</td><td>${esc(fmtTime(x.at))}</td></tr>`).join('')}</tbody></table></div>`:'<p class="member-empty">아직 포인트 내역이 없습니다.</p>'}${result.total>30?`<div class="member-pagination">${memberOffset?memberButton('prev','','이전'):''}<span>${Math.floor(memberOffset/30)+1}페이지</span>${result.nextOffset!==null?memberButton('next','','다음'):''}</div>`:''}</section>`;
}
async function editMemberRewards(){
 const r=memberRewardRules;if(!r)return;const exchange=r.pointExchange||{enabled:false,cashUnit:0,pointUnit:0};
 const fields=[{name:'attendanceDays',label:'연속 출석 목표 (1~31일)',type:'number',value:r.attendanceDays},
  {name:'attendancePoints',label:'출석 보상 포인트',type:'number',value:r.attendancePoints},
  {type:'section',label:'포인트 → 충전 잔액 교환'},
  {name:'pointExchangeEnabled',label:'포인트 교환 운영',type:'select',value:String(exchange.enabled),options:[{value:'false',label:'준비 중'},{value:'true',label:'이용 가능'}]},
  {name:'cashUnit',label:'교환 후 받는 충전 잔액 (원)',type:'number',value:exchange.cashUnit},
  {name:'pointUnit',label:'교환할 포인트 단위 (P)',type:'number',value:exchange.pointUnit}];
 const values=await openModal({title:'출석 · 포인트 보상 기준',fields,confirmLabel:'저장'});if(!values)return;
 await api('/api/member/action',{method:'POST',body:{action:'rewards.save',revision:r.revision,attendanceDays:Number(values.attendanceDays),attendancePoints:Number(values.attendancePoints),pointExchange:{enabled:values.pointExchangeEnabled==='true',cashUnit:Number(values.cashUnit),pointUnit:Number(values.pointUnit)}}});
 toast('보상 기준을 저장했습니다.');await renderMember();
}
