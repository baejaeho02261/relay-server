'use strict';
// Deterministic answers owned by Relay. No external model or payment action runs here.
const crypto=require('node:crypto'),state=require('../core/state');
const DEFAULTS=Object.freeze([
 {id:'FAQ_BALANCE',question:'충전 잔액은 어디에서 확인하나요?',answer:'홈의 MY에서 충전 잔액을 확인할 수 있습니다. 잔액 패널을 펼치면 포인트 잔액도 확인할 수 있어요. 앱 내 충전과 간편결제는 지원하지 않습니다. 잔액 지급이나 내역 확인은 관리자에게 문의해주세요.',keywords:['잔액','입금','적립','지급']},
 {id:'FAQ_GAME',question:'게임 이용권은 어떻게 구매하나요?',answer:'발견에서 게임을 펼친 뒤 구매하기를 누르면 충전 잔액으로 1회용 이용권을 바로 구매합니다. 이용권에서 게임 파일을 휴대폰에 다운로드하고 PC MoaPlayConnect의 연결 인증을 완료하면 시작할 수 있습니다. 사용한 이용권은 다시 사용할 수 없습니다.',keywords:['게임','구매','이용권','가격','다운로드']},
 {id:'FAQ_QR',question:'출입증 QR은 무엇인가요?',answer:'출입증 QR은 기기 사용 승인을 위한 코드입니다. 앱에 표시된 출입증 QR을 캡처해 관리자에게 전달하세요. QR 확인 시간이 지나면 새 QR을 사용해주세요. 출입증 승인은 잔액을 지급하거나 이용권을 구매하는 기능이 아닙니다.',keywords:['출입증','qr','큐알','승인','코드']},
 {id:'FAQ_REFUND',question:'결제 내역 확인이나 환불 문의는 어디서 하나요?',answer:'메뉴의 결제 내역에서 충전·구매·환불 기록을 확인할 수 있습니다. 환불이나 결제 금액 확인은 상담원 연결로 문의해주세요. 봇은 결제 기록을 변경하거나 환불을 확정하지 않습니다.',keywords:['환불','결제','차감','취소']},
 {id:'FAQ_PROFILE',question:'프로필 사진과 이름은 어디서 바꾸나요?',answer:'마이페이지에서 프로필 편집을 누르고 사진·닉네임·소개를 변경한 뒤 저장하세요. 사진 선택 후 저장까지 해야 피드와 댓글에도 반영됩니다. 최신 내용이 보이지 않으면 입력창을 닫고 목록 맨 위에서 아래로 당겨 새로고침하세요.',keywords:['프로필','사진','닉네임','이름']},
 {id:'FAQ_AUTH',question:'지문 인증이나 기기 승인에 문제가 있어요.',answer:'휴대전화에 지문이 등록되어 있는지 확인해주세요. 앱에 표시된 권한과 인증 안내를 완료한 뒤 다시 시도하세요. 반복해서 실패하면 상담원 연결로 화면의 설명을 알려주세요. 봇이나 상담 메시지에 비밀번호·인증번호를 입력할 필요는 없습니다.',keywords:['지문','인증','생체','권한','로그인']},
 {id:'FAQ_REFRESH',question:'새 게시물이나 변경된 내용이 보이지 않아요.',answer:'목록 맨 위에서 아래로 당긴 뒤 놓으면 최신 내용을 조회합니다. 작성 중인 입력창은 먼저 닫아주세요. 인터넷 연결을 확인하고, 문제가 계속되면 상담원에게 화면과 발생 시점을 알려주세요.',keywords:['갱신','새로고침','업데이트','안보여','안 보여','연결']},
 {id:'FAQ_SOCIAL',question:'게시물은 어디에서 작성하나요?',answer:'피드 오른쪽 위 작성 아이콘으로 게시물을 올릴 수 있습니다. 게시물의 화살표를 누르면 내용을 펼쳐 볼 수 있고, 게시물을 꾹 누르면 리포스트합니다. 프로필 사진과 이름은 마이페이지의 편집 아이콘에서 변경할 수 있습니다.',keywords:['게시물','피드','글쓰기','리포스트']}
].map(x=>Object.freeze({...x,enabled:true})));
function Rows(){return state.supportSettings.knowledge||DEFAULTS;}
function Public(){return Rows().filter(x=>x.enabled).map(({id,question,answer})=>({id,question,answer}));}
function Admin(){return {revision:state.supportSettings.knowledgeRevision||0,items:structuredClone(Rows())};}
function Valid(entry){
 return entry&&typeof entry==='object'&&/^[A-Za-z0-9_-]{4,48}$/.test(entry.id)&&typeof entry.enabled==='boolean'&&
 ['question','answer'].every(k=>typeof entry[k]==='string'&&entry[k].trim()&&entry[k].length<=(k==='question'?80:800)&&!/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(entry[k]))&&
 Array.isArray(entry.keywords)&&entry.keywords.length<=8&&entry.keywords.every(k=>typeof k==='string'&&k.trim()&&/[\p{L}\p{N}]/u.test(k)&&k.length<=24&&!/[\x00-\x1F]/.test(k));
}
function Import(raw={}){
 if(raw.knowledge===undefined)return {};
 if(!Array.isArray(raw.knowledge)||raw.knowledge.length>12||!raw.knowledge.every(Valid)||new Set(raw.knowledge.map(x=>x.id)).size!==raw.knowledge.length)throw Error('SUPPORT_KNOWLEDGE_INVALID');
 return {knowledge:structuredClone(raw.knowledge),knowledgeRevision:Math.max(0,Number(raw.knowledgeRevision)||0)};
}
function Write(body,remove=false){
 const before=state.supportSettings;
 if(!body||body.revision!==(before.knowledgeRevision||0))return {ok:false,reason:'HISTORY_CHANGED'};
 const rows=structuredClone(Rows()),id=remove?body.id:body.entry?.id||'FAQ_'+crypto.randomUUID().replaceAll('-',''),index=rows.findIndex(x=>x.id===id);
 if(remove){if(index<0)return {ok:false,reason:'FAQ_NOT_FOUND'};rows.splice(index,1);}
 else{
  const e=body.entry||{},entry={id,question:typeof e.question==='string'?e.question.trim():e.question,answer:typeof e.answer==='string'?e.answer.trim():e.answer,keywords:Array.isArray(e.keywords)?e.keywords.map(x=>typeof x==='string'?x.trim():x):e.keywords,enabled:e.enabled};
  if(!Valid(entry)||index<0&&rows.length>=12)return {ok:false,reason:'INVALID_SUPPORT_FAQ'};
  if(index<0)rows.push(entry);else rows[index]=entry;
 }
 state.supportSettings={...before,knowledge:rows,knowledgeRevision:(before.knowledgeRevision||0)+1};
 if(!require('../storage/database').SaveDatabase()){state.supportSettings=before;return {ok:false,reason:'STORAGE_SAVE_FAILED'};}
 return {ok:true,knowledge:Admin()};
}
const Normalize=value=>String(value||'').toLowerCase().replace(/[^\p{L}\p{N}]/gu,'');
function Answer(text,settings){
 const query=Normalize(text);
 if(['상담원연결','관리자연결','상담사연결','직원연결','사람연결'].some(x=>query.includes(x)))return {handoff:true,text:settings.adminOnline?'상담원 연결을 요청했습니다. 지금까지의 대화와 함께 전달됩니다. 확인 후 이 대화에서 답변드릴게요.':'상담원 연결 요청을 접수했습니다. 현재 관리자가 오프라인이어서 답변은 나중에 도착할 수 있습니다. 대화는 보관됩니다.'};
 let match,score=0;
 for(const item of Rows().filter(x=>x.enabled)){
  const exact=query===Normalize(item.question),points=exact?100:item.keywords.reduce((n,k)=>n+(query.includes(Normalize(k))?1:0),0);
  if(points>score){match=item;score=points;}
 }
 if(match)return {text:match.answer,faqId:match.id};
 if(/^(안녕|안녕하세요|반가워|ㅎㅇ)/.test(query))return {text:'안녕하세요. FAQ 안내 봇입니다. 잔액, 게임 이용권, 프로필, 지문 인증 등 궁금한 내용을 적어주세요. 상담원이 필요하면 상담원 연결을 눌러주세요.'};
 return {text:'이 질문에 맞는 안내를 찾지 못했어요. 잔액·게임 이용권·프로필·지문 인증처럼 궁금한 항목을 짧게 적어보세요. 자세한 확인이 필요하면 상담원 연결을 눌러주세요.'};
}
module.exports={Public,Admin,Import,Write,Answer};
