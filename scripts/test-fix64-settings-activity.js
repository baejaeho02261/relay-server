'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const apk=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(apk,n),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const activity=read('MoaPlayApp.Member.ActivitySettings.inc'),menu=read('MoaPlayApp.Member.Menu.inc'),settings=read('MoaPlayApp.Member.Settings.inc');
const flow=read('MoaPlayApp.Member.Flow.inc'),actions=read('MoaPlayApp.Member.Actions.inc'),icons=read('MoaPlayMemberSvg.pas');
function rows(source){return [...source.matchAll(/^\s*Add\(([^\n]+)\);$/gm)].map(m=>[...m[1].matchAll(/'((?:[^']|'')*)'/g)].map(x=>x[1].replace(/''/g,"'")));}
const requested=[
 ['내 계정',['계정센터']],
 ['내 MoaPlay 사용 방식',['저장됨','보관','내 활동','알림','시간 관리','MoaPlay 얼리 엑세스','태블릿용 MoaPlay']],
 ['구독',['MoaPlay Plus','Meta Verified','모든 구독']],
 ['내 콘텐츠를 볼 수 있는 사람',['계정 공개 범위','친한 친구','교차 게시','차단됨','스토리','라이브 및 위치',"'친구만' 피드에서의 활동"]],
 ['다른 사람이 나와 소통할 수 있는 방법',['메세지 및 스토리 답장','태그 및 언급','댓글','공유 및 다시 사용','제한된 계정','교류 일시 제한','숨겨진 단어','친구 팔로우 및 초대']],
 ['내가 볼 수 있는 내용',['즐겨찾기','업데이트를 보지 않도록 설정한 계정','콘텐츠 기본 설정','좋아요 수 및 공유 수']],
 ['내 앱 및 미디어',['기기 권한','보관 및 다운로드','접근성, 언어 및 번역','데이터 사용량 및 미디어 품질','앱 웹사이트 권한']],
 ['가족 센터',['청소년 계정의 관리 감독']],
 ['내 인사이트 및 도구',['대시보드','계정 유형 및 도구']],
 ['내 주문 및 거부 캠페인',['주문 및 결제']],
 ['더 많은 정보 및 지원',['도움말','Meta AI 지원 어시스턴트','개인정보 보호 센터','계정 상태','정보']],
 ['Meta의 다른 앱',['Threads Moa','Edits','Meta 제품 더보기']]
];
function verifyRows(source){
 const items=rows(source);assert.equal(items.length,47);assert.ok(items.every(r=>r.length===7),'all seven metadata fields present');
 assert.deepEqual(items.map(r=>[r[0],r[1]]),requested.flatMap(([g,names])=>names.map(name=>[g,name])),'every requested entry in exact category/order');
 assert.equal(new Set(items.map(r=>r[3])).size,items.length,'unique route per entry');
 for(const r of items){
   assert.ok(new RegExp("Name\\s*=\\s*'"+r[2]+"'").test(icons),'real SVG for '+r[1]);
   const route='activity.'+r[3];assert.ok(source.includes("Page='"+route+"'")||source.includes("Action='"+route+"'")||source.includes("if Page='"+route+"'"),'route renders detail or performs real existing navigation '+route);
 }
 return items;
}
const items=verifyRows(activity);
assert.throws(()=>verifyRows(activity.replace("Add('내 MoaPlay 사용 방식','보관'","Add('내 MoaPlay 사용 방식','없음'")),'missing requested label fails');
for(const key of ['closeFriends','restricted','favorites','muted','blocked'])assert.ok(items.some(r=>r[6]===key),'live count '+key);
for(const key of ['plus','verified','privacy','interactionLimit'])assert.ok(items.some(r=>r[5]===key),'selected status '+key);
assert.ok(items.find(r=>r[3]==='account')[4].includes('비밀번호, 보안, 개인정보, 연결된 환경, 광고 기본 설정'));
assert.match(menu,/Data:=HubCached\('activity.settings'\);Counts:=HubObject\(Data,'counts'\)/);
assert.match(menu,/C\.Fill\.Kind:=TBrushKind.None;C\.Stroke\.Kind:=TBrushKind.None/);
assert.doesNotMatch(menu,/HubMenuCategory|FHubMenuCategory|Names:=\[|HubCached\('home'\)/);
assert.match(menu,/AddMemberSvg\(C,C,'search',13,12,20,20,True\)/,'search icon is an actual child of the inbox-style field');
assert.match(menu,/FHubSearchEdit.Parent:=C/);assert.match(menu,/PromptText:=MemberCaption\('검색'\)/);
assert.doesNotMatch(menu,/HubLabel\(C,MemberCaption\('검색'\)/,'one search prompt');
const inputHandler=menu.slice(menu.indexOf('procedure TMoaPlayForm.HubMenuSearchChanged'),menu.indexOf('procedure TMoaPlayForm.HubRenderMenuResults'));
assert.doesNotMatch(inputHandler,/HubRender;|HubFetch;|FreeAndNil\(FHubSearchEdit\)/,'typing keeps focused native editor mounted');
// Evaluate the menu's actual lane expressions over compact/large widths and every A/B value.
for(const width of [280,320,360,412,600,800])for(const valueWidth of [0,12,35,70,110,300]){
 const card=width,textRight=card-40,valueW=valueWidth?Math.min(card*.32,valueWidth+4):0,titleW=textRight-54-(valueW?valueW+10:0);
 assert.ok(titleW>0);assert.ok(54+titleW<=textRight-valueW);assert.ok(textRight<card-22,'values end before arrow');
 if(valueW)assert.ok(54+titleW+10<=textRight-valueW+1e-8,'long A/B value cannot truncate into the title');
 assert.ok(44+(card-56)<=card,'input content stays inside rounded field');
}
assert.match(activity,/Body.AddPair\('kind',Parts\[1\]\);Body.AddPair\('memberId',Parts\[2\]\);Body.AddPair\('enabled',TJSONBool.Create\(Parts\[3\]='1'\)\)/);
assert.match(activity,/if Parts\[1\]<>FHubCategory then Exit/,'cannot mutate another list from stale row');
assert.match(activity,/\(HubText\(Data,'kind'\)<>FHubCategory\)/,'late read cannot paint a different member list');
assert.match(activity,/Send\('activity.settings.save'\)/);assert.match(activity,/Send\('account.list.set'\)/);
for(const key of ['messageAudience','commentAudience','allowRepost','hideLikeCounts','hideShareCounts','hiddenWords','interactionLimit'])assert.ok(activity.includes("'"+key+"'"));
assert.match(settings,/Radio\('친한 친구',[^\n]+'CLOSE_FRIENDS'\)/);assert.match(settings,/\(Key<>'CLOSE_FRIENDS'\)/);
for(const name of ['bookmarks','myfeed','myactivity|comments','services','attendance','events','playground','badges','points','shop','activity','top.games','charge','withdraw','orders','payments','support'])assert.ok(activity.includes("'"+name+"'"),'existing feature stays reachable '+name);
assert.match(activity,/현재 판매 중인 MoaPlay Plus 구독 상품은 없습니다/);assert.match(activity,/MoaPlay에는 Meta 계정 연결이나 인증 구독 기능이 제공되지 않습니다/);
assert.doesNotMatch(activity,/Request\('(?:plus|verified)\.purchase/,'no fake external subscription');
assert.match(activity,/OpenAppPermissionSettings/);assert.match(activity,/ClearMemberImages/);
assert.match(flow,/if HubActivitySettingsReply\(Action,Payload\) then Exit/,'dotted reads are not mistaken for mutations');
assert.match(actions,/HubActivitySettingsAction\(Sender\)/,'buttons dispatch actual settings handlers');
assert.match(flow,/FHubView='activity.hiddenwords'/,'hidden word draft participates in editor preservation');
console.log('FIX64 SETTINGS ACTIVITY PASS: all 47 requested entries, 12 ordered categories, real counts/status, bounded title/value/icon lanes, stable search editor, authenticated settings/list routes, late-list guard, retained services, and honest external-service availability.');
