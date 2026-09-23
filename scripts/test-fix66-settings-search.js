'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const apk=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(apk,n),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const activity=read('MoaPlayApp.Member.ActivitySettings.inc'),menu=read('MoaPlayApp.Member.Menu.inc'),settings=read('MoaPlayApp.Member.Settings.inc'),currency=read('MoaPlayApp.Member.Currency.inc'),chat=read('MoaPlayDirectMessages.pas');
const literals=line=>[...line.matchAll(/'((?:[^']|'')*)'/g)].map(x=>x[1].replace(/''/g,"'"));
const roots=[...activity.matchAll(/^\s*Add\(([^\n]+)\);$/gm)].map(m=>{const [group,title,icon,page,detail,valueKey,countKey]=literals(m[1]);return {group,title,icon,view:'activity.'+page,detail,valueKey,countKey,keywords:''};});
function entries(source){
 const leaves=[...source.matchAll(/^\s*Leaf\(([^\n]+)\);$/gm)].map(m=>{
  const [parent,title,detail,icon,view,keywords]=literals(m[1]),root=roots.find(row=>row.view==='activity.'+parent);
  assert.ok(root,'search parent must exist: '+parent);return {group:root.group+' · '+root.title,title,detail,icon,view,keywords};
 });
 assert.equal(new Set(leaves.map(row=>row.group+'|'+row.title)).size,leaves.length,'unique search title within breadcrumb');
 return [...roots,...leaves];
}
// Compile the production predicate, including its all-word behavior, instead of
// making the test silently accept an independent search implementation.
function predicate(source){
 const body=source.match(/function HubActivitySearchMatch[^]*?begin\n([^]*?)\nend;/)[1];
 let js=body.replace('Result:=True;','let Result=true;')
 .replace(/Haystack:=LowerCase\(([^;]+)\);/,(_,arg)=>'const Haystack=('+arg+').toLowerCase();')
 .replace(/Words:=LowerCase\(Trim\(Query\)\)\.Split\(\[' ',#9,#10,#13\]\);/,'const Words=Query.trim().toLowerCase().split(/[ \\t\\n\\r]/);')
 .replace(/\bRow\.([A-Z])(\w*)/g,(_,first,rest)=>'Row.'+first.toLowerCase()+rest)
 .replace(/MemberCaption\(([^)]+)\)/g,'$1')
 .replace(/for Word in Words do if \(Word<>''\) and not Haystack.Contains\(Word\) then Exit\(False\);/,"for(const Word of Words) if(Word!==''&&!Haystack.includes(Word))return false;");
 return Function('Row','Query',js+'\nreturn Result;');
}
const match=predicate(activity),all=entries(activity),search=q=>all.filter(row=>match(row,q));
const expected={
 '새 팔로워':['settings.notifications'],'답글 알림':['settings.notifications'],
 '화면 테마':['settings'],'다크':['settings'],'구매 활동 공개':['settings'],
 '잔액 순위 비공개':['settings'],'한국어':['settings.language'],'USD':['settings.currency'],
 '코인':['settings.currency'],'프로필 링크':['pdetail.open|links'],'닉네임':['profile'],
 '그리드':['pdetail.open|grid'],'배너 음악':['pdetail.open|banners'],
 '비즈니스':['pdetail.open|accounttype'],'프로필 인증':['pdetail.open|verification'],
 '임시 이미지':['activity.downloads'],'캐시':['activity.downloads'],
 '좋아요 숨기기':['activity.counts'],'공유 수 숨기기':['activity.counts'],
 '메세지 허용':['activity.messages'],'댓글 허용':['activity.comments'],
 '숨길 단어':['activity.hiddenwords'],'기기 권한':['activity.permissions'],
 '포인트 교환':['points'],'출금':['withdraw'],'리포스트 기록':['myactivity|reposts'],
 '뱃지':['badges'],'원화':['settings.currency'],'결제 내역':['payments'],
 '개인정보 처리방침':['activity.policy|privacy'],
 '크래시':['crash'],'블랙잭':['blackjack'],'두더지':['event.whack'],
};
for(const [query,routes] of Object.entries(expected))for(const route of routes)assert.ok(search(query).some(row=>row.view===route),query+' opens '+route);
assert.ok(search('  USD \t ').some(row=>row.view==='settings.currency'));
assert.equal(search('원화 알수없는설정zzzz').length,0,'all query words must match');
assert.equal(search('존재하지않는설정zzzz').length,0);assert.equal(search('').length,all.length);
for(const row of all){assert.ok(row.view);assert.ok(row.title);assert.ok(row.group);}
assert.ok(all.length>=120,'search traverses real nested functions beyond the 47 root rows');
assert.ok(all.filter(row=>row.view.startsWith('settings.')).length>0);
assert.match(menu,/if Row.View.StartsWith\('settings.'\) then C.OnClick:=HubSettingsChanged/,'nested settings route uses the actual settings handler');
assert.doesNotMatch(all.map(row=>row.view).join('\n'),/\.save(?:\n|$)|activity\.toggle|activity\.choose|cache\.clear|permissions\.open|\.delete|\.purchase|pdetail\.toggle/,'search opens controls without changing account or clearing data');
assert.match(menu,/Rows:=HubActivityMenuRows;if Query<>'' then Rows:=HubActivitySearchRows/,'empty query keeps original category ordering');
assert.match(menu,/if not HubActivitySearchMatch\(Row,Query\) then Continue/);
assert.throws(()=>{
 const broken=activity.replace("Row.Keywords+' '","''+' '"),bad=predicate(broken);
 assert.ok(all.some(row=>row.view==='settings.currency'&&bad(row,'USD')));
},'keyword-only nested settings must stay searchable');
const deepRoutes=all.filter(row=>!roots.some(r=>r===row)).map(row=>row.view);
for(const route of ['settings.notifications','settings.language','settings.currency','settings.feed','settings.profile']){
 assert.ok(deepRoutes.includes(route));assert.ok(settings.includes("Action='"+route+"'"),'actual route handler '+route);
}
const handler=menu.slice(menu.indexOf('procedure TMoaPlayForm.HubMenuSearchChanged'),menu.indexOf('procedure TMoaPlayForm.HubRenderMenuResults'));
assert.doesNotMatch(handler,/HubRender;|HubFetch;|FreeAndNil\(FHubSearchEdit\)/,'search retains focused editor and keyboard');
assert.match(menu,/FHubSearchEdit.MaxLength:=80/);assert.match(menu,/PromptText:=MemberCaption\('검색'\)/);
assert.doesNotMatch(menu,/HubLabel\(C,MemberCaption\('검색'\)/,'one chat-style placeholder, no duplicate floating caption');
assert.match(chat,/FSearchBox:=DMRect\(FListHeader,16,4,240,44,MemberSoft,12\)/);
assert.match(menu,/MemberSoft,12\);C.SetBounds\(16,FHubY,Max\(80,FHubPage.Width-32\),44\)/);
assert.match(menu,/AddMemberSvg\(C,C,'search',13,12,20,20,True\)/);
assert.match(menu,/FHubSearchEdit.SetBounds\(42,4,Max\(28,C.Width-52\),36\)/);
assert.match(menu,/C.SetBounds\(0,Y,FHubPage.Width,52\)/,'full-width press hit target');
assert.match(menu,/C.XRadius:=0;C.YRadius:=0;C.HitTest:=True;C.AutoCapture:=True/);
assert.match(menu,/Divider.SetBounds\(0,Y,FHubPage.Width,6\)/,'thick edge-to-edge group separator');
assert.match(settings,/Divider.SetBounds\(0,FHubY,FHubPage.Width,6\)/);
assert.match(currency,/C.SetBounds\(0,Y,W,68\)/);assert.match(currency,/C.XRadius:=0;C.YRadius:=0/);
assert.doesNotMatch(activity,/UiRect\(C,C,MemberTransparent,8\)/,'nested list checkbox matches square rows');
// Production expressions for press row/icon/title/value lanes at different DPIs.
const expressions={textRight:menu.match(/TextRight:=([^;]+);ValueW/)[1],valueW:menu.match(/if Value<>'' then ValueW:=([^;]+);/)[1],titleW:menu.match(/TitleW:=([^;]+);if ValueW/)[1]};
const evaluate=(expr,scope)=>Function(...Object.keys(scope),'return '+expr.replace(/C.Width/g,'width').replace(/Min\(/g,'Math.min(').replace(/HubTextWidth\(Value,12\)/g,'valueTextWidth')+';')(...Object.values(scope));
let geometryCases=0;
for(const width of [240,280,320,360,412,480,600,800,1024])for(const valueTextWidth of [0,12,35,70,110,300]){
 const TextX=54,TextRight=evaluate(expressions.textRight,{width}),ValueW=valueTextWidth?evaluate(expressions.valueW,{width,valueTextWidth}):0;
 const TitleW=evaluate(expressions.titleW,{TextRight,TextX})-(ValueW?ValueW+10:0);
 assert.ok(TitleW>0);assert.ok(TextX+TitleW<=TextRight-ValueW);assert.ok(TextRight<=width-30-10);
 assert.ok(16+22<TextX);assert.ok(42+Math.max(28,width-32-52)<=width-32);
 geometryCases++;
}
console.log(`FIX66 SETTINGS SEARCH PASS: ${all.length} searchable entries, real descendant routes, multiword/alias queries, mutation-free navigation, retained inbox-style search, 6px group dividers, ${geometryCases} full-width layout cases.`);
