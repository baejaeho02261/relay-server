'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const apk=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(apk,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const flow=read('MoaPlayApp.Member.Flow.inc'),actions=read('MoaPlayApp.Member.Actions.inc');
const profileDetails=read('MoaPlayApp.Member.ProfileDetails.inc');
const detailSource=profileDetails.match(/function HubProfileDetailsTitle\(const View:string\):string;\s*begin([\s\S]*?)\nend;/)[1];
const source=flow.match(/function TMoaPlayForm\.HubReadAction:string;\s*begin([\s\S]*?)\nend;/)[1];
// Execute the production route decisions rather than duplicating their table.
function compileRead(body,detail=false){
 let js=body.replace(/Result\s*:=\s*'';/,"let Result='';");
 js=js.replace(/\b(else\s+)?if\s+(.+?)\s+then\s+Result\s*:=\s*([^\n;]+);?/g,(_,otherwise,condition,value)=>{
  const expression=condition.replace(/\.StartsWith\(/g,'.startsWith(').replace(/<>/g,'!==').replace(/(?<![<>=!])=(?!=)/g,'===').replace(/\bor\b/g,'||').replace(/\band\b/g,'&&');
  return `${otherwise?'else ':''}if (${expression}) Result=${value};`;
 });
 return detail?new Function('View',js+'\nreturn Result;'):new Function('FHubView','HubCasinoView','HubProfileDetailsTitle',js+'\nreturn Result;');
}
const originalGames=new Set(['crash','dice','mines','plinko','limbo','hilo','tower']);
const detailsTitle=compileRead(detailSource,true);
function verify(fn,title=detailsTitle){
 const expected={news:'news',catalog:'catalog',feed:'feed',chats:'',me:'me',all:'activity.settings',people:'people','activity.list':'account.list',
  'activity.account':'activity.settings','activity.privacy':'activity.settings','activity.orders':'activity.settings',
  playground:'',casino:'',original:'',attendance:'rewards',events:'rewards',wheel:'rewards',
  points:'rewards',notifications:'notifications',services:'history',activity:'activity','top.games':'topgames',
  orders:'me',payments:'me',profile:'me',charge:'charge',withdraw:'withdraw',
  baccarat:'arcade',roulette:'arcade',slots:'arcade',blackjack:'casino',
  settings:'preferences','settings.notifications':'preferences','settings.currency':'',
  policies:'policies',member:'member',follows:'follows',comments:'thread',
  badges:'badges',shop:'shop',bookmarks:'bookmarks',blocks:'blocks',popular:'popular',
  game:'product',article:'article',home:'',menu:'',
  'profile.links':'profile.details','profile.link.edit':'profile.details',
  'profile.banners':'profile.details','profile.banner.edit':'profile.details',
  'profile.grid':'profile.details','profile.ai':'profile.details',
  'profile.accounttype':'profile.details','profile.verification':'profile.details',
  'profile.unknown':'','profile.link':'','profile.banner':''};
 for(const game of originalGames)expected[game]='casino';
 for(const game of ['dino','flappy','whack','dodge','rhythm'])expected['event.'+game]='rewards';
 for(const [view,action] of Object.entries(expected))assert.equal(fn(view,v=>originalGames.has(v),title),action,view);
}
verify(compileRead(source));
assert.throws(()=>verify(compileRead(source),compileRead(detailSource.replace("View='profile.links'","View='removed-links'"),true)),'profile subpages require explicit mapped routes');
assert.throws(()=>verify(compileRead(source),()=> 'wrong'),'unknown profile pages cannot acquire an endpoint through a blanket prefix');
assert.match(flow,/HubProfileDetailsTitle\(FHubView\)<>'' then HubRenderProfileDetails\(HubCached\('profile.details'\)\)/,'new detail routes use their authenticated data');
assert.throws(()=>verify(compileRead(source.replace("Result:='activity.settings'","Result:='home'"))),'removed Home API dependency is detected');
assert.throws(()=>verify(compileRead(source.replace("FHubView='attendance'","FHubView='removed-attendance'"))),'attendance access cannot disappear with Home');
assert.ok(!fs.existsSync(path.join(apk,'MoaPlayApp.Member.Home.inc')),'Home implementation must be deleted');
const app=read('MoaPlayApp.pas');
assert.doesNotMatch(app,/Member\.Home\.inc/);
for(const include of ['Playground','Activity','Rewards','ActivitySettings','DirectMessages','ProfileDetails','ProfileGallery'])assert.match(app,new RegExp('Member\\.'+include+'\\.inc'));
const members=fs.readdirSync(apk).filter(name=>/^MoaPlayApp\.Member\..*\.inc$/.test(name)).map(read).join('\n');
assert.doesNotMatch(members,/HubRenderHome|HubHomeHeading|HubHomeTile|HubCached\('home'\)|FHubView\s*[=<>]+\s*'menu'|FHubMenuCategory|home\.event/);
assert.match(read('MoaPlayApp.Service.inc'),/FHubView := 'news'/,'service restart must not enter removed Home');
const missingData=flow.indexOf("else if (Action<>'') and not Assigned(HubCached(Action))",flow.indexOf('procedure TMoaPlayForm.HubRenderNow'));
for(const shell of ["else if FHubView='all' then HubRenderMenu","else if FHubView='chats' then HubRenderChats","else if FHubView.StartsWith('activity.') then HubRenderActivitySettings"]){
 const position=flow.indexOf(shell);assert.ok(position>=0&&position<missingData,'settings/chat shells are visible before network data');
}
for(const [view,index] of [['news',0],['catalog',1],['feed',2],['chats',3],['me',4]])
 assert.match(actions,new RegExp("ReturnView='"+view+"' then FDashboardActiveTab:="+index),'menu tab navigation '+view);
assert.match(actions,/FDashboardActiveTab:=2;HubNavigate\('feed'\)/,'popular shortcut activates feed');
assert.match(flow,/FDashboardActiveTab:=2;HubNavigate\('feed'\)/,'repost returns to feed');
assert.match(read('MoaPlayApp.Member.Settings.inc'),/FDashboardActiveTab:=0;HubNavigate\('news'/,'news settings use first tab');
assert.match(read('MoaPlayApp.Member.Media.inc'),/FDashboardActiveTab=4/,'avatar selection uses fifth tab');
const menu=read('MoaPlayApp.Member.Menu.inc'),settings=read('MoaPlayApp.Member.ActivitySettings.inc');
assert.match(menu,/HubCached\('activity.settings'\)/,'new hub uses the account settings response');
assert.match(menu,/Rows:=HubActivityMenuRows/,'category list is supplied by the settings metadata');
assert.doesNotMatch(menu,/FHubMenuCategory|menu.category|HubMenuGroup/,'old category filter buttons stay removed');
for(const route of ['attendance','notifications','events','playground','charge','points','orders','payments'])assert.ok(settings.includes("'"+route+"'"),route+' remains accessible from settings and activity');
// Each menu entry uses the actual account-settings read decision. The special
// account list retains its own endpoint, rather than being swallowed by prefix.
const items=[...settings.matchAll(/\bAdd\(('(?:[^']|'')*'),('(?:[^']|'')*'),('(?:[^']|'')*'),'([^']+)'/g)];
assert.ok(items.length>=40,'complete activity categories remain present');
for(const item of items)assert.equal(compileRead(source)('activity.'+item[4],()=>false,detailsTitle),'activity.settings',item[4]);
const dashboard=read('MoaPlayApp.Dashboard.inc');
const roots=dashboard.slice(dashboard.indexOf('function HubRootView'),dashboard.indexOf('procedure TMoaPlayForm.BuildDashboardUI'));
assert.deepEqual([...roots.matchAll(/(?:\d+:|else)\s*Result:='([^']+)'/g)].map(m=>m[1]),['news','catalog','feed','chats','me']);
assert.doesNotMatch(dashboard,/FDashboardTabLabels|BarBottom|BarW:=Min/,'no tab text or floating capsule spacing');
assert.match(dashboard,/FDashboardTabsCard.XRadius:=0;FDashboardTabsCard.YRadius:=0/);
function predicate(source){return source.replace(/\.StartsWith\(/g,'.startsWith(').replace(/<>/g,'!==').replace(/(?<![<>=!])=(?!=)/g,'===').replace(/\bor\b/g,'||').replace(/\band\b/g,'&&');}
function verifyScope(code){
 const decision=code.match(/if ([^\n]+) then FHubActivityScope:=False\s+else if ([^\n]+) then FHubActivityScope:=True;/);assert.ok(decision,'activity navigation scope decision');
 const update=Function('NewView','previous',`if (${predicate(decision[1])}) return false; if (${predicate(decision[2])}) return true; return previous;`);
 for(const view of ['news','catalog','feed','chats','me'])assert.equal(update(view,true),false,'root tab restores bottom bar: '+view);
 for(const view of ['all','settings','settings.currency','activity.account','activity.orders'])assert.equal(update(view,false),true,'activity route hides bottom bar: '+view);
 for(const view of ['orders','payments','profile','policies','game']){
  assert.equal(update(view,true),true,'descendant retains hub scope');
  assert.equal(update(view,false),false,'ordinary details do not manufacture hub scope');
 }
 assert.match(code,/Snapshot.AddPair\('activityScope',TJSONBool.Create\(FHubActivityScope\)\)/,'history stores actual context before navigating');
 assert.match(code,/FHubActivityScope:=HubBool\(Snapshot,'activityScope'\)/,'back restores the matching tab visibility');
 assert.match(code,/FHubHistory.Count=0 then begin HubNavigate\(HubRootView\(FDashboardActiveTab\)\)/,'empty history returns to its root');
 assert.match(code,/FHubChatHost.Visible:=NewView='chats'/,'navigation switches embedded host immediately');
 assert.match(code,/FHubChatHost.Visible:=FHubView='chats'/,'back restores embedded host visibility');
}
verifyScope(flow);
assert.throws(()=>verifyScope(flow.replace("(NewView='chats')", "(NewView='removed-chats')")),'detect sticky hidden tab bar after leaving activity');
assert.throws(()=>verifyScope(flow.replace("Snapshot.AddPair('activityScope',TJSONBool.Create(FHubActivityScope))",'')),'detect lost back-navigation scope');
assert.match(read('MoaPlayApp.Service.inc'),/FHubActivityScope:=False/,'service reset restores the root tab bar');
console.log('FIX65 NATIVE ROUTES PASS: production read decisions, no Home, five icon-only tabs, activity settings metadata, explicit authenticated profile subpages, preserved feature access, embedded chat shells, scoped history and service reset.');
