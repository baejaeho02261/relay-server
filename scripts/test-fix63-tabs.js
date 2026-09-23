'use strict';
// FIX65 updates the existing dashboard geometry contract. These checks execute
// native layout expressions; Android rendering still requires a device build.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const apk=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(apk,name),'utf8').replace(/^\uFEFF/,'');
function between(source,start,end){const a=source.indexOf(start),b=source.indexOf(end,a+start.length);assert.ok(a>=0&&b>a,start);return source.slice(a,b);}
function expression(text,scope){
 assert.match(text,/^[\w\s.+*/(),-]+$/);
 const js=text.replace(/\bMin\(/g,'Math.min(').replace(/\bMax\(/g,'Math.max(');
 return Function(...Object.keys(scope),'return '+js)(...Object.values(scope));
}
function assignment(source,name,scope){const m=source.match(new RegExp('\\b'+name+':=([^;]+);'));assert.ok(m,name);return expression(m[1],scope);}
function bounds(source,name,scope){
 const m=source.match(new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\.SetBounds\\(([^;]+)\\);'));assert.ok(m,name);
 let level=0,start=0;const args=[];
 for(let i=0;i<m[1].length;i++){const c=m[1][i];if(c==='(')level++;if(c===')')level--;if(c===','&&level===0){args.push(m[1].slice(start,i));start=i+1;}}
 args.push(m[1].slice(start));assert.equal(args.length,4,name);
 return args.map(arg=>expression(arg,scope));
}
function bottomHeight(layout,view,inHub,keyboardTop){
 const predicates=[...layout.matchAll(/if ([^;\r\n]+) then BottomHeight:=0;/g)].map(x=>x[1]);
 assert.equal(predicates.length,2,'activity scope and keyboard both own bar visibility');
 const source=predicates.map(p=>p.replace(/\.StartsWith\(/g,'.startsWith(').replace(/\bor\b/g,'||').replace(/\band\b/g,'&&').replace(/(?<![<>=!])=(?!=)/g,'==='));
 return source.some(p=>Function('FHubView','FHubActivityScope','FSupportKeyboardTop','return ('+p+')')(view,inHub,keyboardTop))?0:assignment(layout,'BarH',{});
}
function headerHeight(layout,view,chat){
 const decision=layout.match(/if ([^;\r\n]+) then HeaderHeight:=0;/);assert.ok(decision,'thread owns the shared header visibility');
 const condition=decision[1].replace(/Assigned\(([^)]+)\)/g,'Boolean($1)').replace(/\bnot\b/g,'!').replace(/\band\b/g,'&&').replace(/(?<![<>=!])=(?!=)/g,'===');
 const hidden=Function('FHubView','FHubDirectMessages','return ('+condition+')')(view,chat);
 return hidden?0:assignment(layout,'HeaderHeight',{});
}
function checkChatLayoutCallbacks(dashboard,adapter,chat){
 assert.match(adapter,/FHubDirectMessages.OnLayout:=HubDirectMessagesLayout/);
 assert.match(adapter,/FHubDirectMessages.OnLayout:=nil/,'dispose detaches the form callback');
 const callback=dashboard.slice(dashboard.indexOf('procedure TMoaPlayForm.HubDirectMessagesLayout'));
 assert.match(callback,/if FClosing or \(FHubView<>'chats'\) then Exit;[\s\S]*ResizeDashboardUI;/);
 const notify=between(chat,'procedure TMoaPlayDirectMessages.NotifyLayout;','procedure TMoaPlayDirectMessages.UpdatePeerHeader');
 assert.match(notify,/if FLayoutNotifying or not Visible or not Assigned\(FOnLayout\) then Exit/,'hidden component cannot mutate active page geometry');
 assert.match(notify,/if FLayoutReported and \(FReportedListMode=FListMode\) then Exit/,'polls do not repeatedly relayout unchanged chrome');
 assert.match(notify,/FLayoutNotifying:=True;[\s\S]*try FOnLayout\(Self\);finally FLayoutNotifying:=False;end/,'synchronous resize callbacks cannot recurse');
 const list=between(chat,'procedure TMoaPlayDirectMessages.ShowList;','procedure TMoaPlayDirectMessages.OpenMember');
 assert.ok(list.indexOf('FListMode:=True')<list.indexOf('NotifyLayout;'),'list state precedes the layout callback');
 assert.match(list,/NotifyLayout;LayoutWindow;Render;Fetch/,'inbox restores account header before requesting data');
 const thread=between(chat,'procedure TMoaPlayDirectMessages.SetThread','procedure TMoaPlayDirectMessages.ShowList;');
 assert.match(thread,/FListMode:=False/);assert.ok(thread.indexOf('FListMode:=False')<thread.indexOf('NotifyLayout;'),'thread state precedes its layout callback');
}
function checkNavigation(dashboard,theme){
 const root=between(dashboard,'function HubRootView','procedure TMoaPlayForm.BuildDashboardUI');
 const routes=[...root.matchAll(/(?:\d+:|else)\s*Result:='([^']+)'/g)].map(m=>m[1]);
 assert.deepEqual(routes,['news','catalog','feed','chats','me']);
 assert.doesNotMatch(dashboard+theme,/nav-selection/,'no selected enclosure is constructed or recolored');
 assert.doesNotMatch(dashboard,/'home'|FDashboardTabLabels/,'deleted home and tab captions never return');
 assert.match(dashboard,/Names := \['news','discover','feed','paperplane','user'\]/);
 assert.match(dashboard,/FDashboardTabs\[I\]\.Fill\.Kind:=TBrushKind.None/);
 assert.match(theme,/Tab.Fill.Kind:=TBrushKind.None;Tab.Stroke.Kind:=TBrushKind.None/);
 assert.match(dashboard,/NewTab:=EnsureRange\(Integer\(TControl\(Sender\)\.Tag\),0,4\)/);
 assert.match(dashboard,/FDashboardActiveTab:=EnsureRange\(FDashboardActiveTab,0,4\)/);
 assert.match(dashboard,/FHubTabAvatar.Parent:=FDashboardTabs\[4\]/);
 assert.match(dashboard,/FDashboardActiveTab:=0;HubNavigate\('news'\)/,'hardware back returns to the surviving first tab');
 assert.match(dashboard,/Pulse:=1\+Sin\(Progress\*Pi\)\*0.07/,'existing icon pulse is preserved');
 assert.match(dashboard,/FHubView := 'news'/,'first authorized frame is news');
 assert.match(dashboard,/FDashboardTabsCard.XRadius:=0;FDashboardTabsCard.YRadius:=0/);
 assert.match(dashboard,/FHubChatHost.Parent:=FFinalPanel/,'chat host survives page replacement');
 assert.match(dashboard,/FHubChatHost.Visible:=FHubView='chats';FDashboardScroll.Visible:=not FHubChatHost.Visible/);
 assert.match(dashboard,/FHubDirectMessages.Visible and not FHubDirectMessages.ListMode/,'thread back and root tab back are separate');
 assert.match(dashboard,/if \(NewTab=3\) and Assigned\(FHubDirectMessages\) then FHubDirectMessages.ShowList/,'active chat tab returns to its list');
}
function Check(){
 const dashboard=read('MoaPlayApp.Dashboard.inc'),theme=read('MoaPlayApp.Theme.inc');checkNavigation(dashboard,theme);
 const layout=between(dashboard,'procedure TMoaPlayForm.ResizeDashboardUI;','procedure TMoaPlayForm.HubUpdateHeader;');
 const cardSource=layout.slice(layout.indexOf('FDashboardTabsCard.SetBounds'));
 const adapter=read('MoaPlayApp.Member.DirectMessages.inc'),chatSource=read('MoaPlayDirectMessages.pas');
 checkChatLayoutCallbacks(dashboard,adapter,chatSource);
 assert.match(layout,/FHubTitleBar.Visible:=HeaderHeight>0/);
 for(const view of ['news','catalog','feed','me','chats'])for(const component of [null,{ListMode:true},{ListMode:false}])
  assert.equal(headerHeight(layout,view,component),view==='chats'&&component&&!component.ListMode?0:56,'shared header visibility '+view);
 assert.throws(()=>headerHeight(layout.replace('then HeaderHeight:=0','then HeaderHeight:=56'),'chats',{ListMode:false}),'thread-specific geometry must remain explicit');
 assert.throws(()=>checkChatLayoutCallbacks(dashboard,adapter.replace('FHubDirectMessages.OnLayout:=HubDirectMessagesLayout','FHubDirectMessages.OnLayout:=nil'),chatSource),'missing mode-change callback must fail');
 let count=0;
 for(const W of [240,280,320,360,393,412,480,600,800,1024,1440])for(const H of [320,480,640,800,1280])for(const ComposerHeight of [0,92,124])for(const ListMode of [true,false]){
  const scope={W,H,ComposerHeight,HeaderHeight:headerHeight(layout,'chats',{ListMode})};scope.BarH=assignment(layout,'BarH',scope);scope.BottomHeight=assignment(layout,'BottomHeight',scope);
  scope.TabW=assignment(cardSource,'TabW',scope);
  const bar=bounds(cardSource,'FDashboardTabsCard',scope),scroll=bounds(layout,'FDashboardScroll',scope),composer=bounds(layout,'FHubCommentBar',scope),chat=bounds(layout,'FHubChatHost',scope);
  assert.equal(bar[0],0);assert.equal(bar[2],W,'bar returns to both client edges');
  assert.equal(bar[1]+bar[3],H,'bar rests on the system-safe client bottom');
  assert.ok(scroll[1]+scroll[3]<=composer[1],'content cannot underlap a composer');
  assert.equal(composer[1]+composer[3],bar[1],'no floating capsule gap remains');
  assert.equal(chat[1],ListMode?56:0);assert.equal(chat[1]+chat[3],bar[1],'inbox reserves account header; thread occupies its own header area');
  if(!ListMode)assert.equal(chat[3],H-scope.BottomHeight,'thread has no blank 56px account-header strip');
  for(let I=0;I<5;I++){
   const values={...scope,I},tab=bounds(cardSource,'FDashboardTabs[I]',values),icon=bounds(cardSource,'FDashboardIcons[I]',values);
   assert.ok(tab[2]>=48&&tab[3]>=48,'full-size touch targets survive narrow screens');
   assert.ok(tab[0]>=0&&tab[0]+tab[2]<=bar[2]+0.001,'all five tabs remain inside the bar');
   assert.ok(icon[0]>=0&&icon[0]+icon[2]<=tab[2],'icon is inside its hit target');
   assert.equal(icon[1]+icon[3]/2,tab[3]/2,'unlabelled icons remain vertically centered');
  }
  // Keyboard and settings modes consume all of the original client area.
  scope.BottomHeight=0;const input=bounds(layout,'FHubCommentBar',scope),fullChat=bounds(layout,'FHubChatHost',scope);
  assert.equal(input[1]+input[3],H);assert.equal(fullChat[1]+fullChat[3],H);count++;
 }
 for(const view of ['news','catalog','feed','chats','me'])assert.equal(bottomHeight(layout,view,false,0),60,view);
 for(const view of ['all','settings','settings.currency','activity.privacy'])assert.equal(bottomHeight(layout,view,view.startsWith('activity.'),0),0,view);
 for(const view of ['profile','game','bookmarks','policies']){
  assert.equal(bottomHeight(layout,view,true,0),0,'hub descendant stays immersive');
  assert.equal(bottomHeight(layout,view,false,0),60,'same view outside hub restores tabs');
 }
 for(const view of ['comments','compose','editpost','chats','profile.link.edit','profile.banner.edit'])assert.equal(bottomHeight(layout,view,false,260),0,'native keyboard reveals entire composer');
 const header=between(dashboard,'procedure TMoaPlayForm.HubUpdateHeader;','procedure TMoaPlayForm.UpdateDashboard;');
 assert.match(header,/FHubHeaderCreate.Visible:=FHubView='me'/);
 assert.match(header,/FHubHeaderAction.TagString:='chat.compose'/);
 assert.match(dashboard,/FHubHeaderAccount.TagString:='profile.account'/);
 assert.match(header,/FHubHeaderTitle.Visible:=not FHubHeaderAccount.Visible/);
 for(const W of [240,320,393,600,1024])for(const TextWidth of [18,90,180,480,1800]){
  const scope={FHubTitleBar:{Width:W},Title:'@member',HubTextWidth:()=>TextWidth};scope.AccountW=assignment(header,'AccountW',scope);
  const account=bounds(header,'FHubHeaderAccount',scope),label=bounds(header,'FHubHeaderAccountLabel',scope),arrow=bounds(header,'FHubHeaderAccountChevron',scope);
  assert.equal(account[0]+account[2]/2,W/2,'account title stays centered');
  assert.ok(account[0]>=60&&account[0]+account[2]<=W-60,'account does not cover left/right actions');
  assert.ok(label[0]+label[2]<=arrow[0]&&arrow[0]+arrow[2]<=account[2],'long handles truncate before chevron');
 }
 const dock=read('MoaPlayApp.Member.GameWindow.inc');
 assert.match(dock,/FDashboardTabsCard.Visible then Bottom:=FDashboardTabsCard.Position.Y/,'floating tools track the actual bar top');
 assert.match(layout,/SetMoaPlayMessageBottom\(FDashboardTabsCard.Position.Y\)/,'toasts remain above the bar');
 assert.throws(()=>checkNavigation(dashboard.replace("0: Result:='news'","0: Result:='home'"),theme),'detect deleted home navigation');
 assert.throws(()=>checkNavigation(dashboard+'\nnav-selection',theme),'detect selected enclosure regression');
 assert.throws(()=>checkNavigation(dashboard.replace('FDashboardTabsCard.XRadius:=0','FDashboardTabsCard.XRadius:=32'),theme),'detect floating capsule regression');
 return count;
}
module.exports={Check};
if(require.main===module)console.log('FIX65 TABS PASS: five icon-only routes, flat bar, scoped/keyboard visibility, callback-driven inbox/thread headers, centered account handles, '+Check()+' composer layouts.');
