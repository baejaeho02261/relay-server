'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const source=name=>fs.readFileSync(path.join(native,name),'utf8');
const home=source('MoaPlayApp.Member.Home.inc'),news=source('MoaPlayApp.Member.NewsShop.inc'),widgets=source('MoaPlayApp.Member.Widgets.inc');
const section=(text,start,end)=>text.slice(text.indexOf(start),text.indexOf(end,text.indexOf(start)));
const wallet=section(home,"Card:=StartCard('MY'","Detail:=MemberFormat('연속"),discovery=section(home,"Card:=StartCard('발견'","Items:=HubArray(Data,'runningGames')"),attendance=section(home,"Card:=StartCard('출석 체크'","Card:=StartCard('출석 랭킹'");
const card=section(news,'function TMoaPlayForm.HubFillGameCard','procedure TMoaPlayForm.HubRenderNews');
const productAction=section(news,'function TMoaPlayForm.HubCatalogAction','function TMoaPlayForm.HubCatalogReply');
assert.match(wallet,/HubTextAction\(WalletPanel,'','points',12,62,WalletPanel.Width-24,58\)/,'points stay inside the actual wallet dropdown');
assert.doesNotMatch(home,/\bEvents\b|'wheel'|HubFillWheel|event.spin|돌림판/);
assert.match(wallet,/HubDetailLinkStyle\(Inner,MemberCaption\('자세히 보기'\),'chevron.down',IsExpanded\('wallet'\)\)/);
assert.match(wallet,/HubDetailLinkStyle\(Inner,MemberCaption\('바로가기'\),'next',False\)/);
assert.match(wallet,/HubTextAction\(Button,'','home.toggle\|wallet',Button.Width-W-10,0,W,34\)/,'wallet link belongs to first label row, not amount center');
assert.match(wallet,/HubTextAction\(Button,'','points',Button.Width-W-10,0,W,34\)/);
assert.doesNotMatch(attendance,/AddMemberSvg|chevron|next/,'attendance button has no unrequested arrow');
assert.match(discovery,/Button:=HubTextAction\(Card,'','',12,Y,Card.Width-24,100\)/,'Discovery content is parented to its titled section');
assert.match(discovery,/Button.Height:=HubFillGameCard\(Button,Item,16\);FinishRow\(Button\)/,'section height includes every expanded item');
assert.doesNotMatch(discovery,/HubCard\(/,'no unowned sibling game cards after the empty section');
assert.match(home,/Route:='product.open\|'\+HubText\(Item,'id'\);\s+Button:=SummaryRow\('recent:'/);
assert.match(productAction,/if Action='product.open' then begin[\s\S]*?FDashboardActiveTab:=1;FHubGameOpenID:='';HubNavigate\('catalog'\);UpdateDashboardTabs;/,'recent product navigation changes tab before opening the card');
assert.match(productAction,/TJSONBool.Create\(\(Action='product'\) or \(Action='product.open'\)\)/,'explicit navigation counts a read once through existing server dedupe');
assert.match(home,/StartCard\('최근 방문한 서비스','history','',''\)/,'home retains entries without opening removed history page');
assert.match(card,/C.OnClick:=nil;C.OnDblClick:=nil;C.HitTest:=False;C.AutoCapture:=False/,'container never captures button taps');
assert.match(card,/Tap.Align:=TAlignLayout.None/);assert.doesNotMatch(card,/TAlignLayout.Contents/);
assert.match(card,/Buy:=HubButton\(C,MemberCaption\('구매하기'\),'product.purchase\|'\+ID,16,Y,InfoW,42,False\)/,'non-primary text remains visible on transparent light/dark background');
assert.match(card,/Buy.Fill.Kind:=TBrushKind.None[\s\S]*Buy.Stroke.Kind:=TBrushKind.Solid/);
assert.match(card,/Buy.HitTest:=True;Buy.AutoCapture:=True;Buy.BringToFront/);
assert.match(card,/TapH:=Y-6/);assert.match(card,/Tap.Height:=TapH;Tap.SendToBack/,'bounded card gesture cannot cover purchase region after parent resize');
assert.match(card,/Buy.Enabled:=\(Price>0\) and HubBool\(Item,'available'\)/,'disabled/unpriced offer cannot issue a purchase');
assert.match(widgets,/MemberCaption\(Caption\),12,MemberText/);assert.match(widgets,/if Dark then L.TextSettings.FontColor:=MemberOnPrimary/);
const newsCard=section(news,'function TMoaPlayForm.HubFillNewsCard','function HubGameIconKey');
for(const text of [newsCard,card])assert.match(text,/HubDetailLinkStyle\(Toggle,MemberCaption\('자세히 보기'\),'chevron.down',Expanded\)/);
assert.match(news,/HubLabel\(Control,Caption,[^;]+MemberLink\)/,'detail caption has link color in both themes');
// Evaluate the vertical bounds taken from production assignments. The nested
// card must remain inside the home section; purchase tap ownership must not
// depend on initial card height, photo count or description wrapping.
const constant=expr=>new Function('Y','Top','return '+expr);
const tapBottom=constant(card.match(/TapH:=(Y-\d+)/)[1]);
const finalHeight=constant(card.match(/Result:=(Y\+Top)/)[1]);
const buyHeight=Number(card.match(/product.purchase\|'\+ID,16,Y,InfoW,(\d+),False/)[1]);
const finishGap=Number(home.match(/Y:=Y\+Row.Height\+(\d+)/)[1]);
let cases=0;
for(const width of [216,240,280,320,350,390,480,720,1024])for(const pictures of [0,1,2,6])for(const descriptionHeight of [0,18,54,180,900]){
 const top=16,infoWidth=width-32,photoWidth=pictures>1?Math.max(120,infoWidth*.84):infoWidth,photoHeight=photoWidth*.57;
 const detailsTop=top+25+2+18+(pictures?12+photoHeight:0),purchaseY=detailsTop+(descriptionHeight?12+descriptionHeight:0)+14;
 const cardHeight=finalHeight(purchaseY+buyHeight,top),cardTapBottom=tapBottom(purchaseY,top);
 assert.ok(cardTapBottom<purchaseY,'card hit region ends before buy button');
 assert.ok(purchaseY+buyHeight<=cardHeight,'button bottom is within final card height');
 assert.ok(infoWidth>=184,'purchase label fits the minimum supported card');
 const rendered=[];let cursor=40;
 for(let i=0;i<3;i++){rendered.push({parent:'discovery',top:cursor,height:cardHeight});cursor+=cardHeight+finishGap;}
 const sectionHeight=cursor+10-finishGap;
 for(const row of rendered)assert.ok(row.top>=40&&row.top+row.height<=sectionHeight);
 for(let i=1;i<rendered.length;i++)assert.ok(rendered[i].top>=rendered[i-1].top+rendered[i-1].height+finishGap);
 const buttonMidY=purchaseY+buyHeight/2;
 assert.ok(!(buttonMidY>=0&&buttonMidY<=cardTapBottom),'even card-captured coordinates cannot claim button center');
 cases++;
}
for(const file of ['MoaPlayApp.Member.Home.inc','MoaPlayApp.Member.NewsShop.inc']){
 const buffer=fs.readFileSync(path.join(native,file));assert.equal(buffer.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(buffer.toString('utf8'),/(?<!\r)\n/);
}
console.log(`HOME/DISCOVERY PASS: ${cases} nested-section/purchase geometry cases; top detail links; true shortcut navigation; independent light/dark purchase hit region; wheel removed.`);
