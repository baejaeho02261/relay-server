'use strict';
// Source and geometry checks supplement server mention tests. They do not execute FMX.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(base,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const widgets=read('MoaPlayApp.Member.Widgets.inc');
const compose=read('MoaPlayApp.Member.Compose.inc'),feed=read('MoaPlayApp.Member.Feed.inc'),links=read('MoaPlayMentionLinks.pas'),tools=read('MoaPlayApp.Member.PostTools.inc');
// The platform text layout can ignore color attributes. Render actual colored
// glyphs clipped to the very same regions used by the touch targets.
assert.match(links,/FPaintLayout.Font.Assign\(Source.Font\);FPaintLayout.Color:=MemberLink/);
assert.match(links,/FPaintLayout.Text:=Source.Text;FPaintLayout.WordWrap:=Source.WordWrap/);
assert.match(links,/FPaintLayout.MaxSize:=Source.MaxSize/);
assert.match(links,/Canvas.IntersectClipRect\(LocalRect\)/);
assert.match(links,/FInk.FPaintLayout.RenderLayout\(Canvas\)/);
assert.match(links,/if not Assigned\(Ink\) then begin Ink:=TMentionLinkInk.Create\(Parent\);Ink.Configure\(Layout\);end/,'one shared shaped layout per body');
assert.equal((links.match(/TTextLayoutManager.DefaultTextLayout.Create/g)||[]).length,1);
assert.match(links,/FInk.FreeNotification\(Self\)/);assert.match(links,/AComponent=FInk\) then FInk:=nil/);
assert.match(links,/Tap:=TMentionLinkOverlay.Create\(Parent\);Tap.Parent:=Host/,'text owns links but does not block their hit testing');
assert.match(links,/Origin:=Host.AbsoluteToLocal\(Parent.LocalToAbsolute\(PointF\(0,0\)\)\)/);
assert.match(links,/Lookup.TryGetValue\(Token.Handle,ID\)/,'no unauthorized text becomes a profile route');
assert.match(links,/Tap.TouchScope:=Scope;Tap.TagString:=ActionPrefix\+ID/);
assert.match(links,/finally Layout.EndUpdate;end;[\s\S]*Regions:=Layout.RegionForRange\(Range\)/);
assert.doesNotMatch(links,/Underline|fsUnderline|Members.Free|Parent.Free/);
assert.match(feed,/CanOpen and \(Node is TRectangle\)[\s\S]*Node.TagString.StartsWith\('member\|'/,'quoted links remain available only when their source is available');
const location=links.match(/Tap.SetBounds\((Origin.X\+Bounds.Left),(Origin.Y\+Bounds.Top),Bounds.Width,Bounds.Height\)/);
const paintOrigin=links.match(/TMatrix.CreateTranslation\((-FRegionOrigin.X),(-FRegionOrigin.Y)\)\*Matrix/);
assert.match(links,/FPaintLayout.TopLeft:=Source.TopLeft/);
assert.ok(location);assert.ok(paintOrigin);
const place=location.slice(1).map(s=>Function('Origin','Bounds','return '+s));
const paint=paintOrigin.slice(1).map(s=>Function('FRegionOrigin','return '+s));
let cases=0;
for(const Origin of [{X:16,Y:32},{X:12,Y:8},{X:0,Y:0},{X:44,Y:-350}])
 for(const TopLeft of [{X:0,Y:0},{X:2,Y:3}])
  for(const Bounds of [{Left:0,Top:0,Width:26,Height:18},{Left:50,Top:22,Width:80,Height:18},{Left:0,Top:44,Width:42,Height:18}]){
   const actual=place.map(f=>f(Origin,Bounds)),ink=paint.map((f,i)=>f({X:Bounds.Left,Y:Bounds.Top})+(i?TopLeft.Y:TopLeft.X));
   assert.equal(actual[0]+ink[0],Origin.X+TopLeft.X,'the overlay and base text have the same glyph origin');
   assert.equal(actual[1]+ink[1],Origin.Y+TopLeft.Y,'wrapped lines and scroll positions cannot displace glyphs');cases++;
  }
// One compose card, a plain title placeholder, no duplicated question field,
// and an actual question supplied to the unchanged server poll contract.
assert.match(compose,/C:=HubCard\(400\);C.Fill.Kind:=TBrushKind.None;C.Fill.Color:=MemberTransparent;C.XRadius:=12;C.YRadius:=12/);
assert.match(compose,/C.Stroke.Kind:=TBrushKind.Solid;C.Stroke.Color:=MemberBorder/);
assert.match(compose,/Box.Stroke.Kind:=TBrushKind.None;FHubComposeBody:=Box/);
assert.match(compose,/Result.FloatingLabel:=False;Result.FixedLabel:=False/);
assert.match(compose,/FHubEdits\[0\]:=EditAt\(C,Title,'제목을 작성하세요',16,90\)/);
assert.doesNotMatch(compose,/FHubEdits\[1\]:=|투표 질문을 작성하세요|PromptText:=MemberCaption\('이야기를 작성하세요'\)/);
assert.match(compose,/PromptText:=MemberCaption\('서로를 존중하는 글/);
assert.match(compose,/Question:=Trim\(FHubMemo.Text\)/);assert.match(compose,/Question:=Trim\(FHubEdits\[0\].Text\)/);
assert.match(compose,/HubNumber\(Existing,'total'\)>0\)\) then Exit\(Existing.ToJSON\)/);
assert.match(compose,/Obj.AddPair\('question',Question\)/);
const cut=compose.match(/N:=(Min\((\d+),Length\(Question\)\))/);assert.ok(cut);
const count=Function('Question','return '+cut[1].replace('Min','Math.min').replace('Length(Question)','Question.length'));
for(const Question of ['안녕하세요','a'.repeat(89)+'🙂','a'.repeat(88)+'🙂끝','🦊'.repeat(60),'나'.repeat(110)]){
 let n=count(Question);if(n>0&&n<Question.length&&Question.charCodeAt(n-1)>=0xd800&&Question.charCodeAt(n-1)<=0xdbff)n--;
 const result=Question.slice(0,n).trim();assert.ok(result.length<=Number(cut[2]));assert.equal(result.isWellFormed(),true);cases++;
}
assert.match(widgets,/function HubBodyHeight\(const Text:string; Width,FontSize:Single; Bold:Boolean=False\)/);
assert.match(widgets,/if Bold or \(FontSize>=17\) then Layout.Font.Style:=\[TFontStyle.fsBold\]/);
assert.match(feed,/HubBodyHeight\(Title,C.Width-32,16,True\)/);
assert.match(feed,/HubBodyHeight\(HubText\(Poll,'question'\),C.Width-32,14,True\)/);
assert.match(feed,/AudienceIcon:='closefriends'/);assert.match(tools,/Choice\('친한 친구만','closefriends','CLOSE_FRIENDS'/);
assert.match(feed,/if HubBool\(Post,'own'\) then begin[\s\S]*AudienceText:=Text/);
assert.match(feed,/AudienceText,C.Width-36-AudienceW,HeaderTop\+3,AudienceW-16,18/);
assert.match(feed,/'post.menu','more\|post\|'.*C.Width-52,HeaderTop-10,44,44/);
for(const headerTop of [16,34]){
 const nicknameCenter=headerTop+3+18/2,audienceCenter=headerTop+3+18/2,menuCenter=headerTop-10+44/2;
 assert.equal(nicknameCenter,audienceCenter);assert.equal(nicknameCenter,menuCenter);cases++;
}
for(const width of [280,320,360,412,480,600,1000]){
 const outer=width-40,body=outer-32,poll=body-24;
 assert.ok(poll>100&&poll<body);assert.equal((body-poll)/2,12);cases++;
}
for(const name of ['MoaPlayApp.Member.Compose.inc','MoaPlayApp.Member.Feed.inc','MoaPlayApp.Member.PostTools.inc','MoaPlayMentionLinks.pas']){
 const bytes=fs.readFileSync(path.join(base,name));assert.equal(bytes.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(bytes.toString('utf8'),/(?<!\r)\n/);
}
console.log(`FIX69 feed/mentions PASS: ${cases} glyph/geometry/UTF-16 cases, explicit color paint, sibling touch ownership, authorized links, single compose surface and poll contract. Delphi/device execution remains required.`);
