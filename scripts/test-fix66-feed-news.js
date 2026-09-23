'use strict';
// FIX66 behavior contracts migrated to the intentional FIX68 transparent
// surfaces and inline news reader. The still-shipped glass helper keeps its
// independent lifetime/color guards. Delphi GPU
// output and Android touch dispatch still require the native device build.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const dir=path.join(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(dir,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const section=(s,a,b)=>{const from=s.indexOf(a),to=s.indexOf(b,from+a.length);assert.ok(from>=0&&to>from);return s.slice(from,to);};
const feed=read('MoaPlayApp.Member.Feed.inc'),news=read('MoaPlayApp.Member.NewsShop.inc'),glass=read('MoaPlayGlassCard.pas'),social=read('MoaPlayApp.Member.Social.inc');
const post=section(feed,'function TMoaPlayForm.HubFillPostCard','function TMoaPlayForm.HubQuoteCard');
const card=section(feed,'procedure TMoaPlayForm.HubPostCard','procedure TMoaPlayForm.HubRenderFeed');
assert.doesNotMatch(post,/MediaFirst|ActionY|Copy\(Body,1,240\)/,'restore complete content and its saved order');
assert.match(post,/if HubText\(Post,'imagePosition','after'\)='before' then begin ImageH:=HubPostPhoto/);
assert.match(post,/if HubText\(Post,'imagePosition','after'\)<>'before' then begin ImageH:=HubPostPhoto/);
assert.ok(post.indexOf("Body:=HubText(Post,'body')")<post.indexOf("HubReaction(C,'heart'"));
for(const key of ['heart','bubble','repost','paperplane'])assert.ok(post.includes("HubReaction(C,'"+key+"'"));
assert.match(post,/HubMentionBody\(C,Body,HubArray\(Post,'mentionMembers'\)/);
assert.match(feed,/HubMentionBody\(C,Text,HubArray\(Item,'mentionMembers'\)/);
assert.match(post,/HubVisibleCount\(Post,'likes'\)/);assert.match(post,/HubVisibleCount\(Post,'reposts'\)/);assert.match(post,/HubVisibleCount\(Post,'shares'\)/);
// Bookmark moved into the post menu; the acknowledged mutation remains real.
const menu=section(social,'procedure TMoaPlayForm.HubOpenMore','function TMoaPlayForm.HubPostPhoto');
assert.match(menu,/if HubBool\(Item,'bookmarked'\) then Row\('저장 취소','bookmark','social.save'\) else Row\('저장','bookmark','social.save'\)/);
assert.match(social,/if Action='social.save' then begin[\s\S]*?Body.AddPair\('saved',TJSONBool.Create\(not HubBool\(Item,'bookmarked'\)\)\);Send\('bookmark.set'\)/);
assert.match(card,/C:=HubCard\(100\);C.TagString:='comments\|'/);
assert.match(card,/C.Fill.Kind:=TBrushKind.None;C.Fill.Color:=MemberTransparent;C.XRadius:=12;C.YRadius:=12/);
assert.match(card,/C.Stroke.Kind:=TBrushKind.Solid;C.Stroke.Color:=MemberBorder/);
assert.doesNotMatch(card,/MemberFrostedCard|HubGlassCardStyle|Fill.Kind:=TBrushKind.Bitmap/,'posted photos cannot tint the surrounding panel');
assert.doesNotMatch(card,/C.Position.X:=0|C.Width:=FHubPage.Width|Highlight:=False|FHubY:=FHubY-/);
const filter=section(feed,'procedure TMoaPlayForm.HubRenderFeed','procedure TMoaPlayForm.HubRenderComments');
assert.match(filter,/Caption:=MemberCaption\('최신순'\)/);assert.match(filter,/Action:='feed.sort\|popular'/);
assert.match(filter,/AddMemberSvg\(B,B,'sort'/);assert.doesNotMatch(filter,/Filter\(/);
const newsCard=section(news,'function TMoaPlayForm.HubFillNewsCard','procedure HubGamePhoto');
assert.match(newsCard,/HubContentReadStyle\(C\)/);
assert.doesNotMatch(newsCard,/열람하려면 게시글을 눌러주세요|AddMemberSvg\(C,C,'next'|Copy\(Preview|C.Position.X:=0/);
assert.match(newsCard,/C.TagString:='article\|'\+ID;C.OnClick:=HubActionClick/,'entire news card remains interactive');
assert.match(newsCard,/HubText\(Full,'id'\)<>ID/,'a stale article cannot replace another card');
assert.match(newsCard,/if Assigned\(Full\) then Preview:=HubText\(Full,'body'\)/,'explicit open reveals complete server body inline');
assert.match(newsCard,/HubBodyHeight\(Preview,InfoW,14\)/,'long inline content grows rather than being truncated');
assert.match(newsCard,/MemberCaption\('조회수'\)/);
const newsStyle=section(news,'procedure HubContentReadStyle','function TMoaPlayForm.HubNewsAction');
assert.match(newsStyle,/Card.Fill.Kind:=TBrushKind.None;Card.XRadius:=12;Card.YRadius:=12/);
assert.match(newsStyle,/Card.Stroke.Kind:=TBrushKind.Solid;Card.Stroke.Color:=MemberBorder/);
assert.doesNotMatch(newsStyle,/MemberFrostedCard|HubGlassCardStyle|HitTest|OnClick/);
const newsAction=section(news,'function TMoaPlayForm.HubNewsAction','function TMoaPlayForm.HubNewsReply');
assert.match(newsAction,/FHubNewsOpenID:=ID/);assert.match(newsAction,/Body.AddPair\('countView',TJSONBool.Create\(True\)\)/);
assert.doesNotMatch(newsAction,/HubNavigate\('article'/,'news no longer routes into a separate article page');
const article=section(news,'procedure TMoaPlayForm.HubRenderArticle','procedure TMoaPlayForm.HubRenderGame');
assert.match(article,/HubRenderNews\(HubCached\('news'\)\)/,'legacy article snapshots resolve to the inline reader');
assert.doesNotMatch(article,/MemberFrostedCard|FHubSelected|HubCard\(/);
const quote=section(feed,'function TMoaPlayForm.HubQuoteCard','procedure TMoaPlayForm.HubPostCard');
assert.match(quote,/HubBool\(Quote,'unavailable'\)/);assert.match(quote,/ReadOnlyTree\(C\)/);
assert.match(quote,/C.TagString:='quote.open\|'/);assert.match(post,/SelfQuote/);
// The optional glass helper remains passive and bounded for any other caller;
// transparent feed/news cards above explicitly cannot call it.
assert.match(glass,/const SampleSize=64/);assert.match(glass,/Bitmap:=Card.Fill.Bitmap.Bitmap/);
assert.match(glass,/Bitmap.SetSize\(SampleSize,SampleSize\)/);assert.match(glass,/if HasPhoto then FrostedBlur\(Bitmap\)/);
assert.match(glass,/finally Photo.Free;end/);assert.match(glass,/finally Bitmap.Unmap\(Data\);end/);
assert.doesNotMatch(glass,/\.OnClick\s*:=|\.OnMouse\w*\s*:=|\.OnPaint\s*:=|\.HitTest\s*:=|\.AutoCapture\s*:=|TTimer\.Create|TBlurEffect|Create\(Card\)|MakeScreenshot|\.Width\s*:=|\.Height\s*:=|\.SetBounds\(/);
assert.match(glass,/Card.Fill.Bitmap.WrapMode:=TWrapMode.TileStretch;Card.Fill.Kind:=TBrushKind.Bitmap/);
const mixBody=section(glass,'function FrostedMix','procedure MemberFrostedCard');
const expr=name=>{const m=mixBody.match(new RegExp('\\b'+name+':=([^;]+);'));assert.ok(m,name);return m[1]
 .replaceAll('Cardinal(','Number(').replaceAll(' shr ',' >>> ').replaceAll(' shl ',' << ').replaceAll(' and ',' & ').replaceAll(' or ',' | ').replaceAll(' div ',' / ').replace(/\$([A-Fa-f\d]+)/g,'0x$1');};
const mix=Function('FromColor','ToColor','Weight',`const R=Math.floor(${expr('R')}),G=Math.floor(${expr('G')}),B=Math.floor(${expr('B')});return (${expr('Result')})>>>0;`);
for(const c of [0,0xffffff,0xdeadbe,0x1a2b3c]){assert.equal(mix(c,0x987654,0)&0xffffff,c);assert.equal(mix(c,0x987654,255)&0xffffff,0x987654);}
const linear=x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4;};
const rgb=c=>[(c>>>16)&255,(c>>>8)&255,c&255],lum=c=>{const [r,g,b]=rgb(c).map(linear);return .2126*r+.7152*g+.0722*b;};
const contrast=(a,b)=>(Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);
const palette=read('MoaPlayMemberTheme.pas');
const colors=name=>{const s=palette.slice(palette.indexOf('function '+name+':TAlphaColor;',palette.indexOf('implementation')));const m=s.match(/begin if DarkValue then Result:=\$([\dA-F]+) else Result:=\$([\dA-F]+);end;/);assert.ok(m,name);return m.slice(1).map(x=>parseInt(x,16)>>>0);};
const [darkSurface,lightSurface]=colors('MemberSurface'),[darkSoft,lightSoft]=colors('MemberSoft'),[darkMuted,lightMuted]=colors('MemberMuted'),[darkBG,lightBG]=colors('MemberBackground');
const tintConfig=glass.match(/if MemberDark then begin Tint:=(\d+);Alpha:=(\d+);end else begin Tint:=(\d+);Alpha:=(\d+);end/);assert.ok(tintConfig);
let cases=0;
for(const [surface,soft,muted,bg,tint,alpha] of [[darkSurface,darkSoft,darkMuted,darkBG,+tintConfig[1],+tintConfig[2]],[lightSurface,lightSoft,lightMuted,lightBG,+tintConfig[3],+tintConfig[4]]]){
 for(let r=0;r<256;r+=17)for(let g=0;g<256;g+=17)for(let b=0;b<256;b+=17)for(const sheen of [6,24]){
  const photo=(r<<16)|(g<<8)|b;
  const tinted=mix(mix(photo,surface,tint),soft,sheen),display=mix(bg,tinted,alpha);
  assert.ok(contrast(muted,display)>=4.5,'muted text remains readable over the full photo gamut');cases++;
 }
}
// Read actual action width bounds, evaluate using the compact card width.
const row=post.match(/W:=Min\(Max\((\d+),(\d+)\+[\s\S]*?Max\((\d+),\(C.Width-(\d+)\)\/(\d+)\)\);/);assert.ok(row);
for(let viewport=240;viewport<=1024;viewport+=4){const width=viewport-40;for(const textWidth of [0,12,40,80,200]){
 const w=Math.min(Math.max(+row[1],+row[2]+textWidth),Math.max(+row[3],(width-row[4])/row[5]));
 assert.ok(w>=44);assert.ok(10+4*w<=width,'four reaction/share targets do not overlap or spill outside the card');
}}
for(const name of ['MoaPlayGlassCard.pas','MoaPlayApp.Member.Feed.inc','MoaPlayApp.Member.NewsShop.inc']){
 const bytes=fs.readFileSync(path.join(dir,name));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);assert.doesNotMatch(bytes.toString('utf8'),/(?<!\r)\n/);
}
console.log(`FIX66→68 FEED/NEWS PASS: transparent rounded cards, complete inline news, preserved order/actions/privacy/quotes, ${cases} retained glass-helper color cases and four-action geometry (Delphi/device not run).`);
