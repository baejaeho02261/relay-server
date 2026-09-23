'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.join(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(root,n),'utf8').replace(/^\uFEFF/,'');
const source=read('MoaPlayDiscoverCard.pas'),news=read('MoaPlayApp.Member.NewsShop.inc'),theme=read('MoaPlayMemberTheme.pas');
const body=source.slice(source.indexOf('function DiscoverCoverRect',source.indexOf('implementation')),source.indexOf('procedure DiscoverBlur'));
function buildCrop(text){
 const expr=name=>text.match(new RegExp(name+':=([^;]+);'))[1];
 const rect=[...text.matchAll(/Result:=RectF\(([\s\S]*?)\);/g)].at(-1)[1];
 return new Function('SourceWidth','SourceHeight','TargetWidth','TargetHeight',`const Max=Math.max,Min=Math.min;const Scale=${expr('Scale')};const CropWidth=${expr('CropWidth')};const CropHeight=${expr('CropHeight')};return [${rect}];`);
}
function checkCrop(crop){
 let count=0;
 for(const sw of [96,160,384,960,2400])for(const sh of [80,384,600,1800])for(const w of [92,106,136,192,244,400])for(const h of [115,132,208,320,520]){
  const r=crop(sw,sh,w,h),cw=r[2]-r[0],ch=r[3]-r[1];
  assert.ok(r[0]>=-.001&&r[1]>=-.001&&r[2]<=sw+.001&&r[3]<=sh+.001,'crop never samples outside image');
  assert.ok(Math.abs(cw/ch-w/h)<1e-6,'cover preserves aspect ratio');
  assert.ok(Math.abs((r[0]+r[2])/2-sw/2)<1e-6&&Math.abs((r[1]+r[3])/2-sh/2)<1e-6,'centered crop');
  assert.ok(Math.abs(cw-sw)<1e-6||Math.abs(ch-sh)<1e-6,'maximal cover crop');count++;
 }
 return count;
}
const cropSamples=checkCrop(buildCrop(body));
assert.throws(()=>checkCrop(buildCrop(body.replace('Scale:=Max','Scale:=Min').replace('constUnused',''))),'contain/stretch regression must fail');
// Extract the actual FIX65 dense grid formulas. Cover/reveal gestures remain
// the same regression contract while columns/insets changed by request.
const catalog=news.slice(news.indexOf('procedure TMoaPlayForm.HubRenderCatalog'),news.indexOf('procedure TMoaPlayForm.HubRenderArticle'));
assert.match(catalog,/Columns:=3;if FHubPage.Width<280 then Columns:=2/);
assert.match(catalog,/C\.TouchScope:=FHubTouch/);assert.match(catalog,/HubFillGameCard\(C,TJSONObject\(V\),0\)/);
const assigned=(s,n)=>{const m=s.match(new RegExp('\\b'+n+':=([^;]+);'));assert.ok(m,n);return m[1];};
const expression=(s,vars)=>Function(...Object.keys(vars),'Max','Min',`return (${s});`)(...Object.values(vars),Math.max,Math.min);
const inset=Number(assigned(catalog,'Inset')),gap=Number(assigned(catalog,'Gap'));
const cardWidth=assigned(catalog,'CardWidth').replaceAll('FHubPage.Width','Width'),cardHeight=assigned(catalog,'CardHeight');
const resize=source.slice(source.indexOf('procedure TMoaPlayDiscoverCard.Resize;'),source.indexOf('procedure TMoaPlayDiscoverCard.PreparePhoto;'));
const initialGlass=assigned(resize,'GlassHeight'),titleExpr=assigned(resize,'TitleHeight');
function glassHeight(height){return Math.min(expression(initialGlass,{Height:height}),Math.max(1,height-8));}
let layouts=0;
for(let width=240;width<=1200;width+=4)for(const count of [1,2,3,7,20]){
 const columns=width<280?2:3,cw=expression(cardWidth,{Width:width,Inset:inset,Gap:gap,Columns:columns}),ch=expression(cardHeight,{CardWidth:cw});
 assert.ok(cw>=90&&ch>=112.5,'small phone targets remain large enough to tap');
 for(let i=0;i<count;i++){
  const x=inset+(i%columns)*(cw+gap),y=Math.floor(i/columns)*(ch+gap);
  assert.ok(x>=inset&&x+cw<=width-inset+.001);assert.ok(y+ch<Math.ceil(count/columns)*(ch+gap));
  const gh=glassHeight(ch),title=expression(titleExpr,{GlassHeight:gh}),desc=Math.max(16,gh-title-20);
  assert.ok(12+title+desc<=gh-3.999,'frost text stays inside the rounded enclosure');
  assert.ok(cw-8-16>=66,'small titles retain usable width');
 }layouts++;
}
// Frost is sampled from the displayed crop, never from a differently aligned
// upload. Blur work is small, lazy and absent from the paint/animation path.
assert.match(source,/Source:=RectF\(FGlass.Position.X\*ScaleX,FGlass.Position.Y\*ScaleY/);
assert.match(source,/Bitmap.SetSize\(64,Max\(1,Round\(64\*FGlass.Height/);
assert.match(source,/if FBlurReady then Exit/);assert.match(source,/if Value then PrepareGlass/);
assert.match(source,/Bitmap.Map\(TMapAccess.ReadWrite,Data\)/);assert.match(source,/Horizontal\[Y\*W\+X\]/);assert.match(source,/Data.SetPixel/);assert.match(source,/finally Bitmap.Unmap\(Data\)/);
assert.doesNotMatch(source,/TBlurEffect|TFloatAnimation|TTimer|procedure .*\.Paint/);
assert.match(source,/Scale:=Min\(MemberDisplayScale\(Self\),1024\/Max\(Width,Height\)\)/);
assert.doesNotMatch(source,/FPhoto\.(SetSize|Clear|Canvas)|MemberLoadBitmap\(Fill/);
// Native click ownership stays in the proven base class. Revealing a title
// may not synthesize navigation or intercept the parent's canceled scroll.
assert.match(source,/class\(TMoaPlayTapRectangle\)/);assert.doesNotMatch(source,/OnClick\s*:=|OnClick\(|HubActionClick|procedure .*\.Click/);
assert.match(source,/FDragging:=True;FHover:=False;Reveal\(False\)/);assert.match(source,/not FDragging and not \(ssLeft in Shift\)/);
assert.match(source,/FGlass.Visible:=False/);assert.match(source,/Result.HitTest:=False/);assert.match(source,/FTint.HitTest:=False/);
assert.match(read('MoaPlayMemberTouch.pas'),/Repaint;if not Rejected then inherited Click/);
// Android may hand scrolling to its viewport without a matching child Up.
// The scope must dispatch the derived cancellation, which removes glass now.
const touch=read('MoaPlayMemberTouch.pas');
assert.match(touch,/procedure CancelTouch; virtual;/);
assert.match(source,/procedure CancelTouch; override;/);
assert.match(touch,/FPressedControl\.CancelTouch/);
const cancel=source.slice(source.indexOf('procedure TMoaPlayDiscoverCard.CancelTouch;'),source.indexOf('procedure TMoaPlayDiscoverCard.HoverEnter'));
assert.match(cancel,/begin\s+inherited;/);
assert.match(cancel,/FDragging:=FDragging or FPressed;FPressed:=False;FHover:=False/);
assert.match(cancel,/if Assigned\(FGlass\) then Reveal\(False\)/);
// Extract the shipped state transition instead of relying on MouseUp delivery.
const assignments=cancel.match(/FDragging:=([^;]+);FPressed:=([^;]+);FHover:=([^;]+);/);
const cancellation=new Function('FDragging','FPressed','FHover',`FDragging=${assignments[1].replace(' or ',' || ')};FPressed=${assignments[2]};FHover=${assignments[3]};return {FDragging,FPressed,FHover};`.replaceAll('False','false'));
for(const dragging of [false,true])for(const pressed of [false,true])for(const hover of [false,true]){
 const state=cancellation(dragging,pressed,hover);
 assert.equal(state.FPressed,false);assert.equal(state.FHover,false);
 assert.equal(state.FDragging,dragging||pressed,'cancel keeps an in-flight gesture from becoming a hover');
}
assert.match(source,/FPressed:=True;FDragging:=False;FHover:=False;Reveal\(True\)/,'fresh down releases the old cancellation latch');
assert.match(source,/FPressed:=False;FDragging:=False;Reveal\(FHover\)/,'release clears the latch');

// UI and native system surfaces must match the user's exact RGB values.
assert.match(theme,/function MemberBackground:TAlphaColor;\s*begin if DarkValue then Result:=\$FF0C0F14 else Result:=\$FFFFFFFF;end;/);
assert.match(theme,/function MemberPrimary:TAlphaColor;\s*begin Result:=\$FF0866DB/);
assert.match(read('MoaPlaySystemBars.pas'),/BarColor:=-15986924;Appearance:=0/);
for(const name of ['discover','paperplane','user.add','chevron.down'])assert.ok(read('MoaPlayMemberSvg.pas').includes("Name = '"+name+"'"));
console.log(`FIX64 DISCOVER PASS: ${cropSamples} source-formula cover crops, ${layouts} responsive grids, lazy bounded image blur, native scroll/tap ownership, exact palettes/system bars.`);
