'use strict';
// Native source/geometry regression checks. These are not a Delphi build or a device rendering test.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const dir=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(dir,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const routine=(s,name)=>{const list=[...s.matchAll(/^(?:procedure|function)\s+([\w.]+)/gm)],i=list.findIndex(m=>m[1]===name);assert.ok(i>=0,name);return s.slice(list[i].index,list[i+1]?.index??s.length);};
const feed=read('MoaPlayApp.Member.Feed.inc'),social=read('MoaPlayApp.Member.Social.inc'),compose=read('MoaPlayApp.Member.Compose.inc'),tools=read('MoaPlayApp.Member.PostTools.inc');
const card=routine(feed,'TMoaPlayForm.HubPostCard'),photo=routine(social,'TMoaPlayForm.HubPostPhoto'),fill=routine(feed,'TMoaPlayForm.HubFillPostCard'),render=routine(compose,'TMoaPlayForm.HubRenderCompose');
assert.doesNotMatch(feed,/MemberFrostedCard\(/,'post photographs cannot alter the surrounding transparent card');
assert.match(card,/Fill.Kind:=TBrushKind.None/);assert.match(card,/XRadius:=12;C.YRadius:=12/);assert.match(card,/Stroke.Kind:=TBrushKind.Solid/);
assert.match(fill,/HubBool\(Post,'own'\)[\s\S]*AudienceText:=Text/,'audience disclosure is only populated for the owner');
assert.match(fill,/'post.menu','more\|post\|'/);assert.doesNotMatch(fill,/'more','more\|post\|'/);
for(const icon of ['heart','bubble','repost','paperplane'])assert.ok(fill.includes("HubReaction(C,'"+icon+"'"));
assert.match(fill,/HubVisibleCount\(Post,'shares'\)/);
assert.match(photo,/Frame.Position.X;W:=Frame.Width/,'tap region follows the actual fitted bitmap, not its reserved maximum width');
assert.match(render,/RightEdge:=Media.Position.X\+Media.Width/,'attachment dismissal uses the same fitted bounds');
assert.match(render,/Max\(0,RightEdge-44\)/);
assert.match(render,/Inset:=16;if Parent=FHubComposeTail then Inset:=0/,'nested poll fields align with title/body outer edges');
assert.match(render,/Parent.Width-Inset\*2,64/);assert.match(render,/Result.Fill.Kind:=TBrushKind.None/);assert.match(render,/Result.Stroke.Kind:=TBrushKind.Solid/);
const menu=routine(social,'TMoaPlayForm.HubOpenMore');
for(const item of ['컷아웃 스티커 만들기','보관','좋아요 수 숨기기','공유 횟수 숨기기','댓글 기능 해제','수정','미리 보기 조정','인사이트 보기','기본 그리드에 고정'])assert.ok(menu.includes(item),item);
assert.match(menu,/if Own then begin[\s\S]*post.tool.archive[\s\S]*post.tool.pin/);
const sheet=routine(tools,'TMoaPlayForm.HubPostToolsSheet');assert.doesNotMatch(sheet,/FreeAndNil\(FHubOverlay\)/,'opening a submenu must not free its active click sender');assert.match(sheet,/Visible:=False/);assert.match(sheet,/Scope.BindScroll\(Scroll\)/);
const actions=routine(tools,'TMoaPlayForm.HubPostToolAction');assert.match(actions,/if not HubBool\(Item,'own'\) then Exit/);assert.match(actions,/revision/);assert.match(actions,/Anchor.Enabled:=False/);assert.match(actions,/HubSendSocial\('post.share',Body\)/);assert.match(actions,/HubOpenSticker\(/);
assert.doesNotMatch(actions,/AndroidToast\('(?:공유했|저장했|스티커를 만들)/,'only a successful server acknowledgement may report completion');
const replies=routine(tools,'TMoaPlayForm.HubPostToolsReply');assert.match(replies,/FHubOverlay.TagString<>'postshare\|'/);assert.match(replies,/FHubOverlay.TagString<>'post.insights\|'/);assert.match(replies,/OnKeyDown:=HubPostShareSearchKeyDown/);
// Evaluate the production fitting algorithm over portrait screenshots, landscapes and extremes.
const media=read('MoaPlayApp.Member.Media.inc'),fit=routine(media,'HubImageNatural');
assert.match(fit,/Scale:=Min\(Max\(1,W\)\/Frame.Fill.Bitmap.Bitmap.Width,Max\(1,MaxHeight\)\/Frame.Fill.Bitmap.Bitmap.Height\)/);
let cases=0;
for(const width of [200,240,280,320,360,412,600])for(const [iw,ih] of [[1080,2340],[720,1920],[1440,3200],[1920,1080],[800,800],[100,4000],[4000,100]]){
 const scale=Math.min(Math.max(1,width)/iw,Math.max(1,520)/ih),w=iw*scale,h=ih*scale,x=12+(width-w)/2,right=x+w,button=Math.max(0,right-44);
 assert.ok(h>0&&h<=520.001&&w>0&&w<=width+.001);assert.ok(right<=width+12+.001);
 assert.ok(Math.abs(button+44-right)<.001,'dismissal target ends exactly at the fitted media right edge');
 cases++;
}
const expr=fill.match(/W:=Min\(Max\((\d+),(\d+)\+[\s\S]*?Max\((\d+),\(C.Width-(\d+)\)\/(\d+)\)\);/);assert.ok(expr);
for(let width=200;width<=1000;width+=8)for(const textWidth of [0,12,40,80,200]){
 const w=Math.min(Math.max(+expr[1],+expr[2]+textWidth),Math.max(+expr[3],(width-expr[4])/expr[5]));
 assert.ok(w>=44);assert.ok(10+w*4<=width,'all four independent action targets fit without overlap');cases++;
}
for(const name of ['MoaPlayApp.Member.Feed.inc','MoaPlayApp.Member.Social.inc','MoaPlayApp.Member.Compose.inc','MoaPlayApp.Member.PostTools.inc']){
 const bytes=fs.readFileSync(path.join(dir,name));assert.equal(bytes.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(bytes.toString('utf8'),/(?<!\r)\n/);
}
console.log(`FIX68 native feed PASS: ${cases} media/action geometry cases, transparent cards and fields, owner controls, real recipient/share flow, safe submenu lifetime. Delphi/device build not executed.`);
