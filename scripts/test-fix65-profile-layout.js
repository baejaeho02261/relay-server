'use strict';
// Check real native geometry, cropping and the public/private profile boundary.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(root,n),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const page=read('MoaPlayApp.Member.MyPage.inc'),gallery=read('MoaPlayApp.Member.ProfileGallery.inc');
function part(s,a,b){const start=s.indexOf(a),end=s.indexOf(b,start+a.length);assert.ok(start>=0&&end>start,`missing ${a}`);return s.slice(start,end);}
function evaluate(expr,scope){
 const code=expr.replace(/\bMax\b/g,'Math.max').replace(/\bMin\b/g,'Math.min').replace(/(?:C|Parent|FHubPage)\.Width/g,'Width');
 assert.match(code,/^[\w\s.()+*/,-]+$/);return Function(...Object.keys(scope),`return (${code})`)(...Object.values(scope));
}
function layout(source){
 const stats=part(source,'procedure TMoaPlayForm.HubProfileStat','function TMoaPlayForm.HubProfileDetails');
 assert.match(stats,/HubCount\(Value\),18,MemberText,TTextAlign.Leading/,'counts share the captions left edge');
 assert.match(stats,/MemberCaption\(Caption\),12,MemberText,TTextAlign.Leading/,'captions align left');
 assert.match(stats,/profile-stat\|/,'live counter identities survive');
 const own=part(source,'procedure TMoaPlayForm.HubRenderMe','procedure TMoaPlayForm.HubRenderMember');
 const size=own.match(/W:=([^;]+);/)[1];
 const origin=own.match(/StatX:=([^;]+);/)[1];
 const calls=[...own.matchAll(/HubProfileStat\(C,'([^']+)','([^']+)',[^\n]+?,(StatX(?:\+W(?:\*2)?)?),35,W,HubText\(Profile,'id'\),(True|False)\)/g)];
 assert.equal(calls.length,3);
 const actions=part(source,'procedure TMoaPlayForm.HubProfileButtons','procedure TMoaPlayForm.HubProfileTabs');
 const ownButtons=part(actions,'if Own then begin','end else begin'),buttonSize=ownButtons.match(/ButtonW:=([^;]+);/)[1];
 const targets=[...ownButtons.matchAll(/HubButton\(Parent,(?:MemberCaption\('[^']+'\)|''),'([^']+)',([^,]+),Y,([^,]+),(\d+),False\)/g)];
 assert.deepEqual(targets.map(x=>x[1]),['profile','profile.share','profile.people']);
 for(const Width of [240,280,320,360,390,412,480,600,800,1024]){
  const W=evaluate(size,{Width}),StatX=evaluate(origin,{Width,W});let last=98;assert.equal(StatX+3*W,Width-16);
  for(const c of calls){const x=evaluate(c[3],{W,StatX});assert.equal(c[4],'True');assert.ok(x>=last,'stats overlap avatar or each other');assert.ok(x+W<=Width-16+0.001);last=x+W;}
  const ButtonW=evaluate(buttonSize,{W:Width});last=0;
  for(const t of targets){const x=evaluate(t[2],{W:Width,ButtonW}),w=evaluate(t[3],{W:Width,ButtonW});assert.ok(x>=last);assert.ok(x+w<=Width-16);assert.ok(w>=38);last=x+w;}
 }
 assert.match(own,/nickname[^\n]+,StatX\+3,16,Max\(1,W-6\),18,11/,'small nickname sits directly above the first count');
 const tabs=part(source,'procedure TMoaPlayForm.HubProfileTabs','procedure TMoaPlayForm.HubRenderMe');
 assert.match(tabs,/Keys:array\[0\.\.3\] of string=\('posts','comments','reposts','tagged'\)/);
 assert.match(tabs,/Icons:array\[0\.\.3\] of string=\('grid','bubble','repost','user.tagged'\)/);
 assert.match(tabs,/HubIconButton\(Parent,Icons\[I\],Target,I\*W\/4,Y,W\/4,48\)/);
 assert.doesNotMatch(tabs,/HubLabel|HubTextAction/,'tabs show icons only');
 const identity=part(source,'procedure TMoaPlayForm.HubProfileIdentityRow','procedure TMoaPlayForm.HubProfileStat');
 assert.match(identity,/MemberCaption\('추가'\)/);assert.match(identity,/Pill.SetBounds\(0,3,58,26\)/);
 assert.equal((identity.match(/Pill.Fill.Kind:=TBrushKind.None;Pill.Stroke.Kind:=TBrushKind.Solid/g)||[]).length,2,'both compact pills retain transparent outlined backgrounds');
 assert.match(actions,/'user.add.solid'/);
 assert.doesNotMatch(source,/HubProfileNoteBubble|profile\.note|메모 남기기/,'profile notes are completely removed');
}
layout(page);
assert.throws(()=>layout(page.replace('HubCount(Value),18,MemberText,TTextAlign.Leading','HubCount(Value),18,MemberText,TTextAlign.Trailing')),'count reverting to right must fail');
assert.throws(()=>layout(page.replace('22+ButtonW,Y,ButtonW','16,Y,ButtonW')),'profile action overlap must fail');
assert.throws(()=>layout(page.replace(/,True\);\n  HubProfileStat/,',False);\n  HubProfileStat')),'stat press feedback is required');
function publicBoundary(source){
 const member=part(source,'procedure TMoaPlayForm.HubRenderMember','procedure TMoaPlayForm.HubRenderHistory');
 assert.match(member,/if HubBool\(Data,'profilePostsHidden'\) then HubEmpty/);
 assert.match(member,/HubProfileButtons\(C,Profile,Own,HubBool\(Data,'isFollowing'\),Y\)/);
 assert.doesNotMatch(source,/'member.badges\|'/,'peer badges moved to the global header');
 const details=part(source,'function TMoaPlayForm.HubProfileDetails','procedure TMoaPlayForm.HubProfileButtons');
 assert.match(details,/HubBool\(Profile,'showVerification'\).*DEVICE_AUTHENTICATED/);
 assert.doesNotMatch(details,/Meta Verified|verified.check|TJSONBool.Create\(True\)|phone|IMEI|deviceId/i);
 assert.match(details,/Count>=5 then Break/);assert.match(details,/Count>=3 then Break/);
 assert.match(details,/URL.StartsWith\('https:\/\/'\) or URL.StartsWith\('http:\/\/'\)/);
 assert.match(details,/'web\|'/);assert.match(details,/'member\|'/);
}
publicBoundary(page);assert.throws(()=>publicBoundary(page.replace("if HubBool(Data,'profilePostsHidden') then HubEmpty","if False then HubEmpty")));
function grid(source){
 const width=source.match(/W:=(Max\(1,\(FHubPage.Width-4\)\/3\));H:=([^;]+);/);assert.ok(width);
 assert.match(source,/C.ClipChildren:=True/);assert.match(source,/HubTextAction\(FHubPage,'','comments\|\'\+ID/);
 assert.match(source,/if Kind='reposts'/);assert.match(source,/Kind='tagged'/);assert.match(source,/HubPaging\(Data\)/);
 assert.match(source,/Encoded:=HubText\(Item,'imageThumb'\)/);assert.match(source,/not HubBool\(Quote,'unavailable'\)/);
 assert.match(source,/PreviewPosition:=HubText\(Item,'previewPosition','center'\)/);
 assert.match(source,/PreviewPosition='top' then CropY:=0/);assert.match(source,/PreviewPosition='bottom' then CropY:=H-Frame.Fill.Bitmap.Bitmap.Height\*Scale/);
 assert.match(source,/HubBool\(Item,'pinned'\) then Icon:='pin'/);
 assert.match(source,/Scale:=Max\(W\/Frame.Fill.Bitmap.Bitmap.Width,H\/Frame.Fill.Bitmap.Bitmap.Height\)/);
 assert.doesNotMatch(source,/\.Resize\(|Resample|FMember.Request|HubFetch|HubPostPhoto\(/,'gallery cannot resample original pixels, fetch on render or open a lightbox');
 for(const Width of [240,280,320,390,432,600,1024])for(const count of [1,2,3,4,12,20,30]){
  const W=evaluate(width[1],{Width}),H=evaluate(width[2],{W});let previous=null;
  for(let i=0;i<count;i++){
   const x=(i%3)*(W+2),y=Math.floor(i/3)*(H+2);assert.ok(x>=0&&x+W<=Width+0.00001);assert.ok(H>W);
   if(previous&&previous.y===y)assert.ok(x>=previous.x+W+1.999);previous={x,y};
   for(const [sw,sh] of [[160,90],[90,160],[400,400],[1080,1920],[4096,800]]){
    const scale=Math.max(W/sw,H/sh),iw=sw*scale,ih=sh*scale,ix=(W-iw)/2,iy=(H-ih)/2;
    for(const position of ['top','center','bottom']){const cropY=position==='top'?0:position==='bottom'?H-ih:(H-ih)/2;assert.ok(cropY<=0.001&&cropY+ih>=H-0.001,'saved crop position always fills tile');}
    assert.ok(iw>=W-0.001&&ih>=H-0.001);assert.ok(ix<=0.001&&iy<=0.001);assert.ok(ix+iw>=W-0.001&&iy+ih>=H-0.001,'cover leaves no unfilled tile');assert.ok(Math.abs(iw/ih-sw/sh)<1e-8,'cover cannot stretch source aspect ratio');
   }
  }
 }
}
grid(gallery);assert.throws(()=>grid(gallery.replace('C.ClipChildren:=True','C.ClipChildren:=False')),'unclipped oversized photos must fail');
for(const name of ['MoaPlayApp.Member.MyPage.inc','MoaPlayApp.Member.ProfileGallery.inc']){
 const bytes=fs.readFileSync(path.join(root,name));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);assert.equal(bytes.toString().replace(/\r\n/g,'').includes('\n'),false);
}
console.log('FIX65 profile contracts PASS on FIX68: compact identity/actions, nickname/stats alignment, removed notes, four icon tabs, safe profile details, responsive 3:4 cover grid, full-post routes and privacy.');
