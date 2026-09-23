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
 const metric=part(source,'procedure HubProfileStatsMetrics','procedure TMoaPlayForm.HubRenderMe');
 const assignment=[...metric.matchAll(/(\w+):=([^;]+);/g)];
 assert.ok(assignment.length>=10,'use the actual native measurement assignments');
 const calls=[...own.matchAll(/HubProfileStat\(C,'([^']+)','([^']+)',HubNumber\(Profile,'[^']+'\),([^,]+),35,([^,]+),HubText\(Profile,'id'\),(True|False)\)/g)];
 assert.equal(calls.length,3);
 assert.match(own,/HubProfileStatsMetrics\(Profile,C.Width,StatX,PostW,FollowerW,FollowingW,Gap\)/);
 const actions=part(source,'procedure TMoaPlayForm.HubProfileButtons','procedure TMoaPlayForm.HubProfileTabs');
 const ownButtons=part(actions,'if Own then begin','end else begin'),buttonSize=ownButtons.match(/ButtonW:=([^;]+);/)[1];
 const targets=[...ownButtons.matchAll(/HubButton\(Parent,(?:MemberCaption\('[^']+'\)|''),'([^']+)',([^,]+),Y,([^,]+),(\d+),False\)/g)];
 assert.deepEqual(targets.map(x=>x[1]),['profile','profile.share','profile.people']);
 const textWidth=(text,size)=>[...text].reduce((n,c)=>n+(c.charCodeAt(0)>255?1:0.61)*size,2);
 const count=value=>value>=10000?(Math.round(value/1000)/10)+'만':value>=1000?(Math.round(value/100)/10)+'천':String(value);
 for(const Width of [240,280,320,360,390,412,480,600,800,1024])for(const Profile of [
  {posts:1,followers:2,following:3},{posts:1234,followers:89765,following:450},{posts:1000000000,followers:9999999999,following:8888888888}
 ]){
  const vars={Width,Profile,HubTextWidth:textWidth,HubCount:count,MemberCaption:s=>s,HubNumber:(p,k)=>p[k]};
  for(const [,name,expr]of assignment){const code=expr.replace(/\bMax\b/g,'Math.max').replace(/\bMin\b/g,'Math.min');vars[name]=Function(...Object.keys(vars),`return (${code})`)(...Object.values(vars));}
  const {X:StatX,PostW,FollowerW,FollowingW,Gap}=vars;let last=98;
  assert.ok(Math.abs(StatX+PostW+FollowerW+FollowingW+2*Gap-(Width-4))<0.001,'entire measured group must reach the right edge');
  assert.ok(StatX>=112-0.001,'compact layout cannot cross the avatar');
  for(const c of calls){const scope={StatX,PostW,FollowerW,FollowingW,Gap},x=evaluate(c[3],scope),w=evaluate(c[4],scope);assert.equal(c[5],'True');assert.ok(x>=last-0.001);assert.ok(x+w<=Width-4+0.001);assert.ok(w>0);last=x+w;}
  const ButtonW=evaluate(buttonSize,{W:Width});last=0;
  for(const t of targets){const x=evaluate(t[2],{W:Width,ButtonW}),w=evaluate(t[3],{W:Width,ButtonW});assert.ok(x>=last);assert.ok(x+w<=Width-4);assert.ok(w>=38);last=x+w;}
  assert.equal(last,Width-4,'people finder aligns with the stats trailing edge');
 }
 assert.match(own,/nickname[^\n]+,StatX\+3,18,Max\(1,PostW-6\),17,11/,'small nickname sits directly above the first count');
 const tabs=part(source,'procedure TMoaPlayForm.HubProfileTabs','procedure HubProfileStatsMetrics');
 assert.match(tabs,/Keys:array\[0\.\.3\] of string=\('posts','comments','reposts','tagged'\)/);
 assert.match(tabs,/Icons:array\[0\.\.3\] of string=\('grid','bubble','repost','user.tagged'\)/);
 assert.match(tabs,/HubIconButton\(Parent,Icons\[I\],Target,I\*W\/4,Y,W\/4,48\)/);
 assert.doesNotMatch(tabs,/HubLabel|HubTextAction/,'tabs show icons only');
 const identity=part(source,'procedure TMoaPlayForm.HubProfileIdentityRow','procedure TMoaPlayForm.HubProfileStat');
 assert.match(identity,/MemberCaption\('추가'\)/);assert.match(identity,/Pill.SetBounds\(0,3,58,26\)/);
 assert.equal((identity.match(/Pill.Fill.Kind:=TBrushKind.None;Pill.Stroke.Kind:=TBrushKind.Solid/g)||[]).length,2,'both compact pills retain transparent outlined backgrounds');
 assert.match(actions,/'user.add.solid'/);
 assert.doesNotMatch(source,/HubProfileNoteBubble|profile\.note|메모 남기기/,'profile notes are completely removed');
 const member=part(source,'procedure TMoaPlayForm.HubRenderMember','procedure TMoaPlayForm.HubRenderHistory');
 assert.doesNotMatch(member,/activity.dashboard/,'visitors cannot see an owner dashboard');
 assert.match(own,/if \(Kind='CREATOR'\) or \(Kind='BUSINESS'\) then begin/);
 const identityAt=own.indexOf('HubProfileIdentityRow'),dashboardAt=own.indexOf("'activity.dashboard'"),buttonsAt=own.indexOf('HubProfileButtons');
 assert.ok(identityAt<dashboardAt&&dashboardAt<buttonsAt,'professional dashboard appears directly under the handle and before buttons');
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
console.log('FIX65 profile contracts PASS on FIX69: right-aligned measured stats/actions, professional dashboard, removed notes, four icon tabs, safe profile details, responsive 3:4 cover grid, full-post routes and privacy.');
// The discovery prompt is an illustration and a real route, including empty
// suggestion payloads. No synthetic member IDs or remote image work on render.
const people=read('MoaPlayApp.Member.People.inc'),navigation=read('MoaPlayApp.Member.Navigation.inc');
const suggestions=part(people,'function TMoaPlayForm.HubProfileSuggestions','procedure TMoaPlayForm.HubRenderPeople');
assert.doesNotMatch(suggestions,/people\.dismiss|HubIconButton\(C,'close'/);
assert.doesNotMatch(suggestions,/Items.Count=0\) then Exit/,'the final finder card remains available without suggestions');
assert.match(suggestions,/if Assigned\(Items\) then for V in Items do/);
assert.match(suggestions,/if Count>=12 then Break/,'native profile cannot construct an unbounded strip');
assert.match(suggestions,/C.TagString:='profile.people';C.OnClick:=HubActionClick/);
assert.match(suggestions,/HubButton\(C,MemberCaption\('모두 보기'\),'profile.people'/);
assert.match(suggestions,/HubPeopleIllustration\(C,5,5,142,101\)/);
assert.match(people,/Action='profile.people' then begin FHubSearchText:='';HubNavigate\('people'\)/);
assert.match(navigation,/MemberDockGlass,24/);assert.match(navigation,/MemberDockGlass,20/);
assert.match(navigation,/Panel.Stroke.Color:=MemberBorder;Panel.Stroke.Thickness:=MemberBorderWidth/);
assert.match(navigation,/TMoaPlayTapRectangle\(Row\).TouchScope:=nil/,'sheet taps remain detached from feed scroll scope');
assert.doesNotMatch(navigation,/MakeScreenshot|TTimer.Create|FMember.Request/,'dropdown cannot add per-frame or network work');
const art=part(people,'Art.Svg.Source:=','function TMoaPlayForm.HubProfileSuggestions');
const payload=[...art.matchAll(/'([^']*)'/g)].map(x=>x[1]).join('');
const doc=new(require('jsdom').JSDOM)(payload,{contentType:'image/svg+xml'}).window.document;
assert.equal(doc.querySelectorAll('parsererror').length,0);assert.equal(doc.documentElement.getAttribute('viewBox'),'0 0 160 112');
for(const group of doc.querySelectorAll('g[clip-path]'))assert.ok(doc.querySelector(group.getAttribute('clip-path').slice(4,-1)));
assert.equal(doc.querySelectorAll('image,script,foreignObject,a').length,0,'illustration cannot load remote resources or intercept clicks');
for(const file of ['MoaPlayApp.Member.People.inc','MoaPlayApp.Member.Navigation.inc']){
 const bytes=fs.readFileSync(path.join(root,file));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);assert.equal(bytes.toString().replace(/\r\n/g,'').includes('\n'),false);
}
console.log('FIX69 profile finder/navigation PASS: bounded real suggestions, illustration validity, working empty-state finder route and common translucent dropdown.');
