'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(native,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const profile=read('MoaPlayApp.Member.MyPage.inc'),flow=read('MoaPlayApp.Member.Flow.inc');
const own=profile.split('procedure TMoaPlayForm.HubRenderMe')[1].split('procedure TMoaPlayForm.HubRenderMember')[0];
const peer=profile.split('procedure TMoaPlayForm.HubRenderMember')[1].split('procedure TMoaPlayForm.HubRenderInfo')[0];
for(const source of [own,peer]){
 for(const caption of ['게시물','팔로워','팔로잉'])assert.ok(source.includes(`HubProfileStat(C,'${caption}'`));
 assert.match(source,/HubRenderOwnComments\(HubObject\(Data,'comments'\)\)/);
 assert.match(source,/HubRenderProfileGallery\(HubObject\(Data,'posts'\)/);
 assert.match(source,/HubProviderMark\(C,Profile,L,/);
}
assert.match(profile,/Captions:array\[0\.\.3\] of string=\('게시글','댓글','리포스트함','태그한 게시글'\)/);
const tabs=profile.split('procedure TMoaPlayForm.HubProfileTabs')[1].split('{ Measure compact columns')[0];
assert.doesNotMatch(tabs,/HubIconButton|AddMemberSvg/);
assert.match(tabs,/Target:=Action\+'\|'\+Keys\[I\]/);
assert.match(peer,/HubBool\(Data,'profilePostsHidden'\)/);
assert.doesNotMatch(peer,/accountEmail/);
assert.match(own,/Email:=Trim\(HubText\(Profile,'accountEmail'\)\)/);
assert.doesNotMatch(profile,/HubTitleBadge|HubRenderBadges/);
assert.match(flow,/\(Action='me'\).*?\(FHubView='me'\).*?Body\.AddPair\('postCards'/);
assert.match(flow,/Body\.AddPair\('activity',FHubMyActivity\)/);
const mark=read('MoaPlayProviderMark.pas');
assert.match(mark,/GetValue<Boolean>\('accountLinked',False\)/);
assert.match(mark,/GetValue<Boolean>\('accountVerified',False\)/);
assert.match(mark,/\(Result<>'kakao'\) and \(Result<>'google'\)/);
assert.match(mark,/Child\.TagObject=NameLabel/,'repeated layout reuses the original mark');
assert.match(mark,/if Reserve=0 then begin if Assigned\(Mark\) then Mark.Visible:=False/,'revocation removes an existing mark');
assert.match(mark,/Layout.Font.Assign\(NameLabel.TextSettings.Font\)/,'position uses actual styled native font');
assert.match(mark,/AddMemberSvg\(NameLabel,Parent,Icon/,'name owns mark so removing a label removes its mark');
assert.match(mark,/Mark.HitTest:=False/);
// Evaluate the actual numeric bounds from the native source, including unusually
// long translated captions and 240dp split-screen width. FMX glyph rasterization
// still requires a native device; these checks guard overlap and right gutters.
function evaluate(expr,vars){const js=expr.replace(/\bMax\b/g,'Math.max').replace(/\bMin\b/g,'Math.min');assert.match(js,/^[\w\s.,+*/()\[\]-]+$/);return Function(...Object.keys(vars),`return (${js});`)(...Object.values(vars));}
function expr(source,name){const hit=new RegExp('\\b'+name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+':=([^;]+);').exec(source);assert.ok(hit,name);return hit[1];}
const metrics=profile.split('procedure HubProfileStatsMetrics')[1].split('procedure TMoaPlayForm.HubRenderMe')[0];
let scenarios=0;
for(const Width of [240,280,320,360,390,412,480,640,1024])for(const measured of [[42,42,42],[52,64,64],[120,105,91]]){
 const v={Width,Gap:4,PostW:measured[0],FollowerW:measured[1],FollowingW:measured[2]};
 v.Available=evaluate(expr(metrics,'Available'),v);v.Scale=evaluate(expr(metrics,'Scale'),v);
 for(const key of ['PostW','FollowerW','FollowingW'])v[key]*=v.Scale;
 const x=evaluate(expr(metrics,'X'),v);assert.ok(x>=109.999,'stats clear 80dp portrait plus14dp gap');
 assert.ok(Math.abs(x+v.PostW+v.FollowerW+v.FollowingW+v.Gap*2-(Width-16))<0.001,'all columns end at16dp gutter');
 for(const widths of [[39,27,64,82],[64,58,108,136]]){
  const InnerW=Width-32,Total=widths.reduce((a,b)=>a+b,0),scope={InnerW,Total};
  const Extra=evaluate(expr(tabs,'Extra'),scope),Scale=evaluate(expr(tabs,'Scale'),scope);
  const out=widths.map(w=>w*Scale+Extra);assert.ok(out.every(w=>w>0));assert.ok(Math.abs(out.reduce((a,b)=>a+b,0)-InnerW)<0.001);
 }
 for(const AvailableWidth of [24,36,80,140,Width-32])for(const Measured of [11,44,180,1000])for(const Reserve of [0,18]){
  const LabelWidth=evaluate(expr(mark,'LabelWidth'),{Measured,AvailableWidth,Reserve});
  assert.ok(LabelWidth>=1&&LabelWidth+Reserve<=AvailableWidth,'name and provider fit allocated width');
 }
 scenarios++;
}
// Real server projections must populate each restored tab and keep peer privacy.
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-profile-restoration-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';
try{
 require('../core/utils').EnsureDirs();const s=require('../services/member/store'),commerce=require('../services/member/commerce'),profiles=require('../services/member/profiles');
 const db=s.DB(),a={id:'USR-OWNER',subject:'OWNER',nickname:'회원 이름',bio:'',avatar:'',balance:10,points:12,createdAt:1},b={id:'USR-PEER',subject:'PEER',nickname:'다른 회원',bio:'',avatar:'',balance:20,createdAt:2};
 db.profiles.OWNER=a;db.profiles.PEER=b;
 const now=Date.now();const p1={id:'POST-OWN',accountId:a.id,title:'본인 글',body:'내용',at:now-3000,deleted:false,hidden:false};
 const p2={id:'POST-PEER',accountId:b.id,title:'상대 글',body:'내용',at:now-2000,deleted:false,hidden:false,gifId:require('../services/member/gifs').List().items[0].id,taggedMemberIds:[a.id]};
 db.posts[p1.id]=p1;db.posts[p2.id]=p2;
 db.comments['COM-OWN']={id:'COM-OWN',postId:p2.id,accountId:a.id,body:'내 댓글',at:now-1000,parentId:'',deleted:false,hidden:false};
 db.repostEvents['REPOST-OWN']={id:'REPOST-OWN',postId:p2.id,accountId:a.id,at:now};
 db.follows[a.id+':'+b.id]={follower:a.id,following:b.id,at:now};db.follows[b.id+':'+a.id]={follower:b.id,following:a.id,at:now};
 const expected={posts:'POST-OWN',comments:'COM-OWN',reposts:'POST-PEER',tagged:'POST-PEER'};
 for(const activity of Object.keys(expected)){
  const own=commerce.Mine(a,{activity,postCards:true}),peer=profiles.Read(b,{id:a.id,activity,postCards:true});
  const key=activity==='comments'?'comments':'posts';
  assert.ok(own[key].items.some(row=>row.id===expected[activity]),`owner ${activity} loads actual cards`);
  assert.ok(peer[key].items.some(row=>row.id===expected[activity]),`peer ${activity} loads actual cards`);
  assert.equal(peer.profile.accountEmail,undefined);assert.equal(peer.profile.balance,undefined);
  if(activity!=='comments')assert.ok(own[key].items.every(row=>row.author?.id),'postCards returns full author projection');
 }
 const p=commerce.Mine(a,{}).profile;assert.equal(p.posts,1);assert.equal(p.followers,1);assert.equal(p.following,1);
 a.profilePostsVisibility='PRIVATE';
 const privatePeer=profiles.Read(b,{id:a.id,activity:'posts',postCards:true});assert.equal(privatePeer.profilePostsHidden,true);assert.equal(privatePeer.posts.items.length,0);
 for(const file of ['MoaPlayApp.Member.MyPage.inc','MoaPlayApp.Member.Relationships.inc','MoaPlayProviderMark.pas']){
  const bytes=fs.readFileSync(path.join(native,file));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);assert.equal(bytes.toString().replace(/\r\n/g,'').includes('\n'),false);
 }
 console.log(`Profile restoration PASS: ${scenarios} compact summary scenarios; four text tabs load full cards; peer privacy; provider mark ownership and geometry.`);
}finally{fs.rmSync(dir,{recursive:true,force:true});}
