'use strict';
// Actual member-service projections exercise the new full profile cards. Native
// geometry contracts are separate and do not substitute for an FMX device run.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix71-social-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),lm=require('../license/licenseManager');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX71-SOCIAL-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=lm.CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;require('./helpers/member-identity-fixture')(c);return c;}
const run=(c,action,body={})=>hub.Execute(c,'FIX71-SOCIAL-'+(++serial),action,body),own=c=>s.Account(c);
function post(c,body){s.Atomic(()=>{own(c).last_post=0;});return run(c,'post.create',{channel:'PUBG',...body}).post;}
function comment(c,body){s.Atomic(()=>{own(c).last_comment=0;});return run(c,'comment.create',body).comment;}
function publicAuthor(author){assert.ok(author.id);assert.equal(author.accountLabel,'검증된 테스트 계정');for(const field of ['providerIdentity','subject','email','sub','accessToken','balance','points','preferences'])assert.equal(author[field],undefined,field+' cannot leak in a profile card');}
try{
 const a=client(7101),b=client(7102),c=client(7103);for(const client of [a,b,c])run(client,'me');
 const body='긴 본문과 실제 내용을 그대로 보여주세요. '.repeat(55),gifId=require('../services/member/gifs').List().items[0].id;
 const full=post(a,{title:'프로필 원문',body,gifId,poll:{question:'선택해주세요',options:['첫째','둘째']}}),peer=post(b,{title:'인용 원문',body:'공개 원문입니다.'});
 const cards=run(a,'me',{activity:'posts',postCards:true}).posts;
 const item=cards.items.find(x=>x.id===full.id);assert.equal(item.body,body.trim());assert.ok(item.body.length>140);assert.equal(item.poll.options.length,2);assert.ok(item.gif);publicAuthor(item.author);assert.equal(item.own,true);
 const remote=run(b,'member',{id:own(a).id,activity:'posts',postCards:true}).posts.items.find(x=>x.id===full.id);assert.equal(remote.body,item.body);assert.equal(remote.own,false);publicAuthor(remote.author);
 const quote=post(a,{body:'인용해서 남깁니다.',quotePostId:peer.id});
 run(a,'repost.set',{postId:full.id,value:true});run(a,'repost.set',{postId:full.id,value:true});
 const rows=run(a,'me',{activity:'reposts',postCards:true}).reposts.items,replays=rows.filter(x=>x.activityKind==='repost');
 assert.equal(replays.length,2);assert.equal(new Set(replays.map(x=>x.eventId)).size,2);assert.ok(rows.some(x=>x.id===quote.id&&x.quote.body==='공개 원문입니다.'));
 for(const row of replays){assert.equal(row.body,body.trim());assert.equal(row.repostedBy.id,own(a).id);assert.equal(row.repostedBy.at,row.activityAt);assert.equal(row.repostedBy.accountLabel,'검증된 테스트 계정');}
 const first=comment(a,{postId:peer.id,body:'내가 남긴 댓글 전체입니다. '.repeat(18)});comment(b,{postId:peer.id,parentId:first.id,body:'답글입니다.'});run(b,'comment.react',{id:first.id,value:1});
 const comments=run(a,'me',{activity:'comments',postCards:true}).comments.items,shown=comments.find(x=>x.id===first.id);
 assert.equal(shown.body,first.body);assert.equal(shown.postTitle,peer.title);assert.equal(shown.postId,peer.id);assert.equal(shown.likes,1);assert.equal(shown.replies,1);assert.equal(shown.own,true);publicAuthor(shown.author);
 // Labels can find a profile but never become primary keys or resolve an
 // ambiguous provider name to an arbitrary account.
 assert.throws(()=>run(a,'profile.details.save',{banners:[{kind:'profile',title:'계정',memberId:'검증된 테스트 계정'}]}),/PROFILE_BANNER_INVALID/);
 s.Atomic(()=>{own(b).providerIdentity.label='고유한 연결 계정';});
 const linked=run(a,'profile.details.save',{banners:[{kind:'profile',title:'친구 계정',memberId:'고유한 연결 계정'}]}).profile.banners[0];
 assert.equal(linked.memberId,own(b).id);assert.equal(linked.accountLabel,'고유한 연결 계정');
 assert.equal(run(a,'people',{q:'고유한 연결 계정'}).items[0].id,own(b).id);
 const linkedAgain=run(a,'profile.details.save',{banners:[{...linked,accountLabel:'forged display label'}]}).profile.banners[0];assert.equal(linkedAgain.accountLabel,'고유한 연결 계정');assert.equal(linkedAgain.memberId,own(b).id);
 s.Atomic(()=>{own(b).providerIdentity.label='검증된 테스트 계정';});
 const tagged=post(b,{body:'태그된 원문',gifId,taggedMemberIds:[own(a).id]});
 const tags=run(a,'me',{activity:'tagged',postCards:true}).tagged.items;assert.equal(tags[0].id,tagged.id);assert.equal(tags[0].body,'태그된 원문');assert.ok(tags[0].gif);publicAuthor(tags[0].author);
 run(b,'preferences.save',{profilePostsVisibility:'PRIVATE'});
 assert.equal(run(a,'me',{activity:'tagged',postCards:true}).tagged.total,0);
 const hiddenQuote=run(a,'me',{activity:'reposts',postCards:true}).reposts.items.find(x=>x.id===quote.id);assert.equal(hiddenQuote.quote.unavailable,true);assert.equal(hiddenQuote.quote.body,undefined);
 run(a,'preferences.save',{profilePostsVisibility:'PRIVATE'});
 for(const activity of ['posts','comments','reposts','tagged']){const hidden=run(c,'member',{id:own(a).id,activity,postCards:true});assert.equal(hidden.profilePostsHidden,true);assert.equal(hidden.posts.total,0);if(activity==='comments')assert.equal(hidden.comments.total,0);}
 run(a,'preferences.save',{profilePostsVisibility:'PUBLIC'});run(b,'preferences.save',{profilePostsVisibility:'PUBLIC'});run(a,'block.set',{id:own(b).id,blocked:true});assert.equal(run(a,'me',{activity:'tagged',postCards:true}).tagged.total,0);
 // Provider account labels must remain authoritative while an old text draft exists.
 const base=path.resolve(__dirname,'../../MoaPlayApp_Android64'),read=n=>fs.readFileSync(path.join(base,'MoaPlayApp.Member.'+n+'.inc'),'utf8').replace(/\r/g,'');
 const edit=read('ProfileEdit'),flow=read('Flow'),social=read('Social'),tools=read('PostTools'),delta=read('Delta'),live=read('Live');
 for(const text of [delta,live])assert.match(text,/Name='repostedBy'\) and \(HubText\(Obj,'activityKind'\)='repost'\) then Continue/,'live count patches cannot overwrite historical event attribution');
 assert.match(delta,/for Cache in FHubCache.Values do PatchComment\(Cache,Comment\)/);assert.match(delta,/total'\)-MatchCount/,'deleting repeated activity copies adjusts the complete page total');
 assert.match(delta,/Action='comment.thread'\) then Count:=HubCount\(HubNumber\(Item,'replies'\)\)/,'profile reply counts cannot become post comment totals');
 assert.match(edit,/Field\('계정',HubText\(Profile,'accountLabel'/);assert.match(edit,/FHubEdits\[1\].ReadOnly:=True;FHubEdits\[1\].CanFocus:=False;FHubEdits\[1\].HitTest:=False/);
 assert.equal((flow.match(/\(\(FHubView<>'profile'\) or \(I<>1\)\)/g)||[]).length,2,'readonly provider label is neither saved nor restored as a mutable draft');
 assert.match(social,/\(Kind='comment'\) and \(HubText\(Obj,'postId'\)<>''\)/,'cache search distinguishes comments from posts');assert.match(social,/Result:=FindPost\(HubCached\(HubReadAction\)\)/);
 const share=tools.slice(tools.indexOf("if Action='post.share.send' then begin"),tools.indexOf("if Action='post.tool.cutout'"));
 assert.match(share,/FHubOverlay.TagString<>'postshare\|'\+ItemID/);assert.match(share,/not Assigned\(FHubSocialQueue\)/);
 const dispatch=share.indexOf("HubSendSocial('post.share',Body)");assert.ok(dispatch>0);assert.doesNotMatch(share.slice(dispatch),/Anchor\./,'dispatch may destroy its sender; no subsequent control dereference');
 console.log('FIX71 SOCIAL/PROFILE PASS: full authorized post/poll/GIF/comment cards, exact repost event attribution, four-tab privacy and blocking, verified account display, draft isolation and share sender lifetime contracts.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
