'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix74-feed-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),db=require('../storage/database'),lm=require('../license/licenseManager');let serial=0;
function client(n){
 const id=String(n).padStart(16,'0'),key='FIX74-FEED-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};
 state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));
 c.licenseKey=lm.CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;require('./helpers/member-identity-fixture')(c);return c;
}
const run=(c,action,body={},requestId='FIX74-FEED-'+(++serial))=>hub.Execute(c,requestId,action,body),own=c=>s.Account(c),ids=data=>data.items.map(x=>x.id).sort();
function post(c,body){s.Atomic(()=>{own(c).last_post=0;});return run(c,'post.create',body).post;}
try{
 const a=client(7401),b=client(7402);run(a,'me');run(b,'me');
 const legacy=post(a,{body:'기존 전체 이야기'}),pubg=post(a,{channel:'PUBG',title:'이전 배틀그라운드',body:'그대로 남는 글',poll:{question:'어떤가요?',options:['좋아요','보통이에요']}}),valorant=post(b,{channel:'VALORANT',body:'기존 발로란트 이야기'}),privatePost=post(a,{audience:'PRIVATE',body:'비공개 글'});
 assert.equal(s.DB().posts[pubg.id].channel,undefined,'new posts no longer store a channel');
 s.Atomic(()=>{s.DB().posts[pubg.id].channel='PUBG';s.DB().posts[valorant.id].channel='VALORANT';s.DB().posts[pubg.id].at=Date.now()-120000;});
 const visible=[legacy.id,pubg.id,valorant.id].sort();
 for(const channel of [undefined,'PUBG','VALORANT',''])assert.deepEqual(ids(run(b,'feed',{channel})),visible,'legacy channel query must not hide old posts');
 assert.ok(run(a,'feed').items.some(row=>row.id===privatePost.id));
 assert.equal(run(b,'thread',{postId:pubg.id,countView:false}).post.channel,undefined,'retired metadata is not projected');
 assert.deepEqual(run(b,'live',{scope:'feed',query:{channel:'PUBG'},posts:[pubg.id,valorant.id]}).scope.map(x=>x.split('/')[0]).sort(),visible,'live updates have the same unified membership');
 const original=structuredClone(s.DB().posts[pubg.id]),body={postId:pubg.id,value:true},request='FIX74-DIRECT-PEER-HOLD';
 const first=run(b,'repost.set',body,request),key=own(b).id+':'+pubg.id;
 assert.equal(first.reposted,true);assert.equal(first.post.repostedBy.id,own(b).id);assert.equal(first.post.author.id,own(a).id);
 assert.deepEqual(s.DB().posts[pubg.id],original,'direct repost preserves source text, poll, author, timestamp and media');
 assert.equal(Object.values(s.DB().posts).filter(row=>row.quotePostId===pubg.id).length,0,'holding a peer post does not open/create a composer quote');
 assert.equal(run(b,'feed').items[0].id,pubg.id,'a peer repost promotes the original to the top');
 const at=s.DB().reposts[key].at,eventCount=Object.values(s.DB().repostEvents).length;
 const replay=run(b,'repost.set',body,request);assert.equal(replay.post.repostedBy.at,first.post.repostedBy.at);assert.equal(s.DB().reposts[key].at,at);assert.equal(Object.values(s.DB().repostEvents).length,eventCount,'retries do not add another repost event');
 for(let i=0;i<4;i++){const previous=s.DB().reposts[key].at;run(b,'repost.set',body);assert.ok(s.DB().reposts[key].at>previous,'each new held gesture can promote again');}
 const self=run(a,'repost.set',body);assert.equal(self.post.repostedBy.id,own(a).id);assert.equal(run(b,'feed').items[0].id,pubg.id);
 assert.throws(()=>run(b,'repost.set',{...body,value:false},request),/REQUEST_REUSED/);
 const save=db.SaveDatabase,committedAt=s.DB().reposts[key].at;db.SaveDatabase=()=>false;
 try{assert.throws(()=>run(b,'repost.set',body),/STORAGE_SAVE_FAILED/);}finally{db.SaveDatabase=save;}
 assert.equal(s.DB().reposts[key].at,committedAt,'a failed commit cannot reorder a post');
 run(a,'activity.settings.save',{allowRepost:false});
 assert.throws(()=>run(b,'repost.set',body),/REPOST_UNAVAILABLE/,'peer repost respects owner sharing settings');
 assert.equal(run(b,'repost.set',{...body,value:false}).reposted,false,'an existing repost can still be withdrawn');
 run(a,'repost.set',body);run(a,'activity.settings.save',{allowRepost:true});
 assert.throws(()=>run(b,'repost.set',{postId:privatePost.id,value:true}),/POST_NOT_FOUND/);
 run(a,'block.set',{id:own(b).id,blocked:true});assert.throws(()=>run(b,'repost.set',body),/POST_NOT_FOUND/);run(a,'block.set',{id:own(b).id,blocked:false});
 s.Atomic(()=>{s.DB().posts[pubg.id].archived=true;});assert.throws(()=>run(b,'repost.set',body),/POST_NOT_FOUND/);assert.throws(()=>run(a,'repost.set',body),/POST_ARCHIVED/);
 s.Atomic(()=>{s.DB().posts[pubg.id].archived=false;});
 run(a,'post.edit',{id:pubg.id,revision:s.DB().posts[pubg.id].revision||0,body:original.body});assert.equal(s.DB().posts[pubg.id].channel,undefined,'editing cleans retired channel metadata');
 assert.equal(db.ImportDatabaseObject(db.BuildDatabaseObject()),true);assert.equal(run(a,'feed').items[0].id,pubg.id,'repost promotion survives reload');
 const base=path.resolve(__dirname,'../../MoaPlayApp_Android64'),read=n=>fs.readFileSync(path.join(base,n),'utf8').replace(/\r/g,'');
 const feed=read('MoaPlayApp.Member.Feed.inc'),compose=read('MoaPlayApp.Member.Compose.inc'),social=read('MoaPlayApp.Member.Social.inc'),touch=read('MoaPlayFeedCard.pas');
 const fill=feed.split('function TMoaPlayForm.HubFillPostCard')[1].split('function TMoaPlayForm.HubQuoteCard')[0];
 assert.doesNotMatch(fill,/HubReaction|post\.menu|more\|post\|/);assert.match(fill,/chevron\.down/);assert.match(fill,/if not Expanded then begin Result:=/);
 assert.match(feed,/C.OnOpen:=HubPostToggle;C.OnHold:=HubPostHold/);assert.match(feed,/HubSendSocial\('repost.set',Body\)/);assert.match(feed,/feed\.expanded/);
 assert.doesNotMatch(feed,/feed\.channel|feed\.sort/);
 for(const file of ['Flow','Actions','Delta'])assert.doesNotMatch(read(`MoaPlayApp.Member.${file}.inc`),/FHubFeedChannel|FHubComposeChannel|feed\.channel|feed\.sort/,'retired channel filters cannot survive in fetch, cache or action paths');assert.doesNotMatch(compose,/FHubComposeChannel|FHubFeedChannel|Body.AddPair\('channel'/);
 assert.match(compose,/C.SetBounds\(12,C.Position.Y,Max\(1,FHubPage.Width-24\),C.Height\)/);assert.match(compose,/Box.SetBounds\(0,64,C.Width,284\)/);
 const action=social.split("if (Action='repost') or (Action='repost.confirm') then begin")[1].split("if Action='poll.vote'")[0];assert.doesNotMatch(action,/HubNavigate|HubOpenRepostConfirm/);
 assert.match(touch,/procedure TMoaPlayFeedTap.CancelTouch;[\s\S]*?FHoldTimer.Enabled:=False;inherited/);assert.match(touch,/FWasHeld:=True;FDown:=False/);assert.match(touch,/if FWasHeld then Exit/);
 for(const width of [320,360,390,412,480])assert.equal((width-(width-24))/2,12,'title/body edges share the same small outer margin');
 for(const file of ['Feed','Compose','Social']){const bytes=fs.readFileSync(path.join(base,`MoaPlayApp.Member.${file}.inc`));assert.equal(bytes.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(bytes.toString('utf8'),/(?<!\r)\n/);}
 console.log('FIX74 FEED PASS: unified legacy/current posts and live scopes, direct peer/self hold repost, retry idempotence, repeated promotion, content preservation, authorization/privacy/sharing preference, rollback/reload, disclosure rendering and composer margins.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
