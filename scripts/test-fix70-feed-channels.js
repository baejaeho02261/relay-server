'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix70-feed-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),db=require('../storage/database'),lm=require('../license/licenseManager');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX70-FEED-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=lm.CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;require('./helpers/member-identity-fixture')(c);return c;}
const run=(c,action,body={})=>hub.Execute(c,'FIX70-FEED-'+(++serial),action,body),own=c=>s.Account(c),snapshot=()=>JSON.stringify(s.DB()),ids=data=>data.items.map(x=>x.id).sort();
function reject(fn,error){const before=snapshot();assert.throws(fn,error);assert.equal(snapshot(),before,'rejected mutation must be atomic');}
function post(c,body){s.Atomic(()=>{own(c).last_post=0;});return run(c,'post.create',body).post;}
try{
 const a=client(7001),b=client(7002);for(const c of [a,b])run(c,'me');
 const legacy=post(a,{body:'기존 게시글'}),pubg=post(a,{channel:'PUBG',body:'배틀그라운드 이야기'}),valorant=post(a,{channel:'VALORANT',body:'발로란트 이야기'}),privatePost=post(a,{channel:'PUBG',audience:'PRIVATE',body:'본인만 보는 글'});
 s.Atomic(()=>{delete s.DB().posts[legacy.id].channel;});
 assert.deepEqual(ids(run(b,'feed',{channel:'PUBG'})),[pubg.id]);assert.deepEqual(ids(run(b,'feed',{channel:'VALORANT'})),[valorant.id]);
 assert.deepEqual(ids(run(b,'feed',{channel:''})),[legacy.id,pubg.id,valorant.id].sort());assert.deepEqual(ids(run(a,'feed',{channel:'PUBG'})),[pubg.id,privatePost.id].sort());
 assert.equal(run(b,'thread',{postId:legacy.id,countView:false}).post.channel,'');
 for(const channel of ['CS2','pubg',{},[]]){reject(()=>run(a,'feed',{channel}),/INPUT_INVALID/);reject(()=>run(a,'post.edit',{id:pubg.id,revision:0,body:'invalid edit',channel}),/INPUT_INVALID/);}
 const pg=run(b,'feed',{channel:'PUBG'});assert.equal(run(b,'feed',{channel:'PUBG',_ifNoneMatch:pg.contentTag}).unchanged,true);
 const changed=run(b,'feed',{channel:'VALORANT',_since:pg.revision,_ifNoneMatch:pg.contentTag});assert.notEqual(changed.unchanged,true);assert.deepEqual(ids(changed),[valorant.id]);
 assert.deepEqual(ids(run(b,'feed',{channel:'VALORANT',_since:pg.revision})),[valorant.id],'revision alone cannot hide a channel switch');
 assert.ok(run(b,'live',{scope:'feed',query:{channel:'PUBG'},posts:[pubg.id]}).scope.every(x=>x.startsWith(pubg.id+'/')));
 assert.equal(run(a,'post.edit',{id:pubg.id,revision:s.DB().posts[pubg.id].revision||0,channel:'VALORANT',body:'Moved to Valorant'}).post.channel,'VALORANT');
 assert.deepEqual(ids(run(b,'feed',{channel:'PUBG'})),[]);assert.deepEqual(ids(run(b,'feed',{channel:'VALORANT'})),[pubg.id,valorant.id].sort());
 assert.deepEqual(run(b,'live',{scope:'feed',query:{channel:'PUBG'},posts:[pubg.id]}).scope,[]);
 run(b,'block.set',{id:own(a).id,blocked:true});assert.deepEqual(run(b,'feed',{channel:'VALORANT'}).items,[]);run(b,'block.set',{id:own(a).id,blocked:false});
 run(a,'post.edit',{id:pubg.id,revision:s.DB().posts[pubg.id].revision||0,body:'legacy editor'});assert.equal(s.DB().posts[pubg.id].channel,'VALORANT');
 assert.equal(db.ImportDatabaseObject(db.BuildDatabaseObject()),true);assert.equal(run(b,'thread',{postId:pubg.id,countView:false}).post.channel,'VALORANT');
 const base=path.resolve(__dirname,'../../MoaPlayApp_Android64'),read=n=>fs.readFileSync(path.join(base,n),'utf8').replace(/\r/g,'');
 const feed=read('MoaPlayApp.Member.Feed.inc'),compose=read('MoaPlayApp.Member.Compose.inc'),flow=read('MoaPlayApp.Member.Flow.inc'),delta=read('MoaPlayApp.Member.Delta.inc'),actions=read('MoaPlayApp.Member.Actions.inc');
 assert.match(flow,/Body.AddPair\('channel',FHubFeedChannel\)/);assert.match(flow,/Obj.AddPair\('channel',FHubComposeChannel\)/);assert.match(flow,/FHubComposeChannel:=HubText\(Obj,'channel',FHubComposeChannel\)/);
 assert.match(actions,/FHubCache.Remove\('feed'\);FHubQueries.Remove\('feed'\);HubNavigate/);assert.match(delta,/FHubFeedChannel<>''\) and \(HubText\(Post,'channel'\)<>FHubFeedChannel/);
 assert.match(feed,/'more\|post\|'.*C.Width-52,6,44,44/);assert.doesNotMatch(feed,/AddMemberSvg\(C,C,AudienceIcon/);
 assert.doesNotMatch(feed,/Channel\('전체'/);assert.doesNotMatch(compose,/post.channel|procedure Channel/);assert.doesNotMatch(actions,/Action='post.channel'/);
 assert.match(compose,/if FHubView='compose' then begin[\s\S]*FHubComposeChannel:=FHubFeedChannel/);
 assert.match(flow,/if FHubView='editpost' then FHubComposeChannel:=HubText\(Obj,'channel',FHubComposeChannel\)/,'a saved draft cannot override the selected new-post channel');
 assert.match(compose,/C.Stroke.Kind:=TBrushKind.None;\n  C.AutoCapture/);assert.match(compose,/Box.Stroke.Kind:=TBrushKind.Solid;Box.Stroke.Color:=MemberBorder/);assert.match(compose,/Body.AddPair\('channel',FHubComposeChannel\)/);
 for(const width of [320,360,390,412,480]){const cw=Math.min(202,Math.max(176,width-112)),left=width-20-cw;assert.ok(left>=88);assert.equal(left+cw,width-20);}
 for(const file of ['Feed','Compose','Flow','Delta','Actions']){const bytes=fs.readFileSync(path.join(base,`MoaPlayApp.Member.${file}.inc`));assert.equal(bytes.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(bytes.toString('utf8'),/(?<!\r)\n/);}
 console.log('FIX70 FEED PASS: legacy/all and game channels, create/edit persistence, privacy/block filtering, live scopes, conditional read isolation, atomic invalid edits, draft preservation and aligned standalone inputs.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
