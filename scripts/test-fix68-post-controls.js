'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix68-post-controls-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),db=require('../storage/database'),lm=require('../license/licenseManager'),mentions=require('../services/member/mentions');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX68-POST-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=lm.CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
const run=(c,action,body={},id)=>hub.Execute(c,id||'FIX68-POST-'+(++serial),action,body),own=c=>s.Account(c),snapshot=()=>JSON.stringify(s.DB()),ids=result=>result.mentionMembers.map(x=>x.id);
function reject(fn,error){const before=snapshot();assert.throws(fn,error);assert.equal(snapshot(),before,'rejected change must roll back state');}
function post(c,body,id){s.Atomic(()=>{own(c).last_post=0;});return run(c,'post.create',body,id).post;}
function comment(c,body){s.Atomic(()=>{own(c).last_comment=0;});return run(c,'comment.create',body).comment;}
try{
 const a=client(6801),b=client(6802),c=client(6803),d=client(6804);for(const item of [a,b,c,d])run(item,'me');
 for(const [item,handle] of [[a,'alice'],[b,'bob'],[c,'carol'],[d,'dora']])run(item,'profile.save',{handle});
 const mine=post(a,{title:'게시글',body:'공유할 내용'}),other=post(b,{body:'다른 회원 글'});
 const settings=(actor,id,patch,requestId)=>run(actor,'post.settings',{id,revision:s.DB().posts[id].revision||0,...patch},requestId);
 reject(()=>settings(b,mine.id,{hideLikeCounts:true}),/NOT_OWNER/);
 for(const patch of [{hideLikeCounts:1},{commentsDisabled:'yes'},{audience:'ADMIN'},{previewPosition:'center'},{revision:999,hideLikeCounts:true},{balance:10}])reject(()=>settings(a,mine.id,patch),/INPUT_INVALID|CONTENT_CHANGED/);
 comment(b,{postId:mine.id,body:'첫 댓글'});settings(a,mine.id,{commentsDisabled:true});
 reject(()=>run(c,'comment.create',{postId:mine.id,body:'새 댓글'}),/COMMENTS_DISABLED/);
 const existing=run(a,'thread',{postId:mine.id,countView:false}).comments.items[0];
 reject(()=>run(c,'comment.create',{postId:mine.id,parentId:existing.id,body:'새 답글'}),/COMMENTS_DISABLED/);
 assert.equal(run(b,'thread',{postId:mine.id,countView:false}).comments.total,1);
 settings(a,mine.id,{commentsDisabled:false});comment(c,{postId:mine.id,body:'열린 댓글'});
 run(b,'react',{postId:mine.id,value:1},'FIX68-OLD-REACTION');settings(a,mine.id,{hideLikeCounts:true,hideShareCounts:true});
 const hidden=run(b,'thread',{postId:mine.id,countView:false}).post;assert.equal(hidden.likes,null);assert.equal(hidden.reposts,null);assert.equal(hidden.shares,null);assert.equal(hidden.audience,undefined);assert.equal(hidden.ownHideLikeCounts,undefined);
 assert.equal(run(a,'thread',{postId:mine.id,countView:false}).post.ownHideLikeCounts,true);assert.equal(run(a,'post.insights',{id:mine.id}).insights.likes,1);reject(()=>run(b,'post.insights',{id:mine.id}),/NOT_OWNER/);
 settings(a,mine.id,{hideLikeCounts:false,hideShareCounts:false});
 // Post audiences apply across feed, direct reads, photos, reactions, quotes,
 // recommendations, retained live objects, shares and historical retries.
 settings(a,mine.id,{audience:'CLOSE_FRIENDS'});assert.equal(run(b,'feed').items.some(x=>x.id===mine.id),false);
 for(const [action,body] of [['thread',{postId:mine.id}],['photo',{id:mine.id}],['react',{postId:mine.id,value:1}],['post.share',{id:mine.id,memberId:own(c).id}]])reject(()=>run(b,action,body),/POST_NOT_FOUND/);
 run(a,'account.list.set',{kind:'closeFriends',memberId:own(b).id,enabled:true});assert.ok(run(b,'feed').items.some(x=>x.id===mine.id));
 assert.deepEqual(run(a,'post.recipients',{id:mine.id}).items.map(x=>x.id),[own(b).id]);
 reject(()=>run(a,'post.share',{id:mine.id,memberId:own(c).id}),/POST_SHARE_UNAVAILABLE/);
 settings(a,mine.id,{audience:'FOLLOWERS'});assert.equal(run(b,'feed').items.some(x=>x.id===mine.id),false);run(b,'follow.set',{id:own(a).id,following:true});assert.ok(run(b,'feed').items.some(x=>x.id===mine.id));
 settings(a,mine.id,{audience:'PUBLIC'});run(a,'preferences.save',{profilePostsVisibility:'PRIVATE'});assert.equal(run(a,'thread',{postId:mine.id,countView:false}).post.audienceLabel,'나만 보기');reject(()=>run(b,'thread',{postId:mine.id}),/POST_NOT_FOUND/);run(a,'preferences.save',{profilePostsVisibility:'PUBLIC'});
 const recipient=run(a,'post.recipients',{id:mine.id,q:'@BoB',limit:1});assert.equal(recipient.query,'@BoB');assert.equal(recipient.postId,mine.id);assert.equal(recipient.items[0].id,own(b).id);assert.equal(recipient.hasMore,false);
 const body={id:mine.id,memberId:own(b).id},share=run(a,'post.share',body,'FIX68-POST-SHARE-ONCE'),threadId=share.thread.id;
 assert.equal(share.messages.at(-1).sharedPost.body,'공유할 내용');assert.equal(run(b,'dmthread',{id:threadId}).messages.at(-1).sharedPost.title,'게시글');
 assert.equal(run(a,'post.insights',{id:mine.id}).insights.shares,1);let before=snapshot();run(a,'post.share',body,'FIX68-POST-SHARE-ONCE');assert.equal(snapshot(),before);assert.equal(run(a,'post.insights',{id:mine.id}).insights.shares,1);
 const receipt=s.DB().operations[own(a).id+':FIX68-POST-SHARE-ONCE'].result;assert.deepEqual(Object.keys(receipt).sort(),['id','postId','sentMessageId','sentSeq']);
 settings(a,mine.id,{audience:'PRIVATE'});assert.deepEqual(run(b,'react',{postId:mine.id,value:1},'FIX68-OLD-REACTION').post,{id:mine.id,unavailable:true});assert.deepEqual(run(b,'dmthread',{id:threadId}).messages.at(-1).sharedPost,{id:mine.id,unavailable:true});assert.ok(run(b,'live',{posts:[mine.id]}).removedPosts.includes(mine.id));settings(a,mine.id,{audience:'PUBLIC'});
 run(c,'block.set',{id:own(a).id,blocked:true});reject(()=>run(a,'post.share',{id:mine.id,memberId:own(c).id}),/POST_SHARE_UNAVAILABLE/);run(c,'block.set',{id:own(a).id,blocked:false});
 run(c,'activity.settings.save',{messageAudience:'NONE'});assert.equal(run(a,'post.recipients',{id:mine.id}).items.some(x=>x.id===own(c).id),false);reject(()=>run(a,'post.share',{id:mine.id,memberId:own(c).id}),/POST_SHARE_UNAVAILABLE/);
 run(b,'activity.settings.save',{allowRepost:false});reject(()=>run(a,'post.share',{id:other.id,memberId:own(d).id}),/REPOST_UNAVAILABLE/);
 // Both settings and sending a DM roll back entirely if saving fails.
 const save=db.SaveDatabase;try{db.SaveDatabase=()=>false;reject(()=>settings(a,mine.id,{archived:true}),/STORAGE_SAVE_FAILED/);reject(()=>run(a,'post.share',{id:mine.id,memberId:own(d).id}),/STORAGE_SAVE_FAILED/);}finally{db.SaveDatabase=save;}
 settings(a,mine.id,{pinned:true});const tiles=run(a,'me').posts.items;assert.equal(tiles[0].id,mine.id);assert.equal(tiles[0].pinned,true);
 const pins=[post(a,{body:'두번째'}),post(a,{body:'세번째'}),post(a,{body:'네번째'})];settings(a,pins[0].id,{pinned:true});settings(a,pins[1].id,{pinned:true});reject(()=>settings(a,pins[2].id,{pinned:true}),/POST_PIN_LIMIT/);
 settings(a,mine.id,{archived:true});assert.equal(run(a,'archives').items[0].id,mine.id);assert.equal(run(b,'archives').total,0);assert.equal(run(a,'feed').items.some(x=>x.id===mine.id),false);assert.equal(run(a,'me').posts.items.some(x=>x.id===mine.id),false);assert.equal(run(a,'archives').items[0].pinned,false);assert.equal(run(a,'me').profile.posts,3);assert.equal(run(a,'live',{profiles:[own(a).id]}).profiles[0].posts,3);assert.equal(run(a,'dmthread',{id:threadId}).messages.at(-1).sharedPost.unavailable,true);
 reject(()=>run(a,'post.share',body),/POST_ARCHIVED/);settings(a,mine.id,{archived:false});assert.ok(run(b,'feed').items.some(x=>x.id===mine.id));
 run(b,'dm.delete',{id:threadId,confirmed:true});assert.deepEqual(run(a,'post.share',body,'FIX68-POST-SHARE-ONCE').messages,[]);
 // A transparent native cutout must stay transparent in every wire preview.
 const {PNG}=require('pngjs'),png=new PNG({width:420,height:240});for(let y=0;y<png.height;y++)for(let x=0;x<png.width;x++){const i=(y*png.width+x)*4;png.data[i]=220;png.data[i+1]=40;png.data[i+2]=90;png.data[i+3]=x<210?0:255;}
 const picture=post(a,{body:'컷아웃',image:'data:image/png;base64,'+PNG.sync.write(png).toString('base64')}),stored=s.DB().posts[picture.id],media=require('../services/member/media');
 for(const value of [stored.image,stored.imageFeed,stored.imageThumb,media.FeedImage(stored),media.LegacyFeedImage(stored)]){assert.ok(value.startsWith('data:image/png;base64,'));const decoded=PNG.sync.read(Buffer.from(value.split(',')[1],'base64'));assert.equal(decoded.data[3],0);assert.ok(decoded.data.some((v,i)=>i%4===3&&v===255));}
 settings(a,picture.id,{previewPosition:'bottom'});assert.equal(run(a,'me').posts.items.find(x=>x.id===picture.id).previewPosition,'bottom');
 const storedDB=db.BuildDatabaseObject();assert.equal(db.ImportDatabaseObject(storedDB),true);assert.equal(run(a,'post.insights',{id:mine.id}).insights.shares,1);
 before=snapshot();run(a,'archives');run(a,'post.insights',{id:mine.id});run(a,'post.recipients',{id:mine.id});run(a,'dmthread',{id:threadId});assert.equal(snapshot(),before,'read projections do not mutate');
 const legacy=structuredClone(s.DB());delete legacy.postShares;s.Import({memberHub:legacy});assert.deepEqual(s.DB().postShares,{},'FIX67 storage migrates without shared posts table');
 console.log('FIX68 POST CONTROLS PASS: owner authorization, revision/type guards, archive retrieval, profile pin limit/order, audiences across reads/writes/live, comment/reply enforcement, private counters/insights, recipient filtering, dynamic DM shares, idempotency, deletion, rollback, persistence and alpha-safe PNG previews.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
