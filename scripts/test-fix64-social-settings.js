'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix64-social-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),db=require('../storage/database');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX64-SOCIAL-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
const run=(c,action,body={},id)=>hub.Execute(c,id||'FIX64-SOCIAL-'+(++serial),action,body),own=c=>s.Account(c),snapshot=()=>JSON.stringify(s.DB());
function rejected(fn,error){const before=snapshot();assert.throws(fn,error);assert.equal(snapshot(),before,'rejected change must be atomic');}
function failSave(fn){const save=db.SaveDatabase;try{db.SaveDatabase=()=>false;rejected(fn,/STORAGE_SAVE_FAILED/);}finally{db.SaveDatabase=save;}}
try{
 const a=client(6401),b=client(6402),c=client(6403),d=client(6404);for(const client of [a,b,c,d])run(client,'me');
 s.Atomic(()=>{own(a).nickname='앨리스';own(b).nickname='밥';own(c).nickname='캐럴';own(d).nickname='데이브';own(b).balance=923847;own(b).activitySettings={hiddenWords:'private secret'};});
 let before=snapshot(),people=run(a,'people');assert.equal(snapshot(),before);assert.equal(people.total,3);assert.ok(people.items.every(p=>p.id!==own(a).id));
 const peer=people.items.find(p=>p.id===own(b).id);for(const key of ['subject','balance','points','preferences','activitySettings','accountLists','dismissedPeople'])assert.equal(peer[key],undefined,key+' private');
 assert.equal(run(a,'people',{q:'밥'}).items[0].id,own(b).id);assert.equal(run(a,'people',{q:'@'+s.Handle(own(b))}).total,1);
 const pages=[run(a,'people',{limit:2}),run(a,'people',{limit:2,offset:2})];assert.equal(new Set(pages.flatMap(x=>x.items.map(y=>y.id))).size,3);
 for(const body of [{limit:31},{offset:-1},{q:{}},{q:'x'.repeat(101)}])rejected(()=>run(a,'people',body),/INPUT_INVALID/);
 const dismissed={memberId:own(c).id};run(a,'people.dismiss',dismissed,'FIX64-DISMISS');before=snapshot();run(a,'people.dismiss',dismissed,'FIX64-DISMISS');assert.equal(snapshot(),before);assert.equal(run(a,'people').total,2);assert.equal(run(b,'people').total,3);
 run(d,'block.set',{id:own(a).id,blocked:true});assert.equal(run(a,'people').total,1);run(d,'block.set',{id:own(a).id,blocked:false});
 // FIX66 removes profile notes entirely; old persisted content remains inert.
 s.Atomic(()=>{own(b).profileNote={text:'이전 버전의 메모',expiresAt:Date.now()+86400000};});
 rejected(()=>run(b,'profile.note',{text:'작성 불가'}),/UNKNOWN_ACTION/);
 rejected(()=>run(b,'profile.note',{text:''}),/UNKNOWN_ACTION/);
 run(b,'preferences.save',{profilePostsVisibility:'PRIVATE'});
 assert.equal(run(a,'people',{q:'밥'}).items[0].note,undefined);assert.equal(run(a,'member',{id:own(b).id}).profile.note,undefined);assert.equal(run(b,'me').profile.note,undefined);assert.equal(s.PublicProfile(own(b)).note,undefined);const ownViewer=run(b,'people').viewer;assert.equal(ownViewer.note,undefined);for(const key of ['balance','points','inventory','preferences','accountLists','activitySettings'])assert.equal(ownViewer[key],undefined,'common viewer remains a public projection');
 run(b,'preferences.save',{profilePostsVisibility:'CLOSE_FRIENDS'});run(b,'account.list.set',{kind:'closeFriends',memberId:own(a).id,enabled:true});
 assert.equal(run(a,'member',{id:own(b).id}).profile.note,undefined);assert.equal(run(c,'member',{id:own(b).id}).profile.note,undefined);
 let settings=run(a,'activity.settings');assert.equal(settings.status.plus.active,false);assert.equal(settings.status.verified.available,false);assert.equal(settings.capabilities.stories,false);assert.equal(settings.profile.id,own(a).id);
 for(const patch of [{messageAudience:'bad'},{allowRepost:'false'},{balance:123},{hiddenWords:'a'.repeat(1001)},{hiddenWords:Array.from({length:51},(_,i)=>i).join(',')},{profilePostsVisibility:'bad'},{currencyReference:{}}])rejected(()=>run(a,'activity.settings.save',patch),/INPUT_INVALID/);
 failSave(()=>run(a,'activity.settings.save',{messageAudience:'NONE'},'FIX64-PREFS-FAIL'));assert.equal(run(a,'activity.settings').preferences.messageAudience,'EVERYONE');
 run(a,'activity.settings.save',{language:'en',displayCurrency:'USD',hideLikeCounts:true,hideShareCounts:true});assert.equal(run(a,'preferences').preferences.language,'en');assert.equal(run(a,'activity.settings').preferences.displayCurrency,'USD');assert.equal(run(a,'me').profile.preferences.hideLikeCounts,true);assert.equal(run(a,'me').profile.preferences.hideShareCounts,true);
 for(const kind of ['closeFriends','restricted','favorites','muted']){
  run(a,'account.list.set',{kind,memberId:own(b).id,enabled:true});assert.equal(run(a,'activity.settings').counts[kind],1);assert.equal(run(b,'activity.settings').counts[kind],kind==='closeFriends'?1:0);
  const selected=run(a,'account.list',{kind});assert.equal(selected.total,1);assert.equal(selected.items[0].selected,true);
  const candidates=run(a,'account.list',{kind,candidates:true});assert.equal(candidates.total,3);assert.equal(candidates.selectedCount,1);assert.equal(candidates.items.find(x=>x.id===own(b).id).selected,true);
  assert.equal(run(a,'account.list',{kind,candidates:true,q:'캐럴'}).items[0].selected,false);
  failSave(()=>run(a,'account.list.set',{kind,memberId:own(b).id,enabled:false}));run(a,'account.list.set',{kind,memberId:own(b).id,enabled:false});
 }
 rejected(()=>run(a,'account.list.set',{kind:'admin',memberId:own(b).id,enabled:true}),/INPUT_INVALID/);rejected(()=>run(a,'account.list.set',{kind:'favorites',memberId:own(a).id,enabled:true}),/INPUT_INVALID/);
 run(b,'activity.settings.save',{hiddenWords:'',commentAudience:'NONE',allowRepost:false,profilePostsVisibility:'PUBLIC'});
 const post=run(b,'post.create',{body:'예쁜 하루'}).post;
 rejected(()=>run(a,'comment.create',{postId:post.id,body:'안녕하세요'}),/INTERACTION_UNAVAILABLE/);rejected(()=>run(a,'post.create',{body:'인용',quotePostId:post.id}),/REPOST_UNAVAILABLE/);
 run(b,'activity.settings.save',{commentAudience:'FOLLOWING'});rejected(()=>run(a,'comment.create',{postId:post.id,body:'안녕하세요'}),/INTERACTION_UNAVAILABLE/);run(b,'follow.set',{id:own(a).id,following:true});
 const comment=run(a,'comment.create',{postId:post.id,body:'좋은 날'}).comment;assert.equal(comment.body,'좋은 날');assert.equal(comment.likes,null);assert.equal(comment.hideLikeCounts,true);const hiddenComment=run(a,'comment.react',{id:comment.id,value:1,_delta:true}).comment;assert.equal(hiddenComment.hideLikeCounts,true);assert.equal(hiddenComment.likes,null);assert.equal(run(c,'thread',{postId:post.id,countView:false}).comments.items.find(x=>x.id===comment.id).likes,1,'other viewers retain their own counter preference');
 run(b,'activity.settings.save',{hiddenWords:'금지어'});rejected(()=>run(a,'comment.edit',{id:comment.id,revision:0,body:'금지어'}),/INTERACTION_UNAVAILABLE/);
 const view=run(a,'thread',{postId:post.id,countView:false}).post;assert.equal(view.likes,null);assert.equal(view.reposts,null);assert.equal(view.hideLikeCounts,true);
 run(a,'activity.settings.save',{hiddenWords:'예쁜'});assert.ok(!run(a,'feed').items.some(x=>x.id===post.id));run(a,'activity.settings.save',{hiddenWords:''});
 run(a,'account.list.set',{kind:'muted',memberId:own(b).id,enabled:true});assert.ok(!run(a,'feed').items.some(x=>x.id===post.id));assert.ok(run(c,'feed').items.some(x=>x.id===post.id));run(a,'account.list.set',{kind:'muted',memberId:own(b).id,enabled:false});
 run(b,'account.list.set',{kind:'restricted',memberId:own(a).id,enabled:true});rejected(()=>run(a,'comment.create',{postId:post.id,body:'제한'}),/INTERACTION_UNAVAILABLE/);rejected(()=>run(a,'dm.open',{memberId:own(b).id}),/INTERACTION_UNAVAILABLE/);run(b,'account.list.set',{kind:'restricted',memberId:own(a).id,enabled:false});
 run(b,'activity.settings.save',{messageAudience:'NONE'});rejected(()=>run(a,'dm.open',{memberId:own(b).id}),/INTERACTION_UNAVAILABLE/);run(b,'activity.settings.save',{messageAudience:'EVERYONE'});
 const thread=run(c,'dm.open',{memberId:own(b).id}).thread.id;run(c,'dm.send',{id:thread,text:'새 대화'});
 assert.equal(run(b,'dm',{folder:'messages'}).total,0);const requests=run(b,'dm',{folder:'requests',q:'캐럴'});assert.equal(requests.total,1);assert.equal(requests.requestCount,1);assert.equal(requests.folder,'requests');assert.equal(requests.q,'캐럴');assert.equal(requests.items[0].isRequest,true);
 assert.equal(run(c,'dm',{mode:'inbox',query:'밥'}).total,1);const exactQuery='@'+s.Handle(own(b)).toUpperCase();const exactResult=run(c,'dm',{folder:'messages',q:' '+exactQuery+' '});assert.equal(exactResult.q,exactQuery);assert.equal(exactResult.total,1);assert.ok(requests.suggestions.every(x=>x.id!==own(b).id&&!x.isFollowing));
 rejected(()=>run(c,'dm.accept',{id:thread}),/DM_REQUEST_REQUIRED/);rejected(()=>run(d,'dm.accept',{id:thread}),/DM_NOT_FOUND/);failSave(()=>run(b,'dm.accept',{id:thread},'FIX64-ACCEPT'));assert.equal(run(b,'dmthread',{id:thread}).thread.isRequest,true);
 run(b,'dm.accept',{id:thread},'FIX64-ACCEPT');assert.equal(run(b,'dm',{folder:'messages'}).total,1);assert.equal(run(b,'dm',{folder:'requests'}).total,0);
 s.Atomic(()=>{delete s.DB().directThreads[thread].pendingTo;delete s.DB().directThreads[thread].initiatorId;});assert.equal(run(b,'dm',{folder:'messages'}).items[0].id,thread,'legacy threads stay inbox');
 run(b,'activity.settings.save',{messageAudience:'NONE'});rejected(()=>run(c,'dm.send',{id:thread,text:'설정 후 보내기'}),/INTERACTION_UNAVAILABLE/);assert.equal(run(c,'dmthread',{id:thread}).thread.canSend,false);run(b,'activity.settings.save',{messageAudience:'EVERYONE'});
 rejected(()=>run(c,'dm.send',{id:thread,text:'금지어 포함'}),/INTERACTION_UNAVAILABLE/);
 const declined=run(d,'dm.open',{memberId:own(b).id}).thread.id;run(d,'dm.send',{id:declined,text:'삭제할 요청'},'FIX64-DELETE-SECRET');run(b,'dm.decline',{id:declined,confirmed:true});assert.equal(run(d,'dmthread',{id:declined}).thread.deleted,true);assert.equal(snapshot().includes('삭제할 요청'),false);assert.deepEqual(run(d,'dm.send',{id:declined,text:'삭제할 요청'},'FIX64-DELETE-SECRET').messages,[]);
 const reply=run(a,'dm.open',{memberId:own(d).id}).thread.id;run(a,'dm.send',{id:reply,text:'안녕'});run(d,'dm.send',{id:reply,text:'답장'});assert.equal(run(d,'dmthread',{id:reply}).thread.isRequest,false);
 const stored=db.BuildDatabaseObject();assert.equal(db.ImportDatabaseObject(stored),true);assert.equal(run(a,'activity.settings').preferences.displayCurrency,'USD');assert.equal(run(a,'people').items.some(x=>x.id===own(c).id),false);assert.equal(run(b,'dmthread',{id:thread}).messages[0].text,'새 대화');
 before=snapshot();run(a,'people');run(a,'activity.settings');run(a,'account.list',{kind:'closeFriends',candidates:true});run(b,'dm',{folder:'messages'});assert.equal(snapshot(),before,'all new reads are pure');
 assert.equal(db.SaveDatabase(),true);const databasePath=require.resolve('../storage/database'),storePath=require.resolve('../services/member/store');const check=require('node:child_process').spawnSync(process.execPath,['-e',`require(${JSON.stringify(databasePath)}).LoadDatabase();const a=require('node:assert/strict'),s=require(${JSON.stringify(storePath)}),p=s.ProfileById('${own(a).id}');a.equal(p.displayCurrency,'USD');a.ok(p.dismissedPeople.includes('${own(c).id}'));a.equal(s.DB().directThreads['${thread}'].messages[0].text,'새 대화');a.equal(s.DB().directThreads['${declined}'].deletedAt>0,true);`],{cwd:process.cwd(),env:process.env,encoding:'utf8',timeout:20000});assert.equal(check.status,0,check.stdout+check.stderr);
 console.log('FIX64 SOCIAL SETTINGS PASS: authenticated suggestions, removed note API/projections, typed settings, account-list isolation, interaction enforcement, request inbox/search/accept/decline, legacy threads, replay, rollback and persistence.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
