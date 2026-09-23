'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix66-mentions-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),db=require('../storage/database'),lm=require('../license/licenseManager'),mentions=require('../services/member/mentions');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX66-MENTION-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=lm.CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
const run=(c,action,body={},id)=>hub.Execute(c,id||'FIX66-MENTION-'+(++serial),action,body),own=c=>s.Account(c),snapshot=()=>JSON.stringify(s.DB()),ids=result=>result.mentionMembers.map(x=>x.id);
function reject(fn,error){const before=snapshot();assert.throws(fn,error);assert.equal(snapshot(),before,'rejected change must roll back state');}
function post(c,body,id){s.Atomic(()=>{own(c).last_post=0;});return run(c,'post.create',body,id).post;}
function comment(c,body){s.Atomic(()=>{own(c).last_comment=0;});return run(c,'comment.create',body).comment;}
try{
 const a=client(6601),b=client(6602),c=client(6603),d=client(6604);for(const item of [a,b,c,d])run(item,'me');
 reject(()=>run(a,'profile.note',{text:'삭제된 메모 API'}),/UNKNOWN_ACTION/);assert.equal(run(a,'me').profile.note,undefined);
 for(const [item,handle] of [[a,'alice'],[b,'bob'],[c,'carol']])run(item,'profile.save',{handle});
 const samples=[['@bob',['bob']],['안녕 @BOB, (@carol)!',['bob','carol']],['abc@bob.example user+name@bob.example',[]],['https://example.com/@bob https://example.com/#(@carol) mailto:@bob www.example.com/@carol',[]],['@@bob @bob@carol @'+('b'.repeat(25)),[]],['@ab @b._ @bob.',['b._','bob.']],['🙂 @bob\n@carol',['bob','carol']],['한글@bob x_@carol 𝒜@bob 𐐀@carol',[]]];
 for(const [text,expected] of samples){const parsed=mentions.Tokens(text);assert.deepEqual(parsed.map(x=>x.handle),expected,text);for(const token of parsed)assert.equal(text.slice(token.start,token.start+token.length).toLowerCase(),'@'+token.handle);}
 const unknown=post(a,{body:'@does_not_exist abc@bob https://example.test/@carol'});assert.deepEqual(ids(unknown),[]);assert.deepEqual(unknown.taggedMemberIds,[]);
 const text=post(a,{title:'오늘 @bob',body:'만나요 @BOB (@carol)',mentionMembers:[{id:own(d).id}],mentions:[{id:own(d).id,textHandles:['forged']}],taggedMembers:[{id:own(d).id}]});assert.deepEqual(ids(text),[own(b).id,own(c).id]);assert.deepEqual(text.taggedMemberIds,[],'text-only mentions do not create media tags');
 assert.deepEqual(Object.keys(text.mentionMembers[0]).sort(),['handle','id','textHandle','textHandles']);assert.equal(text.mentionMembers[0].textHandle,'bob');
 const gifId=require('../services/member/gifs').List().items[0].id;
 const media=post(a,{body:'함께한 @bob',gifId,taggedMemberIds:[own(c).id]});assert.deepEqual(media.taggedMemberIds,[own(c).id,own(b).id]);assert.ok(run(b,'me',{activity:'tagged'}).posts.items.some(x=>x.id===media.id));
 let edited=run(a,'post.edit',{id:media.id,revision:0,body:'@carol 만 남아요'}).post;assert.deepEqual(ids(edited),[own(c).id]);assert.deepEqual(edited.taggedMemberIds,[own(c).id]);assert.equal(run(b,'me',{activity:'tagged'}).posts.items.some(x=>x.id===media.id),false,'removed inline mention leaves tagged gallery');
 edited=run(a,'post.edit',{id:media.id,revision:1,body:'@bob 다시',taggedMemberIds:[]}).post;assert.deepEqual(edited.taggedMemberIds,[own(b).id]);assert.deepEqual(s.DB().posts[media.id].manualTaggedMemberIds,[]);
 edited=run(a,'post.edit',{id:media.id,revision:2,body:'@bob 사진 제거',gifId:''}).post;assert.deepEqual(ids(edited),[own(b).id]);assert.deepEqual(edited.taggedMemberIds,[]);
 reject(()=>run(a,'post.edit',{id:media.id,revision:3,body:'불가능',taggedMemberIds:[own(b).id]}),/PROFILE_TAG_INVALID/);
 // Explicit FIX65 tags remain supported and never trust submitted display data.
 const manual=post(a,{body:'기존 태그',gifId,taggedHandles:['@bob']});assert.deepEqual(manual.taggedMemberIds,[own(b).id]);run(a,'post.edit',{id:manual.id,revision:0,body:'본문만 수정'});assert.deepEqual(s.DB().posts[manual.id].taggedMemberIds,[own(b).id]);
 const poll=post(a,{poll:{question:'누구와 함께 갈까요 @bob',options:['@alice','@carol']}});assert.deepEqual(ids(poll),[own(b).id,own(a).id,own(c).id]);
 const reply=comment(b,{postId:text.id,body:'@alice 확인했어요'});assert.deepEqual(ids(reply),[own(a).id]);const nested=comment(c,{postId:text.id,parentId:reply.id,body:'저도요 @bob'});assert.deepEqual(ids(nested),[own(b).id]);assert.equal(nested.parentId,reply.id);
 assert.deepEqual(ids(run(b,'comment.edit',{id:reply.id,revision:0,body:'태그 없이 수정'}).comment),[]);
 const bio=run(a,'profile.save',{bio:'함께 만들어요 @bob'});assert.deepEqual(ids(bio.profile),[own(b).id]);assert.deepEqual(ids(bio.publicProfile),[own(b).id]);assert.deepEqual(ids(run(c,'member',{id:own(a).id}).profile),[own(b).id]);
 const refreshed=run(a,'profile.details.save',{aiProfile:true});assert.deepEqual(ids(refreshed.publicProfile),[own(b).id]);
 const dm=run(a,'dm.open',{memberId:own(b).id});const sent=run(a,'dm.send',{id:dm.thread.id,text:'@carol 에게도 물어볼까요?'});assert.deepEqual(ids(sent.messages.at(-1)),[own(c).id]);assert.deepEqual(ids(run(b,'dmthread',{id:dm.thread.id}).messages.at(-1)),[own(c).id]);
 // The same rules apply to current projections and immutable operation retries.
 const replayBody={body:'@bob @carol',gifId},replayId='FIX66-MENTION-REPLAY',replayPost=post(a,replayBody,replayId);const before=snapshot();assert.deepEqual(run(a,'post.create',replayBody,replayId).post,replayPost);assert.equal(snapshot(),before);
 run(b,'block.set',{id:own(c).id,blocked:true});assert.deepEqual(ids(run(c,'thread',{postId:text.id,countView:false}).post),[own(c).id]);assert.deepEqual(ids(run(c,'member',{id:own(a).id}).profile),[]);assert.deepEqual(ids(run(b,'dmthread',{id:dm.thread.id}).messages.at(-1)),[]);
 run(b,'block.set',{id:own(a).id,blocked:true});assert.deepEqual(ids(run(a,'post.create',replayBody,replayId).post),[own(c).id]);assert.equal(run(b,'me',{activity:'tagged'}).posts.items.some(x=>x.id===replayPost.id),false);
 run(b,'block.set',{id:own(a).id,blocked:false});run(b,'block.set',{id:own(c).id,blocked:false});run(b,'account.list.set',{kind:'restricted',memberId:own(a).id,enabled:true});assert.deepEqual(ids(post(a,{body:'@bob 제한됨'})),[]);run(b,'account.list.set',{kind:'restricted',memberId:own(a).id,enabled:false});
 run(a,'preferences.save',{profilePostsVisibility:'PRIVATE'});const privatePost=post(a,{body:'@bob',gifId});assert.deepEqual(privatePost.taggedMemberIds,[]);assert.equal(run(b,'me',{activity:'tagged'}).posts.items.some(x=>x.id===privatePost.id),false);run(a,'preferences.save',{profilePostsVisibility:'PUBLIC'});
 // First @handle stays bound to the original account after a permitted rename.
 const oldHandle=s.Handle(own(d)),renamed=post(a,{body:'@'+oldHandle});run(d,'profile.save',{handle:'dora'});let projected=run(a,'thread',{postId:renamed.id,countView:false}).post;assert.equal(projected.mentionMembers[0].id,own(d).id);assert.equal(projected.mentionMembers[0].handle,'dora');assert.equal(projected.mentionMembers[0].textHandle,oldHandle);
 const aliases=post(a,{body:'@dora @'+oldHandle});assert.equal(aliases.mentionMembers.length,1);assert.deepEqual(aliases.mentionMembers[0].textHandles,['dora',oldHandle]);
 // Ten distinct eligible targets, even with duplicate and unknown tokens.
 const extras=[];for(let n=6620;n<6631;n++){const x=client(n);run(x,'me');extras.push(own(x));}
 const capped=post(a,{body:'@missing '+extras.map(p=>'@'+s.Handle(p)).join(' ')});assert.equal(capped.mentionMembers.length,10);assert.equal(new Set(ids(capped)).size,10);
 // Save failures and invalid edits preserve original content and mention bindings.
 const oldSave=db.SaveDatabase;try{db.SaveDatabase=()=>false;reject(()=>run(a,'post.edit',{id:aliases.id,revision:0,body:'@bob'}),/STORAGE_SAVE_FAILED/);}finally{db.SaveDatabase=oldSave;}
 assert.equal(db.SaveDatabase(),true);const script=`require(${JSON.stringify(require.resolve('../storage/database'))}).LoadDatabase();const assert=require('node:assert/strict'),s=require(${JSON.stringify(require.resolve('../services/member/store'))}),m=require(${JSON.stringify(require.resolve('../services/member/mentions'))}),p=s.ProfileById('${own(a).id}');assert.equal(m.Members(s.DB().posts['${renamed.id}'],p)[0].id,'${own(d).id}');assert.equal(m.Members(s.DB().posts['${renamed.id}'],p)[0].handle,'dora');assert.deepEqual(m.Members(p,p,'profile').map(x=>x.id),['${own(b).id}']);assert.ok(s.DB().directThreads['${dm.thread.id}'].messages[0].mentions.length);`;
 const child=require('node:child_process').spawnSync(process.execPath,['-e',script],{cwd:process.cwd(),env:process.env,encoding:'utf8',timeout:20000});assert.equal(child.status,0,child.stdout+child.stderr);
 const pure=snapshot();run(a,'thread',{postId:aliases.id,countView:false});run(a,'me',{activity:'tagged'});run(c,'member',{id:own(a).id});run(a,'dmthread',{id:dm.thread.id});assert.equal(snapshot(),pure,'mention projections never write data');
 console.log('FIX66 MENTIONS PASS: lexical URL/email boundaries, authenticated post/comment/reply/bio/DM writes, inline media tagging and removal, legacy explicit tags, public-safe projections, block/restriction/privacy, immutable retries, handle identity, max 10, rollback, restart and pure reads.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
