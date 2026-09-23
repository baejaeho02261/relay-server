'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix65-news-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),social=require('../services/member/social');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX65-NEWS-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
const run=(c,action,body={})=>hub.Execute(c,'FIX65-NEWS-'+(++serial),action,body);
try{
 const a=client(6511),b=client(6512),owner=run(a,'me').profile,viewer=run(b,'me').profile;
 const article=social.SaveNews({title:'새 소식',body:'첫 줄\r\n\r\n  둘째 줄\t  셋째 줄 '+ '🎉'.repeat(200),category:'NOTICE',published:true});
 const personal=social.SaveNews({title:'개인 공지',body:'PRIVATE_SECRET_ONLY',category:'ALERT',published:true,audience:owner.id});
 const unpublished=social.SaveNews({title:'작성 중',body:'DRAFT_SECRET_ONLY',category:'NOTICE',published:false});
 const deleted=social.SaveNews({title:'삭제 소식',body:'DELETED_SECRET_ONLY',category:'NOTICE',published:true});
 const future=social.SaveNews({title:'예약 소식',body:'SCHEDULED_SECRET_ONLY',category:'EVENT',published:true});
 s.Atomic(()=>{Object.assign(s.DB().news[article.id],{image:'RETIRED_IMAGE_SECRET',imageThumb:'RETIRED_THUMB_SECRET',details:{secret:'RETIRED_DETAIL_SECRET'},privateInternal:'ADMIN_SECRET'});s.DB().news[future.id].publishAt=Date.now()+86400000;s.DB().news[deleted.id].deleted=true;});
 const before=JSON.stringify(s.DB()),list=run(b,'news',{summary:true}),item=list.items.find(x=>x.id===article.id);
 assert.equal(JSON.stringify(s.DB()),before,'summary read must not mutate storage or mark the article as read');assert.equal(list.total,1);assert.equal(item.summary,'첫 줄 둘째 줄 셋째 줄 '+'🎉'.repeat(126));assert.equal([...item.summary].length,140);assert.ok(!/[\r\n\t]/.test(item.summary));assert.ok(!/\p{Surrogate}/u.test(item.summary));
 for(const key of ['body','image','imageThumb','details','privateInternal'])assert.equal(item[key],undefined,key+' stays omitted');assert.equal(item.views,0);assert.equal(item.unread,true);
 for(const secret of ['PRIVATE_SECRET_ONLY','DRAFT_SECRET_ONLY','SCHEDULED_SECRET_ONLY','DELETED_SECRET_ONLY','RETIRED_','ADMIN_SECRET'])assert.ok(!JSON.stringify(list).includes(secret));
 assert.equal(run(a,'news',{summary:true}).items.find(x=>x.id===personal.id).summary,'PRIVATE_SECRET_ONLY','a targeted summary is visible only to its authorized member');
 for(const id of [personal.id,unpublished.id,future.id,deleted.id])assert.throws(()=>run(b,'article',{id}),/NEWS_NOT_FOUND/);
 assert.equal(run(b,'news',{summary:true,_ifNoneMatch:list.contentTag}).unchanged,true);
 s.Atomic(()=>{s.DB().news[article.id].body='변경된\n요약';s.DB().news[article.id].revision++;});
 const changed=run(b,'news',{summary:true,_ifNoneMatch:list.contentTag});assert.notEqual(changed.contentTag,list.contentTag);assert.equal(changed.items[0].summary,'변경된 요약');
 const detail=run(b,'article',{id:article.id});assert.equal(detail.article.body,'변경된\n요약');assert.equal(detail.article.image,undefined);assert.equal(run(b,'news',{summary:true}).items[0].unread,false);
 assert.equal(social.PublicNews({id:'empty',body:' \n\t '},true).summary,'');assert.equal(social.PublicNews({id:'legacy'},true).summary,'');assert.equal(social.PublicNews({id:'full',body:'원문'},false).body,'원문');assert.equal(social.PublicNews({id:'full',body:'원문'},false).summary,undefined);
 assert.equal(list.viewer.id,viewer.id);console.log('FIX65 NEWS SUMMARY PASS: bounded Unicode preview, whitespace normalization, preserved full article, audience/publish/deletion privacy, retired-field omission, pure read and content-token refresh.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
