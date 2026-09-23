'use strict';
// Real authenticated purchase/use, persisted appearance, rollback, replay, and
// backward-compatible two-color requests. UI checks complement runtime coverage.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix68-title-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),store=require('../services/member/store'),hub=require('../services/member/service'),database=require('../storage/database');
let n=0;const run=(c,action,body={},id)=>hub.Execute(c,id||'FIX68-TITLE-'+(++n),action,body),snapshot=()=>JSON.stringify(store.DB());
function client(num){
 const id=String(num).padStart(16,'0'),key='FIX68-TITLE-DEVICE-'+num;
 const c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};
 state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));
 const lm=require('../license/licenseManager');c.licenseKey=lm.CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;
}
function unchanged(fn,pattern){const before=snapshot();assert.throws(fn,pattern);assert.equal(snapshot(),before);}
try{
 const a=client(1),b=client(2);run(a,'me');run(b,'me');
 const post=run(a,'post.create',{body:'투명 칭호 배경 시험'}).post;run(a,'badge.select',{id:'POSTS_1'});
 store.Atomic(()=>{store.Account(a).points=10000;});
 const shop=run(a,'shop'),offer=shop.items.find(item=>item.id==='TITLE_COLOR');assert.equal(offer.price,500);assert.match(offer.description,/배경/);
 const purchase=()=>run(a,'shop.purchase',{itemId:'TITLE_COLOR',revision:shop.rules.revision});purchase();
 const colors={id:'POSTS_1',color:'#123abc',iconColor:'#456def',backgroundColor:'#aabbcc'};
 for(const value of [null,42,[],{},'#123','#00FF00CC','transparent'])unchanged(()=>run(a,'title.color',{...colors,backgroundColor:value}),/TITLE_COLOR_INVALID/);
 unchanged(()=>run(b,'title.color',{...colors,profileId:store.Account(a).id}),/NOT_OWNER/);
 const save=database.SaveDatabase;try{database.SaveDatabase=()=>false;unchanged(()=>run(a,'title.color',colors,'FIX68-BACKGROUND-SAVE'),/STORAGE_SAVE_FAILED/);}finally{database.SaveDatabase=save;}
 const result=run(a,'title.color',colors,'FIX68-BACKGROUND-SAVE');assert.equal(result.inventory.titleColors,0);assert.equal(result.publicProfile.titleBadge.backgroundColor,'#AABBCC');
 const paid=snapshot();run(a,'title.color',colors,'FIX68-BACKGROUND-SAVE');assert.equal(snapshot(),paid,'receipt replay cannot consume twice');
 run(a,'title.color',colors);assert.equal(run(a,'shop').inventory.titleColors,0,'same values consume nothing');
 const oldRequest={id:'POSTS_1',color:'#123ABC',iconColor:'#456DEF'};run(a,'title.color',oldRequest);assert.equal(store.PublicProfile(store.Account(a)).titleBadge.backgroundColor,'#AABBCC','legacy request must keep new background');
 const profileId=store.Account(a).id;
 for(const profile of [run(b,'member',{id:profileId}).profile,run(b,'live',{profiles:[profileId]}).profiles[0],run(b,'badges',{profileId}).profile])assert.equal(profile.titleBadge.backgroundColor,'#AABBCC');
 const feed=run(b,'feed').items||run(b,'feed').posts?.items;assert.ok(feed?.some(row=>row.id===post.id&&row.author?.titleBadge?.backgroundColor==='#AABBCC'),'feed exposes selected appearance');
 unchanged(()=>run(a,'title.color',{...oldRequest,backgroundColor:''}),/TITLE_COLOR_TICKET_REQUIRED/);
 purchase();const clear=run(a,'title.color',{...oldRequest,backgroundColor:''});assert.equal(clear.inventory.titleColors,0);assert.equal(clear.publicProfile.titleBadge.backgroundColor,'');
 purchase();run(a,'title.color',colors);purchase();const legacyChange=run(a,'title.color',{...oldRequest,color:'#112233'});assert.equal(legacyChange.publicProfile.titleBadge.backgroundColor,'#AABBCC');assert.equal(legacyChange.inventory.titleColors,0);
 const expected=store.PublicProfile(store.Account(a)).titleBadge;assert.equal(database.SaveDatabase(),true);
 const {spawnSync}=require('node:child_process');const utilsPath=require.resolve('../core/utils'),databasePath=require.resolve('../storage/database'),storePath=require.resolve('../services/member/store');const check=spawnSync(process.execPath,['-e',`const assert=require('node:assert/strict');require(${JSON.stringify(utilsPath)}).EnsureDirs();require(${JSON.stringify(databasePath)}).LoadDatabase();const s=require(${JSON.stringify(storePath)});assert.deepEqual(s.PublicProfile(s.ProfileById(${JSON.stringify(profileId)})).titleBadge,${JSON.stringify(expected)});`],{cwd:path.resolve(__dirname,'..'),env:process.env,encoding:'utf8',timeout:10000});assert.equal(check.status,0,check.stdout+check.stderr);
 const native=fs.readFileSync(path.join(__dirname,'../../MoaPlayApp_Android64/MoaPlayApp.Member.Widgets.inc'),'utf8');const badge=native.slice(native.indexOf('function HubTitleBadge('),native.indexOf('procedure HubGlassCardStyle'));
 assert.doesNotMatch(badge,/AddMemberSvg/);assert.match(badge,/TTextAlign.Center/);assert.match(badge,/Fill.Kind:=TBrushKind.None/);assert.match(badge,/Stroke.Kind:=TBrushKind.Solid/);assert.match(badge,/MemberTitleFill\(Raw\)/);
 console.log('FIX68 title background PASS: 3-color bundle single consumption, invalid/foreign rejection, failed-save rollback, replay, legacy preservation, transparent reset, public/live/feed projection, fresh-process persistence, centered icon-free translucent title.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
