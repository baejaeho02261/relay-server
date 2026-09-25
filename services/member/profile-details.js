'use strict';
const s=require('./store'),state=require('../../core/state');
const LIMITS={links:5,banners:3,grid:200};
const FIELDS=['links','banners','gridOrder','aiProfile','accountType','showVerification'];
function Url(value,reason){
 if(typeof value!=='string'||value.length>2048||/[\u0000-\u0020\u007f]/.test(value))s.Fail(reason);
 let url;try{url=new URL(value);}catch(_){s.Fail(reason);}
 if(!['http:','https:'].includes(url.protocol)||!url.hostname||url.username||url.password)s.Fail(reason);
 return url.href;
}
function Text(value,max,reason){if(typeof value!=='string'||!value.trim()||[...value].length>max)s.Fail(reason);return s.Text(value,max*2,true);}
function BannerTarget(p,value){
 const direct=s.Resolve(value);if(direct)return direct;
 if(typeof value!=='string'||!value.trim()||value.length>128)return null;
 const label=value.trim().toLocaleLowerCase(),settings=require('./activity-settings');
 const matches=Object.values(s.DB().profiles).filter(target=>settings.Eligible(p,target)&&require('./identity').PublicAccount(target).accountLabel.toLocaleLowerCase()===label);
 // Provider display names are not unique identities. Never pick the first
 // account when several names match; persisted links always use stable IDs.
 return matches.length===1?matches[0]:null;
}
function Fields(p,body){
 const next={};
 for(const key of FIELDS){if(!Object.hasOwn(body,key))continue;const value=body[key];
  if(['aiProfile','showVerification'].includes(key)){if(typeof value!=='boolean')s.Fail('INPUT_INVALID');next[key]=value;}
  if(key==='accountType'){if(!['PERSONAL','CREATOR','BUSINESS'].includes(value))s.Fail('INPUT_INVALID');next[key]=value;}
  if(key==='links'){
   if(!Array.isArray(value)||value.length>LIMITS.links)s.Fail('PROFILE_LINK_INVALID');
   next.links=value.map(row=>{if(!row||Array.isArray(row)||typeof row!=='object'||Object.keys(row).some(k=>!['title','url'].includes(k)))s.Fail('PROFILE_LINK_INVALID');return {title:Text(row.title,60,'PROFILE_LINK_INVALID'),url:Url(row.url,'PROFILE_LINK_INVALID')};});
   if(new Set(next.links.map(x=>x.url)).size!==next.links.length)s.Fail('PROFILE_LINK_INVALID');
  }
  if(key==='banners'){
   if(!Array.isArray(value)||value.length>LIMITS.banners)s.Fail('PROFILE_BANNER_INVALID');
   next.banners=value.map(row=>{
    if(!row||Array.isArray(row)||typeof row!=='object'||!['music','profile'].includes(row.kind)||Object.keys(row).some(k=>!['kind','title','url','memberId','handle','accountLabel'].includes(k)))s.Fail('PROFILE_BANNER_INVALID');
    const title=Text(row.title,60,'PROFILE_BANNER_INVALID');
    if(row.kind==='music'){if(row.memberId!==undefined)s.Fail('PROFILE_BANNER_INVALID');return {kind:'music',title,url:Url(row.url,'PROFILE_BANNER_INVALID')};}
    if(row.url!==undefined)s.Fail('PROFILE_BANNER_INVALID');const target=BannerTarget(p,row.memberId);
    if(!require('./activity-settings').Eligible(p,target))s.Fail('PROFILE_BANNER_INVALID');
    return {kind:'profile',title,memberId:target.id};
   });
  }
  if(key==='gridOrder'){
   if(!Array.isArray(value)||value.length>LIMITS.grid||new Set(value).size!==value.length||value.some(id=>typeof id!=='string'||id.length>80))s.Fail('PROFILE_GRID_INVALID');
   if(value.some(id=>{const row=s.DB().posts[id];return !row||row.accountId!==p.id||row.deleted||row.hidden;}))s.Fail('PROFILE_GRID_INVALID');
   next.gridOrder=[...value];
  }
 }
 return next;
}
let verificationSnapshot=null,verificationCache=new Map();
function Verification(p){
 // A single index per source snapshot prevents every feed author projection
 // from scanning all device identities. It is never persisted or trusted input.
 const signature=[s.DB(),s.DB().revision,state.licenses,state.licenseRevision,state.clientIdentities.size,state.clientInstallations.size,Math.floor(Date.now()/1000)];
 if(!verificationSnapshot||signature.some((value,index)=>value!==verificationSnapshot[index])){
  verificationSnapshot=signature;verificationCache=new Map();
  const index=require('./identity').MemberIndex(),manager=require('../../license/licenseManager');
  for(const license of state.licenses.values()){
   const member=index.get(license.boundClient);
   if(member&&!member.blocked&&manager.GetLicenseStatus(license)==='BOUND')verificationCache.set(member.id,true);
  }
 }
 // Device approval is MoaPlay access, never personal-identity or Meta verification.
 const approved=!p.blocked&&verificationCache.has(p.id);
 return {status:approved?'DEVICE_AUTHENTICATED':'UNVERIFIED',label:approved?'MoaPlay 기기 승인':'기기 승인 내역 없음',verified:false,deviceApproved:approved};
}
function Public(p,own=false){
 return {links:(p.links||[]).map(({title,url})=>({title,url})),banners:(p.banners||[]).filter(row=>row.kind!=='profile'||!!s.ProfileById(row.memberId)&&!s.ProfileById(row.memberId).blocked&&!require('./socialActions').Blocked(p.id,row.memberId)).map(row=>row.kind==='profile'?{...row,handle:s.Handle(s.ProfileById(row.memberId)),accountLabel:require('./identity').PublicAccount(s.ProfileById(row.memberId)).accountLabel}:{...row}),aiProfile:p.aiProfile===true,accountType:['CREATOR','BUSINESS'].includes(p.accountType)?p.accountType:'PERSONAL',showVerification:p.showVerification===true,verification:Verification(p),...(own?{gridOrder:(p.gridOrder||[]).filter(id=>{const row=s.DB().posts[id];return row?.accountId===p.id&&!row.deleted&&!row.hidden;})}:{})};
}
function Read(p,body={}){return {profile:s.PublicProfile(p,true),posts:require('./profile-activity').Page(p,p,{...body,activity:'posts',postCards:false,limit:LIMITS.grid},LIMITS.grid),limits:{...LIMITS}};}
function Save(p,body={}){
 const keys=Object.keys(body).filter(key=>!key.startsWith('_'));if(!keys.some(key=>FIELDS.includes(key))||keys.some(key=>!FIELDS.includes(key)&&key!=='expectedProfileRevision'))s.Fail('INPUT_INVALID');
 if(body.expectedProfileRevision!==undefined&&(!Number.isSafeInteger(body.expectedProfileRevision)||body.expectedProfileRevision!==Math.max(p.profileRevision||0,p.avatarRevision||0)))s.Fail('PROFILE_CHANGED');
 const patch=Fields(p,body);Object.assign(p,patch);p.profileRevision=Math.max(p.profileRevision||0,p.avatarRevision||0)+1;
 return {profile:s.PublicProfile(p,true),publicProfile:s.PublicProfile(p,false,p)};
}
module.exports={Fields,Read,Save,Public,Verification,LIMITS};
