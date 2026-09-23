'use strict';
const s=require('./store');
const listKinds=['closeFriends','restricted','favorites','muted'];
const defaults={messageAudience:'EVERYONE',commentAudience:'EVERYONE',allowRepost:true,hideLikeCounts:false,hideShareCounts:false,hiddenWords:'',interactionLimit:false};
const audiences=['EVERYONE','FOLLOWING','NONE'];
function Values(p){const raw=p?.activitySettings||{};return Object.fromEntries(Object.entries(defaults).map(([key,value])=>[key,typeof raw[key]===typeof value?raw[key]:value]));}
function IDs(p,kind){return Array.isArray(p.accountLists?.[kind])?p.accountLists[kind]:[];}
function Has(p,kind,id){return IDs(p,kind).includes(id);}
function Kind(value){if(!listKinds.includes(value))s.Fail('INPUT_INVALID');return value;}
function Eligible(p,target){return !!target&&target.id!==p.id&&!target.blocked&&!require('./socialActions').Blocked(p.id,target.id);}
function Counts(p){return {...Object.fromEntries(listKinds.map(kind=>[kind,IDs(p,kind).filter(id=>Eligible(p,s.ProfileById(id))).length])),blocked:Object.values(s.DB().blocks).filter(x=>x.accountId===p.id).length};}
function Read(p){return {preferences:{...require('./preferences').Read(p),...Values(p)},profile:s.PublicProfile(p,true),counts:Counts(p),status:{plus:{active:false,available:false},verified:{active:false,available:false},account:{blocked:!!p.blocked}},capabilities:{people:true,notes:true,messageRequests:true,closeFriends:true,restrictions:true,muted:true,favorites:true,hiddenWords:true,stories:false,live:false,crossPosting:false,earlyAccess:false,tabletApp:false,parentalSupervision:false,professionalInsights:false,metaAssistant:false,threads:false,edits:false,metaProducts:false}};}
function Save(p,body){
 const basic=require('./preferences').Read(p),keys=Object.keys(body).filter(key=>!key.startsWith('_'));
 if(!keys.length||keys.some(key=>!Object.hasOwn(defaults,key)&&!Object.hasOwn(basic,key)||key==='currencyReference'))s.Fail('INPUT_INVALID');
 const next={...Values(p)},base={};
 for(const key of keys){const value=body[key];if(!Object.hasOwn(defaults,key)){base[key]=value;continue;}
  if(typeof value!==typeof defaults[key])s.Fail('INPUT_INVALID');
  if(['messageAudience','commentAudience'].includes(key)&&!audiences.includes(value))s.Fail('INPUT_INVALID');
  if(key==='hiddenWords'){if(value.length>1000||value.split(/[\n,]+/).filter(x=>x.trim()).length>50)s.Fail('INPUT_INVALID');next[key]=s.Text(value,1000);}else next[key]=value;
 }
 if(Object.keys(base).length)require('./preferences').Save(p,base);
 p.activitySettings=next;p.profileRevision=Math.max(p.profileRevision||0,p.avatarRevision||0)+1;
 return Read(p);
}
function List(p,body={}){
 const kind=Kind(body.kind),selected=new globalThis.Set(IDs(p,kind)),q=require('./people').Query(body.q);
 if(body.candidates!==undefined&&typeof body.candidates!=='boolean')s.Fail('INPUT_INVALID');
 const rows=Object.values(s.DB().profiles).filter(target=>Eligible(p,target)&&(body.candidates===true||selected.has(target.id))&&require('./people').Matches(target,q));
 rows.sort((a,b)=>Number(selected.has(b.id))-Number(selected.has(a.id))||s.Handle(a).localeCompare(s.Handle(b)));
 const page=require('./people').Page(rows,body);
 return {...page,kind,q,selectedCount:Counts(p)[kind],items:page.items.map(target=>({...require('./people').Public(p,target),selected:selected.has(target.id)}))};
}
function Set(p,body={}){
 const kind=Kind(body.kind),target=s.Resolve(body.memberId);
 if(typeof body.enabled!=='boolean'||!target||target.id===p.id)s.Fail('INPUT_INVALID');
 if(body.enabled&&!Eligible(p,target))s.Fail('MEMBER_NOT_FOUND');
 const ids=new globalThis.Set(IDs(p,kind));if(body.enabled)ids.add(target.id);else ids.delete(target.id);
 if(ids.size>1000)s.Fail('ACCOUNT_LIST_LIMIT');
 p.accountLists={...(p.accountLists||{}),[kind]:[...ids]};
 return {kind,memberId:target.id,enabled:ids.has(target.id),counts:Counts(p)};
}
function AudienceAllows(target,actor,key){if(target.id===actor.id)return true;const v=Values(target);return !Has(target,'restricted',actor.id)&&(!v.interactionLimit||require('./follows').IsFollowing(target.id,actor.id))&&(v[key]==='EVERYONE'||v[key]==='FOLLOWING'&&require('./follows').IsFollowing(target.id,actor.id));}
function ContainsHidden(p,text){const words=Values(p).hiddenWords.toLocaleLowerCase().split(/[\n,]+/).map(x=>x.trim()).filter(Boolean),value=String(text||'').toLocaleLowerCase();return words.some(word=>value.includes(word));}
function CanInteract(target,actor,kind,text=''){return !!target&&AudienceAllows(target,actor,kind==='message'?'messageAudience':'commentAudience')&&(target.id===actor.id||!ContainsHidden(target,text));}
function FeedVisible(p,post){return post.accountId===p.id||(!Has(p,'muted',post.accountId)&&!Has(p,'restricted',post.accountId)&&!ContainsHidden(p,[post.title,post.body].join('\n')));}
function CommentVisible(p,row){return row.accountId===p.id||(!Has(p,'restricted',row.accountId)&&!Has(p,'muted',row.accountId)&&!ContainsHidden(p,row.body));}
module.exports={Read,Save,List,Set,Values,IDs,Has,Counts,Eligible,CanInteract,ContainsHidden,FeedVisible,CommentVisible};
