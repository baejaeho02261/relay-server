'use strict';
// Mentions are derived exclusively from visible user text. Persist account IDs
// so a later handle change cannot redirect an existing mention to somebody else.
const s=require('./store');
const MAX_MEMBERS=10;
function Previous(value,at){
 if(!at)return '';
 const low=value.charCodeAt(at-1),high=at>1?value.charCodeAt(at-2):0;
 return value.slice(at-(low>=0xdc00&&low<=0xdfff&&high>=0xd800&&high<=0xdbff?2:1),at);
}
function Tokens(text){
 const value=String(text||''),out=[],urls=[...String(text||'').matchAll(/(?:[a-z][a-z0-9+.-]*:\/\/|mailto:|www\.)[^\s<>"']+/gi)].map(match=>[match.index,match.index+match[0].length]);
 // Consume the entire ASCII handle before checking length. An overlong name
 // must never turn into a different account's valid 24-character prefix.
 for(const match of value.matchAll(/@([a-z0-9_][a-z0-9_.]*)/gi)){
  const at=match.index,handle=match[1].toLowerCase(),before=Previous(value,at);
  if(before&&/[\p{L}\p{N}_.%+\-@/\\:?=&]/u.test(before)||value[at+match[0].length]==='@'||urls.some(([from,to])=>at>=from&&at<to))continue;
  // This also excludes mailto links and URLs with punctuation before @.
  const token=value.slice(0,at).match(/[^\s<>"'\[\](){}]*$/)?.[0]||'';
  if(/(?:[a-z][a-z0-9+.-]*:\/\/|mailto:|www\.)/i.test(token))continue;
  if(handle.length<3||handle.length>24)continue;
  out.push({handle,start:at,length:match[0].length});
 }
 return out;
}
function Eligible(actor,target){
 return !!actor&&!!target&&!actor.blocked&&!target.blocked&&!require('./socialActions').Blocked(actor.id,target.id)&&(actor.id===target.id||!require('./activity-settings').Has(target,'restricted',actor.id));
}
function Capture(actor,...texts){
 const members=new Map();
 for(const text of texts)for(const {handle} of Tokens(text)){
  const target=s.Resolve('@'+handle);if(!Eligible(actor,target))continue;
  const previous=members.get(target.id);
  if(previous){if(!previous.textHandles.includes(handle))previous.textHandles.push(handle);continue;}
  if(members.size>=MAX_MEMBERS)continue;
  members.set(target.id,{id:target.id,textHandles:[handle]});
 }
 return [...members.values()];
}
function Public(refs,actor,viewer){
 if(!actor||!viewer)return [];
 const seen=new Set(),result=[];
 for(const ref of Array.isArray(refs)?refs:[]){
  if(result.length>=MAX_MEMBERS)break;
  const target=s.ProfileById(ref.id);
  if(seen.has(ref.id)||!Eligible(actor,target)||!Eligible(viewer,target))continue;
  const textHandles=[...new Set((ref.textHandles||[]).filter(handle=>typeof handle==='string'&&/^[a-z0-9_][a-z0-9_.]{2,23}$/.test(handle)))];
  if(!textHandles.length)continue;
  seen.add(ref.id);result.push({id:target.id,handle:s.Handle(target),textHandle:textHandles[0],textHandles});
 }
 return result;
}
function ContentTexts(row){return [row.title,row.body??row.text,row.poll?.question,...(row.poll?.options||[]).map(option=>option.text)];}
function CaptureContent(actor,row){return Capture(actor,...ContentTexts(row));}
function Members(row,viewer,kind='content'){
 const actor=kind==='profile'?row:s.ProfileById(row.accountId||row.senderId);
 const refs=kind==='profile'?row.bioMentions:row.mentions;
 // Existing records are projected safely without silently mutating storage.
 const fallback=kind==='profile'?[row.bio]:ContentTexts(row);
 return Public(refs===undefined?Capture(actor,...fallback):refs,actor,viewer);
}
function FilterProjection(value,viewer){
 if(!value||typeof value!=='object')return value;
 if(Array.isArray(value))return value.map(item=>FilterProjection(item,viewer));
 const copy={...value};
 for(const [key,item] of Object.entries(copy)){
  if(key==='mentionMembers'&&Array.isArray(item)){
   const actor=s.ProfileById(value.author?.id)||s.ProfileById(s.DB().posts[value.id]?.accountId)||s.ProfileById(s.DB().comments[value.id]?.accountId)||(typeof value.id==='string'&&value.id.startsWith('USR-')?s.ProfileById(value.id):null);
   copy[key]=item.filter(ref=>{const target=s.ProfileById(ref.id);return Eligible(viewer,target)&&(!actor||Eligible(actor,target));});
  }else if(item&&typeof item==='object')copy[key]=FilterProjection(item,viewer);
 }
 return copy;
}
module.exports={Tokens,Capture,CaptureContent,ContentTexts,Public,Members,Eligible,FilterProjection,MAX_MEMBERS};
