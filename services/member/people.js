'use strict';
const s=require('./store');
function Query(value){if(value===undefined)return '';if(typeof value!=='string'||value.length>100)s.Fail('INPUT_INVALID');return s.Text(value,100).replace(/^@/,'').toLocaleLowerCase();}
function Matches(p,q){return !q||[p.nickname,s.Handle(p),require('./identity').PublicAccount(p).accountLabel].some(x=>String(x||'').toLocaleLowerCase().includes(q));}
function Page(rows,body={}){const offset=body.offset===undefined?0:body.offset,limit=body.limit===undefined?12:body.limit;if(!Number.isSafeInteger(offset)||offset<0||offset>100000||!Number.isSafeInteger(limit)||limit<1||limit>30)s.Fail('INPUT_INVALID');return {...s.Page(rows,{offset,limit},30),offset};}
function Public(p,target){return {...s.PublicProfile(target,false,p),isFollowing:require('./follows').IsFollowing(p.id,target.id)};}
function Read(p,body={}){
 const q=Query(body.q??body.query),dismissed=new Set(p.dismissedPeople||[]),settings=require('./activity-settings');
 const rows=Object.values(s.DB().profiles).filter(target=>settings.Eligible(p,target)&&!dismissed.has(target.id)&&!settings.Has(p,'muted',target.id)&&!settings.Has(p,'restricted',target.id)&&Matches(target,q));
 rows.sort((a,b)=>Number(require('./follows').IsFollowing(p.id,a.id))-Number(require('./follows').IsFollowing(p.id,b.id))||s.Handle(a).localeCompare(s.Handle(b)));
 const page=Page(rows,body);return {...page,q,items:page.items.map(target=>Public(p,target))};
}
function Dismiss(p,body){const target=s.Resolve(body.memberId);if(!require('./activity-settings').Eligible(p,target))s.Fail('MEMBER_NOT_FOUND');const ids=new Set(p.dismissedPeople||[]);ids.add(target.id);p.dismissedPeople=[...ids].slice(-1000);return {memberId:target.id,dismissed:true};}
module.exports={Read,Dismiss,Public,Query,Matches,Page};
