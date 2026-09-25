'use strict';
const s=require('./store');
function Grant(body,actor){
 // One explicit member, one immutable request. The persisted operation and audit
 // ledger are committed with the balance so a timeout/restart cannot double pay.
 if(Object.keys(body).some(key=>!['action','accountId','amount','reason','requestId','confirmed','confirmedAccountId'].includes(key)))s.Fail('INPUT_INVALID');
 if(typeof body.accountId!=='string')s.Fail('MEMBER_NOT_FOUND');
 if(typeof body.requestId!=='string')s.Fail('REQUEST_ID_INVALID');
 if(body.confirmed!==true||body.confirmedAccountId!==body.accountId)s.Fail('ADMIN_CONFIRM_REQUIRED');
 const amount=s.Money(body.amount,1,Number.MAX_SAFE_INTEGER);
 if(typeof body.reason!=='string')s.Fail('ADMIN_REASON_REQUIRED');const reason=s.Text(body.reason,500,true);if(reason.length<3)s.Fail('ADMIN_REASON_REQUIRED');
 if(typeof actor!=='string'||!actor.trim()||actor.length>200)s.Fail('ADMIN_ONLY');
 const canonical={accountId:body.accountId,amount,reason};
 return s.Operation({id:'ADMIN_WALLET_GRANT'},body.requestId,'wallet.grant',canonical,()=>{
  const p=s.ProfileById(body.accountId);if(!p)s.Fail('MEMBER_NOT_FOUND');if(p.blocked)s.Fail('ACCOUNT_BLOCKED');
  const row=s.Ledger(p,amount,'ADMIN_GRANT',body.requestId);
  Object.assign(row,{actor,reason,requestId:body.requestId,memberHandle:'@'+s.Handle(p)});
  return {...row,nickname:p.nickname};
 });
}
module.exports={Grant};
