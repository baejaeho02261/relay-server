'use strict';
// Compatibility migration only. No withdrawal request, payout or bank interface.
const s=require('./store');
function Pending(p){return Object.values(s.DB().withdrawRequests||{}).filter(x=>x.status==='PENDING'&&(!p||x.accountId===p.id));}
function Ensure(p){
 const rows=Pending(p);if(!rows.length)return {released:0};
 return s.Atomic(()=>{let released=0;
  for(const candidate of rows){
   const row=s.DB().withdrawRequests[candidate.id],owner=s.ProfileById(row.accountId);if(!owner)continue;
   const money=Object.values(s.DB().ledger).filter(x=>x.accountId===owner.id&&x.reference===row.id);
   const reserved=money.find(x=>x.id===row.paymentId&&x.kind==='WITHDRAW_RESERVE'&&x.amount===-row.amount&&Number.isSafeInteger(row.amount)&&row.amount>0);
   const existing=money.find(x=>['WITHDRAW_RELEASE','WITHDRAW_RETIREMENT_RELEASE'].includes(x.kind)&&x.amount===row.amount);
   // Only an actual negative ledger reservation can be returned. Already paid
   // requests never enter this migration; invalid legacy rows remain auditable.
   row.status='RETIRED';row.retiredAt=Date.now();row.retirementReason=reserved?'FEATURE_RETIRED':'RESERVATION_NOT_VERIFIED';
   if(reserved&&!existing){const credit=s.Ledger(owner,row.amount,'WITHDRAW_RETIREMENT_RELEASE',row.id);row.refundId=credit.id;released++;}
   else if(existing)row.refundId=existing.id;
  }return {released};
 });
}
module.exports={Ensure};
