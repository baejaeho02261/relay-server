'use strict';
const s=require('./store');
const REFUND_KIND='GAME_RETIREMENT_REFUND';
const GAMES=new Set(['CRASH','MINES','TOWER','HILO','BLACKJACK']);
// Only a committed negative ledger row proves a deducted stake. Historical
// result metadata, client input and round.betAmount are never credit sources.
function Pending(owner){
 const db=s.DB(),ledger=Object.values(db.ledger),rows=[];
 for(const p of owner?[owner]:Object.values(db.profiles))for(const [game,record] of Object.entries(p.casino||{})){
  const round=record?.active;
  if(!GAMES.has(game)||!round||round.retiredAt||round.game!==game||typeof round.id!=='string'||!round.id)continue;
  const money=ledger.filter(row=>row.accountId===p.id&&row.reference===round.id);
  const done=money.find(row=>(row.kind==='CASINO_PAYOUT'||row.kind===REFUND_KIND||row.kind==='CASINO_REFUND')&&Number.isSafeInteger(row.amount)&&row.amount>=0);
  const bets=money.filter(row=>row.kind==='CASINO_BET'&&row.game===game&&Number.isSafeInteger(row.amount)&&row.amount<0);
  if(!done&&(!bets.length||!bets.some(row=>row.id===round.betId)))continue;
  const amount=done?0:bets.reduce((total,row)=>total-BigInt(row.amount),0n);
  if(typeof amount==='bigint'&&amount>BigInt(Number.MAX_SAFE_INTEGER))s.Fail('BALANCE_INVALID');
  rows.push({accountId:p.id,game,id:round.id,amount:Number(amount),betIds:bets.map(row=>row.id),settledId:done?.id||''});
 }
 return rows;
}
function HasHeadroom(p,amount){
 const reserved=s.ReservedBalance(p),next=p.balance+amount;
 return Number.isSafeInteger(p.balance)&&p.balance>=0&&Number.isSafeInteger(reserved)&&reserved>=0&&
  Number.isSafeInteger(next)&&next>=0&&Number.isSafeInteger(next+reserved);
}
// Call inside the existing mutation transaction. A saturated wallet keeps an
// explicit pending credit; it cannot prevent other members or the server from
// starting. No balance cap or pending-withdrawal reservation is bypassed.
function Apply(pending){
 let refunded=0,reconciled=0,deferred=0;const owners=new Set();
 for(const row of pending){
  const p=s.ProfileById(row.accountId),round=p.casino[row.game].active;owners.add(p.id);
  if(row.amount>0&&!HasHeadroom(p,row.amount)){
   round.retirementStatus='WAITING_FOR_HEADROOM';p.retirementRefundPending=true;deferred++;continue;
  }
  let ledgerId=row.settledId;
  if(row.amount>0){
   const ledger=s.Ledger(p,row.amount,REFUND_KIND,row.id);
   Object.assign(ledger,{game:row.game,betIds:row.betIds,reason:'FEATURE_RETIRED',virtual:true,redeemable:false});ledgerId=ledger.id;refunded++;
  }
  // Keep the original round for audit/recovery; only execution is retired.
  round.retiredAt=Date.now();round.retirementLedgerId=ledgerId;round.retirementStatus=row.amount>0?'REFUNDED':'ALREADY_SETTLED';reconciled++;
 }
 for(const id of owners){
  const p=s.ProfileById(id);
  if(!Object.values(p.casino||{}).some(record=>record.active?.retirementStatus==='WAITING_FOR_HEADROOM'&&!record.active?.retiredAt))delete p.retirementRefundPending;
 }
 return {refunded,reconciled,deferred};
}
function Retry(p){return p.retirementRefundPending?Apply(Pending(p)):{refunded:0,reconciled:0,deferred:0};}
function Ensure(owner){
 const pending=Pending(owner),needed=pending.some(row=>{
  const p=s.ProfileById(row.accountId),round=p.casino[row.game].active;
  return !row.amount||HasHeadroom(p,row.amount)||round.retirementStatus!=='WAITING_FOR_HEADROOM'||!p.retirementRefundPending;
 });
 if(!needed)return {refunded:0,reconciled:0,deferred:pending.length};
 return s.Atomic(()=>Apply(Pending(owner)));
}
module.exports={Ensure,Retry,REFUND_KIND};
