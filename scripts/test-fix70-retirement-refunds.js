'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix70-refunds-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE=process.argv.includes('--json')?'json':'sqlite';require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),database=require('../storage/database'),retirement=require('../services/member/retirement');
const snapshot=()=>JSON.stringify(s.DB());
function addRound(p,game,id,amount,extra={}){
 const betId='PAY-'+id;p.casino[game]={active:{id,game,betId,betAmount:99999999,...extra}};
 s.DB().ledger[betId]={id:betId,accountId:p.id,reference:id,kind:'CASINO_BET',game,amount:-amount,at:1};
 return p.casino[game].active;
}
try{
 s.Atomic(()=>{
  const p=s.DB().profiles.TEST={id:'USR-RETIRE',balance:10000,points:123,eventSpins:2,casino:{},badgeProgress:{version:1,counts:{},seen:{},awards:{BACCARAT_1:{at:1,rewardPoints:50,rewardPaid:true}}}};
  addRound(p,'CRASH','CRASH',1000);addRound(p,'MINES','MINES',500);
  const round=addRound(p,'BLACKJACK','BLACKJACK',2000,{doubled:true,extraBetIds:['PAY-DOUBLE']});
  s.DB().ledger['PAY-DOUBLE']={id:'PAY-DOUBLE',accountId:p.id,reference:round.id,kind:'CASINO_BET',game:'BLACKJACK',amount:-2000,at:2};
  addRound(p,'HILO','SETTLED-LOSS',1000);s.DB().ledger.LOSS={id:'LOSS',accountId:p.id,reference:'SETTLED-LOSS',kind:'CASINO_PAYOUT',amount:0,at:3};
  addRound(p,'TOWER','ALREADY-REFUNDED',200);s.DB().ledger.REFUND={id:'REFUND',accountId:p.id,reference:'ALREADY-REFUNDED',kind:retirement.REFUND_KIND,amount:200,at:3};
  p.skillEvents={games:{DINO:{bestScore:30}}};s.DB().pointLedger.EARNED={id:'EARNED',accountId:p.id,kind:'EVENT_DINO',amount:30,at:1};
  const q=s.DB().profiles.UNPROVED={id:'USR-UNPROVED',balance:50,casino:{}};addRound(q,'CRASH','UNPROVED',200);s.DB().ledger['PAY-UNPROVED'].accountId='USR-SOMEONE-ELSE';
 });
 const initial=snapshot(),save=database.SaveDatabase;
 database.SaveDatabase=()=>false;
 assert.throws(()=>retirement.Ensure(),/STORAGE_SAVE_FAILED/,'failed durable save must stop startup');
 assert.equal(snapshot(),initial,'failed save restores every wallet, marker and ledger');database.SaveDatabase=save;
 const result=retirement.Ensure();assert.deepEqual(result,{refunded:3,reconciled:5,deferred:0});
 let p=s.ProfileById('USR-RETIRE');assert.equal(p.balance,15500,'only committed stakes are refunded, including both blackjack debits');assert.equal(p.points,123);assert.equal(p.eventSpins,2);
 assert.equal(s.ProfileById('USR-UNPROVED').balance,50,'another account ledger cannot authorize a refund');assert.ok(!s.ProfileById('USR-UNPROVED').casino.CRASH.active.retiredAt);
 assert.equal(p.casino.HILO.active.retirementStatus,'ALREADY_SETTLED','zero payout is still a completed loss');
 assert.equal(p.casino.TOWER.active.retirementStatus,'ALREADY_SETTLED');assert.equal(p.casino.BLACKJACK.active.extraBetIds[0],'PAY-DOUBLE');
 const refunds=Object.values(s.DB().ledger).filter(row=>row.kind===retirement.REFUND_KIND);assert.equal(refunds.length,4);assert.equal(refunds.find(row=>row.reference==='BLACKJACK').amount,4000);
 assert.deepEqual(p.badgeProgress.awards.BACCARAT_1,{at:1,rewardPoints:50,rewardPaid:true});assert.equal(s.DB().pointLedger.EARNED.amount,30);assert.equal(p.skillEvents.games.DINO.bestScore,30);
 const committed=snapshot();assert.deepEqual(retirement.Ensure(),{refunded:0,reconciled:0,deferred:0});assert.equal(snapshot(),committed,'restart/no-op must not rewrite or credit twice');
 database.LoadDatabase();assert.equal(s.ProfileById('USR-RETIRE').balance,15500,'refund survives database reload');assert.deepEqual(retirement.Ensure(),{refunded:0,reconciled:0,deferred:0});
 // If an older snapshot restores the active round but already has its refund
 // receipt, that ledger still blocks a duplicate credit independently of flags.
 s.Atomic(()=>{const r=s.ProfileById('USR-RETIRE').casino.CRASH.active;delete r.retiredAt;delete r.retirementStatus;delete r.retirementLedgerId;});
 assert.deepEqual(retirement.Ensure(),{refunded:0,reconciled:1,deferred:0});assert.equal(s.ProfileById('USR-RETIRE').balance,15500);
 // Reserved withdrawal restoration space must also be preserved atomically.
 s.Atomic(()=>{const p=s.DB().profiles.OVERFLOW={id:'USR-OVERFLOW',balance:Number.MAX_SAFE_INTEGER-50,casino:{}};addRound(p,'MINES','HEADROOM',100);});
 assert.deepEqual(retirement.Ensure(),{refunded:0,reconciled:0,deferred:1},'saturated wallet does not block server startup');
 const cap=snapshot();assert.deepEqual(retirement.Ensure(),{refunded:0,reconciled:0,deferred:1});assert.equal(snapshot(),cap,'waiting credit has no repeated write');
 assert.equal(s.ProfileById('USR-OVERFLOW').balance,Number.MAX_SAFE_INTEGER-50);assert.equal(s.ProfileById('USR-OVERFLOW').retirementRefundPending,true);
 s.Atomic(()=>{const p=s.ProfileById('USR-OVERFLOW');s.Ledger(p,-500,'PURCHASE','NEW-PASS');assert.deepEqual(retirement.Retry(p),{refunded:1,reconciled:1,deferred:0});});
 assert.equal(s.ProfileById('USR-OVERFLOW').balance,Number.MAX_SAFE_INTEGER-450);assert.ok(!s.ProfileById('USR-OVERFLOW').retirementRefundPending);
 assert.deepEqual(retirement.Ensure(),{refunded:0,reconciled:0,deferred:0});
 const source=fs.readFileSync(path.resolve(__dirname,'../server.js'),'utf8');assert.ok(source.indexOf(["require(","'./services/member/", "retirement').Ensure()"].join(''))>source.indexOf('LoadDatabase();'));assert.ok(source.indexOf(["require(","'./services/member/", "retirement').Ensure()"].join(''))<source.indexOf('const relayServer ='),'refund migration finishes before accepting traffic');
 console.log('FIX70 retirement refunds PASS ('+process.env.STORAGE_ENGINE+'): committed bet evidence, doubled stake, zero-payout exclusion, existing refund exclusion, privacy, atomic failed-save rollback, deferred cap-safe credit, durable reload and exact-once startup.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
