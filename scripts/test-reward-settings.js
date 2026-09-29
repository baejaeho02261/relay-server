'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix74-rewards-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),rewards=require('../services/member/rewards');
(async()=>{try{
 const p=s.Account({installationDeviceKey:'FIX74_RETAINED_REWARDS'});p.eventSpins=3;p.points=100;p.balance=2000;p.spinChargeRemainder=750;
 s.DB().settings.rewards={...rewards.Rules(),chargeUnit:1000};
 const persisted=JSON.stringify(s.DB().settings.rewards),rules=rewards.Rules();
 assert.equal(Object.hasOwn(rules,'chargeUnit'),false);assert.equal(JSON.stringify(s.DB().settings.rewards),persisted,'read-only old rules projection');
 assert.equal(rewards.GrantCharge,undefined,'removed top-up pathway cannot issue spins');
 let edited=false,saved=false,rendered=false;
 const context={memberOffset:0,esc:String,fmtTime:String,memberMoney:n=>String(n)+'원',memberButton:()=>'<button></button>',toast:()=>{},renderMember:async()=>{rendered=true;},
  openModal:async({fields})=>{edited=true;assert.ok(!fields.some(f=>f.name==='chargeUnit'));assert.ok(!fields.some(f=>f.name==='enabled'));assert.equal(fields.filter(f=>/^points\d$/.test(f.name||'')).length,0);return Object.fromEntries(fields.filter(f=>f.name).map(f=>[f.name,String(f.value)]));},
  api:async(url,{body})=>{assert.equal(url,'/api/member/action');assert.equal(body.action,'rewards.save');assert.equal(Object.hasOwn(body,'chargeUnit'),false);rewards.SaveRules(body,'TEST');saved=true;}}
 vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../public/admin-member-rewards.js'),'utf8')+'\nthis.panel=memberRewardsPanel;this.edit=editMemberRewards;',context);
 const html=context.panel({rules,items:[],total:0,nextOffset:null});assert.doesNotMatch(html,/돌림판|보유 횟수로 이용|보유한 참여 횟수는 그대로 유지/);assert.doesNotMatch(html,/충전 승인|충전 .*당 1회|바카라|룰렛|슬롯/);
 await context.edit();assert.ok(edited&&saved&&rendered);assert.equal(Object.hasOwn(s.DB().settings.rewards,'chargeUnit'),false);
 assert.equal(p.eventSpins,3);assert.equal(p.points,100);assert.equal(p.balance,2000);assert.equal(p.spinChargeRemainder,750,'legacy accounting remainder left intact; no longer usable for a new award');
 assert.equal(rewards.Spin,undefined);s.Atomic(()=>rewards.Check(p));assert.equal(p.eventSpins,3);assert.equal(p.points,100);assert.equal(p.balance,2000);
 assert.throws(()=>rewards.SaveRules({...rules,chargeUnit:1},'STALE'),/CONTENT_CHANGED/);
 const captions=fs.readFileSync(path.join(__dirname,'../../MoaPlayApp_Android64/MoaPlayMemberOptions.Captions.inc'),'utf8');
 assert.doesNotMatch(captions,/충전 후 지급되는|QR 충전 후|개인 지갑|카카오페이|토스페이/);
 console.log('FIX74 REWARDS PASS: legacy turns preserved, retired top-up spin settings absent, admin form saves without chargeUnit, retired spin engine removed and attendance remains active, no dead native top-up guidance.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
