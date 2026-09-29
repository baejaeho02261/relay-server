'use strict';
// FIX71 supersedes the old executable withdrawal queue. Keep its financial
// invariant regression: every proven unprocessed reservation is restored once.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-withdraw-retired-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),retire=require('../services/member/withdraw-retirement'),db=require('../storage/database');
const profile=id=>s.ProfileById(id);
function member(subject,balance){const p={id:s.Id('USR'),subject,nickname:subject,balance:0};s.Atomic(()=>{s.DB().profiles[subject]=p;s.Ledger(p,balance,'TOPUP','SETUP');});return p.id;}
function reserve(account,amount,status='PENDING'){let id;s.Atomic(()=>{id=s.Id('WDR');const ledger=s.Ledger(profile(account),-amount,'WITHDRAW_RESERVE',id);s.DB().withdrawRequests[id]={id,accountId:account,amount,status,paymentId:ledger.id,account:'1234567890',bank:'OLD_BANK',holder:'OLD_MEMBER'};});return id;}
try{
 const a=member('A',Number.MAX_SAFE_INTEGER),b=member('B',10000),first=reserve(a,1000),second=reserve(b,2000),paid=reserve(b,1000,'PAID');
 const snapshot=JSON.stringify(s.DB()),save=db.SaveDatabase;db.SaveDatabase=()=>false;try{assert.throws(()=>retire.Ensure(profile(a)),/STORAGE_SAVE_FAILED/);}finally{db.SaveDatabase=save;}assert.equal(JSON.stringify(s.DB()),snapshot);
 retire.Ensure(profile(a));assert.equal(profile(a).balance,Number.MAX_SAFE_INTEGER,'reservation release reaches exact safe-integer cap without double-counting its hold');assert.equal(profile(b).balance,7000,'per-account fallback never touches another wallet');
 assert.equal(s.DB().withdrawRequests[first].status,'RETIRED');retire.Ensure(profile(a));assert.equal(profile(a).balance,Number.MAX_SAFE_INTEGER);
 retire.Ensure();assert.equal(profile(b).balance,9000);assert.equal(s.DB().withdrawRequests[paid].status,'PAID');assert.equal(s.DB().withdrawRequests[second].status,'RETIRED');
 const already=reserve(b,500);s.Atomic(()=>{const row=s.DB().withdrawRequests[already];row.status='REJECTED';s.Ledger(profile(b),500,'WITHDRAW_RELEASE',already);row.status='PENDING';});retire.Ensure();assert.equal(profile(b).balance,9000,'a corrupt pending flag on an already refunded request cannot credit twice');
 const forged=s.Id('WDR');s.Atomic(()=>s.DB().withdrawRequests[forged]={id:forged,accountId:b,amount:1000000,status:'PENDING',paymentId:s.DB().withdrawRequests[first].paymentId});retire.Ensure();assert.equal(profile(b).balance,9000);assert.equal(s.DB().withdrawRequests[forged].retirementReason,'RESERVATION_NOT_VERIFIED');
 assert.equal(db.ImportDatabaseObject(db.BuildDatabaseObject()),true);retire.Ensure();assert.equal(profile(a).balance,Number.MAX_SAFE_INTEGER);assert.equal(profile(b).balance,9000);
 assert.equal(Object.values(s.DB().ledger).filter(x=>x.kind==='WITHDRAW_RETIREMENT_RELEASE').length,2);
 for(const file of ['../services/member/withdrawals.js','../public/admin-member-withdrawals.js'])assert.ok(!fs.existsSync(path.resolve(__dirname,file)));
 const service=fs.readFileSync(path.resolve(__dirname,'../services/member/service.js'),'utf8');assert.doesNotMatch(service,/'withdraw.request'|withdraw:\(\)=>/);
 const page=fs.readFileSync(path.resolve(__dirname,'../public/index.html'),'utf8');assert.doesNotMatch(page,/member-withdrawals/);
 console.log('FIX71 withdrawal retirement: removal, exact cap, pending proof, paid preservation, replay, durable rollback and restoration passed');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
