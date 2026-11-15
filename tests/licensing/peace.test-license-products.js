'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {Isolated}=require('../fixtures/protocol/peace.completion-6-10-fixture');
const products=require('../../services/licensing/peace.licensed-products');
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
function fixture(seed){
 const state={serviceEnabled:true,maintenanceMode:false},calls={writes:0};let persisted=seed&&structuredClone(seed);
 const api=Isolated('services/licensing/peace.desktop-licenses.js',[],{
  '../../core/peace.runtime-state':state,
  './peace.desktop-journal':{AssertHealthy(){},Load:()=>({exists:!!persisted,state:persisted}),Commit(_previous,next){calls.writes++;persisted=structuredClone(next);}},
  '../bootstrap/peace.desktop-bootstrap':{messages:{},LicenseActivity:()=>null},
  '../devices/peace.desktop-machine-policy':{Public:()=>null},
  '../network/peace.ha-coordinator':{CanAcceptTraffic:()=>true},
  '../../storage/snapshots/peace.database.js':{SaveDatabase:()=>true},
  '../../storage/audit/peace.audit.js':{AppendOperationEvent:()=>({ok:true,sequence:1,hash:'A'.repeat(64)})}
 });return {api,state,calls,persisted:()=>persisted};
}
test('18 stable products have six entries per category and callers cannot mutate the catalogue',()=>{
 const list=products.List();assert.equal(list.length,18);assert.equal(new Set(list.map(x=>x.id)).size,18);
 for(const category of ['cleaner','mobile','spoofer'])assert.equal(list.filter(x=>x.category===category).length,6);
 list[0].id='all';assert.equal(products.Find('all'),null);assert.equal(products.Require('cleaner.pubg').id,'cleaner.pubg');
 assert.deepEqual(products.Projection({}),{productId:'',productName:'',productCategory:'',productAssigned:false});
});
test('new issuance requires one catalogue product and invalid input never commits a license',()=>{
 const f=fixture();
 for(const productId of [undefined,null,'','all','cleaner.*','pubg',['cleaner.pubg'],{},'constructor']){
  const before=JSON.stringify(f.api.DB()),writes=f.calls.writes;
  assert.throws(()=>f.api.Create({label:'synthetic',productId,requestId:crypto.randomUUID()},'TEST'),/DESKTOP_PRODUCT_REQUIRED|DESKTOP_PRODUCT_INVALID/);
  assert.equal(JSON.stringify(f.api.DB()),before);assert.equal(f.calls.writes,writes);
 }
 const result=f.api.Create({label:'PUBG only',productId:'cleaner.pubg',requestId:crypto.randomUUID()},'TEST');
 assert.equal(result.license.productId,'cleaner.pubg');assert.equal(result.license.productAssigned,true);
 assert.equal(result.license.productName,'PUBG: BATTLEGROUNDS');assert.equal(result.license.productCategory,'cleaner');
 assert.equal(f.api.List().products.length,18);assert.equal(f.api.Detail(result.license.id).license.productId,'cleaner.pubg');
 assert(!JSON.stringify(f.api.List()).includes(result.licenseKey));
});
test('receipt retry binds product and reissue changes scope only by issuing a new key',()=>{
 const f=fixture(),body={label:'one',productId:'cleaner.pubg',requestId:crypto.randomUUID()},first=f.api.Create(body,'TEST');
 assert.equal(f.api.Create(body,'TEST').licenseKey,first.licenseKey);
 assert.throws(()=>f.api.Create({...body,productId:'mobile.pubg-mobile'},'TEST'),/DESKTOP_REQUEST_REUSED/);
 const before=JSON.stringify(f.api.DB());
 assert.throws(()=>f.api.Reissue(first.license.id,{reason:'New game',requestId:crypto.randomUUID()},'TEST'),/DESKTOP_PRODUCT_REQUIRED/);
 assert.equal(JSON.stringify(f.api.DB()),before);
 const next=f.api.Reissue(first.license.id,{reason:'New game',productId:'mobile.pubg-mobile',requestId:crypto.randomUUID()},'TEST');
 assert.notEqual(next.licenseKey,first.licenseKey);assert.notEqual(next.license.id,first.license.id);
 assert.equal(next.license.productId,'mobile.pubg-mobile');
 assert.equal(f.api.Detail(first.license.id).license.productId,'cleaner.pubg');
 assert.equal(f.api.Detail(first.license.id).license.status,'REVOKED');
 f.api.Import();assert.equal(f.api.Detail(next.license.id).license.productId,'mobile.pubg-mobile');
});
test('legacy imports and exact old issuance receipts remain unassigned without widening scope',()=>{
 const actor='TEST',id='A'.repeat(24),signingSecret='1'.repeat(64),issuanceNonce='2'.repeat(48);
 const body={label:'legacy',requestId:'LEGACY_REQUEST_1'},key=crypto.createHmac('sha256',Buffer.from(signingSecret,'hex')).update('GAME-DESKTOP-KEY-V2|'+id+'|'+issuanceNonce).digest('hex').toUpperCase();
 const row={id,label:'legacy',keyVersion:2,issuanceNonce,keyHash:hash(key),status:'AVAILABLE',consumed:false,issuedAt:1,issuedBy:actor,expiresAt:0};
 const receiptKey='ADMIN:'+hash(actor)+':'+body.requestId,receipt={fingerprint:hash(JSON.stringify({action:'create',id:'',body})),licenseId:id,action:'create',at:1};
 const f=fixture({schema:1,revision:1,signingSecret,licenses:{[id]:row},receipts:{[receiptKey]:receipt}});
 const retry=f.api.Create(body,actor);assert.equal(retry.licenseKey,key);assert.equal(retry.license.productId,'');assert.equal(retry.license.productAssigned,false);assert.equal(f.calls.writes,0);
 assert.equal(Object.hasOwn(f.api.DB().licenses[id],'productId'),false);
 assert.throws(()=>f.api.Create({...body,requestId:'NEW_REQUEST_123'},actor),/DESKTOP_PRODUCT_REQUIRED/);
 const unknown=structuredClone(f.persisted());unknown.licenses[id].productId='all';
 assert.throws(()=>fixture(unknown).api.DB(),/DESKTOP_STORAGE_INVALID/);
});
test('journal replay rejects changing or retrofitting a license product',()=>{
 const journal=Isolated('services/licensing/peace.desktop-journal.js',['Apply']);
 for(const original of [undefined,'cleaner.pubg']){
  const old={id:'TEST',status:'AVAILABLE',consumed:false,...(original?{productId:original}:{})};
  for(const productId of ['mobile.pubg-mobile',undefined]){
   if(original===productId)continue;
   const next={...old};if(productId===undefined)delete next.productId;else next.productId=productId;
   const state={revision:1,licenses:{TEST:old},receipts:{}};
   assert.throws(()=>journal.__probe.Apply(state,{version:1,revision:2,licenses:[next],receipts:{}}),/DESKTOP_JOURNAL_CORRUPT/);
  }
 }
});
