'use strict';
// This fixture was emitted by the unmodified version 82 service. It is not
// derived using the current implementation, so domain/format regressions fail.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const fixture=require('./fixtures/desktop-license-journal-v1.json');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-license-migration-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';
fs.writeFileSync(path.join(temp,'desktop-license-journal.jsonl'),fixture.journal,{mode:0o600});
require('../core/utils').EnsureDirs();
const d=require('../services/desktopLicenses'),f=require('./desktop-bootstrap-fixture');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex'),device=f.Device();
function call(action,payload){
 const requestId=crypto.randomUUID();payload=f.LicensePayload(device,payload,requestId);
 const payloadJSON=JSON.stringify(payload),base={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:sha(payloadJSON)},c=d.Challenge(base);
 return d.Execute({...base,challengeId:c.challengeId,payloadJSON,signature:f.Sign(device,c.canonical)});
}
try{
 d.Import(undefined);const original=structuredClone(d.DB());
 for(const item of fixture.rows){
  const detail=d.Detail(item.id);assert.equal(detail.licenseKey,item.key,'Original issuance HMAC must survive the rename');
  assert.match(detail.licenseKey,/^[A-F0-9]{64}$/);assert.equal(detail.license.displayId,item.id.slice(3));
  assert.equal(d.DB().licenses[item.id].keyHash,original.licenses[item.id].keyHash);
  assert.ok(!JSON.stringify(d.List()).includes(item.key),'Only the authorized detail endpoint may reveal a key');
  if(item.kind.startsWith('available-')){
   assert.equal(d.Create(item.body,item.actor).licenseKey,item.key,'An old admin retry returns the existing normalized key');
   const input=item.kind==='available-raw'?Buffer.from('4d4f41','hex').toString('ascii')+'-'+item.key.match(/.{8}/g).join('-'):item.key.toLowerCase();
   const result=call('redeem',{licenseKey:input});assert.equal(result.status,'USED');assert.match(result.activationToken,/^[a-f0-9]{64}$/);
   assert.equal(d.DB().licenses[item.id].status,'USED');assert.equal(d.DB().licenses[item.id].keyHash,original.licenses[item.id].keyHash);
   assert.equal(call('verify',{activationToken:result.activationToken}).status,'USED');
   assert.equal(d.Detail(item.id).licenseKey,item.key);
   assert.throws(()=>call('redeem',{licenseKey:item.key}),e=>e.message==='DESKTOP_KEY_USED');
  }else{
   const revoked=item.kind==='revoked';assert.equal(detail.license.status,revoked?'REVOKED':'USED');
   assert.throws(()=>call('redeem',{licenseKey:item.key}),e=>e.message===(revoked?'DESKTOP_REVOKED':'DESKTOP_KEY_USED'));
   assert.deepEqual(d.DB().licenses[item.id],original.licenses[item.id],'Existing consumed/released/revoked history cannot change or revive');
  }
 }
 d.Import(original);
 for(const item of fixture.rows){assert.equal(d.Detail(item.id).licenseKey,item.key);assert.equal(d.Public(d.DB().licenses[item.id]).status,item.kind==='revoked'?'REVOKED':'USED');}
 const latest=require('../services/desktopJournal').Load().state;
 for(const item of fixture.rows.filter(row=>row.kind.startsWith('available-')))assert.equal(latest.licenses[item.id].status,'USED');
 console.log('LEGACY LICENSE MIGRATION PASS: original journal HMACs and admin receipts, normalized/raw old-key input, consumed/released/revoked permanence, new session tokens, durable single-use status.');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
