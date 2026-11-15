'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {OverlayFixture}=require('../fixtures/security/peace.security-state-test-fixture');
const products=require('../../services/licensing/peace.licensed-products'),packet=require('../../services/protocol/peace.packet-schema');
function fixture(options={}){
 const f=OverlayFixture(options),at=Date.now()-1;f.row.status='CLAIMED';f.row.productScopeVersion=1;f.license.productId='cleaner.pubg';
 Object.assign(f.row,{transferVersion:1,transferredAt:at});
 Object.assign(f.parent,{status:'CLOSED',closedByOverlay:true,overlayTransferVersion:1,transferredOverlayId:f.row.id,transferredAt:at});
 return f;
}
function request(f,overrides={}){
 const body={action:'overlayStart',sessionId:f.row.sessionId,sessionToken:'TOKEN',productId:'cleaner.pubg',requestId:crypto.randomUUID(),sequence:1,...overrides};
 body.signature=crypto.sign('sha256',Buffer.from(f.api.__probe.StartCanonical(body)),f.keys.privateKey).toString('base64');return body;
}
test('START admits the signed licensed product without extending any session or license lease',()=>{
 const f=fixture(),body=request(f),before=JSON.stringify([f.parent,f.license]),expires=f.row.sessionExpiresAt;
 assert.equal(f.api.__probe.StartCanonical(body),['COZY-OVERLAY-START-V1',body.sessionId,body.productId,body.requestId,'1'].join('\n'));
 const admitted=packet.ParseRequest(JSON.stringify({operation:'bootstrap',body})).body;
 const reply=f.api.__probe.Start(admitted);packet.ValidateDocument('overlayStart',reply);
 assert.equal(reply.status,'AUTHORIZED');assert.equal(reply.productId,'cleaner.pubg');assert.equal(reply.durationMs,5000);
 assert.equal(reply.sequence,1);assert.equal(reply.requestId,body.requestId);assert.equal(reply.sessionId,f.row.sessionId);
 assert(reply.expiresAt<=expires);assert(reply.expiresAt<=reply.serverTime+30000);assert(reply.expiresAt>=reply.serverTime+5000);
 assert.equal(f.row.sessionExpiresAt,expires);assert.equal(JSON.stringify([f.parent,f.license]),before);
 assert.equal(f.calls.writes,1);f.api.__probe.ValidateStartReceipt(f.row);
 const event=f.calls.events.find(x=>x.kind==='DESKTOP_OVERLAY_PRODUCT_STARTED');assert.equal(event.productId,'cleaner.pubg');
 assert(!JSON.stringify(event).includes('TOKEN'));assert(!JSON.stringify(event).includes(body.signature));
});
test('all 17 other valid cards are denied despite genuine device signatures',()=>{
 const f=fixture(),before=JSON.stringify([f.row,f.parent,f.license]);
 for(const product of products.List())if(product.id!=='cleaner.pubg'){
  assert.throws(()=>f.api.__probe.Start(request(f,{productId:product.id})),/DESKTOP_PRODUCT_NOT_LICENSED/);
 }
 assert.equal(JSON.stringify([f.row,f.parent,f.license]),before);assert.equal(f.calls.writes,0);
});
test('unsigned product, sequence, request and session tampering never grants START',()=>{
 const f=fixture(),body=request(f);
 for(const change of [{productId:'mobile.pubg-mobile'},{requestId:'CHANGED_REQUEST'},{sequence:2},{signature:Buffer.alloc(256).toString('base64')}]){
  assert.throws(()=>f.api.__probe.Start({...body,...change}),/BOOTSTRAP_PROOF_INVALID/);
 }
 assert.throws(()=>f.api.__probe.Start({...body,sessionToken:'WRONG'}),/BOOTSTRAP_SESSION_INVALID/);
 assert.throws(()=>f.api.__probe.Start({...body,sessionId:'A'.repeat(24)}),/BOOTSTRAP_SESSION_INVALID/);
 for(const change of [{productId:'all'},{productId:''},{sequence:0},{sequence:2147483648},{sequence:'1'},{address:'arbitrary'}]){
  assert.throws(()=>packet.ValidateRequest('bootstrap',{...body,...change}),/PROTOCOL_SCHEMA_INVALID/);
  assert.throws(()=>f.api.__probe.Start({...body,...change}),/BOOTSTRAP_INPUT_INVALID/);
 }
 assert.equal(f.calls.writes,0);
});
test('legacy, revoked, expired, untransferred and stale-observation sessions cannot start',()=>{
 for(const mode of ['UNASSIGNED','LICENSE_REVOKED','SESSION_REVOKED','EXPIRED','NOT_TRANSFERRED','STALE','ARTIFACT_REVOKED']){
  const f=fixture();
  if(mode==='UNASSIGNED')delete f.license.productId;
  if(mode==='LICENSE_REVOKED')f.license.status='REVOKED';
  if(mode==='SESSION_REVOKED')f.row.status='REVOKED';
  if(mode==='EXPIRED')f.row.sessionExpiresAt=Date.now()-1;
  if(mode==='NOT_TRANSFERRED'){delete f.row.transferVersion;f.parent.status='CLAIMED';}
  if(mode==='STALE')f.denyFresh();
  if(mode==='ARTIFACT_REVOKED')f.revoked.add('O');
  assert.throws(()=>f.api.__probe.Start(request(f)),/UNASSIGNED|ACTIVATION_INVALID|REVOKED|EXPIRED|NOT_READY|FRESH_OBSERVATION/,mode);
  assert.equal(f.calls.writes,0,mode);
 }
});
test('exact retries retain original grant; older or conflicting sequences never replay',()=>{
 const f=fixture(),body=request(f),first=f.api.__probe.Start(body),writes=f.calls.writes;
 assert.deepEqual(f.api.__probe.Start(body),first);assert.equal(f.calls.writes,writes);
 assert.throws(()=>f.api.__probe.Start(request(f,{sequence:1})),/BOOTSTRAP_REQUEST_REUSED/);
 const second=f.api.__probe.Start(request(f,{sequence:3}));assert.equal(second.sequence,3);
 assert.throws(()=>f.api.__probe.Start(body),/BOOTSTRAP_REQUEST_REUSED/);
 assert.throws(()=>f.api.__probe.Start(request(f,{sequence:2})),/BOOTSTRAP_REQUEST_REUSED/);
 f.license.status='REVOKED';assert.throws(()=>f.api.__probe.Start(body),/DESKTOP_ACTIVATION_INVALID/);
});
test('expired response retry cannot recreate its deadline, including after reloaded receipt',()=>{
 const f=fixture(),body=request(f),first=f.api.__probe.Start(body),saved=structuredClone(f.row.startReceipt),real=Date.now;
 f.row.startReceipt=structuredClone(saved);Date.now=()=>first.expiresAt+1;
 try{assert.throws(()=>f.api.__probe.Start(body),/BOOTSTRAP_EXPIRED/);assert.deepEqual(f.row.startReceipt,saved);assert.equal(f.calls.writes,1);}
 finally{Date.now=real;}
});
test('authority rechecked in the durable transaction blocks revocation races',()=>{
 const f=fixture();f.beforeWrite(()=>{f.license.status='REVOKED';});
 assert.throws(()=>f.api.__probe.Start(request(f)),/DESKTOP_ACTIVATION_INVALID/);
 assert.equal(f.row.startReceipt,undefined);assert.equal(f.calls.events.length,0);
});
test('negotiated verification exposes exactly one product and legacy requests stay compatible',()=>{
 const scoped=fixture({observationId:'a'.repeat(48)+':1'}),body={...scoped.verify,productScopeVersion:1};
 const value=scoped.api.__probe.Verify(body);assert.equal(value.productScopeVersion,1);assert.equal(value.productId,'cleaner.pubg');
 packet.ValidateDocument('overlayVerify',value);scoped.api.__probe.ValidateVerifyReceipt(scoped.row);
 const legacy=fixture();delete legacy.license.productId;
 const empty=legacy.api.__probe.Verify({...legacy.verify,productScopeVersion:1});assert.equal(empty.productId,'');assert.equal(empty.productScopeVersion,1);
 const old=fixture();delete old.row.productScopeVersion;const unchanged=old.api.__probe.Verify(old.verify);assert.equal(Object.hasOwn(unchanged,'productId'),false);assert.equal(Object.hasOwn(unchanged,'productScopeVersion'),false);
 for(const invalid of [{...value,productId:'all'},{...value,productScopeVersion:2}])assert.throws(()=>packet.ValidateDocument('overlayVerify',invalid),/PROTOCOL_SCHEMA_INVALID/);
 for(const key of ['productId','productScopeVersion']){const partial={...value};delete partial[key];assert.throws(()=>packet.ValidateDocument('overlayVerify',partial),/PROTOCOL_SCHEMA_INVALID/);}
});
test('persisted START receipt validation rejects arbitrary product and unbounded metadata',()=>{
 const f=fixture();f.api.__probe.Start(request(f));
 for(const change of [{productId:'all'},{sequence:0},{sequence:2147483648},{until:f.row.startReceipt.at+30001},{until:f.row.startReceipt.at+4999},{fingerprint:'not-a-hash'},{address:'private'}]){
  assert.throws(()=>f.api.__probe.ValidateStartReceipt({...f.row,startReceipt:{...f.row.startReceipt,...change}}),/OVERLAY_STORE_INVALID/);
 }
});
test('claim negotiation is fixed by its recovery fingerprint and cannot accept a caller product',()=>{
 const f=OverlayFixture();f.row.status='READY';f.license.productId='mobile.roblox';
 const body={action:'overlayClaim',overlayId:f.row.id,overlayTicket:'TICKET',binarySha512:f.db.artifacts.O.sha512,crc64:f.db.artifacts.O.crc64,oCodeSha512:f.db.artifacts.O.codeSha512,oCodeCrc64:f.db.artifacts.O.codeCrc64,productScopeVersion:1};
 body.signature=crypto.sign('sha256',Buffer.from(f.api.__probe.Canonical(f.row,'CLAIM')),f.keys.privateKey).toString('base64');
 const first=f.api.__probe.Claim(body);assert.equal(first.productScopeVersion,1);assert.equal(first.productId,'mobile.roblox');assert.equal(f.row.productScopeVersion,1);
 assert.deepEqual(f.api.__probe.Claim(body),first);
 const downgrade={...body};delete downgrade.productScopeVersion;
 assert.throws(()=>f.api.__probe.Claim(downgrade),/BOOTSTRAP_LAUNCHER_USED/);
 assert.throws(()=>f.api.__probe.Claim({...body,productScopeVersion:2}),/BOOTSTRAP_INPUT_INVALID/);
 assert.throws(()=>f.api.__probe.Claim({...body,productId:'cleaner.pubg'}),/BOOTSTRAP_INPUT_INVALID/);
});
test('native product identifiers and global card order agree with the server catalogue',()=>{
 const fs=require('node:fs'),path=require('node:path'),file=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.State.pas');
 if(!fs.existsSync(file))return; // Relay-only deployments do not contain private native sources.
 const {ReadContractFile}=require('../fixtures/source/peace.native-string-contract'),source=ReadContractFile(file,'utf8');
 const body=source.slice(source.indexOf('function OverlayProductID(Card: Integer): string;',source.indexOf('implementation')));
 const mappings=[...body.matchAll(/\b(\d+):\s*Result\s*:=\s*'([^']+)'/g)].slice(0,18);
 assert.equal(mappings.length,18);assert.deepEqual(mappings.map(([_,index,id])=>[Number(index),id]),products.List().map((row,index)=>[index,row.id]));
});

test('scope negotiation cannot be added after a legacy claim or removed after a scoped claim',()=>{
 const legacy=fixture();delete legacy.row.productScopeVersion;
 assert.throws(()=>legacy.api.__probe.Verify({...legacy.verify,productScopeVersion:1}),/BOOTSTRAP_INPUT_INVALID/);
 assert.throws(()=>legacy.api.__probe.Start(request(legacy)),/DESKTOP_PRODUCT_UNASSIGNED/);
 const scoped=fixture();assert.throws(()=>scoped.api.__probe.Verify(scoped.verify),/BOOTSTRAP_INPUT_INVALID/);
 assert.equal(legacy.calls.writes,0);assert.equal(scoped.calls.writes,0);
});
