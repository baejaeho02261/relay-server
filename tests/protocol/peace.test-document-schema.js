'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const contract=require('../../services/protocol/peace.packet-schema'),schema=require('../../contracts/protocol/peace.packet-schema-v1.json'),fixtures=require('../fixtures/protocol/peace.document-schema-cases.json');
const clone=structuredClone;
function Resolve(n){return n.$ref?Resolve(schema.definitions[n.$ref]):n;}
function Sample(n){n=Resolve(n);if(n.anyOf)return Sample(n.anyOf[0]);if(n.enum)return n.enum[0];if(n.type==='integer')return n.minimum;if(n.type==='string'){if(n.pattern?.includes('A-F0-9'))return 'A'.repeat(n.minLength);if(n.pattern?.includes('a-f0-9'))return 'a'.repeat(n.minLength);if(n.pattern?.includes('[A-Z]'))return 'R'.repeat(Math.max(n.minLength||1,1));if(n.pattern)return 'r'.repeat(Math.max(n.minLength||1,1));return '{}'.repeat(Math.ceil((n.minLength||2)/2)).slice(0,Math.max(n.minLength||2,2));}if(n.type==='object')return Object.fromEntries((n.required||[]).map(k=>[k,Sample(n.properties[k])]));throw Error('TEST_SCHEMA_UNHANDLED');}
function Set(root,keys,value){let target=root;for(const key of keys.slice(0,-1))target=target[key];target[keys.at(-1)]=value;}
function Cases(rule,value,at=[]){rule=Resolve(rule);if(rule.anyOf){const selected=rule.anyOf.find(n=>{try{return JSON.stringify(Sample(n))===JSON.stringify(value);}catch{return false;}})||rule.anyOf[0];return Cases(selected,value,at);}
 const rows=[];
 if(rule.type==='object'){
  rows.push({at,value:{...value,unknownField:true},reason:'unknown'});
  for(const key of rule.required){const missing=clone(value);delete missing[key];rows.push({at,value:missing,reason:'missing '+key});}
  for(const [key,child]of Object.entries(rule.properties)){if(!Object.hasOwn(value,key))continue;rows.push({at:[...at,key],value:null,reason:'null '+key});rows.push(...Cases(child,value[key],[...at,key]));}
 }else if(rule.type==='integer'){for(const v of [String(value),rule.minimum-1,rule.maximum+1,value+0.5])rows.push({at,value:v,reason:'integer'});}
 else if(rule.type==='string'){rows.push({at,value:'x'.repeat(rule.maxLength+1),reason:'string limit'});if(rule.minLength>0)rows.push({at,value:'',reason:'empty'});if(rule.pattern)rows.push({at,value:String(value)+'\n',reason:'newline'});}
 else if(rule.enum)rows.push({at,value:typeof value==='boolean'?String(value):'UNSUPPORTED',reason:'enum type/version'});
 return rows;
}
test('all generated response/evidence fixtures have strict recursive field, type and range rules',()=>{
 assert.equal(fixtures.schemaSha512,contract.sha512);assert.equal(fixtures.cases.length,12);let rejected=0;
 for(const row of fixtures.cases){assert.equal(contract.ValidateDocument(row.name,row.value),row.value);assert.deepEqual(contract.ParseDocument(row.name,JSON.stringify(row.value)),row.value);
  for(const mutation of Cases(schema.documents[row.name],row.value)){const body=clone(row.value);let candidate;if(mutation.at.length){Set(body,mutation.at,mutation.value);candidate=body;}else candidate=mutation.value;
   assert.throws(()=>contract.ValidateDocument(row.name,candidate),/PROTOCOL_SCHEMA_INVALID/,row.name+':'+mutation.at.join('.')+':'+mutation.reason);rejected++;
  }
 }
 assert(rejected>400,'recursive adverse cases were exercised');
});
test('optional response fields and every version/status variant remain type checked',()=>{
 const challenge=Sample(schema.documents.authorityChallenge);challenge.mitigationProfile=Sample(schema.definitions.mitigationProfile);challenge.deviceSignalsRequested=true;contract.ValidateDocument('authorityChallenge',challenge);
 for(const key of ['mitigationProfile','deviceSignalsRequested']){const bad=clone(challenge);bad[key]=key==='deviceSignalsRequested'?1:[];assert.throws(()=>contract.ValidateDocument('authorityChallenge',bad));}
 const verify=Sample(schema.documents.overlayVerify);verify.capturePrivacy=false;verify.renewalBudget=Sample(schema.definitions.overlayRenewalBudget);contract.ValidateDocument('overlayVerify',verify);verify.renewalBudget.version=2;assert.throws(()=>contract.ValidateDocument('overlayVerify',verify));
 for(const variant of schema.definitions.overlayAbort.anyOf)contract.ValidateDocument('overlayAbort',Sample(variant));
 const failure=Sample(schema.definitions.authorityPayload.anyOf[1]);contract.ValidateDocument('authorityPayload',failure);failure.measurement='MEASURED';assert.throws(()=>contract.ValidateDocument('authorityPayload',failure));
 for(const diagnostics of schema.definitions.mitigationDiagnostics.anyOf){const evidence=Sample(schema.documents.authorityPayload);evidence.mitigationDiagnostics=Sample(diagnostics);contract.ValidateDocument('authorityPayload',evidence);evidence.mitigationDiagnostics.setError=0x100000000;assert.throws(()=>contract.ValidateDocument('authorityPayload',evidence));}
});
test('wrong role fields, duplicated fields, unknown schema and malformed Unicode never pass document parsing',()=>{
 for(const row of fixtures.cases){assert.throws(()=>contract.ValidateDocument(row.name,{...row.value,role:'A'}));const text=JSON.stringify(row.value),first=Object.keys(row.value)[0];assert.throws(()=>contract.ParseDocument(row.name,'{"'+first+'":null,'+text.slice(1)));}
 assert.throws(()=>contract.ValidateDocument('constructor',{}));assert.throws(()=>contract.ParseDocument('overlayClose','{"sessionId":"\\ud800","status":"CLOSED"}'));
});
test('generated schema is current and actual native parser paths enforce the generated documents before consuming them',()=>{
 const relay=path.resolve(__dirname,'../..'),native=path.resolve(relay,'../Railway');
 const args=['tools/build/peace.generate-packet-schema.js','--check'];if(fs.existsSync(native))args.push('--native-root',native);
 const checked=cp.spawnSync(process.execPath,args,{cwd:relay,encoding:'utf8'});assert.equal(checked.status,0,checked.stderr);
 if(fs.existsSync(native)){
  const client=fs.readFileSync(path.join(native,'Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas'),'utf8'),authority=fs.readFileSync(path.join(native,'Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas'),'utf8');
  assert(client.indexOf('RequireOverlayDocument(Action, TJSONObject(Value))')<client.indexOf('Result := TJSONObject(Value.Clone)'));
  for(const name of ['authorityChallenge','authorityPayload','authorityReply'])assert(authority.includes("RequireAuthorityDocument('"+name+"'"));
  assert(authority.indexOf("RequireAuthorityDocument('authorityPayload'")<authority.indexOf('PayloadText := Evidence.ToJSON'));
  assert(authority.indexOf('IntegritySHA512Text(PayloadText)')>authority.indexOf('PayloadText := Evidence.ToJSON'));
 }
});

test('document parse limits cover a real maximum chunk but reject non-integer and excessive bounds',()=>{
 const value={offset:0,size:262144,data:Buffer.alloc(262144).toString('base64')},text=JSON.stringify(value),bytes=Buffer.byteLength(text);
 assert(bytes>65536&&bytes<contract.maximumDocumentBytes);assert.deepEqual(contract.ParseDocument('overlayChunk',text),value);
 assert.deepEqual(contract.ParseDocument('overlayChunk',text,{maxBytes:bytes}),value);assert.throws(()=>contract.ParseDocument('overlayChunk',text,{maxBytes:bytes-1}));
 for(const maxBytes of [NaN,Infinity,-Infinity,'x','524288',0,-1,1.5,contract.maximumDocumentBytes+1])assert.throws(()=>contract.ParseDocument('overlayChunk',text,{maxBytes}),/PROTOCOL_SCHEMA_INVALID/);
});
test('in-memory response validation rejects malformed Unicode just like the actual Delphi validator',()=>{
 for(const text of ['\ud800','\udfff','x\ud800x','\udc00\ud800']){
  const release=Sample(schema.documents.overlayRelease);release.version=text;assert.throws(()=>contract.ValidateDocument('overlayRelease',release),/PROTOCOL_SCHEMA_INVALID/);
  const prepare=Sample(schema.documents.overlayPrepare);prepare.claimCanonical=text;assert.throws(()=>contract.ValidateDocument('overlayPrepare',prepare),/PROTOCOL_SCHEMA_INVALID/);
 }
 const release=Sample(schema.documents.overlayRelease);release.version='한글 😀';assert.equal(contract.ValidateDocument('overlayRelease',release),release);
});
