'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const schema=require('../../contracts/protocol/spacex.packet-schema-v1.json'),contract=require('../../services/protocol/spacex.packet-schema'),protocol=require('../../services/protocol/spacex.desktop-request-protocol'),fixtures=require('../fixtures/protocol/spacex.packet-schema-cases.json');
let checks=0;function reject(x){assert.throws(()=>contract.ValidateEnvelope(x),/PROTOCOL_SCHEMA_INVALID/);checks++;}
function clone(x){return structuredClone(x);}function resolve(x){return x.$ref?schema.definitions[x.$ref]:x;}
assert.equal(fixtures.schemaSha512,contract.sha512);assert.equal(fixtures.cases.length,46);
for(let i=0;i<fixtures.cases.length;i++){
 const packet=fixtures.cases[i],command=schema.commands[i];
 assert.equal(contract.ValidateEnvelope(packet),packet);protocol.Resolve(packet.operation,packet.body.action);checks++;
 assert.deepEqual(contract.ParseRequest(Buffer.from(JSON.stringify(packet))),packet);checks++;
 const legacy=clone(packet);delete legacy.tlsPinVersion;assert.deepEqual(contract.ValidateEnvelope(legacy),legacy);checks++;
 for(const k of ['operation','body']){const x=clone(packet);delete x[k];reject(x);}
 let x=clone(packet);x.extra=true;reject(x);x=clone(packet);x.body.extra=true;reject(x);
 for(const k of command.body.required){x=clone(packet);delete x.body[k];reject(x);}
 for(const [k,raw]of Object.entries(command.body.properties)){
  const rule=resolve(raw);x=clone(packet);x.body[k]=rule.type==='object'?[]:null;reject(x);
  if(rule.type==='integer'){x=clone(packet);x.body[k]=rule.minimum-1;reject(x);x=clone(packet);x.body[k]=rule.maximum+1;reject(x);x=clone(packet);x.body[k]=rule.minimum+0.5;reject(x);}
  if(rule.maxLength!==undefined){x=clone(packet);x.body[k]='x'.repeat(rule.maxLength+1);reject(x);}
  if(rule.minLength>0){x=clone(packet);x.body[k]='';reject(x);}
  if(rule.enum){x=clone(packet);x.body[k]=typeof rule.enum[0]==='number'?String(rule.enum[0]):'INVALID_ENUM';reject(x);}
 }
 if(command.body.allOrNone){x=clone(packet);x.body[command.body.allOrNone[0]]=3;reject(x);}
 if(command.body.exactlyOne){x=clone(packet);for(const k of command.body.exactlyOne)delete x.body[k];reject(x);x=clone(packet);for(const k of command.body.exactlyOne)x.body[k]=fixtures.cases.find(c=>Object.hasOwn(c.body,k))?.body[k]||'dummy';reject(x);}
}
for(const action of ['chunk','overlayChunk']){
 const packet=clone(fixtures.cases.find(x=>x.body.action===action));
 packet.body.count=2;assert.deepEqual(contract.ParseRequest(JSON.stringify(packet)),packet);checks++;
 for(const invalid of [0,1,3,'2',false]){packet.body.count=invalid;reject(packet);}
}
const good=fixtures.cases.find(x=>x.body.action==='keylessPolicy');
assert.deepEqual(contract.ParseRequest(JSON.stringify(good).replace('"tlsPinVersion":1','"tlsPinVersion":1e0').replace('"version":1','"version":1.0')),good);checks++;
for(const value of [[],null,true,{},1,'x'])reject(value);
for(const value of [0,2,'1',null,false]){const x=clone(good);x.tlsPinVersion=value;reject(x);}
for(const operation of ['overlay','unknown','Bootstrap']){const x=clone(good);x.operation=operation;reject(x);}
const text=JSON.stringify(good),n=Buffer.byteLength(text);assert.deepEqual(contract.ParseRequest(text,{maxBytes:n}),good);assert.throws(()=>contract.ParseRequest(text,{maxBytes:n-1}));checks+=2;
for(const invalid of [text+'x',text.replace('"version":1','"version":1,"version":1'),text.replace('"machineId"','"__proto__"'),text.replace('"launcherId":"','"launcherId":"\\ud800')]){assert.throws(()=>contract.ParseRequest(invalid));checks++;}
const newline=clone(good);newline.body.launcherId='A'.repeat(23)+'\n';reject(newline);
assert.equal(cp.spawnSync(process.execPath,['tools/build/spacex.generate-packet-schema.js','--check'],{cwd:path.resolve(__dirname,'../..'),encoding:'utf8'}).status,0);checks++;
assert.notEqual(cp.spawnSync(process.execPath,['tools/build/spacex.generate-packet-schema.js','--unknown'],{cwd:path.resolve(__dirname,'../..'),encoding:'utf8'}).status,0);checks++;
console.log('PACKET_SCHEMA_TEST_PASS commands='+fixtures.cases.length+' checks='+checks+' (generated-shape fixtures; domain authorization remains mandatory)');
