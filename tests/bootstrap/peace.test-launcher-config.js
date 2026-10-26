'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const codec=require('../../services/bootstrap/peace.launcher-config');
const engine=require('../../services/artifacts/peace.cozy-protection-engine');
const {publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),jwk=publicKey.export({format:'jwk'}),exponent=Buffer.from(jwk.e,'base64url'),modulus=Buffer.from(jwk.n,'base64url'),header=Buffer.alloc(24);
[0x31415352,2048,exponent.length,256,0,0].forEach((n,i)=>header.writeUInt32LE(n,i*4));const publicBlob=Buffer.concat([header,exponent,modulus]);
function Value(){return {schema:2,profile:{version:4,protocol:'GAME-CONNECT-4',host:'relay.example.test',port:443,serverKeyId:crypto.createHash('sha256').update(publicBlob).digest('hex'),serverPublicKey:publicBlob.toString('base64'),tlsServerName:'relay.example.test',tlsCertificateSha256:'a1'.repeat(32)},launcherId:'AB'.repeat(12),launcherTicket:crypto.randomBytes(32).toString('base64url'),expiresAt:1793000000000};}
function Invalid(fn){assert.throws(fn,{message:'BOOTSTRAP_CONFIG_INVALID'});}
test('binary launcher payload roundtrips every exact public-profile and one-time capability field',()=>{const v=Value(),bytes=codec.Encode(v);assert.deepEqual(codec.Decode(bytes),v);assert.ok(bytes.length<=codec.MAX);for(const name of ['schema','profile','launcherId','launcherTicket','expiresAt','serverPublicKey'])assert.equal(bytes.includes(Buffer.from('"'+name+'"')),false);bytes.fill(0);});
test('optional TLS transition state is preserved as bounded authenticated payload data',()=>{const v=Value();v.profile.tlsPinState='{"version":1,"generation":2,"한글":"지원"}';const bytes=codec.Encode(v);assert.equal(bytes.readUInt16LE(10),10);assert.deepEqual(codec.Decode(bytes),v);bytes.fill(0);});
test('new parser rejects the historical plaintext JSON representation',()=>{Invalid(()=>codec.Decode(Buffer.from(JSON.stringify(Value()))));});
test('header identity, version, count, total length and trailing bytes are strict',()=>{const bytes=codec.Encode(Value());for(const [offset,value,size] of [[0,0,1],[8,1,2],[10,8,2],[10,11,2],[12,bytes.length-1,4]]){const changed=Buffer.from(bytes);if(size===1)changed[offset]=value;else if(size===2)changed.writeUInt16LE(value,offset);else changed.writeUInt32LE(value,offset);Invalid(()=>codec.Decode(changed));}Invalid(()=>codec.Decode(bytes.subarray(0,-1)));Invalid(()=>codec.Decode(Buffer.concat([bytes,Buffer.from([0])])));});
test('TLV order, duplicates, lengths and truncated fields fail closed',()=>{const bytes=codec.Encode(Value());for(const [offset,value] of [[16,2],[18,0],[18,254],[18,65535]]){const changed=Buffer.from(bytes);changed.writeUInt16LE(value,offset);Invalid(()=>codec.Decode(changed));}const second=20+bytes.readUInt16LE(18),changed=Buffer.from(bytes);changed.writeUInt16LE(1,second);Invalid(()=>codec.Decode(changed));});
test('exact object and profile schemas reject unknown or unrepresentable input',()=>{const changes=[v=>v.extra=true,v=>v.schema=1,v=>v.launcherId='LA-'+v.launcherId,v=>v.launcherTicket+='=',v=>v.expiresAt=Number.MAX_SAFE_INTEGER+1,v=>v.profile.extra=true,v=>v.profile.protocol='GAME-CONNECT-3',v=>v.profile.port=0,v=>v.profile.host='UPPER.example',v=>v.profile.host='a..test',v=>v.profile.serverKeyId='ff'.repeat(32),v=>v.profile.serverPublicKey+='=',v=>v.profile.tlsPinState=undefined,v=>v.profile.tlsPinState='',v=>v.profile.tlsPinState='x'.repeat(6145),v=>v.profile.tlsPinState='\ud800'];for(const change of changes){const v=Value();change(v);Invalid(()=>codec.Encode(v));}});
test('decoder rejects non-ASCII host, invalid key binding, zero and oversized expiry',()=>{const bytes=codec.Encode(Value());let changed=Buffer.from(bytes);changed[20]=0xff;Invalid(()=>codec.Decode(changed));let cursor=16;const offsets=[];for(let i=0;i<9;i++){offsets.push(cursor+4);cursor+=4+bytes.readUInt16LE(cursor+2);}changed=Buffer.from(bytes);changed[offsets[2]]^=1;Invalid(()=>codec.Decode(changed));for(const n of [0n,9007199254740992n]){changed=Buffer.from(bytes);changed.writeBigUInt64LE(n,offsets[8]);Invalid(()=>codec.Decode(changed));}});
test('new native source parses public V3 without a bearer ticket or decryption call',()=>{const candidates=[path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Application/Cozy.Launcher.pas'),path.resolve(__dirname,'../../../cozy-peace/Railway/Cozy.Source/Cozy.Application/Cozy.Launcher.pas')],native=candidates.find(fs.existsSync);if(!native)return;const s=fs.readFileSync(native,'utf8');assert.match(s,/ConfigMarker: AnsiString = 'COZYA3CONFIG!'/);assert.match(s,/BinaryConfigMarker: AnsiString = 'COZYACF3'/);assert.match(s,/Result := ParsePublicConfig\(Bytes\)/);assert.doesNotMatch(s,/CozyProtectionDecryptConfig|TJSONObject\.ParseJSONValue\(Text\)|LauncherTicket/);for(let i=1;i<=8;i++)assert.ok(s.includes('Field('+i+', '));assert.match(s,/Field\(9, 1, 6144\)/);});

function Template(role){
 // Real templates retain parser marker literals internally. Only a terminal
 // personalization footer makes the file unsuitable for another issuance.
 const input=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture').PE(role,'encrypted-config-test GAMEA80CONFIG! COZYA2CONFIG!'),slot=engine.CreateUnsealedSlot(),bytes=Buffer.concat([input,slot]);
 const pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20),last=table+(bytes.readUInt16LE(pe+6)-1)*40,size=bytes.readUInt32LE(last+16)+slot.length;
 bytes.writeUInt32LE(size,last+8);bytes.writeUInt32LE(size,last+16);bytes.writeUInt32LE(Math.ceil((bytes.readUInt32LE(last+12)+size)/4096)*4096,opt+56);return bytes;
}
test('actual envelope authenticates before binary decoding and rejects wrong template, role, header, nonce, tag and ciphertext',()=>{
 const template=engine.Pack(Template('A'),'A').bytes,other=engine.Pack(Template('A'),'A').bytes,b=engine.Pack(Template('B'),'B').bytes,value=Value(),plain=codec.Encode(value),nonce=crypto.randomBytes(12),box=engine.SealLauncherConfig(template,plain,nonce);
 try{
  assert.deepEqual(codec.Decode(engine.OpenLauncherConfig(template,box)),value);assert.deepEqual(engine.SealLauncherConfig(template,plain,nonce),box);
  for(const offset of [0,16,20,24,36,52,box.length-1]){const changed=Buffer.from(box);changed[offset]^=1;assert.throws(()=>engine.OpenLauncherConfig(template,changed),/^Error: COZY_PROTECTION_/);}
  assert.throws(()=>engine.OpenLauncherConfig(other,box),/COZY_PROTECTION_CONFIG_AUTHENTICATION_FAILED/);assert.throws(()=>engine.OpenLauncherConfig(b,box),/COZY_PROTECTION_CONFIG_TEMPLATE_REQUIRED/);
  // Independent reference: the raw VM key cannot decrypt the config domain.
  const slotAt=template.length-engine.SLOT_BYTES,rawKey=template.subarray(slotAt+40,slotAt+72),configKey=crypto.createHmac('sha512',rawKey).update(Buffer.from('COZY-LAUNCHER-CONFIG-V2\0','ascii')).digest().subarray(0,32);
  try{const reference=crypto.createDecipheriv('aes-256-gcm',configKey,box.subarray(24,36));reference.setAAD(box.subarray(0,36));reference.setAuthTag(box.subarray(36,52));const decoded=Buffer.concat([reference.update(box.subarray(52)),reference.final()]);assert.equal(decoded.equals(plain),true);decoded.fill(0);}
  finally{configKey.fill(0);}
  const dec=crypto.createDecipheriv('aes-256-gcm',rawKey,box.subarray(24,36));dec.setAAD(box.subarray(0,36));dec.setAuthTag(box.subarray(36,52));assert.throws(()=>{dec.update(box.subarray(52));dec.final();});
  assert.equal(box.includes(Buffer.from(value.launcherTicket)),false);assert.equal(box.includes(Buffer.from(value.profile.host)),false);
 }finally{template.fill(0);other.fill(0);b.fill(0);plain.fill(0);nonce.fill(0);box.fill(0);}
});
test('historical non-VM issuance remains compatible while new embedded-key VM issuance is retired',()=>{
 const oldLog=console.log;console.log=()=>{};
 const os=require('node:os'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-config-issue-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
 let bootstrap;
 try{
  require('../../core/peace.utilities').EnsureDirs();bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap');const store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),evidence=require('../../services/artifacts/peace.desktop-packing-evidence'),fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
  fixture.Publish();const old=bootstrap.IssueLauncher({requestId:crypto.randomUUID()},'TEST'),oldBytes=bootstrap.LauncherBytes(old.launcherId);assert.equal(fixture.Config(oldBytes).launcherId,old.launcherId);assert.equal(store.Load().launchers[old.launcherId].configNonce,undefined);
  assert.throws(()=>bootstrap.Publish('A','1.0.3',oldBytes,undefined,{activate:false}),{message:'BOOTSTRAP_TEMPLATE_PERSONALIZED'});
  const jobId=crypto.randomBytes(16).toString('hex'),createdAt=Date.now(),outputs={},records=[];
  for(const role of ['A','B','O']){
   const input=Template(role),source=bootstrap.Publish(role,'1.0.1',input,undefined,{activate:false}),out=engine.Pack(input,role);outputs[role]=out;
   records.push({version:1,purpose:evidence.DOMAIN,jobId,component:role,sourceArtifactId:source.id,inputSha512:out.inputSha512,outputSha512:out.sha512,size:out.bytes.length,toolSha512:out.toolSha512,profileSha512:out.profileSha512,createdAt,actorHash:'ab'.repeat(64)});input.fill(0);
  }
  store.Atomic(db=>evidence.RecordJob(db,records));const selected={};for(const role of ['A','B','O'])selected[role]=bootstrap.Publish(role,'1.0.2',outputs[role].bytes,undefined,{activate:false});store.Atomic(db=>{for(const role of ['A','B','O'])db.active[role]=selected[role].id;});
  const before=Object.keys(store.Load().launchers);assert.throws(()=>bootstrap.IssueLauncher({requestId:crypto.randomUUID()},'TEST'),{message:'COZY_VM_V1_EMBEDDED_KEY_RETIRED'});assert.deepEqual(Object.keys(store.Load().launchers),before);
  for(const output of Object.values(outputs))output.bytes.fill(0);oldBytes.fill(0);
 }finally{console.log=oldLog;bootstrap?.Stop();require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(temp,{recursive:true,force:true});}
});
