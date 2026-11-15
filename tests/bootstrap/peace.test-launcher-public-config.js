'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const codec=require('../../services/bootstrap/peace.launcher-public-config'),legacy=require('../../services/bootstrap/peace.launcher-config');
const key=crypto.generateKeyPairSync('rsa',{modulusLength:2048}).publicKey,blob=require('../../services/network/peace.connect-transport-key').PublicBlob(key);
const value=()=>({schema:3,profile:{version:4,protocol:'GAME-CONNECT-4',host:'relay.example.test',port:443,serverKeyId:crypto.createHash('sha256').update(blob).digest('hex'),serverPublicKey:blob.toString('base64'),tlsServerName:'relay.example.test',tlsCertificateSha256:'a1'.repeat(32)},launcherId:'AB'.repeat(12),expiresAt:1793000000000});
const reject=fn=>assert.throws(fn,{message:'BOOTSTRAP_CONFIG_INVALID'});
test('public V3 schema roundtrips eight fields and optional UTF-8 pin state',()=>{
 for(const pin of [undefined,'{"version":1,"한글":"지원"}']){const v=value();if(pin)v.profile.tlsPinState=pin;const b=codec.Encode(v);assert.deepEqual(codec.Decode(b),v);assert.equal(b.subarray(0,8).toString(),'COZYACF3');assert.equal(b.readUInt16LE(8),3);assert.equal(b.readUInt16LE(10),pin?9:8);assert.equal(b.readUInt32LE(12),b.length);assert.ok(b.length<=codec.MAX);}
});
test('public V3 rejects any credential field and legacy capability representation',()=>{
 for(const name of ['launcherTicket','key','privateKey','license','configNonce','secret'])reject(()=>codec.Encode({...value(),[name]:'forbidden'}));
 const old={...value(),schema:2,launcherTicket:crypto.randomBytes(32).toString('base64url')};reject(()=>codec.Decode(legacy.Encode(old)));reject(()=>legacy.Decode(codec.Encode(value())));reject(()=>codec.Decode(Buffer.from(JSON.stringify(value()))));
 for(const change of [v=>v.schema=2,v=>v.profile.extra=true,v=>v.profile.serverKeyId='00'.repeat(32),v=>v.profile.port=0,v=>v.profile.host='UPPER.test',v=>v.expiresAt=0,v=>v.expiresAt=Number.MAX_SAFE_INTEGER+1,v=>v.profile.tlsPinState='\ud800',v=>v.profile.tlsPinState='x'.repeat(6145)]){const v=value();change(v);reject(()=>codec.Encode(v));}
});
test('public V3 decoder rejects wrong version, counts, order, duplicates, lengths and trailing data',()=>{
 const b=codec.Encode(value());for(const [offset,n,size]of [[0,0,1],[8,2,2],[10,7,2],[10,10,2],[12,b.length-1,4],[16,2,2],[18,0,2],[18,65535,2]]){const changed=Buffer.from(b);if(size===1)changed[offset]=n;else if(size===2)changed.writeUInt16LE(n,offset);else changed.writeUInt32LE(n,offset);reject(()=>codec.Decode(changed));}
 const duplicate=Buffer.from(b);duplicate.writeUInt16LE(1,20+b.readUInt16LE(18));reject(()=>codec.Decode(duplicate));reject(()=>codec.Decode(b.subarray(0,-1)));reject(()=>codec.Decode(Buffer.concat([b,Buffer.from([0])])));
});
test('public V3 decoder enforces field encoding, exact key binding and safe positive expiry',()=>{
 const v=value();v.profile.tlsPinState='valid';const b=codec.Encode(v),offsets=[];for(let cursor=16,i=0;i<9;i++){offsets.push(cursor+4);cursor+=4+b.readUInt16LE(cursor+2);}
 for(const offset of [offsets[0],offsets[4],offsets[8]]){const changed=Buffer.from(b);changed[offset]=255;reject(()=>codec.Decode(changed));}
 const badKey=Buffer.from(b);badKey[offsets[2]]^=1;reject(()=>codec.Decode(badKey));
 for(const n of [0n,9007199254740992n]){const changed=Buffer.from(b);changed.writeBigUInt64LE(n,offsets[7]);reject(()=>codec.Decode(changed));}
});
