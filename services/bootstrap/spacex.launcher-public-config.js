'use strict';
// Public bootstrap connection data. This version deliberately carries no
// launcher ticket, decryption key, license, or executable payload. Possession
// of these bytes grants no execution authority; separate key proofs and
// administrator approval are mandatory on the server.
const crypto=require('node:crypto');
const MAGIC=Buffer.from('COZYACF3','ascii'),MAX=8192,COUNT=8;
function Fail(){const e=Error('BOOTSTRAP_CONFIG_INVALID');e.desktopError=true;e.bootstrapError=true;e.status=400;throw e;}
function Shape(v,names){if(!v||typeof v!=='object'||Array.isArray(v)||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).length!==names.length||names.some(n=>!Object.hasOwn(v,n)))Fail();}
function Host(v){if(typeof v!=='string'||v.length<1||v.length>253||v!==v.toLowerCase()||v.split('.').some(x=>x.length<1||x.length>63||!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x)))Fail();return v;}
function Hex(v,n){if(typeof v!=='string'||v.length!==n*2||!/^[a-f0-9]+$/.test(v))Fail();return Buffer.from(v,'hex');}
function PublicKey(bytes,keyId){
 if(!Buffer.isBuffer(bytes)||bytes.length<281||bytes.length>288||bytes.readUInt32LE(0)!==0x31415352||bytes.readUInt32LE(4)!==2048||bytes.readUInt32LE(12)!==256||bytes.readUInt32LE(16)!==0||bytes.readUInt32LE(20)!==0)Fail();
 const n=bytes.readUInt32LE(8);if(n<1||n>8||bytes.length!==24+n+256||bytes[24]===0||!(bytes[24+n]&128)||!(bytes.at(-1)&1))Fail();
 let exponent=0n;for(let i=0;i<n;i++)exponent=exponent*256n+BigInt(bytes[24+i]);if(exponent<3n||!(exponent&1n)||crypto.createHash('sha256').update(bytes).digest('hex')!==keyId)Fail();
}
function Validate(v){
 Shape(v,['schema','profile','launcherId','expiresAt']);if(v.schema!==3||!Number.isSafeInteger(v.expiresAt)||v.expiresAt<1)Fail();
 const p=v.profile;Shape(p,['version','protocol','host','port','serverKeyId','serverPublicKey','tlsServerName','tlsCertificateSha256',...(Object.hasOwn(p||{},'tlsPinState')?['tlsPinState']:[])]);if(Object.hasOwn(p,'tlsPinState')&&(typeof p.tlsPinState!=='string'||Buffer.byteLength(p.tlsPinState,'utf8')<1||Buffer.byteLength(p.tlsPinState,'utf8')>6144||Buffer.from(p.tlsPinState,'utf8').toString('utf8')!==p.tlsPinState))Fail();
 if(p.version!==4||p.protocol!=='GAME-CONNECT-4'||!Number.isInteger(p.port)||p.port<1||p.port>65535)Fail();Host(p.host);Host(p.tlsServerName);Hex(p.serverKeyId,32).fill(0);Hex(p.tlsCertificateSha256,32).fill(0);
 if(typeof p.serverPublicKey!=='string'||p.serverPublicKey.length<376||p.serverPublicKey.length>384||!/^[A-Za-z0-9+/]+={0,2}$/.test(p.serverPublicKey))Fail();
 const pub=Buffer.from(p.serverPublicKey,'base64');try{if(pub.toString('base64')!==p.serverPublicKey)Fail();PublicKey(pub,p.serverKeyId);}finally{pub.fill(0);}
 if(typeof v.launcherId!=='string'||!/^[A-F0-9]{24}$/.test(v.launcherId))Fail();return v;
}
function Encode(value){
 const v=Validate(value),p=v.profile,port=Buffer.alloc(2),expires=Buffer.alloc(8);port.writeUInt16LE(p.port);expires.writeBigUInt64LE(BigInt(v.expiresAt));
 const fields=[Buffer.from(p.host,'ascii'),port,Hex(p.serverKeyId,32),Buffer.from(p.serverPublicKey,'base64'),Buffer.from(p.tlsServerName,'ascii'),Hex(p.tlsCertificateSha256,32),Buffer.from(v.launcherId,'hex'),expires];
 if(p.tlsPinState!==undefined)fields.push(Buffer.from(p.tlsPinState,'utf8'));
 try{
  const total=16+fields.reduce((n,b)=>n+4+b.length,0);if(total>MAX)Fail();const result=Buffer.alloc(total);MAGIC.copy(result);result.writeUInt16LE(3,8);result.writeUInt16LE(fields.length,10);result.writeUInt32LE(total,12);let offset=16;
  for(let i=0;i<fields.length;i++){result.writeUInt16LE(i+1,offset);result.writeUInt16LE(fields[i].length,offset+2);fields[i].copy(result,offset+4);offset+=4+fields[i].length;}return result;
 }finally{for(const b of fields)b.fill(0);}
}
function Decode(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<16||bytes.length>MAX||!bytes.subarray(0,8).equals(MAGIC)||bytes.readUInt16LE(8)!==3||![COUNT,COUNT+1].includes(bytes.readUInt16LE(10))||bytes.readUInt32LE(12)!==bytes.length)Fail();
 const limits=[[1,253],[2,2],[32,32],[281,288],[1,253],[32,32],[12,12],[8,8],[1,6144]],fields=[];let offset=16;const count=bytes.readUInt16LE(10);
 for(let i=0;i<count;i++){if(offset>bytes.length-4||bytes.readUInt16LE(offset)!==i+1)Fail();const n=bytes.readUInt16LE(offset+2),[min,max]=limits[i];if(n<min||n>max||n>bytes.length-offset-4)Fail();fields.push(bytes.subarray(offset+4,offset+4+n));offset+=4+n;}
 if(offset!==bytes.length||fields[7].readBigUInt64LE()>BigInt(Number.MAX_SAFE_INTEGER))Fail();
 for(const i of [0,4])if(fields[i].some(x=>x<0x21||x>0x7e))Fail();
 let pinState;if(fields[8]){try{pinState=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(fields[8]);}catch(_){Fail();}}
 return Validate({schema:3,profile:{version:4,protocol:'GAME-CONNECT-4',host:fields[0].toString('ascii'),port:fields[1].readUInt16LE(),serverKeyId:fields[2].toString('hex'),serverPublicKey:fields[3].toString('base64'),tlsServerName:fields[4].toString('ascii'),tlsCertificateSha256:fields[5].toString('hex'),...(pinState!==undefined?{tlsPinState:pinState}:{})},launcherId:fields[6].toString('hex').toUpperCase(),expiresAt:Number(fields[7].readBigUInt64LE())});
}
module.exports={Encode,Decode,MAX};
