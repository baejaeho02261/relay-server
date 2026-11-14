'use strict';
// Shared wire constraints for the optional, separately hosted packer. No
// release keys or license decisions belong to this protocol.
const crypto=require('node:crypto');
const MAX_BYTES=64*1024*1024,MAX_MS=180000;
const Sha512=b=>crypto.createHash('sha512').update(b).digest('hex');
const IsDigest=x=>typeof x==='string'&&/^[a-f0-9]{128}$/.test(x);
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Pe(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>MAX_BYTES||bytes.readUInt16LE(0)!==0x5a4d)Fail('PACKING_PE_INVALID');
 const p=bytes.readUInt32LE(60);if(p<64||p+24>bytes.length||bytes.readUInt32LE(p)!==0x4550||bytes.readUInt16LE(p+4)!==0x8664)Fail('PACKING_PE_INVALID');
 const n=bytes.readUInt16LE(p+6),s=bytes.readUInt16LE(p+20),o=p+24;
 if(n<1||n>96||s<112||o+s+n*40>bytes.length||bytes.readUInt16LE(o)!==0x20b||!(bytes.readUInt16LE(p+22)&2)||(bytes.readUInt16LE(p+22)&0x2000))Fail('PACKING_PE_INVALID');
 return true;
}
function Spki(rawCertificate){return Sha512(new crypto.X509Certificate(rawCertificate).publicKey.export({type:'spki',format:'der'}));}
function Equal(a,b){if(!IsDigest(a)||!IsDigest(b))return false;return crypto.timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));}
function ReadBody(req){return new Promise((resolve,reject)=>{
 const length=req.headers['content-length'];
 if(!/^\d{1,9}$/.test(length||'')||Number(length)<512||Number(length)>MAX_BYTES||req.headers['content-encoding']&&req.headers['content-encoding']!=='identity'){req.resume();reject(Error('PACKING_SIZE_INVALID'));return;}
 let size=0,done=false;const chunks=[],timer=setTimeout(()=>finish(Error('PACKING_READ_TIMEOUT')),30000);timer.unref();
 function finish(e){if(done)return;done=true;clearTimeout(timer);if(e){chunks.length=0;req.resume();reject(e);}else resolve(Buffer.concat(chunks,size));}
 req.on('data',b=>{if(done)return;size+=b.length;if(size>Number(length)||size>MAX_BYTES)return finish(Error('PACKING_SIZE_INVALID'));chunks.push(b);});
 req.once('error',finish);req.once('aborted',()=>finish(Error('PACKING_READ_ABORTED')));req.once('end',()=>finish(size===Number(length)?null:Error('PACKING_SIZE_INVALID')));
 });}
module.exports={MAX_BYTES,MAX_MS,Sha512,IsDigest,Pe,Spki,Equal,ReadBody,Fail};
