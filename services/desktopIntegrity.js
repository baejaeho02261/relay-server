'use strict';
// CRC64-ECMA-182: non-reflected, init=0, xorout=0. This checksum detects
// accidental corruption only; SHA-256 + authenticated transport/signatures
// remain mandatory for security. No client memory attestation is implied.
const crypto=require('node:crypto'),high=new Uint32Array(256),low=new Uint32Array(256);
for(let i=0;i<256;i++){
 let value=BigInt(i)<<56n;
 for(let bit=0;bit<8;bit++)value=BigInt.asUintN(64,(value<<1n)^((value&0x8000000000000000n)?0x42F0E1EBA9EA3693n:0n));
 high[i]=Number(value>>32n);low[i]=Number(value&0xffffffffn);
}
function Crc64(bytes){
 if(!Buffer.isBuffer(bytes)&&!(bytes instanceof Uint8Array))throw TypeError('INTEGRITY_BYTES_REQUIRED');
 let hi=0,lo=0;
 for(let i=0;i<bytes.length;i++){const index=(hi>>>24)^bytes[i];hi=(((hi<<8)|(lo>>>24))^high[index])>>>0;lo=((lo<<8)^low[index])>>>0;}
 return hi.toString(16).padStart(8,'0').toUpperCase()+lo.toString(16).padStart(8,'0').toUpperCase();
}
function Digests(bytes){return {sha256:crypto.createHash('sha256').update(bytes).digest('hex'),crc64:Crc64(bytes)};}
module.exports={Crc64,Digests};
