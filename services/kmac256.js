'use strict';
// NIST SP 800-185 KMAC256, not KMACXOF or SHAKE with an appended key.
// Keep the exact pinned upstream implementation. This adapter constrains sizes
// and wipes owned key/state buffers; it does not claim FIPS module validation.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const directory=path.join(__dirname,'vendor','noble-hashes-1.8.0');
const manifest=require('./vendor/noble-hashes-1.8.0/manifest.json');
for(const [file,digest]of Object.entries(manifest)){
 const bytes=fs.readFileSync(path.join(directory,file));
 if(crypto.createHash('sha512').update(bytes).digest('hex')!==digest)throw Error('INTEGRITY_HASH_ASSET_INVALID');
}
const {kmac256}=require('./vendor/noble-hashes-1.8.0/sha3-addons');
const MAX_BYTES=64*1024*1024,MAX_OUTPUT=1024;
function Bytes(value,min,max,code){if(!(value instanceof Uint8Array)||value.byteLength<min||value.byteLength>max)throw TypeError(code);return value;}
function Kmac256(key,message,customization='',outputLength=64){
 Bytes(key,32,1024,'KMAC_KEY_INVALID');Bytes(message,0,MAX_BYTES,'KMAC_INPUT_INVALID');
 if(typeof customization!=='string'||Buffer.byteLength(customization)>1024)throw TypeError('KMAC_CUSTOMIZATION_INVALID');
 if(!Number.isSafeInteger(outputLength)||outputLength<32||outputLength>MAX_OUTPUT)throw RangeError('KMAC_OUTPUT_INVALID');
 const state=kmac256.create(key,{dkLen:outputLength,personalization:customization});
 try{return Buffer.from(state.update(message).digest());}finally{state.destroy();}
}
function ServerMac(masterKey,message,purpose){
 Bytes(masterKey,32,64,'KMAC_MASTER_KEY_INVALID');
 if(typeof purpose!=='string'||!/^GAME-[A-Z0-9-]{1,120}-V[1-9][0-9]*$/.test(purpose))throw TypeError('KMAC_PURPOSE_INVALID');
 const info=Buffer.from('GAME-SERVER-KMAC-KEY-V1\n'+purpose,'ascii');
 const key=Buffer.from(crypto.hkdfSync('sha512',masterKey,Buffer.alloc(0),info,32));let tag;
 try{tag=Kmac256(key,message,purpose,64);return tag.toString('hex');}
 finally{key.fill(0);info.fill(0);tag?.fill(0);}
}
// NIST KMAC sample #4: a small startup check independent of application keys.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
const testKey=Buffer.from(Array.from({length:32},(_,i)=>0x40+i));let testTag;
try{
 testTag=Kmac256(testKey,Buffer.from([0,1,2,3]),'My Tagged Application',64);
 if(testTag.toString('hex')!=='20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd')throw Error('KMAC_SELF_TEST_FAILED');
}finally{testKey.fill(0);testTag?.fill(0);}
module.exports={Kmac256,ServerMac,MAX_BYTES,MAX_OUTPUT};
