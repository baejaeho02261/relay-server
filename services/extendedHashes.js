'use strict';
// Synchronous adapter for the unmodified, pinned hash-wasm 4.12.0 binaries.
// These implementations have no native Node ABI or install/build dependency.
// See vendor/hash-wasm-4.12.0/PROVENANCE.txt for source, licenses and extraction.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const directory=path.join(__dirname,'vendor','hash-wasm-4.12.0');
const manifest=require('./vendor/hash-wasm-4.12.0/manifest.json');
const CHUNK_BYTES=16*1024; // Upstream MAIN_BUFFER_SIZE and MAX_HEAP.

function Load(name,digestBytes){
 const asset=manifest.assets[name],binary=fs.readFileSync(path.join(directory,asset.file));
 if(binary.length!==asset.bytes||crypto.createHash('sha512').update(binary).digest('hex')!==asset.sha512)throw Error('INTEGRITY_HASH_ASSET_INVALID');
 const api=new WebAssembly.Instance(new WebAssembly.Module(binary),{}).exports;
 const memory=new Uint8Array(api.memory.buffer,api.Hash_GetBuffer(),CHUNK_BYTES);
 const stateSize=new DataView(api.memory.buffer).getUint32(Number(api.STATE_SIZE.value),true),state=new Uint8Array(api.memory.buffer,api.Hash_GetState(),stateSize);
 return bytes=>{
  if(!(bytes instanceof Uint8Array))throw TypeError('INTEGRITY_BYTES_REQUIRED');
  // Respect offset/length of a Buffer or Uint8Array view without copying input.
  const input=new Uint8Array(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  // XXH3-128 reads a little-endian 64-bit seed from the first eight buffer bytes.
  // BLAKE3 Hash_Init(0) selects unkeyed hashing (no key or derivation context).
  try{
  if(name==='xxhash128')memory.fill(0,0,8);
  api.Hash_Init(0);
  for(let offset=0;offset<input.length;offset+=CHUNK_BYTES){
   const chunk=input.subarray(offset,offset+CHUNK_BYTES);
   memory.set(chunk);api.Hash_Update(chunk.length);
  }
  api.Hash_Final(name==='blake3'?digestBytes:0);
  // The upstream XXH3-128 finalizer writes big-endian/canonical digest bytes.
  // BLAKE3 emits its normal 32-byte digest. Buffer hex is lowercase and padded.
  return Buffer.from(memory.buffer,memory.byteOffset,digestBytes).toString('hex');
  }finally{memory.fill(0);state.fill(0);}
 };
}

// Calls contain no await or callback, so a module's instance cannot interleave
// requests. Workers load their own instances; each call fully resets state.
const Xxh3_128=Load('xxhash128',16),Blake3=Load('blake3',32);
function ExtendedDigests(bytes){return {xxh3_128:Xxh3_128(bytes),blake3:Blake3(bytes)};}

// Standard modes use the pinned upstream implementation, including its ordinary
// BLAKE3 chunk tree. Separate worker threads may own independent hash instances;
// this server does not change digest semantics or invent a hash-of-hashes mode.
const nobleDirectory=path.join(__dirname,'vendor','noble-hashes-1.8.0');
const nobleManifest=require('./vendor/noble-hashes-1.8.0/manifest.json');
for(const [file,digest] of Object.entries(nobleManifest)){
 const bytes=fs.readFileSync(path.join(nobleDirectory,file));
 if(crypto.createHash('sha512').update(bytes).digest('hex')!==digest)throw Error('INTEGRITY_HASH_ASSET_INVALID');
}
const {blake3}=require('./vendor/noble-hashes-1.8.0/blake3');
function Bytes(value){if(!(value instanceof Uint8Array))throw TypeError('INTEGRITY_BYTES_REQUIRED');return value;}
function OutputSize(length){if(!Number.isSafeInteger(length)||length<1||length>65536)throw RangeError('BLAKE3_OUTPUT_INVALID');return length;}
function Blake3Incremental(options={}){
 const {key,context,length=32}=options;OutputSize(length);
 if(key!==undefined&&(Bytes(key).length!==32))throw RangeError('BLAKE3_KEY_INVALID');
 if(context!==undefined&&(typeof context!=='string'||!context.length||Buffer.byteLength(context)>1024))throw TypeError('BLAKE3_CONTEXT_INVALID');
 if(key!==undefined&&context!==undefined)throw TypeError('BLAKE3_MODE_INVALID');
 const hasher=blake3.create({dkLen:length,...(key!==undefined?{key}:{}),...(context!==undefined?{context}:{})});let done=false;
 return {
  update(bytes){if(done)throw Error('BLAKE3_FINALIZED');hasher.update(Bytes(bytes));return this;},
  digest(){if(done)throw Error('BLAKE3_FINALIZED');done=true;try{return Buffer.from(hasher.digest());}finally{hasher.destroy();}},
  destroy(){done=true;hasher.destroy();}
 };
}
function Blake3Mode(bytes,options){const state=Blake3Incremental(options);try{return state.update(bytes).digest();}finally{state.destroy();}}
function Blake3Keyed(key,bytes,length=32){return Blake3Mode(bytes,{key,length});}
function Blake3DeriveKey(context,material,length=32){return Blake3Mode(material,{context,length});}
function Blake3Xof(bytes,length){return Blake3Mode(bytes,{length});}
module.exports={Xxh3_128,Blake3,ExtendedDigests,Blake3Incremental,Blake3Keyed,Blake3DeriveKey,Blake3Xof};
