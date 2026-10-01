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
 if(binary.length!==asset.bytes||crypto.createHash('sha256').update(binary).digest('hex')!==asset.sha256)throw Error('INTEGRITY_HASH_ASSET_INVALID');
 const api=new WebAssembly.Instance(new WebAssembly.Module(binary),{}).exports;
 const memory=new Uint8Array(api.memory.buffer,api.Hash_GetBuffer(),CHUNK_BYTES);
 return bytes=>{
  if(!(bytes instanceof Uint8Array))throw TypeError('INTEGRITY_BYTES_REQUIRED');
  // Respect offset/length of a Buffer or Uint8Array view without copying input.
  const input=new Uint8Array(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  // XXH64 reads a little-endian 64-bit seed from the first eight buffer bytes.
  // BLAKE3 Hash_Init(0) selects unkeyed hashing (no key or derivation context).
  if(name==='xxhash64')memory.fill(0,0,8);
  api.Hash_Init(0);
  for(let offset=0;offset<input.length;offset+=CHUNK_BYTES){
   const chunk=input.subarray(offset,offset+CHUNK_BYTES);
   memory.set(chunk);api.Hash_Update(chunk.length);
  }
  api.Hash_Final(name==='blake3'?digestBytes:0);
  // The upstream XXH64 finalizer writes big-endian/canonical digest bytes.
  // BLAKE3 emits its normal 32-byte digest. Buffer hex is lowercase and padded.
  return Buffer.from(memory.buffer,memory.byteOffset,digestBytes).toString('hex');
 };
}

// Calls contain no await or callback, so a module's instance cannot interleave
// requests. Workers load their own instances; each call fully resets state.
const Xxh64=Load('xxhash64',8),Blake3=Load('blake3',32);
function ExtendedDigests(bytes){return {xxh64:Xxh64(bytes),blake3:Blake3(bytes)};}
module.exports={Xxh64,Blake3,ExtendedDigests};
