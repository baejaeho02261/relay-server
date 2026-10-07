'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const {performance}=require('node:perf_hooks');
const upstream=require('hash-wasm');
const {blake3:nobleBlake3}=require('@noble/hashes/blake3');
const {Xxh3_128,Blake3,ExtendedDigests}=require('../services/extendedHashes');
const {Digests,Crc64}=require('../services/desktopIntegrity');
const fixture=require('./fixtures/extended-hash-vectors.json');

function Bytes(row){
 if(row.pattern==='ascii')return Buffer.from(row.ascii,'ascii');
 const bytes=Buffer.alloc(row.length),pattern=Buffer.from(Array.from({length:251},(_,i)=>i));
 bytes.fill(pattern);return bytes;
}

async function Main(){
 require('./check-extended-hash-assets');
 const streamXxh=await upstream.createXXHash128(0,0),streamBlake=await upstream.createBLAKE3(256);
 const steps=[1,17,31,64,1023,4097,16384,65535];
 let official=0,maximumMs=0;
 for(const row of fixture.cases){
  const bytes=Bytes(row),label=row.pattern+':'+row.length;
  assert.equal(bytes.length,row.length,label);
  const expected={xxh3_128:row.xxh3_128,blake3:row.blake3},before=crypto.createHash('sha512').update(bytes).digest('hex');
  const started=performance.now(),actual=ExtendedDigests(bytes),elapsed=performance.now()-started;
  if(row.length===64*1024*1024)maximumMs=elapsed;
  assert.deepEqual(actual,expected,label);
  assert.match(actual.xxh3_128,/^[a-f0-9]{32}$/);assert.match(actual.blake3,/^[a-f0-9]{64}$/);
  assert.equal(await upstream.xxhash128(bytes,0,0),expected.xxh3_128,label+' public upstream API');
  assert.equal(await upstream.blake3(bytes,256),expected.blake3,label+' public upstream API');
  assert.equal(Buffer.from(nobleBlake3(bytes,{dkLen:32})).toString('hex'),expected.blake3,label+' independent implementation');
  if(row.blake3Source==='BLAKE3-team official test_vectors.json')official++;
  streamXxh.init();streamBlake.init();
  for(let at=0,index=0;at<bytes.length;index++){
   const next=Math.min(bytes.length,at+steps[index%steps.length]),piece=bytes.subarray(at,next);
   streamXxh.update(piece);streamBlake.update(piece);at=next;
  }
  assert.equal(streamXxh.digest(),expected.xxh3_128,label+' segmented upstream');
  assert.equal(streamBlake.digest(),expected.blake3,label+' segmented upstream');
  // Nonzero buffer offset catches accidentally hashing the whole backing store.
  if(row.length<=102400){
   const backing=Buffer.alloc(bytes.length+19,0xa5);bytes.copy(backing,7);
   const view=new Uint8Array(backing.buffer,backing.byteOffset+7,bytes.length);
   assert.equal(Xxh3_128(view),expected.xxh3_128,label+' Uint8Array view');
   assert.equal(Blake3(view),expected.blake3,label+' Uint8Array view');
   assert.deepEqual(backing.subarray(0,7),Buffer.alloc(7,0xa5));
   assert.deepEqual(backing.subarray(7+bytes.length),Buffer.alloc(12,0xa5));
  }
  assert.equal(crypto.createHash('sha512').update(bytes).digest('hex'),before,label+' input stays unchanged');
  const all=Digests(bytes);
  assert.equal(all.sha512,before,label+' SHA-512');
  assert.equal(all.crc64,Crc64(bytes),label+' existing CRC64');
  assert.equal(all.xxh3_128,expected.xxh3_128);assert.equal(all.blake3,expected.blake3);
 }
 assert.equal(official,35,'all upstream BLAKE3 known-answer vectors are retained');
 const empty=fixture.cases.find(row=>row.length===0);
 assert.equal(Xxh3_128(Buffer.alloc(0)),empty.xxh3_128,'previous calls cannot seed the next XXH3-128');
 assert.equal(Blake3(Buffer.alloc(0)),empty.blake3,'previous calls cannot key the next BLAKE3');
 assert.equal(Crc64(Buffer.from('123456789')),'6C40DF5F0B497347','CRC64 ECMA-182 contract remains unchanged');
 assert.equal(Digests(Buffer.from('abc')).sha512,'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f','SHA-512 known answer');
 for(const bad of [null,undefined,'abc',[],{},new ArrayBuffer(8),new Uint16Array(2)]){
  assert.throws(()=>Xxh3_128(bad),/INTEGRITY_BYTES_REQUIRED/);
  assert.throws(()=>Blake3(bad),/INTEGRITY_BYTES_REQUIRED/);
 }
 console.log('EXTENDED HASHES PASS: '+fixture.cases.length+' independent known answers, all 35 official BLAKE3 vectors, upstream public API, chunk boundaries, view offsets, resets, unchanged SHA/CRC');
 console.log('64-MiB extended hash timing (informational): '+maximumMs.toFixed(1)+' ms');
}
Main().catch(error=>{console.error(error);process.exitCode=1;});
