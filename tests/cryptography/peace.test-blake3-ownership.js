'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {createRequire}=require('node:module');
const actual=require("../../services/cryptography/peace.extended-hashes");
const {blake3}=require("../../services/cryptography/vendor/noble-hashes-1.8.0/peace.blake3.js");
let checks=0;const test=(name,fn)=>{fn();checks++;console.log('PASS '+name);};
const material=Buffer.from(Array.from({length:4099},(_,i)=>i%251)),materialCopy=Buffer.from(material);
test('Real repeated keyed MACs never erase Buffer, offset-view or Uint8Array owner keys',()=>{
 const backing=Buffer.alloc(48,7),key=backing.subarray(9,41),before=Buffer.from(backing);
 const expected=Buffer.from(blake3(material,{key:Uint8Array.from(key)}));
 for(const original of [key,Uint8Array.from(key)]){
  const first=actual.Blake3Keyed(original,material),second=actual.Blake3Keyed(original,material);
  assert.deepEqual(first,expected);assert.deepEqual(second,expected);
  assert.deepEqual(Buffer.from(original),Buffer.alloc(32,7));
 }
 assert.deepEqual(backing,before);assert.deepEqual(material,materialCopy);
});
test('Incremental stream owns its key before caller mutation and explicit destruction',()=>{
 const key=Buffer.alloc(32,19),original=Buffer.from(key),stream=actual.Blake3Incremental({key});
 key.fill(23);stream.update(material.subarray(0,1024)).update(material.subarray(1024));
 assert.deepEqual(stream.digest(),Buffer.from(blake3(material,{key:Uint8Array.from(original)})));
 stream.destroy();assert.deepEqual(key,Buffer.alloc(32,23));
 const discarded=actual.Blake3Incremental({key});discarded.update(material);discarded.destroy();discarded.destroy();
 assert.deepEqual(key,Buffer.alloc(32,23));assert.throws(()=>discarded.digest(),/BLAKE3_FINALIZED/);
});
test('Derive, unkeyed and XOF preserve caller material on success and failed updates',()=>{
 const context='cozy.Client.Test.KeyOwnership.v1';
 assert.deepEqual(actual.Blake3DeriveKey(context,material),Buffer.from(blake3(material,{context})));
 assert.deepEqual(actual.Blake3Xof(material,65),Buffer.from(blake3(material,{dkLen:65})));
 assert.deepEqual(material,materialCopy);
 for(const options of [{},{context},{key:Buffer.alloc(32,31)}]){
  const original=options.key&&Buffer.from(options.key),stream=actual.Blake3Incremental(options);
  stream.update(material);assert.throws(()=>stream.update('invalid bytes'),/INTEGRITY_BYTES_REQUIRED/);
  assert.throws(()=>stream.digest(),/BLAKE3_FINALIZED/);stream.destroy();
  if(original)assert.deepEqual(options.key,original);
 }
 assert.deepEqual(material,materialCopy);
});
function WithHasher(factory){
 const filename=path.resolve(MODULE_RESOURCE_ROOT,"../services/cryptography/peace.extended-hashes.js"),source=fs.readFileSync(filename,'utf8'),baseRequire=createRequire(filename),module={exports:{}};
 vm.runInNewContext(source,{module,exports:module.exports,require:id=>id==='./vendor/noble-hashes-1.8.0/peace.blake3.js'?{blake3:{create:factory}}:baseRequire(id),__dirname:path.dirname(filename),__filename:filename,Buffer,Uint8Array,WebAssembly,DataView,Error,TypeError,RangeError},{filename});
 return module.exports;
}
test('Private key copies are wiped after construction, update, digest and destroy failures',()=>{
 for(const failure of ['create','update','digest','destroy','none']){
  const key=Buffer.alloc(32,41),original=Buffer.from(key);let owned,destroyed=0;
  const adapter=WithHasher(options=>{
   owned=options.key;assert.notStrictEqual(owned,key);assert.deepEqual(owned,key);
   if(failure==='create')throw Error('INJECTED_CREATE');
   return {update(){if(failure==='update')throw Error('INJECTED_UPDATE');return this;},
    digest(){if(failure==='digest')throw Error('INJECTED_DIGEST');return Buffer.alloc(32,1);},
    destroy(){destroyed++;if(failure==='destroy')throw Error('INJECTED_DESTROY');}};
  });
  if(failure==='create')assert.throws(()=>adapter.Blake3Incremental({key}),/INJECTED_CREATE/);
  else{
   const stream=adapter.Blake3Incremental({key});
   if(failure==='update')assert.throws(()=>stream.update(material),/INJECTED_UPDATE/);
   else if(failure==='digest')assert.throws(()=>stream.digest(),/INJECTED_DIGEST/);
   else if(failure==='destroy')assert.throws(()=>stream.destroy(),/INJECTED_DESTROY/);
   else stream.digest();
   stream.destroy();assert.equal(destroyed,1);assert.throws(()=>stream.update(material),/BLAKE3_FINALIZED/);
  }
  assert.deepEqual(owned,Buffer.alloc(32));assert.deepEqual(key,original);
 }
});
console.log('BLAKE3 OWNERSHIP PASS: '+checks+' groups; caller keys/material preserved, owned copies wiped on all completion/error paths.');
