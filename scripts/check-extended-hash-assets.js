'use strict';
// Verify the vendored WASM bytes against the exact npm-pinned upstream package.
// --write reproduces the assets; it cannot silently approve a new hash/version.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const directory=path.resolve(__dirname,'../services/vendor/hash-wasm-4.12.0');
const manifest=require('../services/vendor/hash-wasm-4.12.0/manifest.json');
const packageDirectory=path.dirname(require.resolve('hash-wasm/package.json'));
assert.equal(require(path.join(packageDirectory,'package.json')).version,manifest.version);
const lock=require('../package-lock.json');
assert.equal(lock.packages['node_modules/hash-wasm'].integrity,manifest.integrity);
for(const [name,asset]of Object.entries(manifest.assets)){
 const source=fs.readFileSync(path.join(packageDirectory,'dist',name+'.umd.min.js'),'utf8');
 const match=source.match(new RegExp('name:"'+name+'",data:"([A-Za-z0-9+/=]+)"'));
 assert.ok(match,'Expected pinned upstream embedded WASM: '+name);
 const binary=Buffer.from(match[1],'base64');
 assert.equal(binary.length,asset.bytes);
 assert.equal(crypto.createHash('sha256').update(binary).digest('hex'),asset.sha256);
 assert.equal(crypto.createHash('sha512').update(binary).digest('hex'),asset.sha512);
 const destination=path.join(directory,asset.file);
 if(process.argv.includes('--write'))fs.writeFileSync(destination,binary);
 else assert.deepEqual(fs.readFileSync(destination),binary);
 assert.deepEqual(WebAssembly.Module.imports(new WebAssembly.Module(binary)),[],'WASM cannot access host functions');
}
console.log('EXTENDED HASH ASSETS PASS: exact pinned upstream bytes, SHA-512 and upstream SHA-256 pins, no host imports');
