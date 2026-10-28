'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),cp=require('node:child_process');
const crc=require('../../services/cryptography/peace.crc-layers');
const prefix=Buffer.from('GAME-CODE-V1\0'),pagePrefix=Buffer.from('COZY-CODE-PAGES-SHA512-V1\0');
function frame(sections){const head=Buffer.alloc(prefix.length+4);prefix.copy(head);head.writeUInt32LE(sections.length,prefix.length);return Buffer.concat([head,...sections.flatMap(({rva,bytes})=>{const row=Buffer.alloc(8);row.writeUInt32LE(rva);row.writeUInt32LE(bytes.length,4);return [row,bytes];})]);}
function reference(code){
 // Independent framing assembly; production preallocation and parser are not reused.
 let p=prefix.length,count=code.readUInt32LE(p);p+=4;const rows=[];
 for(let s=0;s<count;s++){
  let rva=code.readUInt32LE(p),remaining=code.readUInt32LE(p+4);p+=8;
  while(remaining){const size=Math.min(remaining,4096-rva%4096),row=Buffer.alloc(8);row.writeUInt32LE(rva);row.writeUInt32LE(size,4);
   rows.push(Buffer.concat([row,crypto.createHash('sha512').update(Buffer.concat([Buffer.from('COZY-CODE-PAGE-SHA512-V1\0'),row,code.subarray(p,p+size)])).digest()]));
   p+=size;rva+=size;remaining-=size;
  }
 }
 const head=Buffer.alloc(pagePrefix.length+8);pagePrefix.copy(head);head.writeUInt32LE(4096,pagePrefix.length);head.writeUInt32LE(rows.length,pagePrefix.length+4);return Buffer.concat([head,...rows]);
}
const left=Buffer.alloc(4096),right=Buffer.alloc(4096);
Buffer.from('487059d7b605e9ff','hex').copy(left);Buffer.from('48cc3ce6ab789b5c','hex').copy(right);
const ca=frame([{rva:0x1000,bytes:left}]),cb=frame([{rva:0x1000,bytes:right}]);
test('different bytes with equal page CRC are rejected by actual page SHA512 and whole code SHA512',()=>{
 assert.notDeepEqual(left,right);assert.equal(crc.crcHex('crc32c',left),crc.crcHex('crc32c',right));
 assert.deepEqual(crc.codePageManifest(ca),crc.codePageManifest(cb));
 assert.notDeepEqual(crc.codePageSha512Manifest(ca),crc.codePageSha512Manifest(cb));
 assert.notEqual(crypto.createHash('sha512').update(ca).digest('hex'),crypto.createHash('sha512').update(cb).digest('hex'));
});
test('page SHA512 binds RVA, byte length, content and domain',()=>{
 const baseline=crc.codePageSha512Manifest(ca);
 for(const changed of [frame([{rva:0x2000,bytes:left}]),frame([{rva:0x1000,bytes:left.subarray(0,-1)}]),cb])assert.notDeepEqual(crc.codePageSha512Manifest(changed),baseline);
 assert.deepEqual(baseline,reference(ca));
 const digest=baseline.subarray(pagePrefix.length+16,pagePrefix.length+80);
 assert.notDeepEqual(digest,crypto.createHash('sha512').update(left).digest());
});
test('unaligned multi-section pages match independent framed SHA512 reference',()=>{
 for(const length of [1,7,4095,4096,4097,8193]){
  const code=frame([{rva:0x1800,bytes:Buffer.alloc(length,71)},{rva:0x9000,bytes:Buffer.alloc(17,203)}]);
  assert.deepEqual(crc.codePageSha512Manifest(code),reference(code));
 }
});
test('SHA512 manifest rejects malformed section framing and trailing input',()=>{
 const bads=[ca.subarray(0,-1),Buffer.concat([ca,Buffer.from([0])]),frame([]),frame([{rva:0x1000,bytes:Buffer.alloc(0)}]),frame([{rva:0x1000,bytes:Buffer.alloc(16)},{rva:0x1008,bytes:Buffer.alloc(8)}]),frame([{rva:0xfffffff8,bytes:Buffer.alloc(16)}])];
 for(const bad of bads)assert.throws(()=>crc.codePageSha512Manifest(bad),/FRAME_INVALID/);
 assert.throws(()=>crc.codePageSha512Manifest('not bytes'),/BYTES_REQUIRED/);
});
test('maximum own code payload has a finite page-manifest and measurement-array bound',()=>{
 const size=64*1024*1024,code=frame([{rva:0x1000,bytes:Buffer.alloc(size,17)}]);
 const pages=crc.codePageSha512Manifest(code),expected=pagePrefix.length+8+16384*72;
 assert.equal(pages.length,expected);assert.equal(pages.readUInt32LE(pagePrefix.length+4),16384);
 const conservative=size+4096+(16384+96*2+1)*72+64+8*1024*1024+65536;
 assert.equal(conservative,76760712);assert(conservative<2*size);
});
const nativeRoot=path.resolve(__dirname,'../../../Railway');
const native=rel=>fs.readFileSync(path.join(nativeRoot,rel),'utf8').replace(/\r/g,'');
test('native source: disk-origin page baseline, full hashes and two-generation checks all remain',{skip:!fs.existsSync(nativeRoot)},()=>{
 const s=native('Cozy.Source/Cozy.Integrity/Cozy.CodeIntegrity.pas');
 assert.match(s,/FFileMeasurement := Digest\(Normalized[\s\S]*FFilePageSHA512 := CodePageSHA512Manifest\(Normalized/);
 assert.match(s,/CompareMem\(@Actual\[0\], @FFilePageSHA512\[0\]/);assert(s.includes('OWN_CODE_PAGE_SHA512_CHANGED'));
 const bundle=s.slice(s.indexOf('procedure TCodeIntegrity.MeasureBundle('),s.indexOf('function TCodeIntegrity.MeasureCrcLayersNow:',s.indexOf('procedure TCodeIntegrity.MeasureBundle(')));
 for(const check of ['VerifyCodePages(Bytes, ActiveBudget)','VerifyCodePages(AfterBytes, ActiveBudget)','Code.SHA512 <> AfterDigest.SHA512','Code.Size <> AfterDigest.Size','Layers.Free; Layers := nil'])assert(bundle.includes(check),check);
 assert(bundle.indexOf('ClearBytes(Bytes)')<bundle.indexOf('AfterBytes := BuildStream'));
 const core=s.slice(s.indexOf('function TCodeIntegrity.MeasureCrcLayersCore'),s.indexOf('function TCodeIntegrity.MeasureNowCore'));
 assert(core.includes('0: Update(Code)'));assert(core.includes('UpdateCheckerCrc(0'));assert(core.includes('UpdateCheckerCrc(1'));assert(core.includes('UpdateCheckerCrc(2'));
 assert.match(core,/AddPair\('version', 'CRC-LAYERS-V1'\)/);
});
test('native source: acceleration has explicit reference fallback and alignment-safe bounded blocks',{skip:!fs.existsSync(nativeRoot)},()=>{
 const s=native('Cozy.Source/Cozy.Integrity/Cozy.CrcLayers.pas'),probe=native('Cozy.Tests/Cozy.Integrity/Cozy.CrcProbe.dpr');
 for(const marker of ['cmReference','COZY_CRC32C_REFERENCE_ONLY','while Remaining >= 8 do','Move(P^, Chunk[0], 8)','if Count = 0 then Exit'])assert(s.includes(marker),marker);
 for(const marker of ['CRC32C_ALIGNMENT_PARITY','CRC32C_SPLIT_PARITY','PAGE_SHA512_REJECTS_CRC_COLLISION','observedProcessPeakWorkingSetBytes','--maximum-pages'])assert(probe.includes(marker),marker);
});
test('actual portable native probe parity when explicitly provided',{skip:!process.env.CRC_PROBE},()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-page-hash-'));
 try{const file=path.join(dir,'pages.bin');fs.writeFileSync(file,ca);const r=cp.spawnSync(process.env.CRC_PROBE,['--pages-sha512',file],{encoding:'utf8',timeout:30000,maxBuffer:2*1024*1024});assert.ifError(r.error);assert.equal(r.status,0,r.stdout+r.stderr);assert.equal(r.stdout.trim(),'pages='+reference(ca).toString('hex').toUpperCase());}
 finally{fs.rmSync(dir,{recursive:true,force:true});}
});
