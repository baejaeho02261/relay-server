'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {crcTestFixture,fixtureCodeStream}=require('./crc-test-fixture');
const {checkerPlan,checkerStreams,headerMetadata,measureCrcLayers}=require('../services/crcLayers');
const file=crcTestFixture(),plan=checkerPlan(file),code=fixtureCodeStream(file);
assert.equal(plan.status,'measured');assert.deepEqual(plan.roles.nvme,[{rva:0x1000,span:32}]);assert.equal(plan.roles.jones.length,2);assert.equal(plan.roles.iso.length,3);
const checkers=checkerStreams(code,plan),report=measureCrcLayers({code,headers:headerMetadata(file),checkers});
for(const role of ['nvme','jones','iso'])assert.equal(report[role].status,'measured');
const changed=Buffer.from(code);changed[Buffer.byteLength('GAME-CODE-V1\0')+12+0x20]^=1;
const changedReport=measureCrcLayers({code:changed,headers:headerMetadata(file),checkers:checkerStreams(changed,plan)});
assert.notEqual(report.jones.digest,changedReport.jones.digest);assert.equal(report.nvme.digest,changedReport.nvme.digest);assert.equal(report.iso.digest,changedReport.iso.digest);
const reject=mutate=>{const bad=Buffer.from(file);mutate(bad);assert.throws(()=>checkerPlan(bad),/CRC_.*INVALID/);};
reject(b=>b.copy(b,0x680,0x600,0x648)); // duplicate read-only anchor
reject(b=>b.writeUInt32LE(2,0x610)); // unknown anchor schema
reject(b=>b.writeBigUInt64LE(0x140002080n,0x618)); // target outside executable
reject(b=>b.writeBigUInt64LE(0xffffffffffffffffn,0x618)); // out-of-image VA
reject(b=>b.writeUInt16LE(0x3018,0xa08)); // wrong pointer relocation kind
reject(b=>b.writeUInt16LE(0,0xa08)); // missing pointer relocation operand
reject(b=>b.writeUInt16LE(0xa018,0xa0a)); // duplicated operand
reject(b=>b.writeUInt32LE(0,0xa04)); // malformed reloc block
reject(b=>b.writeUInt32LE(0x1000,0x804)); // empty runtime function
reject(b=>b.writeUInt32LE(0x101f,0x80c)); // overlapping runtime functions
reject(b=>b.writeUInt32LE(0x3000,0x804)); // function escapes executable section
reject(b=>b.writeUInt32LE(0x6000,0x808)); // invalid unwind RVA
reject(b=>b.writeUInt32LE(0xc0000040,0x188+2*40+36)); // writable .pdata
reject(b=>b.writeUInt32LE(0x2101,0x808)); // misaligned unwind record
reject(b=>b.writeUInt32LE(0xc0000040,0x188+3*40+36)); // writable relocations
reject(b=>b.writeUInt32LE(0xe0000020,0x188+36)); // writable executable targets
reject(b=>b.writeUInt32LE(0x1000,0x808)); // executable bytes are not unwind metadata
const absent=Buffer.from(file);absent.fill(0,0x600,0x610);assert.equal(checkerPlan(absent).status,'unavailable');
const leaf=Buffer.from(file);leaf.writeUInt32LE(0x1061,0x800+3*12);const partial=checkerPlan(leaf);assert.equal(partial.status,'partial');assert.equal(partial.roles.iso,undefined);
// Delphi Win64 stores the anchor and unwind info in readable, writable .data.
// The authenticated disk file fixes all ranges, while the target code, .pdata
// and relocation directory remain read-only. The native reader verifies every
// runtime anchor field against that retained plan before measuring the code.
const delphi=Buffer.from(file);delphi.fill(0,0x188+40,0x188+48);delphi.write('.data',0x188+40);delphi.writeUInt32LE(0xc0000040,0x188+40+36);
const delphiPlan=checkerPlan(delphi);
assert.equal(delphiPlan.status,'measured');assert.deepEqual(delphiPlan.roles,plan.roles);
assert.deepEqual(checkerStreams(fixtureCodeStream(delphi),delphiPlan),checkers);
const delphiReport=measureCrcLayers({code:fixtureCodeStream(delphi),headers:headerMetadata(delphi),checkers:checkerStreams(fixtureCodeStream(delphi),delphiPlan)});
for(const role of ['nvme','jones','iso']){assert.equal(delphiReport[role].status,'measured');assert.equal(delphiReport[role].digest,report[role].digest);}
function rejectDelphi(mutate){const bad=Buffer.from(delphi);mutate(bad);assert.throws(()=>checkerPlan(bad),/CRC_.*INVALID/);}
rejectDelphi(b=>b.copy(b,0x680,0x600,0x648)); // duplicate .data anchor
rejectDelphi(b=>b.writeUInt32LE(2,0x610));
rejectDelphi(b=>b.writeUInt32LE(7,0x614));
rejectDelphi(b=>b.writeBigUInt64LE(0x140002080n,0x618)); // data target
rejectDelphi(b=>b.writeUInt16LE(0,0xa08));
rejectDelphi(b=>b.writeUInt32LE(0x21ff,0x808)); // truncated/misaligned unwind info
rejectDelphi(b=>b.writeUInt32LE(0x6000,0x808));
rejectDelphi(b=>b.writeUInt32LE(0xc0000040,0x188+2*40+36));
rejectDelphi(b=>b.writeUInt32LE(0xc0000040,0x188+3*40+36));
for(const flags of [0x80000040,0xe0000040,0x60000040]){
 const unsupported=Buffer.from(delphi);unsupported.writeUInt32LE(flags,0x188+40+36);
 assert.equal(checkerPlan(unsupported).status,'unavailable'); // non-readable/executable registry
}
// Optional private release inputs, never retained as repository fixtures.
// Set CRC_NATIVE_IMAGES to a platform-delimited list of original PE paths.
for(const filename of (process.env.CRC_NATIVE_IMAGES||'').split(path.delimiter).filter(Boolean)){
 const input=fs.readFileSync(filename),actualPlan=checkerPlan(input),baseline=require('../services/desktopIntegrity').CodeImage(input);
 assert.equal(actualPlan.status,'measured',path.basename(filename));
 for(const role of ['nvme','jones','iso'])assert.equal(baseline.crcLayers[role].status,'measured',path.basename(filename)+'/'+role);
 assert.equal(require('../services/desktopCrcPolicy').Compare(baseline.crcLayers,baseline.crcLayers).complete,true,path.basename(filename));
 console.log('CRC complete checker coverage: '+path.basename(filename));
}
console.log('CRC file-bound readonly/data anchors, DIR64 operands, exact .pdata spans and mutation/negative cases passed.');
