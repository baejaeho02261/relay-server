'use strict';
// Input bytes only. No implementation-generated digest is a test expectation.
const {crcTestFixture}=require("../runtime/peace.crc-test-fixture");
function fixtures(){
 const rows=[],base=crcTestFixture(),opt=0x98,table=0x188;
 const add=(id,edit=()=>{},accepted=true,source=base)=>{const bytes=Buffer.from(source);edit(bytes);rows.push({id,bytes,accepted});};
 add('complete-checker-coverage');
 for(let i=0;i<6;i++)add('checker-code-'+i,b=>{b[0x400+i*32+9]^=0x40;});
 add('code-outside-checkers',b=>{b[0x5e0]^=1;});
 add('selected-entry-point-header',b=>b.writeUInt32LE(0x1001,opt+16));
 add('excluded-checksum-header',b=>b.writeUInt32LE(0x12345678,opt+64));
 add('excluded-section-name',b=>b.write('.other',table));
 add('absent-anchor',b=>b.fill(0,0x600,0x610));
 add('missing-one-function-range',b=>b.writeUInt32LE(0x1061,0x824));
 add('missing-ecma-function-range',b=>b.writeUInt32LE(0x1001,0x800));
 add('no-unwind-directory',b=>b.fill(0,opt+136,opt+144));
 add('shared-function-range',b=>b.writeBigUInt64LE(0x140001020n,0x628));
 add('writable-disk-anchor-metadata',b=>b.writeUInt32LE(0xc0000040,table+40+36));
 const relocated=Buffer.from(base);
 relocated.writeUInt32LE(32,opt+156);relocated.writeUInt32LE(0x1000,0xa14);relocated.writeUInt32LE(12,0xa18);
 relocated.writeUInt16LE(0xa0c0,0xa1c);relocated.writeUInt16LE(0,0xa1e);relocated.writeBigUInt64LE(0x140002100n,0x4c0);
 add('dir64-code-relocation',()=>{},true,relocated);
 add('dir64-original-value-normalized',b=>b.writeBigUInt64LE(0x140003000n,0x4c0),true,relocated);
 add('highlow-code-relocation',b=>b.writeUInt16LE(0x30c0,0xa1c),true,relocated);
 add('relocation-code-boundary-reject',b=>b.writeUInt16LE(0xa1fc,0xa1c),false,relocated);
 add('relocation-unsupported-code-kind-reject',b=>b.writeUInt16LE(0x50c0,0xa1c),false,relocated);
 const combined=Buffer.from(base);
 combined.writeUInt32LE(0x2050,opt+112);combined.writeUInt32LE(0xb0,opt+116);
 for(const [offset,value] of [[12,0x20a0],[16,1],[20,2],[24,2],[28,0x2078],[32,0x2080],[36,0x2088]])combined.writeUInt32LE(value,0x650+offset);
 combined.writeUInt32LE(0x1000,0x678);combined.writeUInt32LE(0x20d0,0x67c);combined.writeUInt32LE(0x20b0,0x680);combined.writeUInt32LE(0x20c0,0x684);
 combined.writeUInt16LE(0,0x688);combined.writeUInt16LE(1,0x68a);
 for(const [at,text] of [[0x6a0,'combined.dll\0'],[0x6b0,'Direct\0'],[0x6c0,'Forward\0'],[0x6d0,'MODULE.Target\0']])combined.write(text,at,'ascii');
 add('complete-checkers-and-exports',()=>{},true,combined);
 add('export-direct-target-change',b=>b.writeUInt32LE(0x1004,0x678),true,combined);
 add('export-forwarder-change',b=>{b[0x6d0]^=1;},true,combined);
 add('export-string-invalid-partial',b=>{b[0x6d0]=32;},true,combined);
 add('export-ordinal-invalid-partial',b=>b.writeUInt16LE(2,0x688),true,combined);
 const paged=Buffer.from(base);
 paged.writeUInt32LE(0x1008,table+8);paged.writeUInt32LE(0x1ff8,table+12);
 paged.writeUInt32LE(0x5000,table+40+12);paged.writeUInt32LE(0x6000,table+80+12);paged.writeUInt32LE(0x7000,table+120+12);paged.writeUInt32LE(0x8000,opt+56);
 paged.fill(0,opt+136,opt+144);paged.fill(0,opt+152,opt+160);paged.fill(0,0x600,0x610);
 add('unaligned-multiple-pages-zero-fill',()=>{},true,paged);
 add('second-page-raw-change',b=>{b[0x40b]^=1;},true,paged);
 const multi=Buffer.alloc(0xe00);base.copy(multi);multi.writeUInt16LE(5,0x86);multi.writeUInt32LE(0x7000,opt+56);
 const fifth=table+160;multi.write('.extra',fifth);multi.writeUInt32LE(0x1001,fifth+8);multi.writeUInt32LE(0x5000,fifth+12);
 multi.writeUInt32LE(512,fifth+16);multi.writeUInt32LE(0xc00,fifth+20);multi.writeUInt32LE(0x60000020,fifth+36);
 for(let i=0;i<512;i++)multi[0xc00+i]=(i*7+91)&255;
 add('multiple-executable-sections-zero-fill',()=>{},true,multi);
 add('second-executable-section-change',b=>{b[0xc01]^=1;},true,multi);
 add('section-table-order-independent-code',b=>{const first=Buffer.from(b.subarray(table,table+40));b.copy(b,table,fifth,fifth+40);first.copy(b,fifth);},true,multi);
 for(const [id,edit] of [
  ['duplicate-anchor',b=>b.copy(b,0x680,0x600,0x648)],
  ['anchor-version',b=>b.writeUInt32LE(2,0x610)],
  ['anchor-count',b=>b.writeUInt32LE(7,0x614)],
  ['anchor-data-target',b=>b.writeBigUInt64LE(0x140002080n,0x618)],
  ['anchor-target-overflow',b=>b.writeBigUInt64LE(0xffffffffffffffffn,0x618)],
  ['anchor-relocation-kind',b=>b.writeUInt16LE(0x3018,0xa08)],
  ['anchor-relocation-missing',b=>b.writeUInt16LE(0,0xa08)],
  ['anchor-relocation-duplicate',b=>b.writeUInt16LE(0xa018,0xa0a)],
  ['relocation-block-truncated',b=>b.writeUInt32LE(21,0xa04)],
  ['unwind-misaligned',b=>b.writeUInt32LE(0x2101,0x808)],
  ['pdata-overlap',b=>b.writeUInt32LE(0x101f,0x80c)],
  ['pdata-writable',b=>b.writeUInt32LE(0xc0000040,table+2*40+36)],
  ['executable-writable',b=>b.writeUInt32LE(0xe0000020,table+36)],
  ['relocation-directory-writable',b=>b.writeUInt32LE(0xc0000040,table+3*40+36)],
 ])add('reject-'+id,edit,false);
 return rows;
}
module.exports={fixtures};
