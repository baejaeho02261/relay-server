'use strict';
// Shared PE64 fixture: first code bytes remain raw offset 512 / RVA 0x1000.
// Read-only data contains the retained checker anchor, unwind entries, pdata
// and relocations. No executable is emitted or executed by this test helper.
function crcPeFixture(marker='GAME-CRC-FIXTURE'){
 const file=Buffer.alloc(1536),pe=0x80,opt=pe+24,table=opt+240,base=0x140000000n;
 file.writeUInt16LE(0x5a4d);file.writeUInt32LE(pe,0x3c);file.writeUInt32LE(0x4550,pe);file.writeUInt16LE(0x8664,pe+4);file.writeUInt16LE(2,pe+6);file.writeUInt16LE(240,pe+20);
 file.writeUInt16LE(0x20b,opt);file.writeUInt32LE(0x1000,opt+16);file.writeUInt32LE(0x1000,opt+20);file.writeBigUInt64LE(base,opt+24);file.writeUInt32LE(4096,opt+32);file.writeUInt32LE(512,opt+36);file.writeUInt32LE(0x3000,opt+56);file.writeUInt32LE(512,opt+60);file.writeUInt32LE(16,opt+108);
 for(const [i,[name,rva,raw,flags]] of [['.text',0x1000,512,0x60000020],['.rdata',0x2000,1024,0x40000040]].entries()){const at=table+i*40;file.write(name,at);file.writeUInt32LE(512,at+8);file.writeUInt32LE(rva,at+12);file.writeUInt32LE(512,at+16);file.writeUInt32LE(raw,at+20);file.writeUInt32LE(flags,at+36);}
 for(let i=0;i<512;i++)file[512+i]=(i*17+3)&255;
 if(marker)Buffer.from(String(marker)).copy(file,528,0,128);
 Buffer.from('47435243414e4348038d47912a60b5ec','hex').copy(file,1024);file.writeUInt32LE(1,1040);file.writeUInt32LE(6,1044);
 for(let i=0;i<6;i++){file.writeBigUInt64LE(base+0x1000n+BigInt(i*32),1048+i*8);file.writeUInt32LE(0x1000+i*32,1280+i*12);file.writeUInt32LE(0x1020+i*32,1284+i*12);file.writeUInt32LE(0x2080+i*4,1288+i*12);file[1152+i*4]=1;file.writeUInt16LE(0xa018+i*8,1416+i*2);}
 file.writeUInt32LE(0x2100,opt+136);file.writeUInt32LE(72,opt+140);file.writeUInt32LE(0x2180,opt+152);file.writeUInt32LE(20,opt+156);file.writeUInt32LE(0x2000,1408);file.writeUInt32LE(20,1412);
 return file;
}
module.exports={crcPeFixture};
