'use strict';
// Synthetic AMD64 PE for strict CRC anchor/.pdata parser tests only.
function crcTestFixture(){
 const file=Buffer.alloc(0xc00),pe=0x80,opt=pe+24,table=opt+240,base=0x140000000n;
 file.writeUInt16LE(0x5a4d);file.writeUInt32LE(pe,0x3c);file.writeUInt32LE(0x4550,pe);file.writeUInt16LE(0x8664,pe+4);file.writeUInt16LE(4,pe+6);file.writeUInt16LE(240,pe+20);
 file.writeUInt16LE(0x20b,opt);file.writeUInt32LE(0x1000,opt+16);file.writeUInt32LE(0x1000,opt+20);file.writeBigUInt64LE(base,opt+24);file.writeUInt32LE(0x1000,opt+32);file.writeUInt32LE(0x200,opt+36);file.writeUInt32LE(0x5000,opt+56);file.writeUInt32LE(0x400,opt+60);file.writeUInt32LE(16,opt+108);
 const sections=[['.text',0x1000,0x400,0x60000020],['.rdata',0x2000,0x600,0x40000040],['.pdata',0x3000,0x800,0x40000040],['.reloc',0x4000,0xa00,0x42000040]];
 for(const [i,[name,rva,raw,flags]] of sections.entries()){const at=table+i*40;file.write(name,at);file.writeUInt32LE(0x200,at+8);file.writeUInt32LE(rva,at+12);file.writeUInt32LE(0x200,at+16);file.writeUInt32LE(raw,at+20);file.writeUInt32LE(flags,at+36);}
 for(let i=0;i<0x200;i++)file[0x400+i]=(i*17+3)&255;
 Buffer.from('47435243414e4348038d47912a60b5ec','hex').copy(file,0x600);file.writeUInt32LE(1,0x610);file.writeUInt32LE(6,0x614);
 for(let i=0;i<6;i++){file.writeBigUInt64LE(base+0x1000n+BigInt(i*0x20),0x618+i*8);file.writeUInt32LE(0x1000+i*0x20,0x800+i*12);file.writeUInt32LE(0x1020+i*0x20,0x804+i*12);file.writeUInt32LE(0x2100+i*4,0x808+i*12);file[0x700+i*4]=1;file.writeUInt16LE(0xa018+i*8,0xa08+i*2);}
 file.writeUInt32LE(0x3000,opt+136);file.writeUInt32LE(72,opt+140);file.writeUInt32LE(0x4000,opt+152);file.writeUInt32LE(20,opt+156);file.writeUInt32LE(0x2000,0xa00);file.writeUInt32LE(20,0xa04);
 return file;
}
function fixtureCodeStream(file){const prefix=Buffer.from('GAME-CODE-V1\0'),head=Buffer.alloc(prefix.length+12);prefix.copy(head);head.writeUInt32LE(1,prefix.length);head.writeUInt32LE(0x1000,prefix.length+4);head.writeUInt32LE(0x200,prefix.length+8);return Buffer.concat([head,file.subarray(0x400,0x600)]);}
module.exports={crcTestFixture,fixtureCodeStream};
