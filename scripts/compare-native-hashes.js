'use strict';
// Executes real compiled probes. References are public hash-wasm/noble algorithms
// and independent bitwise CRC/PE framing below; no production hashing imports.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const upstream=require('hash-wasm'),{blake3}=require('@noble/hashes/blake3');
const specs=[
 ['CRC-64/ECMA-182',64,false,0x42F0E1EBA9EA3693n,0n,0n,0x6C40DF5F0B497347n],
 ['CRC-64/NVME',64,true,0xAD93D23594C93659n,0xFFFFFFFFFFFFFFFFn,0xFFFFFFFFFFFFFFFFn,0xAE8B14860A799888n],
 ['CRC-64/JONES',64,true,0xAD93D23594C935A9n,0xFFFFFFFFFFFFFFFFn,0n,0xCAA717168609F281n],
 ['CRC-64/XZ',64,true,0x42F0E1EBA9EA3693n,0xFFFFFFFFFFFFFFFFn,0xFFFFFFFFFFFFFFFFn,0x995DC9BBDF1939FAn],
 ['CRC-64/WE',64,false,0x42F0E1EBA9EA3693n,0xFFFFFFFFFFFFFFFFn,0xFFFFFFFFFFFFFFFFn,0x62EC59E3F1A4F00An],
 ['CRC-64/GO-ISO',64,true,0x1Bn,0xFFFFFFFFFFFFFFFFn,0xFFFFFFFFFFFFFFFFn,0xB90956C775A41001n],
 ['CRC-32/ISCSI',32,true,0x1EDC6F41n,0xFFFFFFFFn,0xFFFFFFFFn,0xE3069283n],
 ['CRC-16/ARC',16,true,0x8005n,0n,0n,0xBB3Dn],['CRC-8/SMBUS',8,false,0x07n,0n,0n,0xF4n]];
function reflect(v,width){let r=0n;for(let i=0;i<width;i++){r=r*2n+(v&1n);v>>=1n;}return r;}
function crc(spec,bytes){const [,w,ref,p,init,xor]=spec,mask=(1n<<BigInt(w))-1n,top=1n<<BigInt(w-1);let v=ref?reflect(init,w):init;for(let b of bytes){if(ref)b=Number(reflect(BigInt(b),8));v^=BigInt(b)<<BigInt(w-8);for(let i=0;i<8;i++)v=((v<<1n)^((v&top)?p:0n))&mask;}if(ref)v=reflect(v,w);return (v^xor).toString(16).padStart(w/4,'0').toUpperCase();}
function u32(x){const b=Buffer.alloc(4);b.writeUInt32LE(x);return b;}
function parameterBytes(){return Buffer.concat(specs.map(([,w,r,p,i,x,c])=>{const b=Buffer.alloc(34);b[0]=w;b[1]=+r;[p,i,x,c].forEach((v,j)=>b.writeBigUInt64LE(v,2+8*j));return b;}));}
function tables(){return Buffer.concat(specs.map(([,w,r,p])=>{const b=Buffer.alloc(2048),mask=(1n<<BigInt(w))-1n,poly=r?reflect(p,w):p;for(let i=0;i<256;i++){let v=r?BigInt(i):BigInt(i)<<BigInt(w-8);for(let j=0;j<8;j++)v=r?(v>>1n)^((v&1n)?poly:0n):((v<<1n)^((v&(1n<<BigInt(w-1)))?poly:0n))&mask;b.writeBigUInt64LE(v&mask,i*8);}return b;}));}
function pages(code){const prefix=Buffer.from('GAME-CODE-V1\0');assert(code.subarray(0,prefix.length).equals(prefix));let at=prefix.length,count=code.readUInt32LE(at),rows=[];at+=4;for(let s=0;s<count;s++){let rva=code.readUInt32LE(at),n=code.readUInt32LE(at+4);at+=8;while(n){const size=Math.min(n,4096-(rva&4095));rows.push(Buffer.concat([u32(rva),u32(size),u32(parseInt(crc(specs[6],code.subarray(at,at+size)),16))]));at+=size;rva+=size;n-=size;}}assert.equal(at,code.length);return Buffer.concat([Buffer.from('CRC-PAGES-V1\0'),u32(4096),u32(rows.length),...rows]);}
function exportBytes(file){const pe=file.readUInt32LE(60),opt=pe+24,offset=opt+112,rva=file.readUInt32LE(offset),n=file.readUInt32LE(offset+4),table=opt+file.readUInt16LE(pe+20);let raw=-1;for(let i=0;i<file.readUInt16LE(pe+6);i++){const s=table+i*40,start=file.readUInt32LE(s+12),size=file.readUInt32LE(s+16);if(rva>=start&&rva+n<=start+size)raw=file.readUInt32LE(s+20)+rva-start;}assert(raw>=0&&raw+n<=file.length);return Buffer.concat([Buffer.from('GAME-EXPORT-V1\0'),u32(offset),file.subarray(offset,offset+8),file.subarray(raw,raw+n)]);}
function run(exe,args){const p=spawnSync(exe,args,{encoding:'utf8',timeout:60000,maxBuffer:1024*1024,windowsHide:true});if(p.error)throw p.error;assert.equal(p.status,0,p.stdout+p.stderr);return p.stdout.trim();}
async function main(){const args={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];args[key]=key==='--portable-only'?true:process.argv[++i];}const portable=args['--portable-only']===true;for(const k of portable?['--hash-probe','--crc-probe','--mode-probe']:['--hash-probe','--crc-probe','--mode-probe','--pe-probe'])assert(args[k]&&fs.statSync(args[k]).isFile(),'Actual compiled '+k+' required');const temp=fs.mkdtempSync(path.join(os.tmpdir(),'native-differential-'));let hashCases=0,crcCases=0,exportCases=0;
 try{const file=path.join(temp,'input.bin');
  for(const n of [0,1,3,63,64,65,127,128,129,239,240,241,255,256,257,1023,1024,1025,4097,65539,1048577]){
   const bytes=Buffer.alloc(n);for(let i=0;i<n;i++)bytes[i]=i%251;fs.writeFileSync(file,bytes);const xx=await upstream.xxhash128(bytes),b=Buffer.from(blake3(bytes)).toString('hex'),sha=crypto.createHash('sha512').update(bytes).digest('hex');assert.equal(await upstream.blake3(bytes),b);
   for(const step of n>100000?[1025,65536]:[1,31,1025,65536]){assert.deepEqual(run(args['--hash-probe'],[file,String(step)]).split('\t'),[String(n),xx,b,sha]);hashCases++;}
   if(n<=65539){const actual=Object.fromEntries(run(args['--crc-probe'],[file]).split(/\r?\n/).map(x=>x.split('=')));for(const spec of specs){assert.equal(actual[spec[0]],crc(spec,bytes));crcCases++;}assert.equal(actual.parameters,crc(specs[4],parameterBytes()));assert.equal(actual.tables,crc(specs[4],tables()));}
  }
  const vectors=require('../../GameConnect_Win64/tests/blake3-official-full-vectors.json');
  for(const v of vectors.cases){const bytes=Buffer.alloc(v.input_len);for(let i=0;i<bytes.length;i++)bytes[i]=i%251;fs.writeFileSync(file,bytes);const xx=await upstream.xxhash128(bytes),sha=crypto.createHash('sha512').update(bytes).digest('hex');
   for(const [mode,field] of [['hash','hash'],['keyed','keyed_hash'],['derive','derive_key']])for(const [n,seek] of [[131,0],[68,63]]){
    const ref=v[field].slice(seek*2,(seek+n)*2);assert.deepEqual(run(args['--mode-probe'],[file,'1025',mode,String(n),String(seek)]).split('\t'),[String(bytes.length),xx,ref,sha]);hashCases++;
   }
  }
  for(const [rva,n] of [[0x1800,0x1801],[0x1000,4096],[0x1fff,8193]]){const code=Buffer.concat([Buffer.from('GAME-CODE-V1\0'),u32(1),u32(rva),u32(n),Buffer.alloc(n,17)]);fs.writeFileSync(file,code);assert.equal(run(args['--crc-probe'],['--pages',file]),'pages='+pages(code).toString('hex').toUpperCase());crcCases++;}
  if(!portable){const fixture=require('./test-desktop-pe-exports').Fixture();
  for(const mutate of [()=>{},b=>b.writeUInt32LE(4100,1064),b=>b[1128]^=1,b=>b[1104]^=1]){const bytes=Buffer.from(fixture);mutate(bytes);fs.writeFileSync(file,bytes);const actual=JSON.parse(run(args['--pe-probe'],[file])),framed=exportBytes(bytes);assert.equal(actual.accepted,true);assert.equal(actual.exportStatus,'MEASURED');assert.equal(actual.exportSha512,crypto.createHash('sha512').update(framed).digest('hex'));assert.equal(actual.exportCrc64,crc(specs[0],framed));assert.equal(actual.exportXxh3_128,await upstream.xxhash128(framed));assert.equal(actual.exportBlake3,Buffer.from(blake3(framed)).toString('hex'));exportCases++;}}
  console.log(JSON.stringify({status:'PASS',scope:portable?'PORTABLE_PASCAL_HASH_CRC':'WINDOWS_PASCAL_WITH_EXPORTS',hashCases,crcCases,exportCases,exportComparison:portable?'NOT_RUN':'PASS',actualNativeExecuted:true,independentReferences:['hash-wasm XXH3-128','noble BLAKE3','official BLAKE3 all modes/XOF','Node SHA-512','bitwise CRC9','independent parameters/tables/pages/EAT framing']}));
 }finally{fs.rmSync(temp,{recursive:true,force:true});}}
if(require.main===module)main().catch(e=>{console.error(e);process.exitCode=1;});
module.exports={specs,crc,pages,parameterBytes,tables,exportBytes};
