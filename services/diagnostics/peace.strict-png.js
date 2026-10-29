'use strict';
// A deliberately small PNG profile for user-previewed canvas still images.
// It never decodes arbitrary image formats or trusts compressed dimensions.
const zlib=require('node:zlib'),{promisify}=require('node:util');
const inflate=promisify(zlib.inflate);
const LIMITS=Object.freeze({maxPngBytes:2*1024*1024,maxWidth:4096,maxHeight:4096,maxPixels:4194304,maxChunks:128});
const SIGNATURE=Buffer.from([137,80,78,71,13,10,26,10]);
const table=new Uint32Array(256);for(let i=0;i<256;i++){let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;table[i]=c>>>0;}
function Crc(bytes){let c=0xffffffff;for(const b of bytes)c=table[(c^b)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
function Fail(){throw Object.assign(Error('CAPTURE_PNG_INVALID'),{desktopError:true,status:400});}
async function Normalize(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<57||bytes.length>LIMITS.maxPngBytes||!bytes.subarray(0,8).equals(SIGNATURE))Fail();
 let at=8,chunks=0,width=0,height=0,channels=0,ended=false,idatStarted=false,idatEnded=false;const idats=[],kept=[];
 const ancillary=new Set();
 while(at<bytes.length){
  if(++chunks>LIMITS.maxChunks||bytes.length-at<12)Fail();
  const size=bytes.readUInt32BE(at);if(size>LIMITS.maxPngBytes||size>bytes.length-at-12)Fail();
  const nameBytes=bytes.subarray(at+4,at+8),name=nameBytes.toString('latin1'),payload=bytes.subarray(at+8,at+8+size),end=at+12+size;
  if(!/^[A-Za-z]{4}$/.test(name)||Crc(bytes.subarray(at+4,at+8+size))!==bytes.readUInt32BE(at+8+size))Fail();
  if(chunks===1&&name!=='IHDR')Fail();
  if(name==='IHDR'){
   if(chunks!==1||size!==13)Fail();width=payload.readUInt32BE(0);height=payload.readUInt32BE(4);
   if(!width||!height||width>LIMITS.maxWidth||height>LIMITS.maxHeight||width*height>LIMITS.maxPixels||payload[8]!==8||![2,6].includes(payload[9])||payload[10]||payload[11]||payload[12])Fail();
   channels=payload[9]===6?4:3;kept.push(bytes.subarray(at,end));
  }else if(name==='IDAT'){
   if(!width||idatEnded||!size)Fail();idatStarted=true;idats.push(payload);kept.push(bytes.subarray(at,end));
  }else if(name==='IEND'){
   if(!idatStarted||size||end!==bytes.length)Fail();ended=true;kept.push(bytes.subarray(at,end));
  }else{
   // Strip only narrowly understood non-text color/density hints. Animation,
   // EXIF, ICC profiles, text, unknown chunks and duplicate hints are rejected.
   const lengths={sRGB:1,gAMA:4,cHRM:32,pHYs:9};
   if(idatStarted||!Object.hasOwn(lengths,name)||size!==lengths[name]||ancillary.has(name))Fail();
   if(name==='sRGB'&&payload[0]>3||name==='gAMA'&&!payload.readUInt32BE(0)||name==='pHYs'&&payload[8]>1)Fail();
   ancillary.add(name);
  }
  if(idatStarted&&name!=='IDAT')idatEnded=true;
  at=end;
 }
 if(!ended||!idats.length)Fail();
 const stride=width*channels+1,expected=stride*height,compressed=Buffer.concat(idats);let result;
 try{
  // libuv performs bounded inflation off the server event loop. bytesWritten
  // rejects a second zlib member or trailing bytes hidden inside an IDAT.
  result=await inflate(compressed,{maxOutputLength:expected,info:true});
  if(result.buffer.length!==expected||result.engine.bytesWritten!==compressed.length)Fail();
  for(let row=0;row<height;row++)if(result.buffer[row*stride]>4)Fail();
  const normalized=Buffer.concat([SIGNATURE,...kept]);
  return {bytes:normalized,width,height,format:'PNG_RGB8_OR_RGBA8_STILL'};
 }catch(_){Fail();}
 finally{compressed.fill(0);result?.buffer?.fill(0);}
}
module.exports={LIMITS,Normalize,Crc};
