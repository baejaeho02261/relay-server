'use strict';
// Application-level signatures for the exact personalized launcher. This is
// not a Windows Authenticode signature or a publisher-trust attestation.
const crypto=require('node:crypto');
const publicConfig=require('./peace.launcher-public-config');
const ENV='DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64';
const DOMAIN=Buffer.from('COZY-ISSUED-A-V1','ascii');
const FOOTER=Buffer.from('COZYA4SIGNED!','ascii');
const ANCHOR_MAGIC=Buffer.from('COZYAISSUERKEY1!','ascii');
const HEADER_SIZE=184,SIGNATURE_SIZE=256,TAIL_SIZE=HEADER_SIZE+SIGNATURE_SIZE+FOOTER.length;
const PUBLIC_BLOB_SIZE=283,ANCHOR_SIZE=16+32+PUBLIC_BLOB_SIZE,MAX_TEMPLATE=64*1024*1024;
const FORMAT='COZY_A_SIGNED_V1',PURPOSE='ISSUED_LAUNCHER';
if(DOMAIN.length!==16||FOOTER.length!==13||ANCHOR_MAGIC.length!==16||TAIL_SIZE!==453||ANCHOR_SIZE!==331)throw Error('ISSUED_A_FORMAT_INTERNAL');
let cached;
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.bootstrapError=true;e.status=status;throw e;}
function Digest(bytes,algorithm='sha512'){return crypto.createHash(algorithm).update(bytes).digest();}
function Plain(v){return !!v&&Object.getPrototypeOf(v)===Object.prototype;}
function ExactBase64(value,max){if(typeof value!=='string'||!value.length||value.length>Math.ceil(max/3)*4||!/^[A-Za-z0-9+/]+={0,2}$/.test(value))Fail('ISSUED_A_SIGNATURE_INVALID');const bytes=Buffer.from(value,'base64');if(bytes.length>max||bytes.toString('base64')!==value)Fail('ISSUED_A_SIGNATURE_INVALID');return bytes;}
function PublicIdentity(publicKey){
 let key;try{key=publicKey?.type==='public'?publicKey:crypto.createPublicKey(publicKey);}catch(_){Fail('ISSUED_A_SIGNING_KEY_INVALID',503);}
 if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength!==2048||key.asymmetricKeyDetails?.publicExponent!==65537n)Fail('ISSUED_A_SIGNING_KEY_INVALID',503);
 const jwk=key.export({format:'jwk'}),exponent=Buffer.from(jwk.e,'base64url'),modulus=Buffer.from(jwk.n,'base64url'),blob=Buffer.alloc(PUBLIC_BLOB_SIZE);
 if(exponent.toString('hex')!=='010001'||modulus.length!==256||!(modulus[0]&128)||!(modulus[255]&1))Fail('ISSUED_A_SIGNING_KEY_INVALID',503);
 [0x31415352,2048,3,256,0,0].forEach((v,i)=>blob.writeUInt32LE(v,i*4));exponent.copy(blob,24);modulus.copy(blob,27);
 return {publicKey:key,blob,keyId:Digest(blob,'sha256').toString('hex')};
}
function IdentityFromBlob(blob){
 if(!Buffer.isBuffer(blob)||blob.length!==PUBLIC_BLOB_SIZE||[0x31415352,2048,3,256,0,0].some((v,i)=>blob.readUInt32LE(i*4)!==v)||blob.subarray(24,27).toString('hex')!=='010001'||!(blob[27]&128)||!(blob[282]&1))Fail('ISSUED_A_TRUST_ANCHOR_INVALID');
 let publicKey;try{publicKey=crypto.createPublicKey({key:{kty:'RSA',e:blob.subarray(24,27).toString('base64url'),n:blob.subarray(27).toString('base64url')},format:'jwk'});}catch(_){Fail('ISSUED_A_TRUST_ANCHOR_INVALID');}
 return PublicIdentity(publicKey);
}
function AnchorBytes(publicKey){const identity=PublicIdentity(publicKey);return Buffer.concat([ANCHOR_MAGIC,Buffer.from(identity.keyId,'hex'),identity.blob]);}
function BackedReadonlyRanges(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>MAX_TEMPLATE||bytes.readUInt16LE(0)!==0x5a4d)Fail('ISSUED_A_TEMPLATE_INVALID');
 const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)Fail('ISSUED_A_TEMPLATE_INVALID');
 const count=bytes.readUInt16LE(pe+6),optionalSize=bytes.readUInt16LE(pe+20),optional=pe+24,table=optional+optionalSize;
 if(count<1||count>96||optionalSize<112||table+count*40>bytes.length||bytes.readUInt16LE(optional)!==0x20b)Fail('ISSUED_A_TEMPLATE_INVALID');
 const headers=bytes.readUInt32LE(optional+60),imageSize=bytes.readUInt32LE(optional+56),all=[],virtual=[],ranges=[];
 if(headers<table+count*40||headers>bytes.length)Fail('ISSUED_A_TEMPLATE_INVALID');
 for(let i=0;i<count;i++){
  const p=table+i*40,virtualSize=bytes.readUInt32LE(p+8),rva=bytes.readUInt32LE(p+12),size=bytes.readUInt32LE(p+16),offset=bytes.readUInt32LE(p+20),flags=bytes.readUInt32LE(p+36),mapped=Math.max(virtualSize,size);
  if(rva+mapped>imageSize||size&&(offset<headers||offset+size>bytes.length)||all.some(([a,b])=>size&&offset<b&&offset+size>a)||virtual.some(([a,b])=>mapped&&rva<b&&rva+mapped>a))Fail('ISSUED_A_TEMPLATE_INVALID');
  if(size)all.push([offset,offset+size]);if(mapped)virtual.push([rva,rva+mapped]);
  // Typed public constants can be emitted into .text or .rdata by Delphi.
  if(size&&(flags&0x40000000)&&!(flags&0x80000000)&&!(flags&0x02000000))ranges.push([offset,offset+size]);
 }
 return ranges;
}
function InspectTemplate(bytes){
 const ranges=BackedReadonlyRanges(bytes),anchors=[];
 for(const[from,to]of ranges){let offset=bytes.indexOf(ANCHOR_MAGIC,from);while(offset>=from&&offset+ANCHOR_SIZE<=to){
   try{const identity=IdentityFromBlob(bytes.subarray(offset+48,offset+ANCHOR_SIZE));if(bytes.subarray(offset+16,offset+48).equals(Buffer.from(identity.keyId,'hex')))anchors.push({...identity,offset});}catch(_){}
   offset=bytes.indexOf(ANCHOR_MAGIC,offset+1);
  }}
 if(anchors.length===0)Fail('ISSUED_A_BUILD_UPGRADE_REQUIRED');if(anchors.length!==1)Fail('ISSUED_A_TRUST_ANCHOR_AMBIGUOUS');return anchors[0];
}
function LoadSigner({reserve=false}={}){
 const encoded=process.env[ENV];if(!encoded)Fail('ISSUED_A_SIGNING_KEY_NOT_CONFIGURED',503);
 if(encoded.length>12000)Fail('ISSUED_A_SIGNING_KEY_INVALID',503);
 const fingerprint=Digest(Buffer.from(encoded),'sha256').toString('hex');
 if(!cached||cached.fingerprint!==fingerprint){let clear,privateKey;
  try{clear=ExactBase64(encoded,8192);privateKey=crypto.createPrivateKey(clear);if(privateKey.type!=='private')throw Error();const identity=PublicIdentity(crypto.createPublicKey(privateKey));cached={...identity,privateKey,fingerprint};}
  catch(_){Fail('ISSUED_A_SIGNING_KEY_INVALID',503);}finally{clear?.fill(0);}
 }
 const purposes=require('../security/peace.desktop-key-purposes');purposes[reserve?'Reserve':'Assert'](cached.publicKey,PURPOSE);return cached;
}
function Header(template,config,keyId){
 if(!Buffer.isBuffer(template)||template.length<512||template.length>MAX_TEMPLATE||!Buffer.isBuffer(config)||config.length<16||config.length>publicConfig.MAX||template.length+config.length+TAIL_SIZE>MAX_TEMPLATE||!/^[a-f0-9]{64}$/.test(keyId))Fail('ISSUED_A_SIGNATURE_INVALID');
 const result=Buffer.alloc(HEADER_SIZE);DOMAIN.copy(result);result.writeUInt32LE(template.length,16);result.writeUInt32LE(config.length,20);Buffer.from(keyId,'hex').copy(result,24);Digest(template).copy(result,56);Digest(config).copy(result,120);return result;
}
function SignHeader(header,signer){return crypto.sign('sha256',header,{key:signer.privateKey,padding:crypto.constants.RSA_PKCS1_PADDING});}
function VerifyHeader(header,signature,anchor){return signature.length===SIGNATURE_SIZE&&crypto.verify('sha256',header,{key:anchor.publicKey,padding:crypto.constants.RSA_PKCS1_PADDING},signature);}
function Readiness(template){
 try{if(Buffer.isBuffer(template)&&template.length+publicConfig.MAX+TAIL_SIZE>MAX_TEMPLATE)Fail('ISSUED_A_TEMPLATE_TOO_LARGE');const anchor=InspectTemplate(template),signer=LoadSigner();if(anchor.keyId!==signer.keyId)Fail('ISSUED_A_SIGNING_KEY_MISMATCH');
  // A real signing and verification challenge, without allocating an issuance
  // or inventing a Windows execution result. Domain and template are bound.
  const header=Header(template,Buffer.alloc(16,0x5a),anchor.keyId),signature=SignHeader(header,signer);
  try{if(!VerifyHeader(header,signature,anchor))Fail('ISSUED_A_SIGNATURE_INVALID');}finally{header.fill(0);signature.fill(0);}
  return {ready:true,format:FORMAT,keyId:anchor.keyId,scope:'APPLICATION_SIGNATURE',authenticode:false};
 }catch(error){return {ready:false,format:FORMAT,reason:error.desktopError?error.message:'ISSUED_A_SIGNING_UNAVAILABLE',scope:'APPLICATION_SIGNATURE',authenticode:false};}
}
function RequireReady(template){const ready=Readiness(template);if(!ready.ready)Fail(ready.reason,409);return ready;}
function ValidateReceiptShape(receipt,row){
 const keys=['version','format','keyId','templateSha512','configSha512','finalSha512','envelope'];
 if(!Plain(receipt)||Object.keys(receipt).length!==keys.length||keys.some(k=>!Object.hasOwn(receipt,k))||receipt.version!==1||receipt.format!==FORMAT||!/^[a-f0-9]{64}$/.test(receipt.keyId)||['templateSha512','configSha512','finalSha512'].some(k=>typeof receipt[k]!=='string'||!/^[a-f0-9]{128}$/.test(receipt[k])))Fail('ISSUED_A_RECEIPT_INVALID');
 let envelope;try{envelope=ExactBase64(receipt.envelope,publicConfig.MAX+TAIL_SIZE);if(envelope.length<16+TAIL_SIZE||!envelope.subarray(-FOOTER.length).equals(FOOTER))Fail('ISSUED_A_RECEIPT_INVALID');}finally{envelope?.fill(0);}
 if(row&&receipt.finalSha512!==row.sha512)Fail('ISSUED_A_RECEIPT_INVALID');return receipt;
}
function Parse(template,envelope){
 if(!Buffer.isBuffer(envelope)||envelope.length<16+TAIL_SIZE||envelope.length>publicConfig.MAX+TAIL_SIZE||!envelope.subarray(-FOOTER.length).equals(FOOTER))Fail('ISSUED_A_SIGNATURE_INVALID');
 const config=envelope.subarray(0,envelope.length-TAIL_SIZE),header=envelope.subarray(config.length,config.length+HEADER_SIZE),signature=envelope.subarray(config.length+HEADER_SIZE,config.length+HEADER_SIZE+SIGNATURE_SIZE),anchor=InspectTemplate(template);
 const expected=Header(template,config,anchor.keyId);try{if(!crypto.timingSafeEqual(header,expected)||!VerifyHeader(header,signature,anchor))Fail('ISSUED_A_SIGNATURE_INVALID');}finally{expected.fill(0);}
 const decoded=publicConfig.Decode(config);return {config,header,anchor,decoded};
}
function Create(template,value){
 const anchor=InspectTemplate(template),signer=LoadSigner({reserve:true});if(anchor.keyId!==signer.keyId)Fail('ISSUED_A_SIGNING_KEY_MISMATCH');
 let config,header,signature,envelope,bytes;
 try{config=publicConfig.Encode(value);header=Header(template,config,anchor.keyId);signature=SignHeader(header,signer);envelope=Buffer.concat([config,header,signature,FOOTER]);Parse(template,envelope);bytes=Buffer.concat([template,envelope]);
  const receipt={version:1,format:FORMAT,keyId:anchor.keyId,templateSha512:Digest(template).toString('hex'),configSha512:Digest(config).toString('hex'),finalSha512:Digest(bytes).toString('hex'),envelope:envelope.toString('base64')};ValidateReceiptShape(receipt);return {bytes,receipt};
 }catch(error){bytes?.fill(0);throw error;}finally{config?.fill(0);header?.fill(0);signature?.fill(0);envelope?.fill(0);}
}
function Materialize(template,receipt,row){
 ValidateReceiptShape(receipt,row);let envelope,bytes;
 try{envelope=ExactBase64(receipt.envelope,publicConfig.MAX+TAIL_SIZE);const parsed=Parse(template,envelope);
  if(parsed.anchor.keyId!==receipt.keyId||Digest(template).toString('hex')!==receipt.templateSha512||Digest(parsed.config).toString('hex')!==receipt.configSha512)Fail('ISSUED_A_RECEIPT_INVALID');
  if(row){const expected=publicConfig.Encode({schema:3,profile:row.profile,launcherId:row.id,expiresAt:row.expiresAt});try{if(!parsed.config.equals(expected))Fail('ISSUED_A_RECEIPT_INVALID');}finally{expected.fill(0);}}
  bytes=Buffer.concat([template,envelope]);if(Digest(bytes).toString('hex')!==receipt.finalSha512)Fail('ISSUED_A_RECEIPT_INVALID');return bytes;
 }catch(error){bytes?.fill(0);throw error;}finally{envelope?.fill(0);}
}
function VerifyFinal(bytes,{expectedTemplateSha512,expectedKeyId}={}){
 if(typeof expectedTemplateSha512!=='string'||!/^[a-f0-9]{128}$/.test(expectedTemplateSha512)||typeof expectedKeyId!=='string'||!/^[a-f0-9]{64}$/.test(expectedKeyId))Fail('ISSUED_A_TRUST_CONTEXT_REQUIRED');
 if(!Buffer.isBuffer(bytes)||bytes.length<512+16+TAIL_SIZE||bytes.length>MAX_TEMPLATE)Fail('ISSUED_A_SIGNATURE_INVALID');
 const headerOffset=bytes.length-TAIL_SIZE,header=bytes.subarray(headerOffset,headerOffset+HEADER_SIZE);if(!header.subarray(0,16).equals(DOMAIN))Fail('ISSUED_A_SIGNATURE_INVALID');
 const templateSize=header.readUInt32LE(16),configSize=header.readUInt32LE(20);if(templateSize<512||templateSize>MAX_TEMPLATE||configSize<16||configSize>publicConfig.MAX||templateSize+configSize+TAIL_SIZE!==bytes.length)Fail('ISSUED_A_SIGNATURE_INVALID');
 const parsed=Parse(bytes.subarray(0,templateSize),bytes.subarray(templateSize));if(Digest(bytes.subarray(0,templateSize)).toString('hex')!==expectedTemplateSha512||parsed.anchor.keyId!==expectedKeyId)Fail('ISSUED_A_TRUST_CONTEXT_MISMATCH');return {format:FORMAT,keyId:parsed.anchor.keyId,templateSize,configSize,config:parsed.decoded,sha512:Digest(bytes).toString('hex')};
}
module.exports={ENV,FORMAT,DOMAIN,FOOTER,ANCHOR_MAGIC,ANCHOR_SIZE,HEADER_SIZE,SIGNATURE_SIZE,TAIL_SIZE,PUBLIC_BLOB_SIZE,PublicIdentity,IdentityFromBlob,AnchorBytes,InspectTemplate,LoadSigner,Readiness,RequireReady,Create,Materialize,VerifyFinal,ValidateReceiptShape};
