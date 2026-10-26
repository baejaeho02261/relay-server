'use strict';
// Byte lineage only. Cryptographic Authenticode verification MUST happen on
// Windows; a well-formed WIN_CERTIFICATE is not proof of a valid signature.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const reader=require('../../services/artifacts/peace.bounded-artifact-read');
const audit=require('../../tools/security/peace.audit-client-secrets');
const MAX=64*1024*1024;
function Fail(code){throw Error('CI_AUTHENTICODE_'+code);}
function Sha(bytes){return crypto.createHash('sha512').update(bytes).digest('hex');}
function Read(file){
 if(typeof file!=='string'||!path.isAbsolute(file)||file.includes('\0')||/^[/\\]{2}/.test(file))Fail('ABSOLUTE_LOCAL_FILE_REQUIRED');
 file=path.resolve(file);let at=path.parse(file).root;
 for(const part of file.slice(at.length).split(path.sep).filter(Boolean)){
  at=path.join(at,part);const stat=fs.lstatSync(at);
  if(stat.isSymbolicLink()||at!==file&&!stat.isDirectory())Fail('LINK_FORBIDDEN');
 }
 return reader.Read(file,MAX);
}
function Layout(bytes,role){
 const scan=audit.InspectBytes(bytes,role);
 if(scan.status!=='PASS')Fail('CLIENT_SECRET_OR_EXPOSURE_BLOCKED');
 const pe=bytes.readUInt32LE(60),opt=pe+24,size=bytes.readUInt16LE(pe+20);
 if(size<152||bytes.readUInt32LE(opt+108)<5)Fail('PE_SECURITY_DIRECTORY_REQUIRED');
 const checksum=opt+64,security=opt+144,certificateAt=bytes.readUInt32LE(security),certificateSize=bytes.readUInt32LE(security+4);
 if(!!certificateAt!==!!certificateSize)Fail('PE_CERTIFICATE_RANGE_INVALID');
 return {checksum,security,certificateAt,certificateSize,sha512:Sha(bytes),size:bytes.length};
}
function Unsigned(bytes,role){
 const meta=Layout(bytes,role);
 if(meta.certificateAt||meta.certificateSize)Fail('UNSIGNED_INPUT_REQUIRED');
 if(role==='A'&&['GAMEA80CONFIG!','COZYA2CONFIG!','COZYA3CONFIG!'].some(x=>bytes.subarray(-x.length).equals(Buffer.from(x))))Fail('ISSUED_LAUNCHER_NOT_TEMPLATE');
 return meta;
}
function Inspect(file,role){let bytes;try{bytes=Read(file);const m=Unsigned(bytes,role);return {version:1,role,sha512:m.sha512,size:m.size,clientSecretScan:'PASS',guaranteesAbsenceOfSecrets:false,executed:false};}finally{bytes?.fill(0);}}
function CompareBytes(before,after,role){
 const a=Unsigned(before,role),b=Layout(after,role);
 if(b.checksum!==a.checksum||b.security!==a.security||b.size<=a.size||b.size>MAX)Fail('SIGNED_IMAGE_LAYOUT_CHANGED');
 const expected=(before.length+7)&~7;
 if(b.certificateAt!==expected||b.certificateSize<8||b.certificateSize%8||b.certificateAt+b.certificateSize!==after.length)Fail('CERTIFICATE_APPEND_INVALID');
 for(let i=0;i<before.length;i++){
  if(i>=a.checksum&&i<a.checksum+4||i>=a.security&&i<a.security+8)continue;
  if(before[i]!==after[i])Fail('NON_SIGNATURE_BYTES_CHANGED');
 }
 if(after.subarray(before.length,expected).some(x=>x!==0))Fail('CERTIFICATE_ALIGNMENT_INVALID');
 let at=expected,certificates=0;
 while(at<after.length){
  if(at+8>after.length||++certificates>16)Fail('CERTIFICATE_TABLE_INVALID');
  const length=after.readUInt32LE(at),aligned=(length+7)&~7;
  if(length<9||length>MAX||aligned<length||at+aligned>after.length||after.readUInt16LE(at+4)!==0x0200||after.readUInt16LE(at+6)!==2)Fail('CERTIFICATE_TABLE_INVALID');
  if(after.subarray(at+length,at+aligned).some(x=>x!==0))Fail('CERTIFICATE_PADDING_INVALID');
  at+=aligned;
 }
 return {version:1,kind:'AUTHENTICODE_BYTE_LINEAGE_NOT_APPROVAL',role,inputSha512:a.sha512,outputSha512:b.sha512,inputSize:a.size,outputSize:b.size,onlySignatureMetadataChanged:true,certificateEntries:certificates,signatureCryptographicallyVerified:false,windowsProductExecuted:false,productionApproved:false,publicationPerformed:false};
}
function Compare(input,output,role){let before,after;try{before=Read(input);after=Read(output);return CompareBytes(before,after,role);}finally{before?.fill(0);after?.fill(0);}}
if(require.main===module){try{const[cmd,...args]=process.argv.slice(2);let value;if(cmd==='inspect'&&args.length===2)value=Inspect(...args);else if(cmd==='compare'&&args.length===3)value=Compare(...args);else Fail('ARGUMENTS_INVALID');process.stdout.write(JSON.stringify(value)+'\n');}catch(error){process.stderr.write(/^CI_AUTHENTICODE_[A-Z_]+$/.test(error.message)?error.message+'\n':'CI_AUTHENTICODE_INPUT_REJECTED\n');process.exitCode=1;}}
module.exports={Inspect,Compare,CompareBytes};
