'use strict';
// Read-only final-artifact audit. Never executes an EXE, writes a report/file,
// decrypts a payload, contacts a server or prints matched material/file paths.
// PASS means no covered finding, not proof that arbitrary secrets are absent.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const exposure=require('../../services/artifacts/peace.release-exposure');
const MAX_BYTES=64*1024*1024,ROLES=['A','B','O'];
const HEAD=Buffer.from('COZY-VM-SLOT-V1\0','ascii'),TAIL=Buffer.from('COZY-VM-END--V1\0','ascii');
const COVERAGE=Object.freeze(['KNOWN_PEM_AND_CREDENTIAL_PATTERNS_ASCII_UTF16','PE_DEBUG_METADATA','KNOWN_COZY_VM_V1_EMBEDDED_KEY','COZY_V2_PUBLIC_SLOT_LAYOUT']);
function Fail(code){const e=Error(code);e.auditCode=code;throw e;}
function PeSections(bytes){
 if(bytes.length<512||bytes.readUInt16LE(0)!==0x5a4d)Fail('CLIENT_AUDIT_PE_INVALID');
 const pe=bytes.readUInt32LE(60);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)Fail('CLIENT_AUDIT_PE_INVALID');
 const count=bytes.readUInt16LE(pe+6),len=bytes.readUInt16LE(pe+20),opt=pe+24,table=opt+len,flags=bytes.readUInt16LE(pe+22);
 if(count<1||count>96||len<112||table+count*40>bytes.length||bytes.readUInt16LE(opt)!==0x20b||!(flags&2)||(flags&0x2000))Fail('CLIENT_AUDIT_PE_INVALID');
 const headers=bytes.readUInt32LE(opt+60),image=bytes.readUInt32LE(opt+56),entry=bytes.readUInt32LE(opt+16),sections=[];
 if(headers<table+count*40||headers>bytes.length||!image||!entry||entry>=image)Fail('CLIENT_AUDIT_PE_INVALID');
 for(let i=0;i<count;i++){
  const p=table+i*40,vsize=bytes.readUInt32LE(p+8),rva=bytes.readUInt32LE(p+12),size=bytes.readUInt32LE(p+16),offset=bytes.readUInt32LE(p+20),attributes=bytes.readUInt32LE(p+36),span=Math.max(vsize,size);
  if(!rva||!span||rva+span>image||size&&(offset<headers||offset+size>bytes.length)||sections.some(s=>rva<s.rva+s.span&&rva+span>s.rva||size&&s.size&&offset<s.offset+s.size&&offset+size>s.offset))Fail('CLIENT_AUDIT_PE_INVALID');
  sections.push({vsize,rva,size,offset,attributes,span});
 }
 if(!sections.some(s=>(s.attributes&0x20000000)&&entry>=s.rva&&entry<s.rva+s.size))Fail('CLIENT_AUDIT_PE_INVALID');
 return sections;
}
function InspectBytes(bytes,role){
 if(!ROLES.includes(role))Fail('CLIENT_AUDIT_ROLE_INVALID');
 if(!Buffer.isBuffer(bytes)||bytes.length>MAX_BYTES)Fail('CLIENT_AUDIT_SIZE_INVALID');
 const sections=PeSections(bytes),sha512=crypto.createHash('sha512').update(bytes).digest('hex'),codes=new Set();
 const legacy=exposure.ScanBytes(bytes,{name:role+'.exe'});
 for(const finding of legacy.findings)codes.add(finding.rule);
 let markers=0,slots=0;
 for(let at=bytes.indexOf(HEAD);at>=0;at=bytes.indexOf(HEAD,at+1)){
  if(++markers>256)Fail('CLIENT_AUDIT_MARKER_LIMIT');
  // An ordinary parser string is not a slot. Its fixed layout must match.
  if(at+24>bytes.length||bytes.readUInt16LE(at+18)!==128||bytes.readUInt32LE(at+20)!==4096)continue;
  if(++slots>1)codes.add('COZY_VM_V1_SLOT_DUPLICATE');
  if(at+4096>bytes.length){codes.add('COZY_VM_V1_SLOT_INVALID');continue;}
  const slot=bytes.subarray(at,at+4096),state=slot[25],length=slot.readUInt32LE(28),keyPresent=slot.subarray(40,72).some(x=>x!==0);
  const mapped=sections.some(s=>at>=s.offset&&at+4096<=s.offset+s.size&&at-s.offset+4096<=(s.vsize||s.size)&&(s.attributes&0x40)&&(s.attributes&0x40000000)&&!(s.attributes&0x220000a0));
  const valid=mapped&&slot.readUInt16LE(16)===1&&slot.readUInt16LE(26)===0&&slot.readUInt32LE(32)===1&&slot.readUInt32LE(36)>=1&&slot.readUInt32LE(36)<=1024&&slot.readUInt32LE(100)===1&&!slot.subarray(104,128).some(x=>x!==0)&&slot.subarray(4080).equals(TAIL);
  if(!valid)codes.add('COZY_VM_V1_SLOT_INVALID');
  // A malformed tag/ciphertext does not make serialized key bytes safe.
  if(state===1&&keyPresent)codes.add('COZY_VM_V1_EMBEDDED_KEY');
  if(state===0){if(slot[24]!==0||length!==0||slot.subarray(40,100).some(x=>x!==0)||slot.subarray(128,4080).some(x=>x!==0))codes.add('COZY_VM_V1_SLOT_INVALID');}
  else if(state!==1||![1,2,3].includes(slot[24])||!keyPresent||length<16||length>3952||slot.subarray(128+length,4080).some(x=>x!==0))codes.add('COZY_VM_V1_SLOT_INVALID');
  if(state===1&&slot[24]!==ROLES.indexOf(role)+1)codes.add('COZY_VM_V1_ROLE_MISMATCH');
 }
 if(bytes.includes(Buffer.from('COZY-POLICY-V2\0\0','ascii'))||bytes.includes(Buffer.from('COZY-POLEND-V2\0\0','ascii'))){
  try{const own=require('../../services/artifacts/peace.server-policy-protection').Inspect(bytes);if(!own||own.state!=='BOUND'||own.role!==role)codes.add('COZY_V2_POLICY_ROLE_OR_STATE_INVALID');}
  catch(_){codes.add('COZY_V2_POLICY_SLOT_INVALID');}
 }
 return {role,sha512,size:bytes.length,status:codes.size?'BLOCKED':'PASS',findings:[...codes].sort().map(code=>({code,role,sha512}))};
}
function InspectPath(file){
 const root=path.parse(file).root;let current=root;
 if(!root)Fail('CLIENT_AUDIT_PATH_INVALID');
 for(const part of file.slice(root.length).split(path.sep).filter(Boolean)){
  current=path.join(current,part);const s=fs.lstatSync(current);
  if(s.isSymbolicLink())Fail('CLIENT_AUDIT_LINK_FORBIDDEN');
  if(current!==file&&!s.isDirectory())Fail('CLIENT_AUDIT_PATH_INVALID');
 }
 const stat=fs.lstatSync(file);
 if(!stat.isFile()||stat.nlink!==1)Fail('CLIENT_AUDIT_FILE_INVALID');
 if(stat.size<512||stat.size>MAX_BYTES)Fail('CLIENT_AUDIT_SIZE_INVALID');
 return stat;
}
function ReadFile(input){
 if(typeof input!=='string'||!input||input.length>32768||input.includes('\0')||/^[/\\]{2}/.test(input))Fail('CLIENT_AUDIT_PATH_INVALID');
 const file=path.resolve(input),before=InspectPath(file);let fd,bytes;
 try{
  fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0)|(fs.constants.O_NONBLOCK||0));
  const opened=fs.fstatSync(fd);
  if(!opened.isFile()||opened.nlink!==1||opened.dev!==before.dev||opened.ino!==before.ino||opened.size!==before.size)Fail('CLIENT_AUDIT_FILE_CHANGED');
  bytes=Buffer.alloc(opened.size);let at=0;
  while(at<bytes.length){const n=fs.readSync(fd,bytes,at,Math.min(65536,bytes.length-at),at);if(!n)Fail('CLIENT_AUDIT_FILE_CHANGED');at+=n;}
  const extra=Buffer.alloc(1);if(fs.readSync(fd,extra,0,1,at))Fail('CLIENT_AUDIT_FILE_CHANGED');
  const after=fs.fstatSync(fd),current=InspectPath(file);
  for(const s of [after,current])if(s.size!==opened.size||s.dev!==opened.dev||s.ino!==opened.ino||s.mtimeMs!==opened.mtimeMs||s.ctimeMs!==opened.ctimeMs||s.nlink!==1)Fail('CLIENT_AUDIT_FILE_CHANGED');
  return bytes;
 }catch(e){bytes?.fill(0);throw e;}finally{if(fd!==undefined)fs.closeSync(fd);}
}
function Run(files){
 if(!Array.isArray(files)||files.length!==3)Fail('CLIENT_AUDIT_ARGUMENTS_INVALID');
 const artifacts=[];
 for(let i=0;i<3;i++){
  let bytes;
  try{bytes=ReadFile(files[i]);artifacts.push(InspectBytes(bytes,ROLES[i]));}
  catch(error){artifacts.push({role:ROLES[i],status:'ERROR',error:error.auditCode||'CLIENT_AUDIT_READ_FAILED'});}
  finally{bytes?.fill(0);}
 }
 return {version:1,kind:'CLIENT_STATIC_SECRET_CHECK',status:artifacts.some(x=>x.status==='ERROR')?'ERROR':artifacts.some(x=>x.status==='BLOCKED')?'BLOCKED':'PASS',artifacts,coverage:[...COVERAGE],guaranteesAbsenceOfSecrets:false,unknownOrEncodedSecretsVerified:false,publicTrustAnchorsAreSecrets:false,executablesRun:false,filesWritten:false};
}
if(require.main===module){
 let report;
 try{report=Run(process.argv.slice(2));}
 catch(error){report={version:1,kind:'CLIENT_STATIC_SECRET_CHECK',status:'ERROR',error:error.auditCode||'CLIENT_AUDIT_FAILED',guaranteesAbsenceOfSecrets:false};}
 process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=report.status==='PASS'?0:report.status==='BLOCKED'?1:2;
}
module.exports={Run,InspectBytes,MAX_BYTES};
