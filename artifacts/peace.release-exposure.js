'use strict';
// Static, high-confidence final-output checks. This is not proof that a binary
// contains no secret. Encoded/encrypted/generated secrets require independent review.
// Findings contain rule IDs / offsets only, never matched strings or key bytes.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const VERSION=1,MAX_BYTES=64*1024*1024,MAX_FILES=4096,MAX_TOTAL=512*1024*1024;
const RULES=Object.freeze([
 {id:'PRIVATE_KEY_PEM',source:'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\r\\n ]+[A-Za-z0-9+/=\\r\\n ]{48,16000}-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'},
 {id:'GITHUB_TOKEN',source:'\\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\\b'},
 {id:'SLACK_TOKEN',source:'\\bxox[baprs]-[A-Za-z0-9-]{24,200}\\b'},
 {id:'CREDENTIAL_ASSIGNMENT',source:'(?:ADMIN_SECRET|GAME_RELEASE_APPROVAL_KEY_B64|GAME_CI_ATTESTATION_KEY_B64|AWS_SECRET_ACCESS_KEY|DATABASE_PASSWORD)["\']?\\s*[=:]\\s*["\']?([A-Za-z0-9+/=_-]{20,512})'}
]);
const completed=new Map();let backgroundRequired=false;
const DEV_EXT=/\.(?:pas|dpr|dproj|inc|cpp|c|h|hpp|map|pdb|dcu|obj|o|ilk|idb|mdb|tds|vmp|bak|log)$/i;
function Hash(b){return crypto.createHash('sha512').update(b).digest('hex');}
function Fail(code){const e=Error(code);e.desktopError=true;e.status=409;throw e;}
function ScanBytes(bytes,{name='artifact.exe'}={}){
 if(!Buffer.isBuffer(bytes)||bytes.length>MAX_BYTES)Fail('EXPOSURE_INPUT_LIMIT');
 const findings=[],seen=new Set();let omitted=0;
 function add(rule,offset,encoding='binary'){const key=rule+':'+offset;if(seen.has(key))return;if(findings.length>=64){omitted=Math.min(1000000,omitted+1);return;}seen.add(key);findings.push({rule,offset,encoding,severity:'BLOCK'});}
 if(DEV_EXT.test(name)||/(?:^|[\/\\])(?:\.env(?:\.[^/\\]+)?|id_(?:rsa|ed25519)|.*(?:private|secret)[._-](?:key|token)(?:\..*)?)$/i.test(name))add('DEVELOPMENT_OR_SECRET_FILE',0,'filename');
 const stride=512*1024,overlap=32768;
 for(let at=0;at<bytes.length;at+=stride){const end=Math.min(bytes.length,at+stride+overlap),slice=bytes.subarray(at,end);
  for(const [encoding,width,delta]of [['latin1',1,0],['utf16le',2,0],['utf16le',2,1]]){
   const data=slice.subarray(delta),text=data.toString(encoding);
   for(const rule of RULES){const re=new RegExp(rule.source,'g');let m;while((m=re.exec(text))){const offset=at+delta+m.index*width;if(m.index*width>=stride)break;
     // Configuration placeholders are not credentials. Concrete keys/tokens are.
     if(rule.id==='CREDENTIAL_ASSIGNMENT'&&/^(?:CHANGE_ME|REPLACE_ME|EXAMPLE|REDACTED|YOUR_|PLACEHOLDER)/i.test(m[1]||''))continue;
     add(rule.id,offset,encoding);
    }}
  }
 }
 // Inspect actual PE debug-directory entries; a literal '.pdb' in program logic
 // is not enough to infer a leaked PDB. The full PE validity gate stays separate.
 if(bytes.length>=64&&bytes.readUInt16LE(0)===0x5a4d){const pe=bytes.readUInt32LE(0x3c);
  if(pe<=bytes.length-24&&bytes.readUInt32LE(pe)===0x4550){const n=bytes.readUInt16LE(pe+6),opt=pe+24,len=bytes.readUInt16LE(pe+20),magic=opt+2<=bytes.length?bytes.readUInt16LE(opt):0,dir=magic===0x20b?opt+112:magic===0x10b?opt+96:0;
   if(dir&&dir+56<=opt+len&&opt+len<=bytes.length&&n<=96&&opt+len+n*40<=bytes.length){const rva=bytes.readUInt32LE(dir+48),size=bytes.readUInt32LE(dir+52);let raw=-1;
    for(let i=0;i<n;i++){const s=opt+len+i*40,v=bytes.readUInt32LE(s+12),rs=bytes.readUInt32LE(s+16),rp=bytes.readUInt32LE(s+20);if(rva>=v&&rva-v<=rs&&size<=rs-(rva-v)&&rp+rva-v<=bytes.length-size)raw=rp+rva-v;}
    if(rva&&raw>=0&&size%28===0&&size<=28*128)for(let i=0;i<size;i+=28){const type=bytes.readUInt32LE(raw+i+12);if(type===2||type===17)add(type===2?'PE_CODEVIEW_DEBUG':'PE_EMBEDDED_PDB',raw+i);}
   }
  }
 }
 return {version:VERSION,kind:'STATIC_RELEASE_EXPOSURE',sha512:Hash(bytes),size:bytes.length,status:findings.length?'BLOCKED':'PASS',findings,omittedFindings:omitted,scope:'UNENCRYPTED_ASCII_UTF16_AND_PE_DEBUG',guaranteesAbsenceOfSecrets:false};
}
function Remember(bytes,report){
 const hash=Hash(bytes);if(!report||report.version!==VERSION||report.kind!=='STATIC_RELEASE_EXPOSURE'||report.sha512!==hash||report.size!==bytes.length||!['PASS','BLOCKED'].includes(report.status)||!Array.isArray(report.findings)||report.findings.length>64)Fail('EXPOSURE_RESULT_STALE');
 completed.delete(hash);completed.set(hash,structuredClone(report));while(completed.size>256)completed.delete(completed.keys().next().value);return structuredClone(report);
}
async function Prepare(bytes,key='EXPOSURE'){
 if(!Buffer.isBuffer(bytes)||bytes.length>MAX_BYTES)Fail('EXPOSURE_INPUT_LIMIT');const hash=Hash(bytes);
 const report=await require("../runtime/peace.desktop-work-queue").pe.run({kind:'exposure',bytes},30000,{key});
 if(Hash(bytes)!==hash)Fail('EXPOSURE_RESULT_STALE');return Remember(bytes,report);
}
function AssertBytes(bytes,options){
 let report=require('./peace.desktop-pe-cache').Get(bytes,'exposure')||completed.get(Hash(bytes));
 // Live server never runs a regex/PE exposure scan on its event loop. A fresh
 // upload primes this cache in a worker. Previously stored artifacts can be
 // scanned from the authenticated UI after a server restart. Offline tools run
 // their bounded scan directly and do not rely on a server verdict/cache.
 if(!report){if(backgroundRequired)Fail('ARTIFACT_EXPOSURE_SCAN_REQUIRED');report=ScanBytes(bytes,options);}
 if(report.version!==VERSION||report.sha512!==Hash(bytes))Fail('EXPOSURE_RESULT_STALE');
 if(report.status!=='PASS'){try{require("../security/peace.security-detection").Record('EXPOSURE_BLOCKED',{subject:report.sha512,reason:'ARTIFACT_EXPOSURE_BLOCKED'});}catch(_){}const e=Error('ARTIFACT_EXPOSURE_BLOCKED');e.desktopError=true;e.status=409;e.exposure=structuredClone(report);throw e;}return structuredClone(report);
}
function ScanDirectory(directory){const inputStat=fs.lstatSync(directory);if(!inputStat.isDirectory()||inputStat.isSymbolicLink())Fail('EXPOSURE_LINK_FORBIDDEN');const root=fs.realpathSync(directory),files=[],issues=[];let total=0,entries=0;
 function walk(dir,depth){if(depth>16)Fail('EXPOSURE_DIRECTORY_LIMIT');for(const item of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){if(++entries>MAX_FILES)Fail('EXPOSURE_DIRECTORY_LIMIT');const file=path.join(dir,item.name),rel=path.relative(root,file).split(path.sep).join('/'),st=fs.lstatSync(file);if(st.isSymbolicLink()||st.nlink>1&&!st.isDirectory())Fail('EXPOSURE_LINK_FORBIDDEN');if(st.isDirectory()){walk(file,depth+1);continue;}if(!st.isFile()||++ScanCount>MAX_FILES||st.size>MAX_BYTES||(total+=st.size)>MAX_TOTAL)Fail('EXPOSURE_DIRECTORY_LIMIT');const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));let bytes;
   try{const before=fs.fstatSync(fd);if(before.ino!==st.ino||before.dev!==st.dev||!before.isFile()||before.size!==st.size)Fail('EXPOSURE_FILE_CHANGED');bytes=Buffer.alloc(before.size);let offset=0;while(offset<bytes.length){const n=fs.readSync(fd,bytes,offset,Math.min(1048576,bytes.length-offset),offset);if(!n)Fail('EXPOSURE_FILE_CHANGED');offset+=n;}const extra=Buffer.alloc(1);if(fs.readSync(fd,extra,0,1,offset)!==0)Fail('EXPOSURE_FILE_CHANGED');const after=fs.fstatSync(fd);if(bytes.length!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)Fail('EXPOSURE_FILE_CHANGED');const report=ScanBytes(bytes,{name:rel});files.push({name:rel,...report});if(!/\.(?:exe|json|sig|txt|pub)$/i.test(rel))issues.push({rule:'UNAPPROVED_FILE_TYPE',name:rel});}finally{bytes?.fill(0);fs.closeSync(fd);}
  }}let ScanCount=0;walk(root,0);if(!files.length)Fail('EXPOSURE_EMPTY_DIRECTORY');return {version:VERSION,kind:'FINAL_DISTRIBUTION_SCAN',status:issues.length||files.some(x=>x.status!=='PASS')?'BLOCKED':'PASS',files,issues,totalBytes:total,guaranteesAbsenceOfSecrets:false};}
module.exports={VERSION,MAX_BYTES,RULES,ScanBytes,AssertBytes,ScanDirectory,Hash,Prepare,Remember,Start:()=>{backgroundRequired=true;},Stop:()=>{backgroundRequired=false;completed.clear();}};
