'use strict';
// Test tooling only. Numeric values are emitted independently by the compiled
// Delphi declarations and the Windows SDK, not copied from this field catalog.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const MAX_BYTES=65536,EXPECTED_FIELDS=149;
const contractPath=path.join(__dirname,'./Cozy.native-abi-fields-v1.json');
function Fail(code){throw Error(code);}
function Decode(bytes){if(!Buffer.isBuffer(bytes))Fail('ABI_OUTPUT_TYPE');if(bytes.length>MAX_BYTES)Fail('ABI_OUTPUT_LIMIT');try{return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch(_){Fail('ABI_OUTPUT_UTF8');}}
function Contract(){
 const raw=fs.readFileSync(contractPath);if(raw.length>MAX_BYTES)Fail('ABI_FIELD_CONTRACT_INVALID');
 const c=JSON.parse(Decode(raw));
 if(c.version!==1||c.architecture!=='WIN64'||!Array.isArray(c.fields)||c.fields.length!==EXPECTED_FIELDS||new Set(c.fields).size!==EXPECTED_FIELDS||c.fields.some(x=>typeof x!=='string'||!/^([A-Za-z][A-Za-z0-9_]*)\.([A-Za-z][A-Za-z0-9_]*)$/.test(x)))Fail('ABI_FIELD_CONTRACT_INVALID');
 return c;
}
function Parse(output,fields=Contract().fields){
 const text=Buffer.isBuffer(output)?Decode(output):output;
 if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>MAX_BYTES)Fail('ABI_OUTPUT_LIMIT');
 const normalized=text.replace(/\r\n/g,'\n').replace(/\n$/,'');
 const result=new Map(),expected=new Set(fields);
 for(const line of normalized.split('\n')){
  const m=/^([A-Za-z][A-Za-z0-9_]*\.[A-Za-z][A-Za-z0-9_]*)=([0-9]{1,20})$/.exec(line);
  if(!m)Fail('ABI_OUTPUT_FORMAT');
  if(!expected.has(m[1]))Fail('ABI_FIELD_UNEXPECTED');
  if(result.has(m[1]))Fail('ABI_FIELD_DUPLICATE');
  const value=BigInt(m[2]);if(value>0xffffffffffffffffn)Fail('ABI_VALUE_RANGE');
  result.set(m[1],value);
 }
 if(fields.some(x=>!result.has(x)))Fail('ABI_FIELD_MISSING');
 return result;
}
function Compare(delphiOutput,sdkOutput){
 const fields=Contract().fields,a=Parse(delphiOutput,fields),b=Parse(sdkOutput,fields);
 const differences=fields.filter(x=>a.get(x)!==b.get(x)).map(field=>({field,delphi:a.get(field).toString(),sdk:b.get(field).toString()}));
 return{version:1,architecture:'WIN64',fieldCount:fields.length,match:!differences.length,differences,contractSha512:crypto.createHash('sha512').update(fs.readFileSync(contractPath)).digest('hex')};
}
function RunProbe(executable){
 const full=path.resolve(executable),stat=fs.lstatSync(full);
 if(!stat.isFile()||stat.isSymbolicLink()||path.extname(full).toLowerCase()!=='.exe'||stat.size<1||stat.size>16*1024*1024)Fail('ABI_PROBE_FILE_INVALID');
 const result=spawnSync(full,[],{cwd:path.dirname(full),encoding:null,timeout:20000,maxBuffer:MAX_BYTES,windowsHide:true});
 if(result.error)Fail(result.error.code==='ETIMEDOUT'?'ABI_PROBE_TIMEOUT':'ABI_PROBE_EXECUTION_FAILED');
 if(result.signal||result.status!==0)Fail('ABI_PROBE_NONZERO_EXIT');
 if(result.stderr?.length)Fail('ABI_PROBE_STDERR');
 return result.stdout;
}
function Main(args){
 if(args.length!==2)Fail('ABI_ARGUMENTS_INVALID');
 if(process.platform!=='win32'||process.arch!=='x64')Fail('ABI_WINDOWS_X64_REQUIRED');
 const result=Compare(RunProbe(args[0]),RunProbe(args[1]));
 console.log(JSON.stringify({...result,nativeExecuted:true,node:process.version}));
 if(!result.match)Fail('ABI_VALUES_DIFFER');
 console.log('PASS: '+result.fieldCount+' production Delphi / Windows SDK ABI values match.');
}
if(require.main===module){try{Main(process.argv.slice(2));}catch(e){console.error(/^ABI_[A-Z0-9_]+$/.test(e.message)?e.message:'ABI_CHECK_FAILED');process.exitCode=1;}}
module.exports={Contract,Decode,Parse,Compare};
