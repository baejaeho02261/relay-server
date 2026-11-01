#!/usr/bin/env node
'use strict';
// Static public-key inspection only. Never executes the selected file or reads
// configured signing keys, credentials, or server state.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const signing=require('../../services/bootstrap/peace.issued-a-signing');
const bounded=require('../../services/artifacts/peace.bounded-artifact-read');
const KEY_ID=/^[a-f0-9]{64}$/;
function Fail(code){throw Error(code);}
function Arguments(args){
 const values={};
 for(let i=0;i<args.length;i+=2){
  const name=args[i],value=args[i+1];
  if(!['--launcher','--expected-key-id'].includes(name)||typeof value!=='string'||!value.length||Object.hasOwn(values,name))Fail('ISSUED_A_INSPECT_USAGE');
  values[name]=value;
 }
 if(!values['--launcher']||!path.isAbsolute(values['--launcher']))Fail('ISSUED_A_INSPECT_ABSOLUTE_PATH_REQUIRED');
 if(Object.hasOwn(values,'--expected-key-id')&&!KEY_ID.test(values['--expected-key-id']))Fail('ISSUED_A_INSPECT_KEY_ID_INVALID');
 return values;
}
function Inspect(args){
 const values=Arguments(args),file=path.resolve(values['--launcher']),expectedKeyId=values['--expected-key-id']??null;
 // Refuse both file symlinks and linked parent directories.
 for(let cursor=file;;cursor=path.dirname(cursor)){
  if(fs.lstatSync(cursor).isSymbolicLink())Fail('ISSUED_A_INSPECT_SYMLINK_DENIED');
  if(path.dirname(cursor)===cursor)break;
 }
 let bytes;
 try{
  bytes=bounded.Read(file,64*1024*1024);
  const anchor=signing.InspectTemplate(bytes),matchesExpected=expectedKeyId===null?null:anchor.keyId===expectedKeyId;
  return {
   ok:matchesExpected!==false,
   ...(matchesExpected===false?{error:'ISSUED_A_EXPECTED_KEY_MISMATCH'}:{}),
   keyId:anchor.keyId,expectedKeyId,matchesExpected,
   comparison:expectedKeyId===null?'NOT_REQUESTED':matchesExpected?'MATCH':'MISMATCH',
   sizeBytes:bytes.length,sha512:crypto.createHash('sha512').update(bytes).digest('hex'),
   windowsExecution:'NOT_RUN',serverState:'NOT_CHECKED'
  };
 }finally{bytes?.fill(0);}
}
function ErrorResult(error){
 const code=typeof error?.message==='string'&&/^[A-Z][A-Z0-9_]+$/.test(error.message)?error.message:'ISSUED_A_INSPECT_FAILED';
 return {ok:false,error:code,windowsExecution:'NOT_RUN',serverState:'NOT_CHECKED'};
}
if(require.main===module){
 let result;try{result=Inspect(process.argv.slice(2));}catch(error){result=ErrorResult(error);}
 process.stdout.write(JSON.stringify(result)+'\n');
 if(!result.ok)process.exitCode=1;
}
module.exports={Inspect,Arguments,ErrorResult};

