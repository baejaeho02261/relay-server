'use strict';
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const {Certificates,Cases,Serve,Evaluate}=require('./native-receive-fixture');
const hash=file=>crypto.createHash('sha512').update(fs.readFileSync(file)).digest('hex');
function Execute(exe,args){return new Promise((resolve,reject)=>{const child=cp.spawn(exe,args,{windowsHide:true,stdio:['ignore','pipe','pipe']});let stdout='',stderr='',size=0;const timer=setTimeout(()=>child.kill(),7000);child.stdout.on('data',b=>{size+=b.length;if(size>65536)child.kill();else stdout+=b;});child.stderr.on('data',b=>{size+=b.length;if(size>65536)child.kill();else stderr+=b;});child.once('error',reject);child.once('close',(code,signal)=>{clearTimeout(timer);if(code!==0||signal||stderr||size>65536)return reject(Error('RECEIVE_NATIVE_EXECUTION_FAILED'));try{const lines=stdout.trim().split(/\r?\n/);if(lines.length!==1)throw Error();resolve(JSON.parse(lines[0]));}catch(_){reject(Error('RECEIVE_NATIVE_RESULT_INVALID'));}});});}
async function Run(probe,openssl='openssl'){
 if(process.platform!=='win32'||process.arch!=='x64')return {version:1,outcome:'NOT_RUN',reason:'WINDOWS_X64_SCHANNEL_REQUIRED',nativeExecuted:false,hardwareLoss:'NOT_RUN'};
 const source=fs.realpathSync(probe),before=hash(source),root=fs.mkdtempSync(path.join(os.tmpdir(),'game-receive-')),results=[];
 try{
  const copy=path.join(root,'TlsReceiveProbe.exe');fs.copyFileSync(source,copy,fs.constants.COPYFILE_EXCL);const {identity,pin}=Certificates(root,openssl);
  for(const row of Cases()){
   const nonce=crypto.randomBytes(16).toString('hex'),server=await Serve(row,identity,nonce);
   try{const observed=await Execute(copy,[row.id,String(server.port),row.wrongPin?'0'.repeat(64):pin,String(row.limit),row.mode,nonce,path.join(root,nonce+'.received')]);results.push(Evaluate(row,observed,server.observation,nonce));}
   catch(error){results.push({id:row.id,outcome:'FAIL',reason:/^RECEIVE_[A-Z_]+$/.test(error.message)?error.message:'RECEIVE_CASE_FAILED',wire:{...server.observation}});}
   finally{await server.close();}
  }
  const unchanged=hash(source)===before&&hash(copy)===before;
  return {version:1,outcome:unchanged&&results.every(x=>x.outcome==='PASS')?'PASS':'FAIL',nativeExecuted:true,scope:'ISOLATED_NATIVE_RECEIVE_BOUNDARIES_ONLY',productSessionLease:'NOT_RUN',hardwareLoss:'NOT_RUN',probeSha512:before,inputsUnchanged:unchanged,cases:results};
 }finally{fs.rmSync(root,{recursive:true,force:true});}
}
if(require.main===module){(async()=>{try{const args=process.argv.slice(2),opts={};for(let i=0;i<args.length;i+=2){if(!['--probe','--output','--openssl'].includes(args[i])||!args[i+1]||opts[args[i]])throw Error('RECEIVE_ARGUMENTS');opts[args[i]]=args[i+1];}if(!opts['--probe']||!opts['--output'])throw Error('RECEIVE_ARGUMENTS');const result=await Run(opts['--probe'],opts['--openssl']);fs.writeFileSync(opts['--output'],JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({outcome:result.outcome,nativeExecuted:result.nativeExecuted,cases:result.cases?.length||0}));if(result.outcome==='FAIL')process.exitCode=1;}catch(error){console.error(/^RECEIVE_[A-Z_]+$/.test(error.message)?error.message:'RECEIVE_RUN_FAILED');process.exitCode=1;}})();}
module.exports={Run,Execute};
