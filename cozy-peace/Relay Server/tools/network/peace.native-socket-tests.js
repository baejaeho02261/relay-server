'use strict';
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {Certificates}=require('../integrity/peace.native-receive-fixture');
const {Execute}=require('../integrity/peace.native-receive-fault-tests');
const {Cases,Serve,Evaluate}=require('./peace.native-socket-fixture');
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
async function Run(probe,openssl='openssl'){
 if(process.platform!=='win32'||process.arch!=='x64')return {version:1,outcome:'NOT_RUN',nativeExecuted:false,reason:'WINDOWS_X64_REQUIRED'};
 if(!path.isAbsolute(probe))throw Error('SOCKET_ABSOLUTE_PROBE_PATH_REQUIRED');
 const original=fs.readFileSync(probe);require('../runtime/peace.manual-windows-tests').Pe64(original);
 const digest=hash(original),root=fs.mkdtempSync(path.join(os.tmpdir(),'Cozy-Socket-')),rows=[];
 try{
  const copy=path.join(root,'Cozy.RelaySocketProbe.exe');fs.writeFileSync(copy,original,{flag:'wx'});
  const contracts=await Execute(copy,['--contracts']);
  if(contracts.contractProbeExecuted!==true||contracts.outcome!=='PASS')throw Error('SOCKET_CONTRACT_PROBE_FAILED');
  const {identity,pin}=Certificates(root,openssl);
  for(const row of Cases()){
   const nonce=crypto.randomBytes(16).toString('hex');let server;
   try{server=await Serve(row,identity,nonce);const observed=await Execute(copy,[row.id,row.host,String(server.port),row.wrongPin?'0'.repeat(64):pin,String(row.budget),String(row.cancelAfter),String(row.closeAfter),nonce]);rows.push(Evaluate(row,observed,server.wire,nonce));}
   catch(error){rows.push({id:row.id,outcome:(row.host==='::1'&&['EAFNOSUPPORT','EADDRNOTAVAIL'].includes(error.code))?'NOT_RUN':'FAIL',reason:/^SOCKET_[A-Z_]+$/.test(error.message)?error.message:'SOCKET_CASE_FAILED'});}
   finally{if(server)await server.close();}
  }
  const unchanged=hash(fs.readFileSync(probe))===digest&&hash(fs.readFileSync(copy))===digest;
  return {version:1,outcome:!unchanged||rows.some(x=>x.outcome==='FAIL')?'FAIL':rows.some(x=>x.outcome!=='PASS')?'INCOMPLETE':'PASS',nativeExecuted:true,scope:'ISOLATED_PRODUCTION_SOCKET_AND_SCHANNEL',probeSha512:digest,inputsUnchanged:unchanged,contracts,cases:rows};
 }finally{fs.rmSync(root,{recursive:true,force:true});}
}
if(require.main===module)(async()=>{try{const options={},args=process.argv.slice(2);for(let i=0;i<args.length;i+=2){if(!['--probe','--output','--openssl'].includes(args[i])||!args[i+1]||options[args[i]])throw Error('SOCKET_ARGUMENTS');options[args[i]]=args[i+1];}if(!options['--probe']||!options['--output'])throw Error('SOCKET_ARGUMENTS');const result=await Run(options['--probe'],options['--openssl']);fs.writeFileSync(options['--output'],JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({outcome:result.outcome,nativeExecuted:result.nativeExecuted,cases:result.cases?.length||0}));process.exitCode=result.outcome==='PASS'?0:result.outcome==='NOT_RUN'?2:1;}catch(error){console.error(/^SOCKET_[A-Z_]+$/.test(error.message)?error.message:'SOCKET_RUN_FAILED');process.exitCode=1;}})();
module.exports={Run};
