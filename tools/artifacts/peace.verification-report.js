'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Operator-recorded observations with reproducible file bindings. This tool
// never runs a test, upgrades NOT_RUN to PASS, signs evidence, or authorizes a
// publication. Raw logs, local paths and credentials are not exported.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const svc=require("../../services/runtime/peace.desktop-manual-verification"),bounded=require("../../services/artifacts/peace.bounded-artifact-read");
const {CATALOG,EXECUTION}=require("../../services/runtime/peace.desktop-verification-catalog");
const hash=bytes=>crypto.createHash('sha512').update(bytes).digest('hex');
const read=(file,max=64*1024*1024)=>bounded.Read(path.resolve(file),max);
const json=file=>require("../../services/protocol/peace.strict-json").Parse(read(file,256*1024),{maxBytes:256*1024,maxDepth:12,maxNodes:20000});
function Fail(code){throw Error(code);}
function Shape(value,keys){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(value,k)))Fail('VERIFICATION_TOOL_INPUT_INVALID');}
function Binding(context){
 if(context&&Object.hasOwn(context,'ok')){if(context.ok!==true)Fail('VERIFICATION_CONTEXT_INVALID');const {ok,...value}=context;context=value;}
 Shape(context,['version','kind','manifestId','sourceManifestSha512','artifacts','policy','catalog','readOnly','usedForPublicationAuthorization']);
 if(context.version!==1||context.kind!=='MANUAL_VERIFICATION_CONTEXT'||context.readOnly!==true||context.usedForPublicationAuthorization!==false||!context.catalog||JSON.stringify(context.catalog)!==JSON.stringify(CATALOG))Fail('VERIFICATION_CONTEXT_INVALID');
 Shape(context.artifacts,['A','B','O']);if([context.manifestId,context.sourceManifestSha512,...Object.values(context.artifacts)].some(x=>typeof x!=='string'||!/^[a-f0-9]{128}$/.test(x)))Fail('VERIFICATION_CONTEXT_INVALID');
 return {manifestId:context.manifestId,sourceManifestSha512:context.sourceManifestSha512,artifacts:context.artifacts,policy:svc.ValidatePolicyStamp(context.policy)};
}
function WriteNew(output,value){
 if(fs.existsSync(output))Fail('VERIFICATION_OUTPUT_ALREADY_EXISTS');
 require("../../services/storage/peace.durable-file").Atomic(output,Buffer.from(JSON.stringify(value,null,2)+'\n'),{createOnly:true});return output;
}
function Prepare(contextFile,artifactFiles,output,sourceManifestFile=path.join(MODULE_RESOURCE_ROOT,'../maintenance/source-manifest.json')){
 if(!['win32','linux','darwin'].includes(process.platform)||!['x64','arm64'].includes(process.arch))Fail('VERIFICATION_UNSUPPORTED_HOST');
 const binding=Binding(json(contextFile));Shape(artifactFiles,['A','B','O']);
 const source=path.resolve(sourceManifestFile),files=Object.fromEntries(['A','B','O'].map(k=>[k,path.resolve(artifactFiles[k])]));
 if(hash(read(source,8*1024*1024))!==binding.sourceManifestSha512)Fail('VERIFICATION_SOURCE_MISMATCH');
 for(const role of ['A','B','O'])if(hash(read(files[role]))!==binding.artifacts[role])Fail('VERIFICATION_ARTIFACT_MISMATCH_'+role);
 const document={version:1,kind:'OPERATOR_VERIFICATION_INPUT',binding,sourceManifestFile:source,artifactFiles:files,runId:'manual-'+crypto.randomUUID(),startedAt:new Date().toISOString(),platform:process.platform,architecture:process.arch,domains:CATALOG.map(d=>({id:d.id,checks:d.checks.map(c=>({id:c.id,outcome:'NOT_RUN',scope:c.allowedScopes[0],reasonCode:'NOT_EXECUTED',evidenceFile:null,subjectArtifacts:c.allowedScopes[0]==='SELECTED_FINAL_ABO'?{...binding.artifacts}:null}))}))};
 WriteNew(output,document);return document;
}
function Finalize(inputFile,output){
 const input=json(inputFile);Shape(input,['version','kind','binding','sourceManifestFile','artifactFiles','runId','startedAt','platform','architecture','domains']);
 if(input.version!==1||input.kind!=='OPERATOR_VERIFICATION_INPUT'||input.platform!==process.platform||input.architecture!==process.arch)Fail('VERIFICATION_EXECUTION_HOST_MISMATCH');
 Shape(input.binding,['manifestId','sourceManifestSha512','artifacts','policy']);Shape(input.artifactFiles,['A','B','O']);Shape(input.binding.artifacts,['A','B','O']);
 if(typeof input.sourceManifestFile!=='string'||Object.values(input.artifactFiles).some(x=>typeof x!=='string')||!Array.isArray(input.domains))Fail('VERIFICATION_TOOL_INPUT_INVALID');
 const sourceManifestUnchanged=hash(read(input.sourceManifestFile,8*1024*1024))===input.binding.sourceManifestSha512;
 const artifacts=Object.fromEntries(['A','B','O'].map(k=>[k,{sha512:input.binding.artifacts[k],unchanged:hash(read(input.artifactFiles[k]))===input.binding.artifacts[k]}]));
 const evidenceFiles=new Map(),domains=input.domains.map(domain=>{
  Shape(domain,['id','checks']);if(!Array.isArray(domain.checks))Fail('VERIFICATION_TOOL_INPUT_INVALID');
  return {id:domain.id,checks:domain.checks.map(check=>{
   Shape(check,['id','outcome','scope','reasonCode','evidenceFile','subjectArtifacts']);let evidenceSha512=null;
   if(check.outcome==='NOT_RUN'){if(check.evidenceFile!==null)Fail('VERIFICATION_UNEXECUTED_EVIDENCE');}
   else{
    if(typeof check.evidenceFile!=='string'||!check.evidenceFile)Fail('VERIFICATION_EVIDENCE_FILE_REQUIRED');
    const file=path.resolve(path.dirname(inputFile),check.evidenceFile);evidenceSha512=hash(read(file,16*1024*1024));evidenceFiles.set(file,evidenceSha512);
   }
   return {id:check.id,outcome:check.outcome,scope:check.scope,execution:check.outcome==='NOT_RUN'?'NOT_EXECUTED':EXECUTION[check.scope],evidenceSha512,reasonCode:check.reasonCode,subjectArtifacts:check.subjectArtifacts};
  })};
 });
 const report=svc.ValidateReport({version:3,kind:'MANUAL_VERIFICATION',runId:input.runId,startedAt:input.startedAt,finishedAt:new Date().toISOString(),platform:input.platform,architecture:input.architecture,manifestId:input.binding.manifestId,sourceManifestSha512:input.binding.sourceManifestSha512,sourceManifestUnchanged,artifacts,policy:input.binding.policy,domains,nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false});
 // Reject files changing while the public report is assembled. The operator
 // report still does not prove an unmonitored input was never changed/restored.
 for(const [file,before] of evidenceFiles)if(hash(read(file,16*1024*1024))!==before)Fail('VERIFICATION_EVIDENCE_CHANGED');
 if(hash(read(input.sourceManifestFile,8*1024*1024))!==report.sourceManifestSha512)report.sourceManifestUnchanged=false;
 for(const k of ['A','B','O'])if(hash(read(input.artifactFiles[k]))!==report.artifacts[k].sha512)report.artifacts[k].unchanged=false;
 if(Buffer.byteLength(JSON.stringify(report))>65536)Fail('VERIFICATION_REPORT_TOO_LARGE');
 WriteNew(output,report);return report;
}
async function Main(){
 const readline=require('node:readline/promises'),rl=readline.createInterface({input:process.stdin,output:process.stdout});
 const ask=async message=>(await rl.question(message)).trim().replace(/^"(.*)"$/,'$1');
 try{
  let [action,...args]=process.argv.slice(2);if(!['prepare','finalize'].includes(action))Fail('VERIFICATION_TOOL_ARGUMENTS');
  const suffix=new Date().toISOString().replace(/[-:.]/g,'')+'-'+crypto.randomBytes(4).toString('hex');
  if(action==='prepare'){
   if(args.length!==0&&args.length!==4)Fail('VERIFICATION_TOOL_ARGUMENTS');
   if(!args.length){args=[await ask('Exported verification-context JSON path: ')];for(const role of ['A','B','O'])args.push(await ask(role+' FINAL EXE path: '));}
   const output=path.join(MODULE_RESOURCE_ROOT,'verification-input-'+suffix+'.json');Prepare(args[0],{A:args[1],B:args[2],O:args[3]},output);
   console.log(output);console.log('All checks start as NOT_RUN. Record only observed outcomes, exact scope, reason code and existing evidenceFile. Then run Create_Verification_Report.bat with this input.');
  }else{
   if(args.length>1)Fail('VERIFICATION_TOOL_ARGUMENTS');const input=args[0]||await ask('Reviewed verification-input JSON path: '),output=path.join(MODULE_RESOURCE_ROOT,'verification-report-'+suffix+'.json');
   const report=Finalize(path.resolve(input),output);console.log(output);console.log(JSON.stringify({operatorRecorded:true,inputsUnchanged:report.sourceManifestUnchanged&&Object.values(report.artifacts).every(x=>x.unchanged),ciEvidenceCreated:false,publicationApproval:false}));
  }
 }finally{rl.close();}
}
if(require.main===module)Main().catch(error=>{console.error(/^[A-Z0-9_]+$/.test(error.message)?error.message:'VERIFICATION_TOOL_FAILED');process.exitCode=1;});
module.exports={Prepare,Finalize,Binding};
