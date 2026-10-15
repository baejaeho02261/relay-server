'use strict';
const path=require('node:path'),fs=require('node:fs'),{createInterface}=require('node:readline/promises');
const audit=require('./cfg-callsite-audit');
async function Main(){
 let argv=process.argv.slice(2);
 if(!argv.length){
  console.log('Read-only CFG instruction inspection. Select FINAL A/B/O. No rebuild, CI key or server reset.');
  const rl=createInterface({input:process.stdin,output:process.stdout});argv=[];
  try{for(const role of ['A','B','O']){const answer=(await rl.question(role+' full EXE path (Explorer Copy as path is accepted): ')).trim().replace(/^"(.*)"$/s,'$1');if(!answer||!path.isAbsolute(answer))throw Error('CFG_ABSOLUTE_EXE_PATH_REQUIRED');argv.push('--'+role.toLowerCase(),answer);}}
  finally{rl.close();}
  argv.push('--out',path.join(__dirname,'cfg-callsites-'+new Date().toISOString().replace(/[-:.]/g,'')+'-'+require('node:crypto').randomBytes(4).toString('hex')+'.json'));
 }
 const args=audit.Arguments(argv),tool=audit.LocateTool(args['--disassembler']),artifacts={};
 for(const [role,file]of args['--file']?[['FILE',args['--file']]]:[['A',args['--a']],['B',args['--b']],['O',args['--o']]]){
  artifacts[role]=audit.Audit(path.resolve(file),tool);
  console.log(role+': '+artifacts[role].outcome+'; indirect calls '+artifacts[role].counts.indirectCalls+'; unverified transfers '+artifacts[role].counts.unverified);
 }
 const result={version:1,kind:'CFG_FINAL_ARTIFACT_SET',recordedAt:new Date().toISOString(),artifacts,allRuntimeCallsitesVerified:false,windowsEnforcement:'NOT_RUN',ciEvidenceCreated:false,publicationApproval:false};
 fs.writeFileSync(path.resolve(args['--out']),JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
 console.log('Report: '+path.resolve(args['--out']));
 console.log('UNSUPPORTED means the file lacks valid compiler CFG metadata. No PE flags or server requirements were changed.');
 return Object.values(artifacts).some(x=>x.outcome!=='STATIC_SCAN_COMPLETE')?2:0;
}
if(require.main===module)Main().then(code=>{process.exitCode=code;}).catch(e=>{console.error(/^[A-Z0-9_]+$/.test(e.message)?e.message:'CFG_AUDIT_FAILED');process.exitCode=1;});
