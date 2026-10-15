'use strict';
// Execution-only wrapper. Prompt values remain data and never become a shell command.
const fs=require('node:fs'),path=require('node:path'),readline=require('node:readline/promises'),assert=require('node:assert/strict');
const comparison=require('../scripts/compare-native-crc-pe');
async function run(argv=process.argv.slice(2)){
 const noPause=argv.some(arg=>['/nopause','--nopause'].includes(arg.toLowerCase()));
 const corpusOnly=argv.some(arg=>arg.toLowerCase()==='--corpus-only');
 const args=argv.filter(arg=>!['/nopause','--nopause','--corpus-only'].includes(arg.toLowerCase()));
 // Retain the previous optional first positional probe path.
 if(args.length&&!args[0].startsWith('--'))args.unshift('--probe');
 let terminal,options;
 const ask=async prompt=>{
  assert(process.stdin.isTTY,'CRC_PATH_REQUIRED: supply --probe, --a, --b and --o, or select --corpus-only');
  terminal ||= readline.createInterface({input:process.stdin,output:process.stdout});
  const value=(await terminal.question(prompt)).trim();return value.replace(/^"(.*)"$/,'$1');
 };
 try{
  options=comparison.parseArgs(args);
  options.out ||= path.join(__dirname,'crc-pe-comparison-result.json');
  assert(!options.portable,'Use the comparator directly for --portable-only');
  assert(!(corpusOnly&&Object.keys(options.artifacts).length),'CRC_CORPUS_ARTIFACT_CONFLICT');
  options.probe ||= path.resolve(__dirname,'../../GameConnect_Win64/tests/manual-ide/bin/CrcPeProbe.exe');
  if(!fs.existsSync(options.probe)){
   console.log('Build GameConnect_Win64\\tests\\manual-ide\\CrcPeProbe.dproj in the RAD Studio IDE as Win64 Release.');
   options.probe=await ask('CrcPeProbe.exe absolute path: ');
  }
  if(!corpusOnly)for(const role of comparison.ARTIFACT_ROLES)if(!options.artifacts[role]){
   options.artifacts[role]=await ask('Final '+role+' EXE absolute path: ');
   assert(path.isAbsolute(options.artifacts[role]),'CRC_FINAL_ABSOLUTE_PATH_REQUIRED: '+role);
  }
  const result=comparison.execute(options);
  console.log('Result: '+path.resolve(options.out));
  console.log('Final A/B/O comparison: '+result.finalArtifactComparison);
  if(result.finalArtifactComparison!=='PASS')console.log('Corpus/self-image checks do not complete the final A/B/O comparison.');
  return result;
 }catch(error){
  options ||= comparison.rejectedArguments(args,path.join(__dirname,'crc-pe-comparison-result.json'),path.resolve(__dirname,'../../GameConnect_Win64/tests/manual-ide/bin/CrcPeProbe.exe'));
  if(options?.out)try{comparison.saveReport(options,error.crcReport||{status:'FAIL',error:String(error.message).slice(0,1000),nativeMappedImageComparison:'NOT_RUN',finalArtifactComparison:'NOT_RUN',approvalCreated:false});}catch{}
  console.error(error.message);error.reported=true;throw error;
 }finally{
  if(!noPause&&process.stdin.isTTY){terminal ||= readline.createInterface({input:process.stdin,output:process.stdout});await terminal.question('Press Enter to close...');}
  terminal?.close();
 }
}
if(require.main===module)run().catch(error=>{if(!error.reported)console.error(error.message);process.exitCode=1;});
module.exports={run};
