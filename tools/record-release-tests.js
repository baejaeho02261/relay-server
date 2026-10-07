'use strict';
// Run on the operator / CI machine, not inside the distributed Windows client.
// The tool READS existing artifacts and logs. It never executes untrusted EXEs,
// uploads private keys, infers PASS from a log, or fabricates Windows results.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const hash=x=>crypto.createHash('sha512').update(x).digest('hex');
const plain=x=>!!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
function FileDigest(file,limit) {const st=fs.statSync(file);if(!st.isFile()||st.size>limit)throw Error('EVIDENCE_FILE_INVALID');const b=fs.readFileSync(file);if(b.length!==st.size)throw Error('EVIDENCE_FILE_CHANGED');return hash(b);}
function Template(aFile,bFile,manifestFile,oFile) {
 return {version:1,...(oFile?{oSha512:FileDigest(oFile,128*1024*1024)}:{}),aSha512:FileDigest(aFile,128*1024*1024),bSha512:FileDigest(bFile,128*1024*1024),sourceManifestSha512:FileDigest(manifestFile,8*1024*1024),checks:Object.fromEntries(['nativeBuild','apiProbe','integration'].map(name=>[name,{status:'NOT_RUN',logs:[]}])),note:'Tests not executed. Update only from actual operator or CI results.'};
}
function Record(aFile,bFile,manifestFile,checksFile,oFile) {
 const aSha512=FileDigest(aFile,128*1024*1024),bSha512=FileDigest(bFile,128*1024*1024),sourceManifestSha512=FileDigest(manifestFile,8*1024*1024);
 if(fs.statSync(checksFile).size>65536)throw Error('CHECKS_TOO_LARGE');const checks=JSON.parse(fs.readFileSync(checksFile,'utf8').replace(/^\uFEFF/,''));
 if(!plain(checks)||Object.keys(checks).sort().join(',')!==(oFile?'aSha512,bSha512,checks,note,oSha512,sourceManifestSha512,version':'aSha512,bSha512,checks,note,sourceManifestSha512,version')||checks.version!==1||!plain(checks.checks)||Object.keys(checks.checks).sort().join(',')!=='apiProbe,integration,nativeBuild')throw Error('CHECKS_INVALID');
 const overlay=oFile?{oSha512:FileDigest(oFile,128*1024*1024)}:{};
 if(oFile&&checks.oSha512!==overlay.oSha512)throw Error('CHECKS_ARTIFACT_OR_SOURCE_MISMATCH');
 if(checks.aSha512!==aSha512||checks.bSha512!==bSha512||checks.sourceManifestSha512!==sourceManifestSha512)throw Error('CHECKS_ARTIFACT_OR_SOURCE_MISMATCH');
 if(typeof checks.note!=='string'||!checks.note.trim()||checks.note.length>500||/[\x00-\x1f\x7f]/.test(checks.note))throw Error('CHECKS_NOTE_INVALID');
 const outcomes={},logs=[];
 for(const name of ['nativeBuild','apiProbe','integration']){
   const item=checks.checks[name];if(!plain(item)||Object.keys(item).sort().join(',')!=='logs,status'||!['PASS','FAIL','NOT_RUN'].includes(item.status)||!Array.isArray(item.logs)||item.logs.length>32||item.logs.some(x=>typeof x!=='string'||!x||x.length>4096))throw Error('CHECKS_INVALID');
   if(item.status!=='NOT_RUN'&&!item.logs.length)throw Error('EXECUTED_CHECK_REQUIRES_LOG');
   if(item.status==='NOT_RUN'&&item.logs.length)throw Error('NOT_RUN_MUST_HAVE_NO_EXECUTION_LOG');
   outcomes[name]=item.status;
   for(const [index,file]of item.logs.entries())logs.push({check:name,index,sha512:FileDigest(path.resolve(path.dirname(checksFile),file),32*1024*1024)});
 }
 const report={version:1,...overlay,aSha512,bSha512,sourceManifestSha512,logsSha512:hash(JSON.stringify({version:1,artifacts:{aSha512,bSha512,...overlay,sourceManifestSha512},outcomes,logs})),...outcomes,note:checks.note.trim()};
 return {report,logManifest:{version:1,artifacts:{aSha512,bSha512,...overlay,sourceManifestSha512},outcomes,logs,trust:'OPERATOR_RECORDED_NOT_ATTESTATION'}};
}
if(require.main===module){try{const args=process.argv.slice(2),index=args.indexOf('--overlay');let oFile;if(index>=0){if(index!==args.length-2)throw Error('OVERLAY_ARGUMENT_INVALID');oFile=args[index+1];args.splice(index,2);}if(args[0]==='--template'&&args.length===4){process.stdout.write(JSON.stringify(Template(...args.slice(1),oFile),null,2)+'\n');}else{if(args.length!==4)throw Error('Usage: node tools/record-release-tests.js A.exe B.exe SOURCE_MANIFEST.json checks.json [--overlay O.exe]');const result=Record(...args,oFile);process.stdout.write(JSON.stringify(result.report,null,2)+'\n');process.stderr.write(JSON.stringify(result.logManifest,null,2)+'\n');}}catch(error){console.error(error.code||error.message||'EVIDENCE_FAILED');process.exitCode=1;}}
module.exports={Template,Record,FileDigest};
