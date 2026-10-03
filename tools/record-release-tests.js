'use strict';
// Run on the operator / CI machine, not inside the distributed Windows client.
// The tool READS existing artifacts and logs. It never executes untrusted EXEs,
// uploads private keys, infers PASS from a log, or fabricates Windows results.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const plain=x=>!!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
function FileDigest(file,limit) {const st=fs.statSync(file);if(!st.isFile()||st.size>limit)throw Error('EVIDENCE_FILE_INVALID');const b=fs.readFileSync(file);if(b.length!==st.size)throw Error('EVIDENCE_FILE_CHANGED');return hash(b);}
function Template(aFile,bFile,manifestFile) {
 return {version:1,aSha256:FileDigest(aFile,128*1024*1024),bSha256:FileDigest(bFile,128*1024*1024),sourceManifestSha256:FileDigest(manifestFile,8*1024*1024),checks:Object.fromEntries(['nativeBuild','apiProbe','integration'].map(name=>[name,{status:'NOT_RUN',logs:[]}])),note:'Tests not executed. Update only from actual operator or CI results.'};
}
function Record(aFile,bFile,manifestFile,checksFile) {
 const aSha256=FileDigest(aFile,128*1024*1024),bSha256=FileDigest(bFile,128*1024*1024),sourceManifestSha256=FileDigest(manifestFile,8*1024*1024);
 if(fs.statSync(checksFile).size>65536)throw Error('CHECKS_TOO_LARGE');const checks=JSON.parse(fs.readFileSync(checksFile,'utf8').replace(/^\uFEFF/,''));
 if(!plain(checks)||Object.keys(checks).sort().join(',')!=='aSha256,bSha256,checks,note,sourceManifestSha256,version'||checks.version!==1||!plain(checks.checks)||Object.keys(checks.checks).sort().join(',')!=='apiProbe,integration,nativeBuild')throw Error('CHECKS_INVALID');
 if(checks.aSha256!==aSha256||checks.bSha256!==bSha256||checks.sourceManifestSha256!==sourceManifestSha256)throw Error('CHECKS_ARTIFACT_OR_SOURCE_MISMATCH');
 if(typeof checks.note!=='string'||!checks.note.trim()||checks.note.length>500||/[\x00-\x1f\x7f]/.test(checks.note))throw Error('CHECKS_NOTE_INVALID');
 const outcomes={},logs=[];
 for(const name of ['nativeBuild','apiProbe','integration']){
   const item=checks.checks[name];if(!plain(item)||Object.keys(item).sort().join(',')!=='logs,status'||!['PASS','FAIL','NOT_RUN'].includes(item.status)||!Array.isArray(item.logs)||item.logs.length>32||item.logs.some(x=>typeof x!=='string'||!x||x.length>4096))throw Error('CHECKS_INVALID');
   if(item.status!=='NOT_RUN'&&!item.logs.length)throw Error('EXECUTED_CHECK_REQUIRES_LOG');
   if(item.status==='NOT_RUN'&&item.logs.length)throw Error('NOT_RUN_MUST_HAVE_NO_EXECUTION_LOG');
   outcomes[name]=item.status;
   for(const [index,file]of item.logs.entries())logs.push({check:name,index,sha256:FileDigest(path.resolve(path.dirname(checksFile),file),32*1024*1024)});
 }
 const report={version:1,aSha256,bSha256,sourceManifestSha256,logsSha256:hash(JSON.stringify({version:1,artifacts:{aSha256,bSha256,sourceManifestSha256},outcomes,logs})),...outcomes,note:checks.note.trim()};
 return {report,logManifest:{version:1,artifacts:{aSha256,bSha256,sourceManifestSha256},outcomes,logs,trust:'OPERATOR_RECORDED_NOT_ATTESTATION'}};
}
if(require.main===module){try{if(process.argv[2]==='--template'&&process.argv.length===6){process.stdout.write(JSON.stringify(Template(...process.argv.slice(3)),null,2)+'\n');}else{if(process.argv.length!==6)throw Error('Usage: node tools/record-release-tests.js A.exe B.exe SOURCE_MANIFEST.json checks.json');const result=Record(...process.argv.slice(2));process.stdout.write(JSON.stringify(result.report,null,2)+'\n');process.stderr.write(JSON.stringify(result.logManifest,null,2)+'\n');}}catch(error){console.error(error.code||error.message||'EVIDENCE_FAILED');process.exitCode=1;}}
module.exports={Template,Record,FileDigest};
