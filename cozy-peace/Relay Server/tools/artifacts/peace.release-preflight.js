'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Runs trusted repository tests, never supplied EXEs. Does not compile native
// products, contact production, grant licenses, mint QA PASS or use private keys.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const root=path.resolve(MODULE_RESOURCE_ROOT,'../..'),web=path.join(root,'Relay Server');
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
const STEPS=Object.freeze([
 ['package-files',"../../tools/package-check/verify-package.js",'STATIC_SOURCE'],
 ['web-ui',"tests/web/peace.check-web-ui.js",'STATIC_SOURCE'],
 ['native-project',"tests/network/peace.check-connect-project.js",'STATIC_SOURCE'],
 ['release-safety',"tests/artifacts/peace.test-next-release-safety.js",'ISOLATED_SERVER_TEST'],
 ['protected-dispatch',"tests/authentication/peace.test-protected-dispatch-binding.js",'ISOLATED_SERVER_TEST'],
 ['protected-operations',"tests/authentication/peace.test-protected-operation-security.js",'ISOLATED_SERVER_TEST'],
 ['snapshot-tools',"tests/artifacts/peace.test-release-snapshot-tools.js",'LOCAL_FILE_TEST'],
 ['release-safety-http',"tests/artifacts/peace.test-release-safety-http.js",'ISOLATED_HTTP_TEST'],
 ['auth-choice',"tests/authentication/peace.test-admin-auth-choice.js",'ISOLATED_HTTP_TEST'],
 ['action-binding',"tests/authentication/peace.test-action-bound-approval.js",'ISOLATED_SERVER_TEST'],
 ['action-http',"tests/authentication/peace.test-action-approval-http.js",'ISOLATED_HTTP_TEST'],
 ['action-ui',"tests/authentication/peace.test-action-approval-ui.js",'SCRIPTED_UI_TEST'],
 ['server-boundaries',"tests/runtime/peace.test-server-boundaries.js",'MTLS_ISOLATION_TEST'],
 ['remote-witness',"tests/recovery/peace.test-remote-witness.js",'MTLS_DURABLE_WITNESS_TEST'],
 ['parser-fuzz',"tests/security/peace.test-parser-fuzz-automation.js",'PURE_PARSER_CHILD_PROCESS_TEST'],
 ['resource-budgets',"tests/security/peace.test-security-resource-isolation.js",'BOUNDED_WORKER_FILE_TEST'],
 ['detection-response',"tests/security/peace.test-security-detection.js",'RULE_ENGINE_TEST'],
 ['release-exposure',"tests/artifacts/peace.test-release-exposure.js",'FINAL_ARTIFACT_SCAN_TEST'],
 ['security-center-ui',"tests/security/peace.test-security-center-ui.js",'SCRIPTED_UI_TEST'],
 ['security-center-http',"tests/security/peace.test-security-center-http.js",'ISOLATED_HTTP_REAL_WORKER_TEST'],
 ['tls-file-flush',"tests/network/peace.test-connect-tls-flush.js",'ISOLATED_TLS_FILE_FLUSH_TEST'],
 ['real-sqlite-deadlines',"tests/runtime/peace.test-desktop-deadlines.js",'SQLITE_INTEGRATION']
]);
function Supported(v=process.versions.node){return v===require("../../package.json").engines.node;}
function Environment(){const env={};for(const k of ['PATH','Path','SystemRoot','SYSTEMROOT','WINDIR','COMSPEC','ComSpec','PATHEXT','TEMP','TMP','TMPDIR','USERPROFILE','HOME','APPDATA','LOCALAPPDATA','LANG','LC_ALL','NUMBER_OF_PROCESSORS'])if(process.env[k])env[k]=process.env[k];env.NODE_ENV='test';return env;}
function Run(destination){const dir=path.resolve(destination);fs.mkdirSync(dir,{recursive:false,mode:0o700});const startedAt=Date.now(),results=[];console.log('Preflight tests only; real Windows A/B/O execution is NOT performed.');
 for(const [id,file,scope]of STEPS){const at=Date.now();console.log('Running '+id);const r=cp.spawnSync(process.execPath,[path.resolve(web,file)],{cwd:web,env:Environment(),encoding:'utf8',timeout:300000,maxBuffer:32*1024*1024,windowsHide:true,shell:false});const text=(r.stdout||'')+'\n'+(r.stderr||'')+(r.error?'\n'+r.error.code:'');const log=Buffer.from(text),logFile=id+'.log';fs.writeFileSync(path.join(dir,logFile),log,{flag:'wx',mode:0o600});results.push({id,scope,outcome:r.status===0&&!r.error?'PASS':'FAIL',exitCode:r.status,errorCode:r.error?.code||'',elapsedMs:Date.now()-at,evidenceSha512:hash(log),file:logFile});}
 const supportedRuntime=Supported()&&process.arch==='x64',outcome=results.some(x=>x.outcome==='FAIL')?'FAIL':supportedRuntime?'PASS':'UNSUPPORTED_RUNTIME';const report={version:1,kind:'RELEASE_PREFLIGHT_ONLY',startedAt,finishedAt:Date.now(),runtime:process.version,architecture:process.arch,platform:process.platform,supportedRuntime,outcome,sourceManifestSha512:hash(fs.readFileSync(path.join(web,'maintenance/source-manifest.json'))),windowsProductExecuted:false,publicationApproved:false,privateKeysPassed:false,checks:results};fs.writeFileSync(path.join(dir,'preflight-result.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});return report;}
if(require.main===module){try{if(process.argv.length!==3)throw Error("Usage: node tools/artifacts/peace.release-preflight.js NEW_EVIDENCE_DIRECTORY");const r=Run(process.argv[2]);console.log(JSON.stringify(r,null,2));if(r.outcome!=='PASS')process.exitCode=1;}catch(e){console.error(e.message);process.exitCode=1;}}
module.exports={Run,Supported,STEPS,Environment};
