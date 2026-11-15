'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Keep real exit status/logs for EVERY suite; environment blockers are not PASS.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawnSync}=require('node:child_process');
const root=path.resolve(MODULE_RESOURCE_ROOT,'..'),out=path.resolve(process.argv[2]||path.join(root,'maintenance','server-verification','regression'));
fs.mkdirSync(out,{recursive:true});const data=fs.mkdtempSync(path.join(os.tmpdir(),'game-collect-regression-'));const rows=[];
try{
 for(const [i,args]of require("./peace.regression.js").entries()){
  const suiteData=fs.mkdtempSync(path.join(data,'suite-'));
  const name=args.join(' '),started=new Date().toISOString(),p=spawnSync(process.execPath,[path.join(MODULE_RESOURCE_ROOT,args[0]),...args.slice(1)],{cwd:root,encoding:'utf8',timeout:120000,maxBuffer:16*1024*1024,env:{...process.env,DATA_DIR:suiteData,HA_ENABLED:'0',DESKTOP_RECOVERY_WITNESS_DIR:'',DESKTOP_RECOVERY_WITNESS_REQUIRED:'0'}});
  fs.rmSync(suiteData,{recursive:true,force:true});
  const log=(p.stdout||'')+(p.stderr||'')+(p.error?'\n'+p.error.stack:'');
  const file=String(i+1).padStart(3,'0')+'-'+args[0].replace(/\.js$/,'').replace(/[\\/]/g,'-')+(args.length>1?'-'+args.slice(1).join('-').replace(/[^A-Za-z0-9_-]/g,''):'')+'.log';fs.writeFileSync(path.join(out,file),log);
  const missing=/Cannot find module|MODULE_NOT_FOUND|Could not locate the bindings file/.test(log),status=p.status===0&&!p.error?'PASS':missing?'BLOCKED_DEPENDENCY':log.includes('DESKTOP_WRITER_LOCK_UNAVAILABLE')?'BLOCKED_NATIVE_LOCK':p.error?.code==='ETIMEDOUT'?'TIMEOUT':'FAIL';
  rows.push({name,status,exitCode:p.status,signal:p.signal||null,started,finished:new Date().toISOString(),log:file,error:p.error?.message||''});console.log(status+' '+name);
 }
}finally{fs.rmSync(data,{recursive:true,force:true});}
const summary={generatedAt:new Date().toISOString(),node:process.version,platform:process.platform,architecture:process.arch,requiredEngine:require("../../package.json").engines.node,windowsBuildExecuted:false,counts:Object.fromEntries(['PASS','BLOCKED_DEPENDENCY','BLOCKED_NATIVE_LOCK','TIMEOUT','FAIL'].map(x=>[x,rows.filter(r=>r.status===x).length])),suites:rows};
fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary.counts));process.exitCode=rows.every(x=>x.status==='PASS')?0:1;
