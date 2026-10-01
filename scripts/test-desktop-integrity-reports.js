'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-integrity-reports-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';
require('../core/utils').EnsureDirs();const reports=require('../services/desktopIntegrityReports'),bootstrap=require('../services/desktopBootstrap'),f=require('./desktop-bootstrap-fixture'),integrity=require('../services/desktopIntegrity');
function rejected(code,fn){assert.throws(fn,error=>error.message===code,code);}
function context(){const device=f.Device(),session=f.Session(device);return {device,session,auth:{sessionId:session.sessionId,sessionToken:session.sessionToken,...f.Evidence(device,session)}};}
function signed(ctx,payload){const challenge=reports.Execute({action:'challenge',...ctx.auth}),text=JSON.stringify(payload);return {action:'submit',...ctx.auth,reportId:challenge.reportId,payload:text,signature:f.Sign(ctx.device,reports.Canonical(ctx.auth.sessionId,challenge,text))};}
function own(session){return {version:1,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha256:session.release.codeSha256,codeCrc64:session.release.codeCrc64}};}
function modulePayload(module){return {version:1,check:'MODULE_INVENTORY',reason:'PERIODIC',snapshotId:crypto.randomUUID(),batchIndex:0,batchCount:1,complete:true,truncated:false,totalModules:1,measuredModules:1,modules:[module]};}
function restart(source){return cp.spawnSync(process.execPath,['-e',source],{cwd:__dirname,env:process.env,encoding:'utf8'});}
try{
 const current=context(),good=signed(current,own(current.session));assert.equal(reports.Execute(good).status,'VERIFIED');rejected('INTEGRITY_REPORT_CHALLENGE_INVALID',()=>reports.Execute(good));
 const forged=signed(current,own(current.session));forged.payload=forged.payload.replace(current.session.release.codeSha256,'0'.repeat(64));rejected('INTEGRITY_REPORT_SIGNATURE_INVALID',()=>reports.Execute(forged));
 const badAuth={...current.auth,sessionToken:'x'.repeat(43)};rejected('BOOTSTRAP_SESSION_INVALID',()=>reports.Execute({action:'challenge',...badAuth}));
 const stale=signed(current,own(current.session)),date=Date.now;Date.now=()=>date()+31000;try{rejected('INTEGRITY_REPORT_CHALLENGE_INVALID',()=>reports.Execute(stale));}finally{Date.now=date;}
 const module={name:'ntdll.dll',status:'UNVERIFIED_BASELINE',codeStatus:'MATCH_LOCAL_FILE',fileSha256:'ab'.repeat(32),fileCrc64:'A1'.repeat(8),codeSha256:'cd'.repeat(32),codeCrc64:'B2'.repeat(8)};
 const unknown=reports.Execute(signed(current,modulePayload(module)));assert.equal(unknown.status,'CLIENT_DIAGNOSTIC');let item=reports.List({sessionId:current.session.sessionId}).items[0];assert.equal(item.modules[0].serverComparison,'UNVERIFIED_BASELINE');assert.equal(item.attested,false);
 rejected('INTEGRITY_REPORT_INVALID',()=>reports.Payload(JSON.stringify(modulePayload({...module,name:'C:\\Windows\\ntdll.dll'}))));rejected('INTEGRITY_REPORT_INVALID',()=>reports.Payload(JSON.stringify({...modulePayload(module),modules:Array(17).fill(module)})));rejected('INTEGRITY_REPORT_INVALID',()=>reports.Payload(' '.repeat(10241)));
 // A uses only its signed flow capability, without obtaining a B session.
 const a=f.Device(),began=f.Begin(a),aCtx={device:a,auth:{stage:'A',sessionId:began.begin.flowId,sessionToken:began.begin.downloadTicket,machineId:a.machineId}};
 assert.equal(reports.Execute(signed(aCtx,modulePayload(module))).status,'CLIENT_DIAGNOSTIC');assert.equal(reports.List().items[0].stage,'A');
 const aFailure=reports.Execute(signed(aCtx,{version:1,check:'OWN_IMAGE',reason:'MEASUREMENT_FAILED',own:{status:'READ_ERROR'}}));assert.equal(aFailure.terminate,true);assert.equal(bootstrap.Overview().sessions.find(x=>x.flowId===began.begin.flowId).status,'REVOKED');
 // Trusted baseline publication rejects EXE masquerading as DLL and paths.
 const dll=f.PE('B','known DLL'),pe=dll.readUInt32LE(0x3c);rejected('INTEGRITY_BASELINE_INVALID',()=>reports.RegisterBaseline('ntdll.dll','Windows fixture',dll,'ADMIN'));dll.writeUInt16LE(dll.readUInt16LE(pe+22)|0x2000,pe+22);
 rejected('INTEGRITY_BASELINE_INVALID',()=>reports.RegisterBaseline('../ntdll.dll','',dll,'ADMIN'));const baseline=reports.RegisterBaseline('ntdll.dll','Windows fixture',dll,'ADMIN');assert.equal(reports.RegisterBaseline('ntdll.dll','retry',dll,'ADMIN').id,baseline.id);
 const known={...module,fileSha256:baseline.fileSha256,fileCrc64:baseline.fileCrc64,codeSha256:baseline.codeSha256,codeCrc64:baseline.codeCrc64};assert.equal(reports.Execute(signed(current,modulePayload(known))).status,'CLIENT_DIAGNOSTIC');assert.equal(reports.List({sessionId:current.session.sessionId}).items[0].modules[0].serverComparison,'MATCH_REGISTERED_BASELINE');
 const fail=context(),mismatch=reports.Execute(signed(fail,{...own(fail.session),own:{status:'MEASURED',codeSha256:'0'.repeat(64),codeCrc64:'0'.repeat(16)}}));assert.equal(mismatch.status,'REJECTED');assert.equal(mismatch.terminate,true);assert.equal(bootstrap.Overview().sessions.find(x=>x.id===fail.session.sessionId).codeIntegrityStatus,'REJECTED');assert.equal(bootstrap.Overview().sessions.find(x=>x.id===fail.session.sessionId).status,'REVOKED');
 const badModule=context(),moduleMismatch=reports.Execute(signed(badModule,modulePayload({...known,codeSha256:'0'.repeat(64)})));assert.equal(moduleMismatch.terminate,true);assert.equal(bootstrap.Overview().sessions.find(x=>x.id===badModule.session.sessionId).status,'REVOKED');
 // Even failure to persist diagnostics cannot suppress authorization revocation.
 const diskFailure=context(),badProof=signed(diskFailure,{version:1,check:'OWN_IMAGE',reason:'MEASUREMENT_FAILED',own:{status:'READ_ERROR'}}),rename=fs.renameSync;
 fs.renameSync=(from,to)=>{if(to===reports.FILE)throw Error('TEST_REPORT_DISK_FULL');return rename(from,to);};try{assert.throws(()=>reports.Execute(badProof),/TEST_REPORT_DISK_FULL/);}finally{fs.renameSync=rename;}
 assert.equal(bootstrap.Overview().sessions.find(x=>x.id===diskFailure.session.sessionId).status,'REVOKED');
 // Authenticated inventory is bounded per context, with no token/paths persisted.
 const rate=context();for(let i=0;i<128;i++)reports.Execute({action:'challenge',...rate.auth});rejected('INTEGRITY_REPORT_RATE_LIMIT',()=>reports.Execute({action:'challenge',...rate.auth}));
 const storage=fs.readFileSync(reports.FILE);assert.ok(!storage.includes(Buffer.from(current.session.sessionToken)));assert.ok(!storage.includes(Buffer.from('C:\\Windows')));
 let loaded=restart("const r=require('../services/desktopIntegrityReports');if(r.Baselines().items.length!==1||!r.List().items.some(x=>x.status==='REJECTED'))throw Error('MISSING_REPORTS')");assert.equal(loaded.status,0,loaded.stderr);
 const envelope=JSON.parse(storage);envelope.data.baselines[0].codeSha256='0'.repeat(64);fs.writeFileSync(reports.FILE,JSON.stringify(envelope));loaded=restart("require('../services/desktopIntegrityReports').List()");assert.notEqual(loaded.status,0);assert.match(loaded.stderr,/INTEGRITY_REPORT_STORAGE_INVALID/);fs.writeFileSync(reports.FILE,storage);
 fs.unlinkSync(reports.FILE);loaded=restart("require('../services/desktopIntegrityReports').List()");assert.notEqual(loaded.status,0);assert.match(loaded.stderr,/INTEGRITY_REPORT_STORAGE_INVALID/);
 console.log('INTEGRITY REPORTS PASS: A/B authenticated signed nonce reports, replay/expiry/forgery refusal, bounded basename-only inventory, unknown DLL never trusted, admin DLL hash baselines, code mismatch session revocation even on report-store failure, rate limits, persistent tamper/deletion refusal.');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
