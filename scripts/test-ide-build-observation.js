'use strict';
// Synthetic contract tests only. No Windows compiler or trace is manufactured
// as production evidence; every fixture stays in a disposable temp directory.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const observation=require('../tools/ide-build-observation'),p=require('../services/desktopReleaseProvenance');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'game-ide-observation-fixture-')),native=path.join(root,'native'),bds=path.join(root,'bds'),run=path.join(root,'run');
const hash=observation.hash,put=(f,b)=>{fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,b);},json=(f,v)=>put(f,JSON.stringify(v)+'\n'),get=f=>JSON.parse(fs.readFileSync(f));
const record=f=>({path:f,bytes:fs.statSync(f).size,sha512:hash(fs.readFileSync(f))});
function csv(rows){return ['Process Name','PID','Operation','Path','Result','Detail','Image Path','Command Line'].map(x=>'"'+x+'"').join(',')+'\r\n'+rows.map(r=>r.map(x=>'"'+String(x).replace(/"/g,'""')+'"').join(',')).join('\r\n')+'\r\n';}
function event(pid,operation,file,detail='Offset: 0, Length: 32',name='bds.exe'){return[name,pid,operation,file,'SUCCESS',detail,path.join(bds,'bin',name),'"'+path.join(bds,'bin',name)+'" '+(name==='bds.exe'?'"fixture.dproj"':'')];}
function approve(role,bytes,approvalFile,policyFile,key){const keyId=p.KeyId(key.publicKey),publicKey=key.publicKey.export({type:'spki',format:'pem'}).toString(),sha512=hash(bytes);json(approvalFile,{component:role,version:'1.0.0',sha512,trustedKey:{keyId,publicKey},approval:{keyId,signature:crypto.sign(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,'1.0.0',sha512].join('\n')),key.privateKey).toString('base64')}});json(policyFile,{version:1,revision:1,requireReleaseSignature:true,trustedReleaseKeys:[{keyId,publicKey}],revokedSha512:[]});}
try{
 for(const dir of [native,run,path.join(bds,'bin'),path.join(bds,'include'),path.join(bds,'lib/win64/release')])fs.mkdirSync(dir,{recursive:true});
 for(const [role,name,stage]of [['A','GameLauncher','launcher'],['B','GameConnect','client'],['O','GameOverlay','overlay']]){put(path.join(native,name+'.dpr'),'program '+name+'; begin end.');put(path.join(native,name+'.dproj'),'<Project />');fs.mkdirSync(path.join(native,'build/stage',stage,'Win64/Release'),{recursive:true});}
 put(path.join(native,'Game.Unused.pas'),'unit Game.Unused;');put(path.join(bds,'bin/bds.exe'),'synthetic image identifier, never executed');put(path.join(bds,'lib/win64/release/System.dcu'),'fixture');
 const sessionFile=path.join(run,'session.json'),session={version:1,kind:'IDE_BUILD_OBSERVATION_SESSION',id:'1'.repeat(48),native,bds,inputs:observation.snapshot(native,bds),runtime:record(process.execPath),tool:record(path.resolve(__dirname,'../tools/ide-build-observation.js'))};json(sessionFile,session);
 const properties=role=>({project:path.join(native,{A:'GameLauncher',B:'GameConnect',O:'GameOverlay'}[role]+'.dproj'),configuration:'Release',platform:'Win64',defines:'GAME_APPLICATION_BUILD;RELEASE',references:[]});
 const pe=require('./crc-pe-fixture').crcPeFixture();
 // Missing output is failure even if an external compiler reports exit=0; a
 // stale prebuild EXE is removed only from the exact isolated stage location.
 const aStage=observation.stagePath(session,'A','Release');put(aStage,pe);observation.before(run,'A','Release',properties('A'));assert.equal(fs.existsSync(aStage),false);
 // Generated resources may first appear during prebuild, while source inputs
 // remain immutable. The ready phase binds their exact precompiler hashes.
 put(path.join(native,'GameLauncherResources.res'),'generated resource');observation.ready(run,'A','Release',properties('A'));
 assert.throws(()=>observation.after(run,'A'),/MANUAL_INPUT_MISSING|NATIVE_OUTPUT_MISSING/);assert.equal(fs.existsSync(path.join(run,'A-after.json')),false);
 assert.throws(()=>observation.before(run,'A','Release',properties('A')),/ROLE_ALREADY_USED/);
 put(aStage,Buffer.from('not an EXE'));assert.throws(()=>observation.after(run,'A'),/NATIVE_OUTPUT_NOT_PE64/);
 put(aStage,pe);const after=observation.after(run,'A');assert.equal(after.nativeOutput.sha512,hash(pe));assert.equal(after.independentAttestation,false);
 const b=get(path.join(run,'A-before.json')),r=get(path.join(run,'A-ready.json')),a=get(path.join(run,'A-after.json')),traceFile=path.join(run,'fixture.csv'),pid=1234;
 const rows=[event(r.pid,'ReadFile',r.marker,undefined,'node.exe'),event(pid,'ReadFile',path.join(native,'GameLauncher.dpr')),event(pid,'ReadFile',path.join(bds,'lib/win64/release/System.dcu')),event(pid,'WriteFile',aStage),event(a.pid,'ReadFile',a.marker,undefined,'node.exe')];put(traceFile,csv(rows));
 const trace=observation.corroborate(run,'A',traceFile,pid);assert.equal(trace.mainSourceRead,true);assert.equal(trace.stagedOutputWrite,true);assert.equal(trace.rawTraceAuthenticity,'NOT_ATTESTED');assert.equal(trace.traceCompleteness,'NOT_PROVEN');assert.equal(trace.compilerEnvironment,'NOT_OBSERVED');assert.equal(trace.readOrImageCount,2);assert(!Object.keys(trace.observedInputs).some(x=>x.endsWith('game.unused.pas')));
 for(const [mutate,code]of [r=>r.filter(x=>x[2]!=='WriteFile'),r=>r.filter(x=>!String(x[3]).endsWith('.dpr'))].map(f=>[f,'TRACE_BUILD_IO_NOT_CORROBORATED'])){put(traceFile,csv(mutate(rows)));assert.throws(()=>observation.corroborate(run,'A',traceFile,pid),new RegExp(code));}
 put(traceFile,csv(rows.map((r,i)=>i===1?event(pid,'ReadFile',path.join(root,'unreviewed.pas')):r)));assert.throws(()=>observation.corroborate(run,'A',traceFile,pid),/TRACE_UNSNAPSHOTTED_INPUT/);
 put(traceFile,csv(rows.map((r,i)=>i===1?[...r.slice(0,6),'C:\\evil\\bds.exe',r[7]]:r)));assert.throws(()=>observation.corroborate(run,'A',traceFile,pid),/TRACE_PROCESS_IDENTITY/);
 put(traceFile,csv(rows.map((r,i)=>i===2?[...r.slice(0,7),'different process incarnation']:r)));assert.throws(()=>observation.corroborate(run,'A',traceFile,pid),/TRACE_PID_REUSED/);
 put(traceFile,csv([...rows.slice(0,1),...rows.slice(1,-1).reverse(),rows.at(-1)]));assert.equal(observation.corroborate(run,'A',traceFile,pid).mainSourceRead,true); // Event order is not a fabricated compiler pipeline.
 put(traceFile,csv([...rows].reverse()));assert.throws(()=>observation.corroborate(run,'A',traceFile,pid),/TRACE_MARKERS_MISSING_OR_ORDER/);put(traceFile,csv(rows));
 assert.throws(()=>observation.csv(Buffer.from('"a","b"\n"unterminated')),/TRACE_CSV/);assert.throws(()=>observation.csv(Buffer.from('a,a\n1,2\n')),/TRACE_COLUMNS/);assert.throws(()=>observation.csv(Buffer.from(csv(rows).replace('"Image Path"','"Missing"'))),/TRACE_REQUIRED_COLUMNS/);
 const quoted=csv([event(pid,'ReadFile',path.join(native,'GameLauncher.dpr'),'Length: 32, path: "a,b"\nsecond line')]);assert.equal(observation.csv(Buffer.from(quoted))[0].Detail,'Length: 32, path: "a,b"\nsecond line');assert.equal(observation.csv(Buffer.concat([Buffer.from([255,254]),Buffer.from(quoted,'utf16le')]))[0].PID,String(pid));
 // The final EXE/approval policy are linked to captured bytes, not just to each
 // other. A valid new approval cannot conceal a changed native output.
 const key=crypto.generateKeyPairSync('ed25519'),finalFile=path.join(root,'A-final.exe'),approvalFile=path.join(root,'A.approval.json'),policyFile=path.join(root,'policy.json');put(finalFile,pe);approve('A',pe,approvalFile,policyFile,key);
 const sealed=observation.seal(run,'A',finalFile,approvalFile,policyFile,traceFile,pid);assert.equal(sealed.result.independentProvenance,'NOT_PROVEN');assert.equal(sealed.result.ciEvidence,false);assert.equal(observation.verify(sealed.seal,sealed.sha512,finalFile,approvalFile,policyFile).traceCorroborated,true);
 assert.throws(()=>observation.verify(sealed.seal,'',finalFile,approvalFile,policyFile),/EXTERNAL_DIGEST_REQUIRED/);assert.throws(()=>observation.seal(run,'A',finalFile,approvalFile,policyFile,traceFile,pid),/EEXIST/);
 const saved=fs.readFileSync(sealed.seal);fs.appendFileSync(sealed.seal,' ');assert.throws(()=>observation.verify(sealed.seal,sealed.sha512,finalFile,approvalFile,policyFile),/SEAL_DIGEST_MISMATCH/);put(sealed.seal,saved);
 const retainedTrace=fs.readFileSync(traceFile);fs.appendFileSync(traceFile,'\n');assert.throws(()=>observation.verify(sealed.seal,sealed.sha512,finalFile,approvalFile,policyFile),/SEALED_ARCHIVE_MISMATCH/);put(traceFile,retainedTrace);
 const changed=Buffer.from(pe);changed[600]^=1;put(finalFile,changed);approve('A',changed,approvalFile,policyFile,key);assert.throws(()=>observation.verify(sealed.seal,sealed.sha512,finalFile,approvalFile,policyFile),/SEALED_FILE_MISMATCH/);assert.throws(()=>observation.seal(run,'A',finalFile,approvalFile,policyFile),/FINAL_BYTES_UNLINKED/);put(finalFile,pe);approve('A',pe,approvalFile,policyFile,key);
 // Source mutation between hooks, including newly shadowing candidates, fails.
 observation.before(run,'B','Release',properties('B'));put(path.join(native,'GameConnectResources.res'),'generated resource B');observation.ready(run,'B','Release',properties('B'));put(observation.stagePath(session,'B','Release'),pe);put(path.join(native,'shadow.pas'),'unit shadow;');assert.throws(()=>observation.after(run,'B'),/INPUTS_CHANGED/);fs.unlinkSync(path.join(native,'shadow.pas'));
 put(path.join(native,'GameConnectResources.res'),'changed during compiler');assert.throws(()=>observation.after(run,'B'),/GENERATED_REFERENCES_CHANGED/);put(path.join(native,'GameConnectResources.res'),'generated resource B');
 const newDcu=path.join(native,'build/B/Win64/Release/dcu/Game.New.dcu');put(newDcu,'new generated dcu');observation.after(run,'B');
 const br=get(path.join(run,'B-ready.json')),ba=get(path.join(run,'B-after.json')),bTrace=path.join(run,'b.csv'),bRows=[event(br.pid,'ReadFile',br.marker,undefined,'node.exe'),event(pid,'ReadFile',path.join(native,'GameConnect.dpr')),event(pid,'WriteFile',newDcu),event(pid,'ReadFile',newDcu),event(pid,'WriteFile',observation.stagePath(session,'B','Release')),event(ba.pid,'ReadFile',ba.marker,undefined,'node.exe')];put(bTrace,csv(bRows));
 assert.equal(Object.values(observation.corroborate(run,'B',bTrace,pid).observedInputs).find(x=>x.path===newDcu).inputClass,'GENERATED_DCU_WITH_PRIOR_RECORDED_WRITE');put(bTrace,csv(bRows.filter(x=>!(x[2]==='WriteFile'&&x[3]===newDcu))));assert.throws(()=>observation.corroborate(run,'B',bTrace,pid),/TRACE_DCU_READ_WITHOUT_PRIOR_WRITE/);
 // Clean O trees acquire their exact generated reference set in prebuild.
 observation.before(run,'O','Release',properties('O'));assert.throws(()=>observation.ready(run,'O','Release',properties('O')),/GENERATED_REFERENCE_MISSING/);
 for(const file of ['GameOverlayResources.res','game_imgui_bridge.o','imgui/obj/Win64/game_imgui_bridge.o'])put(path.join(native,file),'generated O reference');
 const oReady=observation.ready(run,'O','Release',properties('O'));assert.equal(Object.keys(oReady.generated.files).length,5);put(observation.stagePath(session,'O','Release'),pe);assert.equal(observation.after(run,'O').role,'O');
 // Strict O relation: exact record sort only, no code/resource changes; a
 // nonzero checksum must be recomputed, not arbitrarily zeroed or forged.
 const original=Buffer.from(pe),first=Buffer.from(original.subarray(1280,1292));original.copy(original,1280,1292,1304);first.copy(original,1292);
 assert.equal(observation.normalizedRelation(original,pe,'O').changed,true);assert.throws(()=>observation.normalizedRelation(original,pe,'B'),/FINAL_BYTES_UNLINKED/);
 const wrong=Buffer.from(pe);wrong[600]^=1;assert.throws(()=>observation.normalizedRelation(original,wrong,'O'),/FINAL_BYTES_UNLINKED/);
 const checksumOriginal=Buffer.from(original),checksumFinal=Buffer.from(pe);checksumOriginal.writeUInt32LE(1,0x80+24+64);assert.throws(()=>observation.normalizedRelation(checksumOriginal,checksumFinal,'O'),/FINAL_BYTES_UNLINKED/);
 const overlap=Buffer.from(original);overlap.writeUInt32LE(0x1000,1280);assert.throws(()=>observation.normalizedRelation(overlap,pe,'O'),/NORMALIZATION_OVERLAP/);
 assert.throws(()=>observation.normalizedRelation(pe,wrong,'O'),/FINAL_BYTES_UNLINKED/);
 // Invalid trust/signature and file aliases never become successful evidence.
 let bad=get(approvalFile);bad.approval.signature=Buffer.alloc(64).toString('base64');json(approvalFile,bad);assert.throws(()=>observation.approved('A',pe,approvalFile,policyFile),/APPROVAL_SIGNATURE/);approve('A',pe,approvalFile,policyFile,key);
 const policy=get(policyFile);policy.revokedSha512=[hash(pe)];json(policyFile,policy);assert.throws(()=>observation.approved('A',pe,approvalFile,policyFile),/APPROVAL_BINDING/);
 const alias=path.join(root,'hardlink.csv');fs.linkSync(traceFile,alias);assert.throws(()=>observation.corroborate(run,'A',traceFile,pid),/MANUAL_INPUT_SIZE_OR_TYPE/);fs.unlinkSync(alias);
 if(process.platform!=='win32')assert.throws(()=>observation.prepare(native,bds,path.join(root,'new-run')),/WINDOWS_NOT_RUN/);
 console.log('PASS: optional IDE observation synthetic contracts; fresh output, changed inputs, real-trace-shaped read/write correlation, strict O byte relation, final approval binding and externally anchored tamper detection. Windows RAD IDE / real ProcMon capture / C# task execution: NOT_RUN. Independent full provenance: NOT_PROVEN.');
}finally{fs.rmSync(root,{recursive:true,force:true});}
