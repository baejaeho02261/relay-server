'use strict';
// Exercise the signed report boundary with real A/B/O capabilities. Synthetic
// legacy baselines below model artifacts published before the coverage guard.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-integrity-reasons-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';
process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../core/utils').EnsureDirs();
const fixture=require('./desktop-bootstrap-fixture'),bootstrap=require('../services/desktopBootstrap'),store=require('../services/desktopBootstrapStore');
const reports=require('../services/desktopIntegrityReports'),integrity=require('../services/desktopIntegrity'),crc=require('../services/crcLayers');
const authority=require('../services/desktopSecurityAuthority'),licenses=require('../services/desktopLicenses');
let checks=0;
function check(label,fn){fn();checks++;console.log('PASS '+label);}
function makeContext(stage){
 const device=fixture.Device(),began=fixture.Begin(device),flow=bootstrap.Initialize().flows[began.begin.flowId];
 if(stage==='A')return {stage,device,bytes:began.bytes,artifactId:bootstrap.Initialize().launchers[flow.launcherId].artifactId,sessionId:flow.sessionId,flowId:flow.id,auth:{stage,sessionId:flow.id,sessionToken:began.begin.downloadTicket,machineId:device.machineId}};
 const bytes=fixture.Download(began.begin),session=fixture.Claim(device,began.begin,fixture.Finish(device,began.begin));
 if(stage==='B')return {stage,device,bytes,artifactId:session.release.id,sessionId:session.sessionId,flowId:flow.id,auth:{stage,sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId}};
 const common={...fixture.Evidence(device,session),bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken,appVersion:'88.0.0'};
 function proof(action,payload){const body={action,requestId:crypto.randomUUID(),deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:fixture.sha512(JSON.stringify(payload))},challenge=licenses.Challenge(body);fixture.ObserveLicense(device,action,body.requestId,body.payloadHash,payload);return licenses.Execute({...body,challengeId:challenge.challengeId,payloadJSON:JSON.stringify(payload),signature:fixture.Sign(device,challenge.canonical)});}
 const issued=licenses.Create({requestId:crypto.randomUUID(),label:'integrity report coverage'},'TEST');
 const activation=proof('redeem',{...common,licenseKey:issued.licenseKey,deviceName:'Report test'});
 const prepared=proof('overlay',{...common,activationToken:activation.activationToken}),chunks=[];
 for(let offset=0;offset<prepared.release.size;offset+=prepared.chunkSize)chunks.push(Buffer.from(bootstrap.Execute({action:'overlayChunk',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,offset}).data,'base64'));
 const finished=bootstrap.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(device,prepared.finishCanonical)});
 const claimed=bootstrap.Execute({action:'overlayClaim',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(device,finished.claimCanonical),binarySha512:prepared.release.sha512,crc64:prepared.release.crc64,oCodeSha512:prepared.release.codeSha512,oCodeCrc64:prepared.release.codeCrc64});
 return {stage,device,bytes:Buffer.concat(chunks),artifactId:claimed.release.id,sessionId:claimed.sessionId,overlayId:prepared.overlayId,parentSessionId:session.sessionId,auth:{stage,sessionId:claimed.sessionId,sessionToken:claimed.sessionToken,machineId:device.machineId}};
}
function ownPayload(ctx){const file=integrity.Digests(ctx.bytes),code=integrity.CodeImage(ctx.bytes);return {version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:code.sha512,codeCrc64:code.crc64,fileXxh3_128:file.xxh3_128,fileBlake3:file.blake3,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3},crcLayers:code.crcLayers};}
function signed(ctx,payload){const challenge=reports.Execute({...ctx.auth,action:'challenge'}),text=JSON.stringify(payload);return {...ctx.auth,action:'submit',reportId:challenge.reportId,payload:text,signature:fixture.Sign(ctx.device,reports.Canonical(ctx.auth.sessionId,challenge,text))};}
function state(ctx){const db=bootstrap.Initialize();return ctx.stage==='O'?db.overlays[ctx.overlayId]:db.flows[ctx.flowId];}
function record(ctx){return reports.List({sessionId:ctx.sessionId}).items.find(item=>item.check==='OWN_CODE');}
function expectRejected(ctx,payload,reason,flags={file:true,code:true}){
 const reply=reports.Execute(signed(ctx,payload));assert.equal(reply.status,'REJECTED');assert.equal(reply.terminate,true);
 const row=record(ctx);assert.equal(row.reason,reason);assert.equal(row.status,'REJECTED');assert.equal(row.fileExtendedVerified,flags.file);assert.equal(row.codeExtendedVerified,flags.code);assert.equal(row.extendedHashesVerified,flags.file&&flags.code);
 assert.equal(state(ctx).status,'REVOKED');assert.equal(state(ctx).reason,'INTEGRITY_'+reason);
 assert.equal(state(ctx).sessionNonce,undefined);assert.equal(state(ctx).downloadNonce,undefined);
 return row;
}
function incomplete(layers){const next=structuredClone(layers),table=crc.tableBytes('ecma182');next.nvme={algorithm:next.nvme.algorithm,role:'ecma-lookup-table',status:'partial',digest:crc.crcHex('nvme',table),bytes:table.length,reason:'CHECKER_RANGES_REQUIRED'};for(const role of ['jones','iso'])next[role]={algorithm:next[role].algorithm,role:next[role].role,status:'unavailable',reason:'CHECKER_RANGES_REQUIRED'};return next;}
function withLegacyBaseline(ctx,fn){
 const partial=incomplete(bootstrap.Initialize().artifacts[ctx.artifactId].crcLayers),authenticate=bootstrap.AuthenticateIntegrityReport;
 // New upload/runtime guards reject partial artifacts before this boundary.
 // Authenticate the real capability first, then model historical baseline
 // evidence without disabling those guards or altering persisted artifacts.
 bootstrap.AuthenticateIntegrityReport=body=>{const row=authenticate(body);return body.sessionId===ctx.auth.sessionId&&body.stage===ctx.stage?{...row,integrityArtifact:{...row.integrityArtifact,crcLayers:partial}}:row;};
 try{return fn(partial);}finally{bootstrap.AuthenticateIntegrityReport=authenticate;}
}
function different(hex){return (hex[0]==='0'?'1':'0')+hex.slice(1);}
try{
 for(const stage of ['A','B','O'])bootstrap.Publish(stage,'88.0.0',fixture.PE(stage));
 for(const stage of ['A','B','O'])check(stage+': matching hashes remain verified while missing checker coverage rejects execution',()=>{
  const ctx=makeContext(stage),payload=ownPayload(ctx);
  if(stage==='A'){const artifact=bootstrap.Initialize().artifacts[ctx.artifactId];assert.notEqual(integrity.Digests(ctx.bytes).sha512,artifact.sha512);assert.equal(payload.own.codeSha512,artifact.codeSha512);}
  assert.equal(reports.Execute(signed(ctx,payload)).status,'VERIFIED');
  withLegacyBaseline(ctx,partial=>{payload.crcLayers=partial;const row=expectRejected(ctx,payload,'CRC_COVERAGE_INCOMPLETE');assert.equal(row.crcComparison.matched,true);assert.equal(row.crcComparison.complete,false);});
  if(stage==='O')assert.equal(Object.values(bootstrap.Initialize().flows).find(row=>row.sessionId===ctx.parentSessionId).status,'CLAIMED');
 });
 check('Code SHA512/CRC64 mismatch keeps its existing failure code',()=>{
  for(const field of ['codeSha512','codeCrc64']){const ctx=makeContext('A'),payload=ownPayload(ctx);payload.own[field]=different(payload.own[field]);expectRejected(ctx,payload,'CODE_HASH_MISMATCH');}
 });
 check('File and code extended mismatches retain independent pair results',()=>{
  for(const [field,reason,flags]of [['fileXxh3_128','FILE_EXTENDED_HASH_MISMATCH',{file:false,code:true}],['fileBlake3','FILE_EXTENDED_HASH_MISMATCH',{file:false,code:true}],['codeXxh3_128','CODE_EXTENDED_HASH_MISMATCH',{file:true,code:false}],['codeBlake3','CODE_EXTENDED_HASH_MISMATCH',{file:true,code:false}]]){const ctx=makeContext('A'),payload=ownPayload(ctx);payload.own[field]=different(payload.own[field]);expectRejected(ctx,payload,reason,flags);}
 });
 check('CRC tampering is reported as CRC_ROLE_MISMATCH',()=>{const ctx=makeContext('A'),payload=ownPayload(ctx);payload.crcLayers.ecma182.digest=different(payload.crcLayers.ecma182.digest);const row=expectRejected(ctx,payload,'CRC_ROLE_MISMATCH');assert.equal(row.crcComparison.signals.find(signal=>signal.role==='ecma182').status,'MISMATCH');});
 check('Incomplete coverage cannot hide a separate code hash mismatch',()=>{const ctx=makeContext('A'),payload=ownPayload(ctx);withLegacyBaseline(ctx,partial=>{payload.crcLayers=partial;payload.own.codeSha512=different(payload.own.codeSha512);expectRejected(ctx,payload,'CODE_HASH_MISMATCH');});});
 check('Missing comparison baseline has a distinct reason',()=>{
  const ctx=makeContext('A'),payload=ownPayload(ctx),authenticate=bootstrap.AuthenticateIntegrityReport;
  // The authentication and signature remain real; emulate unavailable legacy
  // baseline evidence at the report boundary without corrupting the store.
  bootstrap.AuthenticateIntegrityReport=body=>{const row=authenticate(body);return {...row,integrityArtifact:{...row.integrityArtifact,crcLayers:undefined}};};
  try{expectRejected(ctx,payload,'CRC_BASELINE_UNAVAILABLE');}finally{bootstrap.AuthenticateIntegrityReport=authenticate;}
 });
 check('Malformed CRC measurements remain rejected by schema validation',()=>{const ctx=makeContext('A'),payload=ownPayload(ctx);delete payload.crcLayers;assert.throws(()=>reports.Execute(signed(ctx,payload)),/INTEGRITY_REPORT_INVALID/);assert.equal(state(ctx).status,'STARTED');});
 check('READ_ERROR preserves the authority hold and legacy measurement failure paths',()=>{
  const ctx=makeContext('A'),payload={version:1,hashVersion:3,check:'OWN_IMAGE',reason:'MEASUREMENT_FAILED',own:{status:'READ_ERROR'}};
  const reply=reports.Execute(signed(ctx,payload));assert.equal(reply.status,'CLIENT_DIAGNOSTIC');assert.equal(reply.terminate,false);assert.equal(record(ctx).reason,'MEASUREMENT_UNAVAILABLE');assert.equal(state(ctx).status,'STARTED');
  const uses=authority.UsesAuthority;authority.UsesAuthority=()=>false;
  try{expectRejected(ctx,payload,'MEASUREMENT_FAILED',{file:false,code:false});}finally{authority.UsesAuthority=uses;}
 });
 check('A coverage rejection is durably revoked before report storage failure',()=>{
  const ctx=makeContext('A'),payload=ownPayload(ctx);
  withLegacyBaseline(ctx,partial=>{
   payload.crcLayers=partial;const request=signed(ctx,payload),rename=fs.renameSync;
   fs.renameSync=(from,to)=>{if(to===reports.FILE)throw Error('TEST_REPORT_DISK_FULL');return rename(from,to);};
   try{assert.throws(()=>reports.Execute(request),/TEST_REPORT_DISK_FULL/);}finally{fs.renameSync=rename;}
   assert.equal(state(ctx).status,'REVOKED');assert.equal(state(ctx).reason,'INTEGRITY_CRC_COVERAGE_INCOMPLETE');
   const persisted=JSON.parse(fs.readFileSync(path.join(store.DIR,'authority.json'),'utf8'));assert.equal(persisted.flows[ctx.flowId].status,'REVOKED');assert.equal(persisted.flows[ctx.flowId].reason,'INTEGRITY_CRC_COVERAGE_INCOMPLETE');
  });
 });
 console.log(`Integrity rejection reasons: ${checks} checks passed`);
}finally{fs.rmSync(temp,{recursive:true,force:true});}
