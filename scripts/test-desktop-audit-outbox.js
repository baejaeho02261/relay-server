'use strict';
// Real journal/audit crash boundaries. Every process owns an isolated DATA_DIR.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),cp=require('node:child_process');
const mode=process.argv[2];
if(mode==='seed'||mode==='recover'){
 process.env.HA_ENABLED='0';require('../services/desktopSingleWriter').Acquire(process.env.DATA_DIR);require('../core/utils').EnsureDirs();
 const licenses=require('../services/desktopLicenses'),boot=require('../services/desktopBootstrap'),audit=require('../storage/audit'),journal=require('../services/desktopJournal');
 if(mode==='recover'){
  require('../storage/database').LoadDatabase();audit.LoadRecentAudit();
  const expected=JSON.parse(fs.readFileSync(path.join(process.env.DATA_DIR,'expected.json'),'utf8'));
  licenses.ReconcileOperations();const receipt=Object.values(licenses.DB().receipts).find(row=>row.auditEvent?.id===expected.auditId);assert.ok(receipt);
  const ack=licenses.DB().receipts['AUDIT:'+expected.auditId];assert.ok(ack);assert.equal(ack.auditAckFor,expected.auditId);
  const rows=fs.readdirSync(require('../config/config').AUDIT_DIR).flatMap(name=>fs.readFileSync(path.join(require('../config/config').AUDIT_DIR,name),'utf8').trim().split('\n')).filter(Boolean).map(JSON.parse);
  const matches=rows.filter(row=>{try{return JSON.parse(row.detail).auditEventId===expected.auditId;}catch(_){return false;}});
  assert.equal(matches.length,1,'fsync before ACK crash must not duplicate the event');
  const detail=JSON.parse(matches[0].detail);assert.equal(detail.operationId,expected.operationId);assert.equal(detail.id,expected.licenseId);
  if(expected.flow){const flow=boot.Initialize().flows[expected.flow.id];assert.equal(flow.lastLicenseOperationId,expected.operationId);for(const key of ['status','sessionExpiresAt','lastVerifiedAt','licenseLeaseExpiresAt'])assert.equal(flow[key],expected.flow[key],key+' must not change during audit recovery');}
  assert.equal(audit.VerifyAuditChain().ok,true);const revision=licenses.DB().revision;assert.equal(licenses.ReconcileOperations().auditRecovered,0);assert.equal(licenses.DB().revision,revision);
  if(expected.action==='create'){const result=licenses.Create(expected.body,'TEST');assert.equal(result.license.id,expected.licenseId);assert.equal(crypto.createHash('sha256').update(result.licenseKey).digest('hex'),licenses.DB().licenses[result.license.id].keyHash);}
  console.log('OUTBOX_RECOVERED');process.exit(0);
 }
 const action=process.argv[3],boundary=process.argv[4],body={requestVersion:2,requestId:crypto.randomUUID(),label:'outbox',reason:'test operation'};
 const f=require('./desktop-bootstrap-fixture');let run;
 function Proof(device,action,extra){const requestId=crypto.randomUUID(),payload=f.LicensePayload(device,extra,requestId),payloadJSON=JSON.stringify(payload),payloadHash=crypto.createHash('sha512').update(payloadJSON).digest('hex'),base={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash},c=licenses.Challenge(base);f.ObserveLicense(device,action,requestId,payloadHash,payload);return {...base,challengeId:c.challengeId,payloadJSON,signature:f.Sign(device,c.canonical)};}
 if(action==='create')run=()=>licenses.Create(body,'TEST');
 else {const issued=licenses.Create({requestVersion:2,requestId:crypto.randomUUID()},'TEST');if(action==='revoke')run=()=>licenses.Revoke(issued.license.id,body,'TEST');else if(action==='reissue')run=()=>licenses.Reissue(issued.license.id,body,'TEST');else{const device=f.Device();let proof;if(action==='release'){const activated=licenses.Execute(Proof(device,'redeem',{licenseKey:issued.licenseKey}));proof=Proof(device,'release',{activationToken:activated.activationToken});}else proof=Proof(device,'redeem',{licenseKey:issued.licenseKey});run=()=>licenses.Execute(proof);}}
 boot.Initialize();audit.LoadRecentAudit();const before=new Set(Object.keys(licenses.DB().receipts));
 function Capture(){const receipt=Object.entries(licenses.DB().receipts).find(([key,row])=>!before.has(key)&&row.auditEvent)?.[1];assert.ok(receipt);const row=licenses.DB().licenses[receipt.licenseId],flow=Object.values(boot.Initialize().flows).find(item=>item.sessionId===row.bootstrapSessionId);const expected={action,body,licenseId:row.id,auditId:receipt.auditEvent.id,operationId:receipt.operationId||receipt.auditOperationId,flow:flow?Object.fromEntries(['id','status','sessionExpiresAt','lastVerifiedAt','licenseLeaseExpiresAt'].map(key=>[key,flow[key]])):null};fs.writeFileSync(path.join(process.env.DATA_DIR,'expected.json'),JSON.stringify(expected));return expected;}
 if(boundary==='write-failure'){
  const open=fs.openSync;fs.openSync=function(file,flags,...rest){if(path.basename(String(file)).startsWith('audit-')&&flags==='a'){const error=Error('test unavailable');error.code='ENOSPC';throw error;}return open.call(fs,file,flags,...rest);};
  assert.throws(run,error=>error.message==='STORAGE_SAVE_FAILED');fs.openSync=open;Capture();assert.equal(audit.VerifyAuditChain().ok,true);process.exit(90);
 }
 if(boundary==='partial-append'){
  const write=fs.writeFileSync;fs.writeFileSync=function(file,data,...rest){if(typeof file==='number'&&typeof data==='string'&&data.includes('auditEventId')){fs.writeSync(file,data.slice(0,Math.floor(data.length/2)));Capture();process.exit(93);}return write.call(fs,file,data,...rest);};run();throw Error('PARTIAL_APPEND_NOT_REACHED');
 }
 const commit=journal.Commit;journal.Commit=function(previous,next){const isAck=Object.keys(next.receipts).some(key=>key.startsWith('AUDIT:')&&!previous.receipts[key]);if(isAck&&boundary==='before-ack'){Capture();process.exit(91);}const result=commit(previous,next);if(isAck&&boundary==='after-ack'){Capture();process.exit(92);}return result;};run();throw Error('CRASH_BOUNDARY_NOT_REACHED');
}
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-audit-outbox-'));
try{
 let count=0;
 for(const engine of ['json','sqlite'])for(const action of ['create','redeem','release','revoke','reissue'])for(const boundary of ['write-failure','before-ack','after-ack','partial-append']){
  const data=path.join(temp,engine+'-'+action+'-'+boundary),env={...process.env,DATA_DIR:data,STORAGE_ENGINE:engine,HA_ENABLED:'0'};
  const seed=cp.spawnSync(process.execPath,[__filename,'seed',action,boundary],{env,encoding:'utf8',timeout:20000});assert.equal(seed.status,boundary==='write-failure'?90:boundary==='before-ack'?91:boundary==='after-ack'?92:93,seed.stdout+seed.stderr);
  const recover=cp.spawnSync(process.execPath,[__filename,'recover'],{env,encoding:'utf8',timeout:20000});assert.equal(recover.status,0,recover.stdout+recover.stderr);assert.match(recover.stdout,/OUTBOX_RECOVERED/);count++;
 }
 console.log('AUDIT OUTBOX PASS: '+count+' actual failure/crash/restart paths; create/redeem/release/revoke/reissue, JSON/SQLite, append failure, fsynced event before ACK, committed ACK before mirror, one stable operation across three stores, no lease refresh.');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
