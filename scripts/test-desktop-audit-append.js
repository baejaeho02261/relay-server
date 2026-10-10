'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-audit-append-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();const audit=require('../storage/audit'),state=require('../core/state');
try{
 audit.LoadRecentAudit();assert.equal(audit.LogEvent('TEST_SEED','seed',{durable:true}).ok,true);const before={...state.production.auditChain},events=state.events.length,file=audit.AuditFileForTime(Date.now()),original=fs.readFileSync(file),write=fs.writeFileSync;
 fs.writeFileSync=function(fd,data,...rest){if(typeof fd==='number'&&typeof data==='string'&&data.includes('TEST_PARTIAL')){fs.writeSync(fd,data.slice(0,20));const error=Error('partial append');error.code='ENOSPC';throw error;}return write.call(fs,fd,data,...rest);};
 try{assert.equal(audit.LogEvent('TEST_PARTIAL','must be rolled back',{durable:true}).ok,false);}finally{fs.writeFileSync=write;}
 assert.deepEqual(fs.readFileSync(file),original);assert.equal(state.production.auditChain.head,before.head);assert.equal(state.production.auditChain.count,before.count);assert.equal(state.events.length,events);
 if(process.platform!=='win32'){const sync=fs.fsyncSync;fs.fsyncSync=function(fd){if(fs.fstatSync(fd).isDirectory())throw Object.assign(Error('directory unavailable'),{code:'EIO'});return sync(fd);};try{assert.equal(audit.LogEvent('TEST_DIRECTORY','must not ACK',{durable:true}).ok,false);}finally{fs.fsyncSync=sync;}assert.deepEqual(fs.readFileSync(file),original);assert.equal(state.production.auditChain.count,before.count);}
 const id=crypto.randomBytes(32).toString('hex'),detail={operationId:crypto.randomBytes(32).toString('hex'),id:'PUBLIC_ID'},out=audit.AppendOperationEvent(id,'TEST_OPERATION',detail);assert.equal(out.ok,true);const next=audit.AppendOperationEvent(id,'TEST_OPERATION',detail);assert.equal(next.duplicate,true);assert.equal(next.sequence,out.sequence);assert.throws(()=>audit.AppendOperationEvent(id,'TEST_OPERATION',{...detail,id:'OTHER'}),/AUDIT_OPERATION_CONFLICT/);
 assert.equal(audit.VerifyAuditChain().ok,true);assert.equal(audit.AppendOperationEvent(id,'TEST_OPERATION',detail).duplicate,true);
 const good=fs.readFileSync(file);fs.appendFileSync(file,'{"partial":');audit.LoadRecentAudit();assert.deepEqual(fs.readFileSync(file),good);assert.equal(audit.VerifyAuditChain().ok,true);
 fs.appendFileSync(file,'{"complete":"corrupt"}\n');const corrupt=fs.readFileSync(file);audit.LoadRecentAudit();
 // Legacy rows without chain metadata remain readable. A chained row with bad
 // metadata must fail closed and cannot satisfy an operation ACK.
 fs.appendFileSync(file,JSON.stringify({time:Date.now(),type:'BAD',detail:'',sequence:999,previousHash:'0'.repeat(64),hash:'0'.repeat(64)})+'\n');const bad=fs.readFileSync(file);assert.equal(audit.VerifyAuditChain().ok,false);assert.deepEqual(fs.readFileSync(file),bad);assert.throws(()=>audit.AppendOperationEvent(crypto.randomBytes(32).toString('hex'),'NEW',{}),/AUDIT_CHAIN_UNAVAILABLE/);assert.ok(corrupt.length>good.length);
 console.log('AUDIT APPEND PASS: partial-write rollback preserves RAM/disk chain, exact dedupe, conflicting ID rejection, verified restart index, torn-last-append recovery and complete corrupted-chain refusal.');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
