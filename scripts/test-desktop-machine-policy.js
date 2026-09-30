'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-machine-policy-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';
require('../core/utils').EnsureDirs();const d=require('../services/desktopLicenses'),policy=require('../services/desktopMachinePolicy'),f=require('./desktop-bootstrap-fixture'),bootstrap=require('../services/desktopBootstrap');
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
function proof(device,action,payload,override={},requestId=crypto.randomUUID()){
 const bound={...f.LicensePayload(device,payload,requestId),...override},payloadJSON=JSON.stringify(bound),base={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:hash(payloadJSON)},c=d.Challenge(base);
 return {...base,challengeId:c.challengeId,payloadJSON,signature:f.Sign(device,c.canonical)};
}
function call(device,action,payload,override,requestId){return d.Execute(proof(device,action,payload,override,requestId));}
function reject(code,fn){assert.throws(fn,e=>e.message===code,code);}
function mutation(reason){return {reason,requestId:crypto.randomUUID()};}
function restart(source,env={}){return cp.spawnSync(process.execPath,['-e',source],{cwd:path.join(__dirname,'..'),env:{...process.env,...env},encoding:'utf8'});}
async function main(){
 const a=f.Device(),b=f.Device();b.machineId=a.machineId;assert.notEqual(a.deviceId,b.deviceId);const key=d.Create({label:'PC binding'},'ADMIN:test');
 for(const changed of [{machineId:'A'.repeat(64)},{binarySha256:'0'.repeat(64)},{binaryCrc64:'0'.repeat(16)}])reject('BOOTSTRAP_HASH_MISMATCH',()=>call(a,'redeem',{licenseKey:key.licenseKey},changed));
 assert.equal(d.DB().licenses[key.license.id].consumed,false,'Untrusted binary evidence cannot consume a key');
 const signed=proof(a,'redeem',{licenseKey:key.licenseKey}),result=d.Execute(signed);assert.equal(result.status,'USED');
 assert.equal(d.Detail(key.license.id).license.machineId,a.machineId);assert.match(d.Detail(key.license.id).license.binaryCrc64,/^[A-F0-9]{16}$/);
 const retry=proof(a,'verify',{activationToken:result.activationToken});assert.equal(d.Execute(retry).status,'USED');
 const generation=policy.Generation(a.machineId),body=mutation('Administrator blocks this PC');const blocked=policy.Set(a.machineId,true,body,'ADMIN:test');assert.equal(blocked.machine.generation,generation+1);assert.equal(policy.Set(a.machineId,true,body,'ADMIN:test').machine.generation,generation+1,'Retry must not increment epoch again');
 reject('DESKTOP_REQUEST_REUSED',()=>policy.Set(a.machineId,false,body,'ADMIN:test'));
 reject('DESKTOP_MACHINE_BLOCKED',()=>d.Execute(signed));reject('DESKTOP_MACHINE_BLOCKED',()=>d.Execute(retry));
 reject('DESKTOP_MACHINE_BLOCKED',()=>f.Begin(b));assert.equal(d.Detail(key.license.id).license.machineBlocked,true);
 const restarted=restart(`const p=require(require('node:path').resolve('services/desktopMachinePolicy'));try{p.AssertAllowed('${a.machineId}');process.exit(3);}catch(e){if(e.message!=='DESKTOP_MACHINE_BLOCKED')throw e;}console.log('PERSISTENT_BLOCK_OK');`);assert.equal(restarted.status,0,restarted.stderr);assert.match(restarted.stdout,/PERSISTENT_BLOCK_OK/);
 policy.Set(a.machineId,false,mutation('Administrator explicitly allows PC'),'ADMIN:test');assert.equal(policy.Public(a.machineId).blocked,false);
 reject('DESKTOP_MACHINE_SESSION_REVOKED',()=>d.Execute(signed));reject('DESKTOP_MACHINE_SESSION_REVOKED',()=>d.Execute(retry));
 reject('DESKTOP_KEY_USED',()=>call(b,'redeem',{licenseKey:key.licenseKey}));
 const fresh=d.Create({label:'New session after explicit unblock'},'ADMIN:test');assert.equal(call(b,'redeem',{licenseKey:fresh.licenseKey}).status,'USED');
 const session=JSON.parse(signed.payloadJSON);reject('DESKTOP_MACHINE_SESSION_REVOKED',()=>bootstrap.Gate(session.bootstrapSessionId,session.bootstrapSessionToken,a.deviceId,{machineId:a.machineId,binarySha256:session.binarySha256,binaryCrc64:session.binaryCrc64}));
 const c=f.Device(),concurrent=d.Create({label:'Concurrent one-use'},'ADMIN:test'),signed1=proof(c,'redeem',{licenseKey:concurrent.licenseKey}),signed2=proof(c,'redeem',{licenseKey:concurrent.licenseKey});
 const outcomes=await Promise.allSettled([Promise.resolve().then(()=>d.Execute(signed1)),Promise.resolve().then(()=>d.Execute(signed2))]);assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);assert.equal(outcomes.find(x=>x.status==='rejected').reason.message,'DESKTOP_KEY_USED');
 const bytes=fs.readFileSync(policy.FILE),lines=bytes.toString('utf8').trim().split('\n'),last=JSON.parse(lines.at(-1));last.body.blocked=true;lines[lines.length-1]=JSON.stringify(last);fs.writeFileSync(policy.FILE,lines.join('\n')+'\n');let tamper=restart("require(require('node:path').resolve('services/desktopMachinePolicy')).Load()");assert.notEqual(tamper.status,0);assert.match(tamper.stderr,/DESKTOP_MACHINE_POLICY_CORRUPT/);fs.writeFileSync(policy.FILE,bytes);
 fs.unlinkSync(policy.FILE);tamper=restart("require(require('node:path').resolve('services/desktopMachinePolicy')).Load()");assert.notEqual(tamper.status,0);assert.match(tamper.stderr,/DESKTOP_MACHINE_POLICY_CORRUPT/);fs.writeFileSync(policy.FILE,bytes);
 fs.writeFileSync(policy.FILE,bytes.subarray(0,bytes.indexOf(10)+1));tamper=restart("require(require('node:path').resolve('services/desktopMachinePolicy')).Load()");assert.notEqual(tamper.status,0);assert.match(tamper.stderr,/DESKTOP_MACHINE_POLICY_CORRUPT/);fs.writeFileSync(policy.FILE,bytes);
 const headFile=policy.FILE+'.head',headBytes=fs.readFileSync(headFile),headRecord=JSON.parse(headBytes),secret=fs.readFileSync(policy.KEY),signHead=body=>({body,mac:crypto.createHmac('sha256',secret).update('DESKTOP_MACHINE_POLICY-HEAD-V1\n'+JSON.stringify(body)).digest('hex')});
 // Simulate a crash after the checkpoint prepare but before the next append.
 fs.writeFileSync(headFile,JSON.stringify(signHead({...headRecord.body,pending:{seq:headRecord.body.current.seq+1,hash:'a'.repeat(64)}})));tamper=restart("require(require('node:path').resolve('services/desktopMachinePolicy')).Load()");assert.equal(tamper.status,0,tamper.stderr);assert.deepEqual(JSON.parse(fs.readFileSync(headFile)),headRecord);
 // Simulate a crash after the append fsync but before settling its checkpoint.
 const policyEntries=bytes.toString('utf8').trim().split('\n').map(JSON.parse),previous=policyEntries.at(-2);fs.writeFileSync(headFile,JSON.stringify(signHead({version:1,current:{seq:previous.seq,hash:previous.mac},pending:headRecord.body.current})));tamper=restart("require(require('node:path').resolve('services/desktopMachinePolicy')).Load()");assert.equal(tamper.status,0,tamper.stderr);assert.deepEqual(JSON.parse(fs.readFileSync(headFile)),headRecord);
 fs.unlinkSync(headFile);tamper=restart("require(require('node:path').resolve('services/desktopMachinePolicy')).Load()");assert.notEqual(tamper.status,0);assert.match(tamper.stderr,/DESKTOP_MACHINE_POLICY_CORRUPT/);fs.writeFileSync(headFile,headBytes);
 const journal=require('../services/desktopJournal'),journalBytes=fs.readFileSync(journal.FILE),journalRows=journalBytes.toString('utf8').trim().split('\n').map(JSON.parse);let prev='0'.repeat(64);for(const row of journalRows){if(row.body.licenses[0])row.body.licenses[0].label='tampered';row.prev=prev;row.hash=hash(String(row.seq)+'|'+row.prev+'|'+JSON.stringify(row.body));prev=row.hash;}fs.writeFileSync(journal.FILE,journalRows.map(JSON.stringify).join('\n')+'\n');tamper=restart("require(require('node:path').resolve('services/desktopJournal')).Load()");assert.notEqual(tamper.status,0);assert.match(tamper.stderr,/DESKTOP_JOURNAL_CORRUPT/);fs.writeFileSync(journal.FILE,journalBytes.subarray(0,journalBytes.indexOf(10)+1));tamper=restart("require(require('node:path').resolve('services/desktopJournal')).Load()");assert.notEqual(tamper.status,0);assert.match(tamper.stderr,/DESKTOP_JOURNAL_CORRUPT/);fs.writeFileSync(journal.FILE,journalBytes);
 console.log('MACHINE POLICY PASS: signed machine/binary evidence, first-use atomic consumption, blocked fresh keys, persistent HMAC policy, exact-receipt denial, explicit unblock with old-session revocation, new-session use, HMAC journal corruption refusal.');
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>fs.rmSync(temp,{recursive:true,force:true}));
