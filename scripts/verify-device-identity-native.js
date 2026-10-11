'use strict';
// Real Windows CNG/PCP/TBS probe driver. Reads trust supplied by the operator;
// never adds roots or relabels software/synthetic verification as hardware.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),{spawn}=require('node:child_process'),readline=require('node:readline');
const tpm=require('../services/desktopTpmAttestation');
const exe=path.resolve(process.argv[2]||''),trustFile=process.argv[3],namespace='f00dface'+crypto.randomBytes(28).toString('hex');
if(process.platform!=='win32')throw Error('WINDOWS_REQUIRED');if(!fs.statSync(exe).isFile())throw Error('PROBE_EXE_REQUIRED');
async function run(platform,keepForReopen,expectedPublic){
 const nonce=crypto.randomBytes(32),child=spawn(exe,[],{stdio:['pipe','pipe','inherit'],windowsHide:true}),lines=readline.createInterface({input:child.stdout,crlfDelay:Infinity})[Symbol.asyncIterator](),timer=setTimeout(()=>child.kill(),120000);let secret;
 const send=o=>child.stdin.write(JSON.stringify(o)+'\n');
 const next=async()=>{const r=await lines.next();if(r.done)throw Error('PROBE_RESPONSE_MISSING');const value=JSON.parse(r.value);if(value.error)throw Error(value.error);return value;};
 try{send({namespace,platform,nonce:nonce.toString('base64')});const first=await next(),pub=require('../services/desktopLicenses').ParseKey(first.publicKey).key;
 assert.equal(first.privateExportBlocked,true);if(expectedPublic)assert.equal(first.publicKey,expectedPublic);
 assert(crypto.verify('sha256',Buffer.from('GAME-DEVICE-NATIVE-PROBE-V1\n'+nonce.toString('base64')),pub,Buffer.from(first.signature,'base64')));
 if(platform){if(!trustFile)throw Error('MANUFACTURER_TRUST_JSON_REQUIRED');const trust=JSON.parse(fs.readFileSync(path.resolve(trustFile),'utf8')),v=tpm.VerifyCertify(first.evidence,nonce,first.publicKey,trust);secret=crypto.randomBytes(32);send({activationBlob:tpm.MakeCredential(v.ekPublic,v.akName,secret).toString('base64')});const activated=await next();assert(tpm.Equal(Buffer.from(activated.secret,'base64'),secret));assert(crypto.verify('sha256',Buffer.from('GAME-DEVICE-NATIVE-ACTIVATE-V1\n'+activated.secret),pub,Buffer.from(activated.signature,'base64')));}
 send({keepForReopen});const end=await next();assert.equal(end.closed,true);assert.equal(end.deleted,!keepForReopen);child.stdin.end();return first.publicKey;
 }finally{secret?.fill(0);nonce.fill(0);clearTimeout(timer);child.kill();}
}
(async()=>{const first=await run(false,true);await run(false,false,first);console.log('PASS: real CNG persisted key reopened across processes; private export rejected; test key deleted.');if(trustFile){await run(true,false);console.log('PASS: real PCP/TBS TPM 2.0 certify, manufacturer EK chain and ActivateCredential verified; test key deleted.');}else console.log('TPM NOT_RUN: supply current manufacturer-trust.json to exercise real hardware attestation.');})().catch(e=>{console.error(e.message);process.exitCode=1;});
