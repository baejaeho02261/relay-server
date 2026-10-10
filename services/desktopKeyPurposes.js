'use strict';
// Immutable purpose reservations, identified by the same canonical SPKI hash
// for every algorithm. Contains public fingerprints only, never key material.
// A failed later enrollment may leave a reservation; it grants no authority.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const config=require('../config/config');
const FILE=path.join(config.DATA_DIR,'desktop-key-purposes.json');
const MARKER=path.join(config.DATA_DIR,'desktop-key-purposes.initialized');
const PURPOSES=['RELEASE_APPROVAL','CI_ATTESTATION','SERVER_TRANSPORT','SERVER_TLS'];
let poisoned=false;
function Fail(code){const e=Error(code);e.desktopError=true;e.status=409;throw e;}
function Fingerprint(publicKey){let key;try{key=publicKey?.type==='public'?publicKey:crypto.createPublicKey(publicKey);}catch(_){Fail('SECURITY_KEY_PURPOSE_INVALID');}return crypto.createHash('sha512').update(key.export({type:'spki',format:'der'})).digest('hex');}
function Sync(){if(process.platform==='win32')return;const fd=fs.openSync(config.DATA_DIR,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Validate(value){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!=='entries,revision,version'||value.version!==1||!Number.isSafeInteger(value.revision)||value.revision<0||!value.entries||Object.getPrototypeOf(value.entries)!==Object.prototype||Object.keys(value.entries).length>2048)Fail('SECURITY_KEY_PURPOSE_STORAGE_INVALID');for(const[id,r]of Object.entries(value.entries)){if(!/^[a-f0-9]{128}$/.test(id)||!r||Object.keys(r).sort().join(',')!=='firstSeenAt,purpose'||!PURPOSES.includes(r.purpose)||!Number.isSafeInteger(r.firstSeenAt)||r.firstSeenAt<1)Fail('SECURITY_KEY_PURPOSE_STORAGE_INVALID');}return value;}
// Reads never claim ownership or mutate storage. Reservations are append-only;
// an existing matching identity is safe to inspect in a diagnostic process.
function Read(){if(poisoned)Fail('SECURITY_KEY_PURPOSE_RESTART_REQUIRED');let current;if(!fs.existsSync(FILE)){if(fs.existsSync(MARKER))Fail('SECURITY_KEY_PURPOSE_STORAGE_MISSING');return {version:1,revision:0,entries:{}};}const st=fs.lstatSync(FILE);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size>1024*1024)Fail('SECURITY_KEY_PURPOSE_STORAGE_INVALID');try{current=Validate(JSON.parse(fs.readFileSync(FILE,'utf8')));}catch(_){Fail('SECURITY_KEY_PURPOSE_STORAGE_INVALID');}if(fs.existsSync(MARKER)){const mark=fs.lstatSync(MARKER);if(!mark.isFile()||mark.isSymbolicLink()||mark.nlink!==1||fs.readFileSync(MARKER,'utf8')!=='GAME-KEY-PURPOSES-V1\n')Fail('SECURITY_KEY_PURPOSE_STORAGE_INVALID');}else if(current.revision>0)Fail('SECURITY_KEY_PURPOSE_STORAGE_MISSING');return current;}
function Assert(publicKey,purpose){if(!PURPOSES.includes(purpose))Fail('SECURITY_KEY_PURPOSE_INVALID');const id=Fingerprint(publicKey),existing=Read().entries[id];if(existing&&existing.purpose!==purpose)Fail('SECURITY_KEY_PURPOSE_CONFLICT');return id;}
function Reserve(publicKey,purpose){if(!PURPOSES.includes(purpose))Fail('SECURITY_KEY_PURPOSE_INVALID');const id=Fingerprint(publicKey),observed=Read().entries[id];if(observed){if(observed.purpose!==purpose)Fail('SECURITY_KEY_PURPOSE_CONFLICT');return id;}
// Acquire before a new reservation and re-read: a different owner may have
// appended a conflicting purpose since the first, read-only inspection.
require('./desktopSingleWriter').Acquire(config.DATA_DIR,{haEnabled:config.HA_ENABLED});
const before=Read(),existing=before.entries[id];if(existing){if(existing.purpose!==purpose)Fail('SECURITY_KEY_PURPOSE_CONFLICT');return id;}const next=structuredClone(before);next.entries[id]={purpose,firstSeenAt:Date.now()};next.revision++;Validate(next);const temp=FILE+'.'+crypto.randomBytes(12).toString('hex')+'.pending';let fd,renamed=false;try{fd=fs.openSync(temp,'wx',0o600);fs.writeFileSync(fd,JSON.stringify(next)+'\n');fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;if(!fs.existsSync(MARKER)){const mark=fs.openSync(MARKER,'wx',0o600);try{fs.writeFileSync(mark,'GAME-KEY-PURPOSES-V1\n');fs.fsyncSync(mark);}finally{fs.closeSync(mark);}Sync();}fs.renameSync(temp,FILE);renamed=true;Sync();return id;}catch(_){poisoned=true;Fail(renamed?'SECURITY_KEY_PURPOSE_RESTART_REQUIRED':'SECURITY_KEY_PURPOSE_SAVE_FAILED');}finally{if(fd!==undefined)fs.closeSync(fd);fs.rmSync(temp,{force:true});}}
function Summary(){const s=Read();return{version:1,revision:s.revision,counts:Object.fromEntries(PURPOSES.map(p=>[p,Object.values(s.entries).filter(r=>r.purpose===p).length])),storage:'PUBLIC_FINGERPRINTS_ONLY',immutable:true};}
module.exports={Assert,Reserve,Fingerprint,Summary,FILE,MARKER};
