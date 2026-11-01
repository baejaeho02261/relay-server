'use strict';
// Public authority metadata only. Private signing material is server environment
// input and is never stored here. An absent ring retains the legacy deployment.
const crypto=require('node:crypto');
const MAX_KEYS=32,KEY=/^[a-f0-9]{64}$/;
const states=['ACTIVE','RETIRING','REVOKED'];
function Fail(code,status=409){const e=Error('ISSUED_A_'+code);e.desktopError=true;e.bootstrapError=true;e.status=status;throw e;}
function Plain(v){return !!v&&Object.getPrototypeOf(v)===Object.prototype;}
function Exact(v,keys){return Plain(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));}
function ValidateState(s){
 if(!Exact(s,['version','revision','nextGeneration','keys'])||s.version!==1||!Number.isSafeInteger(s.revision)||s.revision<1||
    !Number.isSafeInteger(s.nextGeneration)||s.nextGeneration<2||!Plain(s.keys)||Object.keys(s.keys).length<1||Object.keys(s.keys).length>MAX_KEYS)Fail('KEYRING_STORAGE_INVALID',503);
 const generations=new Set();
 for(const[id,r]of Object.entries(s.keys)){
  if(!KEY.test(id)||!Exact(r,['generation','state','createdAt','changedAt','origin'])||!Number.isSafeInteger(r.generation)||r.generation<1||
     r.generation>=s.nextGeneration||generations.has(r.generation)||!states.includes(r.state)||!Number.isSafeInteger(r.createdAt)||r.createdAt<1||
     !Number.isSafeInteger(r.changedAt)||r.changedAt<r.createdAt||!['LEGACY_RECEIPT','CONFIGURED_SIGNER','REGISTERED_PUBLIC_KEY'].includes(r.origin))Fail('KEYRING_STORAGE_INVALID',503);
  generations.add(r.generation);
 }
 if(s.nextGeneration!==Math.max(...generations)+1)Fail('KEYRING_STORAGE_INVALID',503);
 return s;
}
function Store(){return require('./peace.desktop-bootstrap-store');}
function State(db=Store().Load()){return db.issuedAKeyring?ValidateState(db.issuedAKeyring):null;}
function AssertUse(keyId,{sign=false,db}={}){
 if(!KEY.test(keyId||''))Fail('SIGNATURE_INVALID');
 const s=State(db);if(!s)return null;
 const row=s.keys[keyId];if(!row)Fail('SIGNING_KEY_UNKNOWN');
 if(row.state==='REVOKED')Fail('SIGNING_KEY_REVOKED',403);
 if(sign&&row.state!=='ACTIVE')Fail('SIGNING_KEY_RETIRING');
 return row;
}
function AssertLauncher(row,db){if(row?.finalIssuedSignature)AssertUse(row.finalIssuedSignature.keyId,{db});}
function References(db,keyId){
 const issued=new Set(Object.values(db.launchers||{}).filter(r=>r.finalIssuedSignature?.keyId===keyId).map(r=>r.id));
 return {issued:issued.size,unused:Object.values(db.launchers||{}).filter(r=>issued.has(r.id)&&r.status==='AVAILABLE').length,
  liveFlows:Object.values(db.flows||{}).filter(r=>issued.has(r.launcherId)&&!['CLOSED','REVOKED','EXPIRED'].includes(r.status)).length,
  liveOverlays:Object.values(db.overlays||{}).filter(r=>issued.has(db.flows?.[r.parentFlowId]?.launcherId)&&!['CLOSED','REVOKED','EXPIRED'].includes(r.status)).length};
}
function Status(){
 const db=Store().Load(),s=State(db);let configured=[],configurationError='';
 try{configured=require('./peace.issued-a-signing').ConfiguredPublic();}catch(error){configurationError=/^ISSUED_A_[A-Z0-9_]+$/.test(error.message)?error.message:'ISSUED_A_SIGNING_KEY_INVALID';}
 return {version:1,managed:!!s,revision:s?.revision||0,nextGeneration:s?.nextGeneration||1,maxKeys:MAX_KEYS,
  configurationError,configuredKeyIds:configured.map(r=>r.keyId),
  keys:s?Object.entries(s.keys).map(([keyId,r])=>({keyId,...r,privateKeyConfigured:configured.some(c=>c.keyId===keyId),...References(db,keyId)})).sort((a,b)=>a.generation-b.generation):[],
  legacyKeyId:configured.find(r=>r.legacy)?.keyId||'',legacyReceiptKeyIds:[...new Set(Object.values(db.launchers||{}).map(r=>r.finalIssuedSignature?.keyId).filter(x=>KEY.test(x||'')))].sort(),
  privateMaterialIncluded:false,wireFormat:'COZY_A_SIGNED_V1',revocationScope:'SERVER_AUTHORITY_AND_NEW_USE',offlineRevocation:false};
}
function Revision(body,s){if(!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision!==(s?.revision||0))Fail('KEYRING_CONFLICT');}
function Public(value){
 if(!Exact(value,['version','algorithm','keyId','publicBlob'])||value.version!==1||value.algorithm!=='RSA2048-PKCS1-SHA256'||
    !KEY.test(value.keyId||'')||typeof value.publicBlob!=='string'||value.publicBlob.length!==380)Fail('PUBLIC_JSON_INVALID',400);
 const bytes=Buffer.from(value.publicBlob,'base64');
 if(bytes.toString('base64')!==value.publicBlob)Fail('PUBLIC_JSON_INVALID',400);
 const identity=require('./peace.issued-a-signing').IdentityFromBlob(bytes);if(identity.keyId!==value.keyId)Fail('PUBLIC_JSON_INVALID',400);return identity;
}
function Mutate(body,actor='ADMIN'){
 if(!Plain(body)||!['initialize','register','state'].includes(body.action))Fail('KEYRING_INPUT_INVALID',400);
 const fields=body.action==='register'?['action','expectedRevision','publicKey']:body.action==='state'?['action','expectedRevision','keyId','state']:['action','expectedRevision'];
 if(!Exact(body,fields))Fail('KEYRING_INPUT_INVALID',400);
 const store=Store(),before=State();Revision(body,before);
 const signing=require('./peace.issued-a-signing');let identity;
 if(body.action==='initialize'){
  if(before)Fail('KEYRING_ALREADY_MANAGED');
  identity=signing.ConfiguredSigner(); // The current legacy key is explicit.
 }else if(!before)Fail('KEYRING_REQUIRED');
 if(body.action==='register'){
  identity=Public(body.publicKey);if(before.keys[identity.keyId])Fail('KEY_ALREADY_REGISTERED');
  if(Object.keys(before.keys).length>=MAX_KEYS)Fail('KEYRING_CAPACITY');
  const signer=signing.ConfiguredSigner(identity.keyId),challenge=crypto.randomBytes(32);
  try{const proof=crypto.sign('sha256',challenge,{key:signer.privateKey,padding:crypto.constants.RSA_PKCS1_PADDING});
   try{if(!crypto.verify('sha256',challenge,{key:identity.publicKey,padding:crypto.constants.RSA_PKCS1_PADDING},proof))Fail('SIGNING_KEY_MISMATCH');}finally{proof.fill(0);}
  }finally{challenge.fill(0);}
 }
 if(identity)require('../security/peace.desktop-key-purposes').Reserve(identity.publicKey,'ISSUED_LAUNCHER');
 if(body.action==='state'&&(!KEY.test(body.keyId||'')||!['RETIRING','REVOKED'].includes(body.state)))Fail('KEYRING_INPUT_INVALID',400);
 const audit=require('../storage/peace.desktop-operation-audit');
 const result=audit.Run('ISSUED_A_KEYRING_CHANGE',actor,{state:body.action==='state'?body.state:'ACTIVE',...(identity||body.keyId?{subject:identity?.keyId||body.keyId}: {})},db=>{
  let s=State(db);Revision(body,s);const at=Date.now();if(!Number.isSafeInteger(at)||at<1)Fail('KEYRING_CLOCK_INVALID');
  if(body.action==='initialize'){
   if(s)Fail('KEYRING_ALREADY_MANAGED');
   const legacy=[...new Set(Object.values(db.launchers||{}).map(r=>r.finalIssuedSignature?.keyId).filter(x=>KEY.test(x||'')))];
   if(!legacy.includes(identity.keyId))legacy.push(identity.keyId);legacy.sort();if(legacy.length>MAX_KEYS)Fail('KEYRING_CAPACITY');
   s={version:1,revision:1,nextGeneration:legacy.length+1,keys:{}};
   legacy.forEach((id,i)=>{s.keys[id]={generation:i+1,state:id===identity.keyId?'ACTIVE':'RETIRING',createdAt:at,changedAt:at,origin:id===identity.keyId?'CONFIGURED_SIGNER':'LEGACY_RECEIPT'};});db.issuedAKeyring=s;
  }else if(body.action==='register'){
   if(s.keys[identity.keyId])Fail('KEY_ALREADY_REGISTERED');if(Object.keys(s.keys).length>=MAX_KEYS)Fail('KEYRING_CAPACITY');
   s.keys[identity.keyId]={generation:s.nextGeneration++,state:'ACTIVE',createdAt:at,changedAt:at,origin:'REGISTERED_PUBLIC_KEY'};s.revision++;
  }else{
   const row=s.keys[body.keyId];if(!row)Fail('SIGNING_KEY_UNKNOWN');
   if(row.state==='REVOKED')Fail('KEY_REVOKED_IRREVERSIBLE');
   if(row.state===body.state)Fail('KEY_STATE_UNCHANGED');
   if(at<row.changedAt)Fail('KEYRING_CLOCK_INVALID');
   row.state=body.state;row.changedAt=at;s.revision++;
   if(row.state==='REVOKED'){
    const boot=require('./peace.desktop-bootstrap'),launchers=new Set(),liveOverlayParents=new Set(Object.values(db.overlays||{}).filter(r=>!['CLOSED','REVOKED','EXPIRED'].includes(r.status)).map(r=>r.parentFlowId));
    for(const r of Object.values(db.launchers||{}))if(r.finalIssuedSignature?.keyId===body.keyId){launchers.add(r.id);if(r.status==='AVAILABLE'){r.status='REVOKED';r.revokedAt=at;boot.RetireLauncher(r,at);}}
    for(const r of Object.values(db.flows||{}))if(launchers.has(r.launcherId)&&(!['CLOSED','REVOKED','EXPIRED'].includes(r.status)||liveOverlayParents.has(r.id))){r.status='REVOKED';r.revokedAt=at;r.reason='ISSUED_A_SIGNING_KEY_REVOKED';const launcher=db.launchers[r.launcherId];launcher.status='REVOKED';launcher.revokedAt=at;boot.RetireLauncher(launcher,at);boot.RetireFlow(r,db);}
   }
  }
  ValidateState(s);return {revision:s.revision,action:body.action,keyId:identity?.keyId||body.keyId||'',state:body.action==='state'?body.state:'ACTIVE'};
 });
 return {result,status:Status()};
}
module.exports={MAX_KEYS,ValidateState,State,AssertUse,AssertLauncher,Status,Mutate};
