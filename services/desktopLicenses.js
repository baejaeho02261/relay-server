'use strict';
// Desktop authorization is separate from archived CLIENT/QR/biometric records.
const crypto=require('node:crypto'),state=require('../core/state'),machinePolicy=require('./desktopMachinePolicy');
const CHALLENGE_MS=120000,LEASE_MS=120000;
const challenges=new Map(),seen=new Map(),verifyReceipts=new Map();
let authorityLoaded=false;
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
const now=()=>Date.now();
const messages={DESKTOP_SINGLE_USE_ONLY:'라이선스는 기간제 없이 1회용으로만 발급할 수 있습니다.',INPUT_INVALID:'입력 내용을 확인해 주세요.',HTTPS_REQUIRED:'HTTPS 서버 주소를 사용해 주세요.',DESKTOP_BROWSER_FORBIDDEN:'Windows 앱에서 다시 요청해 주세요.',DESKTOP_KEY_INVALID:'라이선스 키를 확인해 주세요.',DESKTOP_KEY_USED:'이미 사용한 라이선스 키입니다.',DESKTOP_REVOKED:'관리자가 이 라이선스를 해지했습니다.',DESKTOP_RELEASED:'연결 해제된 라이선스입니다. 새 키가 필요합니다.',DESKTOP_EXPIRED:'라이선스가 만료되었습니다.',DESKTOP_DEVICE_MISMATCH:'라이선스가 연결된 Windows 기기에서 실행해 주세요.',DESKTOP_ACTIVATION_INVALID:'인증 정보를 확인할 수 없습니다. 라이선스를 다시 확인해 주세요.',DESKTOP_PROOF_INVALID:'기기 서명을 확인하지 못했습니다.',DESKTOP_CHALLENGE_EXPIRED:'인증 요청이 만료되었습니다. 다시 시도해 주세요.',DESKTOP_REQUEST_REUSED:'요청 번호가 다른 작업에 사용되었습니다.',DESKTOP_RATE_LIMIT:'요청이 많습니다. 잠시 후 다시 시도해 주세요.',DESKTOP_CAPACITY:'인증 요청이 많습니다. 잠시 후 다시 시도해 주세요.',SERVICE_DISABLED:'서비스가 일시 중지되었습니다.',STORAGE_SAVE_FAILED:'저장하지 못했습니다. 같은 요청으로 다시 시도해 주세요.'};
Object.assign(messages,require('./desktopBootstrap').messages,{DESKTOP_MACHINE_INVALID:'PC 식별 정보를 확인하지 못했습니다.',DESKTOP_MACHINE_BLOCKED:'관리자가 이 PC의 사용을 차단했습니다.',DESKTOP_MACHINE_SESSION_REVOKED:'PC 정책 변경으로 이전 연결이 종료되었습니다. 새 프로그램으로 시작해 주세요.',DESKTOP_BINARY_INVALID:'등록된 실행 파일과 일치하지 않습니다.'});
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Empty(){return {schema:1,revision:0,signingSecret:'',licenses:{},receipts:{}};}
function DB(){if(!authorityLoaded)Import(undefined);return state.desktopLicenses||(state.desktopLicenses=Empty());}
function Plain(value){return !!value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;}
function Import(value){
 const journal=require('./desktopJournal').Load();
 if(journal.exists)value=journal.state;
 else if(value&&Object.keys(value.licenses||{}).length)throw Error('DESKTOP_JOURNAL_MISSING');
 if(value===undefined||value===null){state.desktopLicenses=Empty();authorityLoaded=true;return;}
 if(!Plain(value)||value.schema!==1||!Number.isSafeInteger(value.revision)||value.revision<0||!Plain(value.licenses)||!Plain(value.receipts)||typeof value.signingSecret!=='string'||value.signingSecret&&!/^[a-f0-9]{64}$/.test(value.signingSecret))throw Error('DESKTOP_STORAGE_INVALID');
 for(const [id,row]of Object.entries(value.licenses)){
  if(!/^(?:DL-)?[A-F0-9]{24}$/.test(id)||!Plain(row)||row.id!==id||!['AVAILABLE','ACTIVE','USED','REVOKED','RELEASED'].includes(row.status)||!/^[a-f0-9]{64}$/.test(row.keyHash)||typeof row.consumed!=='boolean'||!Number.isSafeInteger(row.expiresAt)||row.expiresAt<0)throw Error('DESKTOP_STORAGE_INVALID');
  if(row.keyVersion!==undefined&&row.keyVersion!==2||row.activationVersion!==undefined&&row.activationVersion!==2||row.status==='USED'&&!row.consumed||row.status==='AVAILABLE'&&row.consumed||!/^[a-f0-9]{48}$/.test(row.issuanceNonce))throw Error('DESKTOP_STORAGE_INVALID');
  if(row.machineId!==undefined&&(!/^[A-F0-9]{64}$/.test(row.machineId)||!/^[a-f0-9]{64}$/.test(row.binarySha256||'')||!/^[A-F0-9]{16}$/.test(row.binaryCrc64||'')||!Number.isSafeInteger(row.machinePolicyGeneration)||row.machinePolicyGeneration<0))throw Error('DESKTOP_STORAGE_INVALID');
  if(row.bootstrapSessionId!==undefined&&!/^(?:DS-)?[A-F0-9]{24}$/.test(row.bootstrapSessionId))throw Error('DESKTOP_STORAGE_INVALID');
  if(row.consumed&&(!/^[A-F0-9]{64}$/.test(row.deviceId)||!row.publicKey||!/^[a-f0-9]{64}$/.test(row.tokenHash)||!/^[a-f0-9]{48}$/.test(row.activationNonce)))throw Error('DESKTOP_STORAGE_INVALID');
 }
 if(Object.keys(value.licenses).length&&!value.signingSecret)throw Error('DESKTOP_STORAGE_INVALID');
 state.desktopLicenses=structuredClone(value);authorityLoaded=true;challenges.clear();seen.clear();verifyReceipts.clear();
}
function Available(){if(!state.serviceEnabled||state.maintenanceMode||!require('./haCoordinator').CanAcceptTraffic())Fail('SERVICE_DISABLED',503);}
function Atomic(fn){
 if(!require('./haCoordinator').CanAcceptTraffic())Fail('SERVICE_DISABLED',503);const previous=structuredClone(DB());
 let committed=false;
 try{const result=fn();DB().revision++;require('./desktopJournal').Commit(previous,DB());committed=true;
  // The journal has committed. A failed JSON/SQLite mirror must never roll a
  // consumed key back to AVAILABLE; the next start recovers from the journal.
  if(!require('../storage/database').SaveDatabase())console.error('DESKTOP_MIRROR_SAVE_FAILED: durable journal commit retained');return result;}
 catch(error){if(!committed)state.desktopLicenses=previous;if(error.desktopError)throw error;Fail('STORAGE_SAVE_FAILED',503);}
}
function Status(row){if(row.status==='REVOKED')return row.status;if(row.expiresAt&&row.expiresAt<=now())return 'EXPIRED';return row.consumed?'USED':'AVAILABLE';}
function Public(row){const current=seen.get(row.id),durable=require('./desktopBootstrap').LicenseActivity(row.id),machine=row.machineId?machinePolicy.Public(row.machineId):null,machineSessionRevoked=!!machine&&(machine.blocked||row.machinePolicyGeneration!==machine.generation),active=Status(row)==='USED'&&!row.releasedAt&&row.status!=='RELEASED'&&!machineSessionRevoked;return {id:row.id,displayId:row.id.replace(/^DL-/,''),label:row.label,status:Status(row),issuedAt:row.issuedAt,activatedAt:row.activatedAt||0,expiresAt:row.expiresAt,consumed:row.consumed,deviceId:row.deviceId||'',deviceName:row.deviceName||'',machineId:row.machineId||'',machineBlocked:!!machine?.blocked,machinePolicy:machine,machineSessionRevoked,binarySha256:row.binarySha256||'',binaryCrc64:row.binaryCrc64||'',appVersion:current?.appVersion||durable?.appVersion||row.appVersion||'',lastVerifiedAt:Math.max(current?.at||0,durable?.lastVerifiedAt||0,row.activatedAt||0),leaseExpiresAt:active?Math.max(current?.leaseExpiresAt||0,durable?.leaseExpiresAt||0):0,bootstrapSessionId:row.bootstrapSessionId||durable?.sessionId||'',revokedAt:row.revokedAt||0,releasedAt:row.releasedAt||0,reason:row.reason||''};}
function Text(value,max,required=false){if(typeof value!=='string'||value.length>max||/[\u0000-\u001f\u007f]/.test(value)||required&&!value.trim())Fail('INPUT_INVALID');return value.trim();}
function Expiry(body){
 // Purchase duration is not an authorization lease. FIX81 issues only a single
 // use; old journal deadlines remain authoritative and are never rewritten.
 if(body.expiresAt!==undefined&&body.expiresAt!==0||body.validDays!==undefined&&body.validDays!==0)Fail('DESKTOP_SINGLE_USE_ONLY');
 return 0;
}
// Historical domains are byte constants solely for reading pre-rename journal
// credentials. Their hashes and consumed state are never rewritten or revived.
const legacyKeyPrefix=Buffer.from('4d4f41','hex').toString('ascii');
const legacyKeyDomain=Buffer.from('4d4f41504c41592d4445534b544f502d4b45592d56317c','hex').toString('ascii');
const legacyActivationDomain=Buffer.from('4d4f41504c41592d4445534b544f502d41435449564154494f4e2d56317c','hex').toString('ascii');
function NormalizeKey(value){
 if(typeof value!=='string'||value.length>100)Fail('DESKTOP_KEY_INVALID');
 const key=value.trim().toUpperCase();if(/^[A-F0-9]{64}$/.test(key))return key;
 if(new RegExp('^'+legacyKeyPrefix+'(?:-[A-F0-9]{8}){8}$').test(key))return key.slice(legacyKeyPrefix.length+1).replace(/-/g,'');
 Fail('DESKTOP_KEY_INVALID');
}
function LegacyFormattedKey(raw){return legacyKeyPrefix+'-'+raw.match(/.{8}/g).join('-');}
function KeyHashes(value){const key=NormalizeKey(value);return [hash(key),hash(LegacyFormattedKey(key))];}
function StoredKey(row){
 const digest=crypto.createHmac('sha256',Buffer.from(DB().signingSecret,'hex')).update((row.keyVersion===2?'GAME-DESKTOP-KEY-V2|':legacyKeyDomain)+row.id+'|'+row.issuanceNonce).digest('hex').toUpperCase();
 return row.keyVersion===2?digest:LegacyFormattedKey(digest);
}
function IssuedKey(row){const key=StoredKey(row);if(hash(key)!==row.keyHash)Fail('DESKTOP_KEY_INVALID',409);return NormalizeKey(key);}
function NewRow(body,actor){
 const label=Text(body.label||'',120),expiresAt=Expiry(body),id=crypto.randomBytes(12).toString('hex').toUpperCase();
 DB().signingSecret||=crypto.randomBytes(32).toString('hex');
 const row={id,label,keyVersion:2,issuanceNonce:crypto.randomBytes(24).toString('hex'),status:'AVAILABLE',consumed:false,issuedAt:now(),issuedBy:String(actor||'ADMIN').slice(0,120),expiresAt},key=StoredKey(row);row.keyHash=hash(key);DB().licenses[id]=row;
 return {licenseKey:key,license:Public(row)};
}
function Detail(id){const row=DB().licenses[id];if(!row)Fail('DESKTOP_KEY_INVALID',404);return {license:Public(row),licenseKey:IssuedKey(row)};}
function AdminReceipt(action,id,body,actor,fn){
 if(!Plain(body))Fail('INPUT_INVALID');
 if(body.requestId===undefined)return Atomic(fn);
 if(!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId))Fail('INPUT_INVALID');
 const key='ADMIN:'+hash(String(actor))+':'+body.requestId,fingerprint=hash(JSON.stringify({action,id,body})),old=DB().receipts[key];
 if(old){if(old.fingerprint!==fingerprint)Fail('DESKTOP_REQUEST_REUSED',409);const row=DB().licenses[old.licenseId];if(!row||row.consumed||Status(row)!=='AVAILABLE')Fail('DESKTOP_KEY_USED',409);return {license:Public(row),licenseKey:IssuedKey(row),...(old.replacedId?{replacedId:old.replacedId}:{})};}
 return Atomic(()=>{const result=fn();DB().receipts[key]={fingerprint,licenseId:result.license.id,action,replacedId:result.replacedId||'',at:now()};return result;});
}
function Create(body={},actor){if(!Plain(body))Fail('INPUT_INVALID');Expiry(body);return AdminReceipt('create','',body,actor,()=>NewRow(body,actor));}
function Reason(body){const reason=Text(body.reason,300,true);if(reason.length<3)Fail('INPUT_INVALID');return reason;}
function Revoke(id,body={},actor){const reason=Reason(body);return Atomic(()=>{const row=DB().licenses[id];if(!row)Fail('DESKTOP_KEY_INVALID',404);if(row.status!=='REVOKED'){row.status='REVOKED';row.revokedAt=now();row.revokedBy=String(actor||'ADMIN').slice(0,120);row.reason=reason;}return {license:Public(row)};});}
function Reissue(id,body={},actor){if(!Plain(body))Fail('INPUT_INVALID');Expiry(body);const reason=Reason(body);return AdminReceipt('reissue',id,body,actor,()=>{const old=DB().licenses[id];if(!old)Fail('DESKTOP_KEY_INVALID',404);old.status='REVOKED';old.revokedAt=now();old.revokedBy=String(actor||'ADMIN').slice(0,120);old.reason=reason;return {...NewRow({...body,label:body.label===undefined?old.label:body.label},actor),replacedId:id};});}
function List(body={}){const q=String(body.q||'').trim().toLowerCase().slice(0,120),status=String(body.status||'');if(status&&!['AVAILABLE','USED','REVOKED','EXPIRED'].includes(status))Fail('INPUT_INVALID');const all=Object.values(DB().licenses).map(Public),counts={AVAILABLE:0,USED:0,REVOKED:0,EXPIRED:0};for(const row of all)counts[row.status]++;return {items:all.filter(row=>(!status||row.status===status)&&(!q||[row.id,row.label,row.deviceId,row.deviceName].some(v=>String(v||'').toLowerCase().includes(q)))).sort((a,b)=>b.issuedAt-a.issuedAt||a.id.localeCompare(b.id)),counts,totalCount:all.length,revision:DB().revision,serverTime:now()};}
function ParseKey(value){
 if(typeof value!=='string'||value.length>500||!/^[A-Za-z0-9+/]+={0,2}$/.test(value))Fail('DESKTOP_PROOF_INVALID',401);
 const bytes=Buffer.from(value,'base64');if(bytes.toString('base64')!==value||bytes.length<280||bytes.length>288||bytes.readUInt32LE(0)!==0x31415352||bytes.readUInt32LE(4)!==2048||bytes.readUInt32LE(12)!==256||bytes.readUInt32LE(16)!==0||bytes.readUInt32LE(20)!==0)Fail('DESKTOP_PROOF_INVALID',401);
 const expLength=bytes.readUInt32LE(8);if(expLength<1||expLength>8||bytes.length!==24+expLength+256)Fail('DESKTOP_PROOF_INVALID',401);
 const exponent=bytes.subarray(24,24+expLength),modulus=bytes.subarray(24+expLength);if(exponent[0]===0||modulus[0]<128||!(modulus.at(-1)&1))Fail('DESKTOP_PROOF_INVALID',401);
 const exp=BigInt('0x'+exponent.toString('hex'));if(exp<3n||!(exp&1n))Fail('DESKTOP_PROOF_INVALID',401);
 let key;try{key=crypto.createPublicKey({key:{kty:'RSA',n:modulus.toString('base64url'),e:exponent.toString('base64url')},format:'jwk'});}catch(_){Fail('DESKTOP_PROOF_INVALID',401);}
 return {key,publicKey:value,deviceId:hash(bytes).toUpperCase()};
}
function Bind(body){
 if(!Plain(body)||!['redeem','verify','release'].includes(body.action)||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId||'')||!/^[A-F0-9]{64}$/.test(body.deviceId||''))Fail('INPUT_INVALID');
 const parsed=ParseKey(body.publicKey);if(body.deviceId!==parsed.deviceId)Fail('DESKTOP_DEVICE_MISMATCH',403);return parsed;
}
function Canonical(value){return ['GAME-DESKTOP-V1',value.action,value.challengeId,value.nonce,value.requestId,value.deviceId,value.payloadHash,String(value.expiresAt)].join('\n');}
function Prune(){const at=now();for(const [id,c]of challenges)if(c.expiresAt+CHALLENGE_MS<=at)challenges.delete(id);for(const [id,r]of verifyReceipts)if(r.until<=at)verifyReceipts.delete(id);}
function Challenge(body){
 Available();const parsed=Bind(body);if(!/^[a-f0-9]{64}$/.test(body.payloadHash||''))Fail('INPUT_INVALID');Prune();if(challenges.size>=10000)Fail('DESKTOP_CAPACITY',503);
 const value={challengeId:crypto.randomBytes(24).toString('base64url'),nonce:crypto.randomBytes(32).toString('base64url'),action:body.action,requestId:body.requestId,deviceId:parsed.deviceId,publicKey:parsed.publicKey,payloadHash:body.payloadHash,expiresAt:now()+CHALLENGE_MS,used:false};challenges.set(value.challengeId,value);
 return {challengeId:value.challengeId,nonce:value.nonce,expiresAt:value.expiresAt,canonical:Canonical(value)};
}
function Payload(body){
 const raw=body.payloadJSON??body.payloadJson;if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>4096)Fail('INPUT_INVALID');let p;try{p=JSON.parse(raw);}catch(_){Fail('INPUT_INVALID');}
 if(!Plain(p))Fail('INPUT_INVALID');const fields=body.action==='redeem'?['licenseKey','deviceName','appVersion','bootstrapSessionId','bootstrapSessionToken','machineId','binarySha256','binaryCrc64']:['activationToken','appVersion','bootstrapSessionId','bootstrapSessionToken','machineId','binarySha256','binaryCrc64'];if(Object.keys(p).some(k=>!fields.includes(k)))Fail('INPUT_INVALID');
 machinePolicy.Validate(p.machineId);if(!/^[a-f0-9]{64}$/.test(p.binarySha256||'')||!/^[A-F0-9]{16}$/.test(p.binaryCrc64||''))Fail('DESKTOP_BINARY_INVALID',403);
 if(p.appVersion!==undefined)Text(p.appVersion,40);if(body.action==='redeem'){NormalizeKey(p.licenseKey);if(p.deviceName!==undefined)Text(p.deviceName,120);}else if(typeof p.activationToken!=='string'||!/^(?:[a-f0-9]{64}|DLA-[A-Za-z0-9_-]{43})$/.test(p.activationToken))Fail('DESKTOP_ACTIVATION_INVALID',401);
 return {payload:p,payloadHash:hash(Buffer.from(raw,'utf8'))};
}
function Token(row){const mac=crypto.createHmac('sha256',Buffer.from(DB().signingSecret,'hex')).update((row.activationVersion===2?'GAME-DESKTOP-ACTIVATION-V2|':legacyActivationDomain)+row.id+'|'+row.deviceId+'|'+row.activationNonce);return row.activationVersion===2?mac.digest('hex'):'DLA-'+mac.digest('base64url');}
function Active(row){if(!row)Fail('DESKTOP_ACTIVATION_INVALID',401);const status=Status(row);if(status==='REVOKED')Fail('DESKTOP_REVOKED',403);if(row.status==='RELEASED'||row.releasedAt)Fail('DESKTOP_RELEASED',403);if(status==='EXPIRED')Fail('DESKTOP_EXPIRED',403);if(status!=='USED')Fail('DESKTOP_ACTIVATION_INVALID',401);}
function Activation(p,deviceId){const digest=hash(p.activationToken),row=Object.values(DB().licenses).find(x=>x.tokenHash===digest);if(!row)Fail('DESKTOP_ACTIVATION_INVALID',401);if(row.deviceId!==deviceId)Fail('DESKTOP_DEVICE_MISMATCH',403);return row;}
function SessionBinding(row,bootstrap){const expected=row.bootstrapSessionId||require('./desktopBootstrap').LicenseActivity(row.id)?.sessionId;if(!expected||expected!==bootstrap.sessionId)Fail('BOOTSTRAP_LICENSE_MISMATCH',403);}
function Result(row,leaseExpiresAt=0){return {licenseId:row.id,status:Status(row),deviceId:row.deviceId,label:row.label,issuedAt:row.issuedAt,activatedAt:row.activatedAt||0,expiresAt:row.expiresAt,leaseExpiresAt,serverTime:now(),revision:DB().revision};}
function Lease(row,appVersion){const leaseExpiresAt=Math.min(now()+LEASE_MS,row.expiresAt||Number.MAX_SAFE_INTEGER);seen.set(row.id,{at:now(),leaseExpiresAt,appVersion:appVersion||row.appVersion||''});return leaseExpiresAt;}
function BootstrapResult(result,payload,deviceId,action){const row=DB().licenses[result.licenseId];require('./desktopBootstrap').TouchLicense(payload.bootstrapSessionId,payload.bootstrapSessionToken,deviceId,row,action,{leaseExpiresAt:result.leaseExpiresAt||0,appVersion:payload.appVersion||''});if(action==='verify')try{require('../web/webEvents').BroadcastEvent({time:now(),type:'DESKTOP_LICENSE_VERIFIED',detail:JSON.stringify({id:row.id,deviceId:row.deviceId,status:Status(row)})});}catch(_){}return result;}
function Activity(action,row){try{require('../storage/audit').LogEvent('DESKTOP_LICENSE_'+action,JSON.stringify({id:row.id,deviceId:row.deviceId,status:Status(row)}));}catch(_){console.error('DESKTOP_LICENSE_AUDIT_FAILED:',action);}}
function Execute(body){
 Available();const parsed=Bind(body),c=challenges.get(body.challengeId);if(!c||c.expiresAt<=now())Fail('DESKTOP_CHALLENGE_EXPIRED',401);
 if(['action','requestId','deviceId','publicKey'].some(k=>body[k]!==c[k]))Fail('DESKTOP_PROOF_INVALID',401);
 const {payload,payloadHash}=Payload(body);if(payloadHash!==c.payloadHash)Fail('DESKTOP_PROOF_INVALID',401);
 if(typeof body.signature!=='string'||body.signature.length!==344||!/^[A-Za-z0-9+/]{342}==$/.test(body.signature))Fail('DESKTOP_PROOF_INVALID',401);
 const signature=Buffer.from(body.signature,'base64');if(signature.length!==256||signature.toString('base64')!==body.signature||!crypto.verify('sha256',Buffer.from(Canonical(c),'utf8'),{key:parsed.key,padding:crypto.constants.RSA_PKCS1_PADDING},signature))Fail('DESKTOP_PROOF_INVALID',401);
 const receiptKey=body.deviceId+':'+body.requestId,receipt=DB().receipts[receiptKey]||verifyReceipts.get(receiptKey),fingerprint=hash(body.action+'|'+payloadHash);
 const bootstrap=require('./desktopBootstrap').Gate(payload.bootstrapSessionId,payload.bootstrapSessionToken,body.deviceId,{allowReleased:body.action==='release'&&receipt?.action==='release',machineId:payload.machineId,binarySha256:payload.binarySha256,binaryCrc64:payload.binaryCrc64});
 if(receipt){
  if(receipt.fingerprint!==fingerprint)Fail('DESKTOP_REQUEST_REUSED',409);
  const row=DB().licenses[receipt.licenseId];if(!row||row.deviceId!==body.deviceId)Fail('DESKTOP_ACTIVATION_INVALID',401);SessionBinding(row,bootstrap);
  if(bootstrap.licenseId&&bootstrap.licenseId!==row.id)Fail('BOOTSTRAP_LICENSE_MISMATCH',409);
  if(body.action==='release'){if(row.status!=='RELEASED'&&!row.releasedAt)Active(row);c.used=true;return BootstrapResult({...Result(row),released:true},payload,body.deviceId,body.action);}
  Active(row);c.used=true;return BootstrapResult({...Result(row,receipt.leaseExpiresAt),...(body.action==='redeem'?{activationToken:Token(row)}:{})},payload,body.deviceId,body.action);
 }
 if(c.used)Fail('DESKTOP_REQUEST_REUSED',409);
 let result;
 if(body.action==='redeem'){
  result=Atomic(()=>{
   const digests=KeyHashes(payload.licenseKey),row=Object.values(DB().licenses).find(x=>digests.includes(x.keyHash));if(!row)Fail('DESKTOP_KEY_INVALID',404);
   if(bootstrap.licenseId&&bootstrap.licenseId!==row.id)Fail('BOOTSTRAP_LICENSE_MISMATCH',409);
   if(Status(row)==='REVOKED')Fail('DESKTOP_REVOKED',403);if(Status(row)==='EXPIRED')Fail('DESKTOP_EXPIRED',403);if(row.consumed)Fail('DESKTOP_KEY_USED',409);
   Object.assign(row,{status:'USED',consumed:true,activationVersion:2,bootstrapSessionId:bootstrap.sessionId,machineId:payload.machineId,machinePolicyGeneration:bootstrap.machinePolicyGeneration,binarySha256:payload.binarySha256,binaryCrc64:payload.binaryCrc64,deviceId:parsed.deviceId,publicKey:parsed.publicKey,deviceName:payload.deviceName||'',appVersion:payload.appVersion||'',activatedAt:now(),activationNonce:crypto.randomBytes(24).toString('hex')});row.tokenHash=hash(Token(row));
   const leaseExpiresAt=Math.min(now()+LEASE_MS,row.expiresAt||Number.MAX_SAFE_INTEGER);DB().receipts[receiptKey]={fingerprint,licenseId:row.id,action:body.action,leaseExpiresAt,at:now()};
   return {...Result(row,leaseExpiresAt),activationToken:Token(row)};
  });
  Activity('USED',DB().licenses[result.licenseId]);
 }else{
  const row=Activation(payload,body.deviceId);Active(row);SessionBinding(row,bootstrap);
  if(bootstrap.licenseId&&bootstrap.licenseId!==row.id)Fail('BOOTSTRAP_LICENSE_MISMATCH',409);
  if(body.action==='verify'){
   const leaseExpiresAt=Lease(row,payload.appVersion);result=Result(row,leaseExpiresAt);verifyReceipts.set(receiptKey,{fingerprint,licenseId:row.id,leaseExpiresAt,until:now()+CHALLENGE_MS*2});
  }else{result=Atomic(()=>{row.status='USED';row.releasedAt=now();row.reason='Windows 앱에서 연결 해제';DB().receipts[receiptKey]={fingerprint,licenseId:row.id,action:body.action,leaseExpiresAt:0,at:now()};return {...Result(row),released:true};});Activity('RELEASED',row);}
 }
 c.used=true;result.revision=DB().revision;if(body.action==='redeem')seen.set(result.licenseId,{at:now(),leaseExpiresAt:result.leaseExpiresAt,appVersion:payload.appVersion||''});return BootstrapResult(result,payload,body.deviceId,body.action);
}
module.exports={CHALLENGE_MS,LEASE_MS,messages,Empty,Import,DB,Public,Detail,Create,Revoke,Reissue,List,Challenge,Execute,ParseKey,Canonical,Fail};
