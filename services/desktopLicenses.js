'use strict';
// Desktop authorization is separate from archived CLIENT/QR/biometric records.
const crypto=require('node:crypto'),state=require('../core/state');
const CHALLENGE_MS=120000,LEASE_MS=120000,MAX_DAYS=3650;
const challenges=new Map(),seen=new Map(),verifyReceipts=new Map();
let authorityLoaded=false;
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
const now=()=>Date.now();
const messages={INPUT_INVALID:'입력 내용을 확인해 주세요.',HTTPS_REQUIRED:'HTTPS 서버 주소를 사용해 주세요.',DESKTOP_BROWSER_FORBIDDEN:'Windows 앱에서 다시 요청해 주세요.',DESKTOP_KEY_INVALID:'라이선스 키를 확인해 주세요.',DESKTOP_KEY_USED:'이미 사용한 라이선스 키입니다.',DESKTOP_REVOKED:'관리자가 이 라이선스를 해지했습니다.',DESKTOP_RELEASED:'연결 해제된 라이선스입니다. 새 키가 필요합니다.',DESKTOP_EXPIRED:'라이선스가 만료되었습니다.',DESKTOP_DEVICE_MISMATCH:'라이선스가 연결된 Windows 기기에서 실행해 주세요.',DESKTOP_ACTIVATION_INVALID:'인증 정보를 확인할 수 없습니다. 라이선스를 다시 확인해 주세요.',DESKTOP_PROOF_INVALID:'기기 서명을 확인하지 못했습니다.',DESKTOP_CHALLENGE_EXPIRED:'인증 요청이 만료되었습니다. 다시 시도해 주세요.',DESKTOP_REQUEST_REUSED:'요청 번호가 다른 작업에 사용되었습니다.',DESKTOP_RATE_LIMIT:'요청이 많습니다. 잠시 후 다시 시도해 주세요.',DESKTOP_CAPACITY:'인증 요청이 많습니다. 잠시 후 다시 시도해 주세요.',SERVICE_DISABLED:'서비스가 일시 중지되었습니다.',STORAGE_SAVE_FAILED:'저장하지 못했습니다. 같은 요청으로 다시 시도해 주세요.'};
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
  if(!/^DL-[A-F0-9]{24}$/.test(id)||!Plain(row)||row.id!==id||!['AVAILABLE','ACTIVE','REVOKED','RELEASED'].includes(row.status)||!/^[a-f0-9]{64}$/.test(row.keyHash)||typeof row.consumed!=='boolean'||!Number.isSafeInteger(row.expiresAt)||row.expiresAt<0)throw Error('DESKTOP_STORAGE_INVALID');
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
function Status(row){if(row.status==='REVOKED'||row.status==='RELEASED')return row.status;if(row.expiresAt&&row.expiresAt<=now())return 'EXPIRED';return row.consumed?'ACTIVE':'AVAILABLE';}
function Public(row){const current=seen.get(row.id),active=Status(row)==='ACTIVE';return {id:row.id,label:row.label,status:Status(row),issuedAt:row.issuedAt,activatedAt:row.activatedAt||0,expiresAt:row.expiresAt,consumed:row.consumed,deviceId:row.deviceId||'',deviceName:row.deviceName||'',appVersion:current?.appVersion||row.appVersion||'',lastVerifiedAt:current?.at||row.activatedAt||0,leaseExpiresAt:active?current?.leaseExpiresAt||0:0,revokedAt:row.revokedAt||0,releasedAt:row.releasedAt||0,reason:row.reason||''};}
function Text(value,max,required=false){if(typeof value!=='string'||value.length>max||/[\u0000-\u001f\u007f]/.test(value)||required&&!value.trim())Fail('INPUT_INVALID');return value.trim();}
function Expiry(body){
 if(body.expiresAt!==undefined){if(!Number.isSafeInteger(body.expiresAt)||body.expiresAt<0||body.expiresAt!==0&&(body.expiresAt<=now()||body.expiresAt>now()+MAX_DAYS*86400000))Fail('INPUT_INVALID');return body.expiresAt;}
 if(body.validDays===undefined||body.validDays===0)return 0;const days=body.validDays;if(!Number.isSafeInteger(days)||days<1||days>MAX_DAYS)Fail('INPUT_INVALID');return now()+days*86400000;
}
function KeyHash(value){if(typeof value!=='string'||value.length>100)Fail('DESKTOP_KEY_INVALID');const key=value.trim().toUpperCase();if(!/^MOA(?:-[A-F0-9]{8}){8}$/.test(key))Fail('DESKTOP_KEY_INVALID');return hash(key);}
function NewRow(body,actor){
 const label=Text(body.label||'',120),expiresAt=Expiry(body),id='DL-'+crypto.randomBytes(12).toString('hex').toUpperCase();
 DB().signingSecret||=crypto.randomBytes(32).toString('hex');
 const row={id,label,issuanceNonce:crypto.randomBytes(24).toString('hex'),status:'AVAILABLE',consumed:false,issuedAt:now(),issuedBy:String(actor||'ADMIN').slice(0,120),expiresAt},key=IssuedKey(row);row.keyHash=hash(key);DB().licenses[id]=row;
 return {licenseKey:key,license:Public(row)};
}
function IssuedKey(row){return 'MOA-'+crypto.createHmac('sha256',Buffer.from(DB().signingSecret,'hex')).update('MOAPLAY-DESKTOP-KEY-V1|'+row.id+'|'+row.issuanceNonce).digest('hex').toUpperCase().match(/.{8}/g).join('-');}
function AdminReceipt(action,id,body,actor,fn){
 if(!Plain(body))Fail('INPUT_INVALID');
 if(body.requestId===undefined)return Atomic(fn);
 if(!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId))Fail('INPUT_INVALID');
 const key='ADMIN:'+hash(String(actor))+':'+body.requestId,fingerprint=hash(JSON.stringify({action,id,body})),old=DB().receipts[key];
 if(old){if(old.fingerprint!==fingerprint)Fail('DESKTOP_REQUEST_REUSED',409);const row=DB().licenses[old.licenseId];if(!row||row.consumed||Status(row)!=='AVAILABLE')Fail('DESKTOP_KEY_USED',409);return {license:Public(row),licenseKey:IssuedKey(row),...(old.replacedId?{replacedId:old.replacedId}:{})};}
 return Atomic(()=>{const result=fn();DB().receipts[key]={fingerprint,licenseId:result.license.id,action,replacedId:result.replacedId||'',at:now()};return result;});
}
function Create(body={},actor){return AdminReceipt('create','',body,actor,()=>NewRow(body,actor));}
function Reason(body){const reason=Text(body.reason,300,true);if(reason.length<3)Fail('INPUT_INVALID');return reason;}
function Revoke(id,body={},actor){const reason=Reason(body);return Atomic(()=>{const row=DB().licenses[id];if(!row)Fail('DESKTOP_KEY_INVALID',404);if(row.status!=='REVOKED'){row.status='REVOKED';row.revokedAt=now();row.revokedBy=String(actor||'ADMIN').slice(0,120);row.reason=reason;}return {license:Public(row)};});}
function Reissue(id,body={},actor){const reason=Reason(body);return AdminReceipt('reissue',id,body,actor,()=>{const old=DB().licenses[id];if(!old)Fail('DESKTOP_KEY_INVALID',404);old.status='REVOKED';old.revokedAt=now();old.revokedBy=String(actor||'ADMIN').slice(0,120);old.reason=reason;return {...NewRow({...body,label:body.label===undefined?old.label:body.label},actor),replacedId:id};});}
function List(body={}){const q=String(body.q||'').trim().toLowerCase().slice(0,120),status=String(body.status||'');if(status&&!['AVAILABLE','ACTIVE','REVOKED','EXPIRED','RELEASED'].includes(status))Fail('INPUT_INVALID');return {items:Object.values(DB().licenses).map(Public).filter(row=>(!status||row.status===status)&&(!q||[row.id,row.label,row.deviceId,row.deviceName].some(v=>v.toLowerCase().includes(q)))).sort((a,b)=>b.issuedAt-a.issuedAt||a.id.localeCompare(b.id)),revision:DB().revision,serverTime:now()};}
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
function Canonical(value){return ['MOAPLAY-DESKTOP-V1',value.action,value.challengeId,value.nonce,value.requestId,value.deviceId,value.payloadHash,String(value.expiresAt)].join('\n');}
function Prune(){const at=now();for(const [id,c]of challenges)if(c.expiresAt+CHALLENGE_MS<=at)challenges.delete(id);for(const [id,r]of verifyReceipts)if(r.until<=at)verifyReceipts.delete(id);}
function Challenge(body){
 Available();const parsed=Bind(body);if(!/^[a-f0-9]{64}$/.test(body.payloadHash||''))Fail('INPUT_INVALID');Prune();if(challenges.size>=10000)Fail('DESKTOP_CAPACITY',503);
 const value={challengeId:crypto.randomBytes(24).toString('base64url'),nonce:crypto.randomBytes(32).toString('base64url'),action:body.action,requestId:body.requestId,deviceId:parsed.deviceId,publicKey:parsed.publicKey,payloadHash:body.payloadHash,expiresAt:now()+CHALLENGE_MS,used:false};challenges.set(value.challengeId,value);
 return {challengeId:value.challengeId,nonce:value.nonce,expiresAt:value.expiresAt,canonical:Canonical(value)};
}
function Payload(body){
 const raw=body.payloadJSON??body.payloadJson;if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>4096)Fail('INPUT_INVALID');let p;try{p=JSON.parse(raw);}catch(_){Fail('INPUT_INVALID');}
 if(!Plain(p))Fail('INPUT_INVALID');const fields=body.action==='redeem'?['licenseKey','deviceName','appVersion']:['activationToken','appVersion'];if(Object.keys(p).some(k=>!fields.includes(k)))Fail('INPUT_INVALID');
 if(p.appVersion!==undefined)Text(p.appVersion,40);if(body.action==='redeem'){KeyHash(p.licenseKey);if(p.deviceName!==undefined)Text(p.deviceName,120);}else if(typeof p.activationToken!=='string'||!/^DLA-[A-Za-z0-9_-]{43}$/.test(p.activationToken))Fail('DESKTOP_ACTIVATION_INVALID',401);
 return {payload:p,payloadHash:hash(Buffer.from(raw,'utf8'))};
}
function Token(row){return 'DLA-'+crypto.createHmac('sha256',Buffer.from(DB().signingSecret,'hex')).update('MOAPLAY-DESKTOP-ACTIVATION-V1|'+row.id+'|'+row.deviceId+'|'+row.activationNonce).digest('base64url');}
function Active(row){if(!row)Fail('DESKTOP_ACTIVATION_INVALID',401);const status=Status(row);if(status==='REVOKED')Fail('DESKTOP_REVOKED',403);if(status==='RELEASED')Fail('DESKTOP_RELEASED',403);if(status==='EXPIRED')Fail('DESKTOP_EXPIRED',403);if(status!=='ACTIVE')Fail('DESKTOP_ACTIVATION_INVALID',401);}
function Activation(p,deviceId){const digest=hash(p.activationToken),row=Object.values(DB().licenses).find(x=>x.tokenHash===digest);if(!row)Fail('DESKTOP_ACTIVATION_INVALID',401);if(row.deviceId!==deviceId)Fail('DESKTOP_DEVICE_MISMATCH',403);return row;}
function Result(row,leaseExpiresAt=0){return {licenseId:row.id,status:Status(row),deviceId:row.deviceId,label:row.label,issuedAt:row.issuedAt,activatedAt:row.activatedAt||0,expiresAt:row.expiresAt,leaseExpiresAt,serverTime:now(),revision:DB().revision};}
function Lease(row,appVersion){const leaseExpiresAt=Math.min(now()+LEASE_MS,row.expiresAt||Number.MAX_SAFE_INTEGER);seen.set(row.id,{at:now(),leaseExpiresAt,appVersion:appVersion||row.appVersion||''});return leaseExpiresAt;}
function Execute(body){
 Available();const parsed=Bind(body),c=challenges.get(body.challengeId);if(!c||c.expiresAt<=now())Fail('DESKTOP_CHALLENGE_EXPIRED',401);
 if(['action','requestId','deviceId','publicKey'].some(k=>body[k]!==c[k]))Fail('DESKTOP_PROOF_INVALID',401);
 const {payload,payloadHash}=Payload(body);if(payloadHash!==c.payloadHash)Fail('DESKTOP_PROOF_INVALID',401);
 if(typeof body.signature!=='string'||body.signature.length!==344||!/^[A-Za-z0-9+/]{342}==$/.test(body.signature))Fail('DESKTOP_PROOF_INVALID',401);
 const signature=Buffer.from(body.signature,'base64');if(signature.length!==256||signature.toString('base64')!==body.signature||!crypto.verify('sha256',Buffer.from(Canonical(c),'utf8'),{key:parsed.key,padding:crypto.constants.RSA_PKCS1_PADDING},signature))Fail('DESKTOP_PROOF_INVALID',401);
 const receiptKey=body.deviceId+':'+body.requestId,receipt=DB().receipts[receiptKey]||verifyReceipts.get(receiptKey),fingerprint=hash(body.action+'|'+payloadHash);
 if(receipt){
  if(receipt.fingerprint!==fingerprint)Fail('DESKTOP_REQUEST_REUSED',409);
  const row=DB().licenses[receipt.licenseId];if(!row||row.deviceId!==body.deviceId)Fail('DESKTOP_ACTIVATION_INVALID',401);
  if(body.action==='release'){if(row.status!=='RELEASED')Active(row);c.used=true;return {...Result(row),released:true};}
  Active(row);c.used=true;return {...Result(row,receipt.leaseExpiresAt),...(body.action==='redeem'?{activationToken:Token(row)}:{})};
 }
 if(c.used)Fail('DESKTOP_REQUEST_REUSED',409);
 let result;
 if(body.action==='redeem'){
  result=Atomic(()=>{
   const digest=KeyHash(payload.licenseKey),row=Object.values(DB().licenses).find(x=>x.keyHash===digest);if(!row)Fail('DESKTOP_KEY_INVALID',404);
   if(Status(row)==='REVOKED')Fail('DESKTOP_REVOKED',403);if(Status(row)==='EXPIRED')Fail('DESKTOP_EXPIRED',403);if(row.consumed)Fail('DESKTOP_KEY_USED',409);
   Object.assign(row,{status:'ACTIVE',consumed:true,deviceId:parsed.deviceId,publicKey:parsed.publicKey,deviceName:payload.deviceName||'',appVersion:payload.appVersion||'',activatedAt:now(),activationNonce:crypto.randomBytes(24).toString('hex')});row.tokenHash=hash(Token(row));
   const leaseExpiresAt=Math.min(now()+LEASE_MS,row.expiresAt||Number.MAX_SAFE_INTEGER);DB().receipts[receiptKey]={fingerprint,licenseId:row.id,action:body.action,leaseExpiresAt,at:now()};
   return {...Result(row,leaseExpiresAt),activationToken:Token(row)};
  });
 }else{
  const row=Activation(payload,body.deviceId);Active(row);
  if(body.action==='verify'){
   const leaseExpiresAt=Lease(row,payload.appVersion);result=Result(row,leaseExpiresAt);verifyReceipts.set(receiptKey,{fingerprint,licenseId:row.id,leaseExpiresAt,until:now()+CHALLENGE_MS*2});
  }else result=Atomic(()=>{row.status='RELEASED';row.releasedAt=now();row.reason='Windows 앱에서 연결 해제';DB().receipts[receiptKey]={fingerprint,licenseId:row.id,action:body.action,leaseExpiresAt:0,at:now()};return {...Result(row),released:true};});
 }
 c.used=true;result.revision=DB().revision;if(body.action==='redeem')seen.set(result.licenseId,{at:now(),leaseExpiresAt:result.leaseExpiresAt,appVersion:payload.appVersion||''});return result;
}
module.exports={CHALLENGE_MS,LEASE_MS,messages,Empty,Import,DB,Public,Create,Revoke,Reissue,List,Challenge,Execute,ParseKey,Canonical,Fail};
