'use strict';
// Synthetic TPM certifier fixture. Actual production certificate, nonce,
// certify-signature and activation-credential crypto run; this is not hardware.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{execFileSync}=require('node:child_process');
const tpm=require('../../../services/devices/peace.desktop-tpm-attestation');
module.exports=function SyntheticTpm(temp){
const b16=x=>{const b=Buffer.alloc(2);b.writeUInt16BE(x);return b;},b32=x=>{const b=Buffer.alloc(4);b.writeUInt32BE(x);return b;},size=b=>Buffer.concat([b16(b.length),b]),hash=b=>crypto.createHash('sha256').update(b).digest();
function key(){return crypto.generateKeyPairSync('rsa',{modulusLength:2048});}
function blob(k){const j=k.publicKey.export({format:'jwk'}),n=Buffer.from(j.n,'base64url'),e=Buffer.from(j.e,'base64url'),h=Buffer.alloc(24);[0x31415352,2048,e.length,n.length,0,0].forEach((v,i)=>h.writeUInt32LE(v,i*4));return Buffer.concat([h,e,n]).toString('base64');}
function pub(k,ak=false){const n=Buffer.from(k.publicKey.export({format:'jwk'}).n,'base64url');return Buffer.concat([b16(1),b16(11),b32(0x40072|(ak?0x10000:0)),b16(0),b16(16),b16(20),b16(11),b16(2048),b32(65537),size(n)]);}
function certify(ak,device,nonce){const a=pub(ak,true),d=pub(device),name=b=>Buffer.concat([b16(11),hash(b)]),attest=Buffer.concat([b32(0xff544347),b16(0x8017),size(name(a)),size(nonce),Buffer.alloc(8),b32(0),b32(0),Buffer.from([1]),Buffer.alloc(8),size(name(d)),size(name(d))]),sig=crypto.sign('sha256',attest,ak.privateKey);return {akPublic:a.toString('base64'),keyPublic:d.toString('base64'),certify:attest.toString('base64'),signature:Buffer.concat([b16(20),b16(11),size(sig)]).toString('base64')};}
function openssl(args){return execFileSync('openssl',args,{cwd:temp,env:{...process.env,OPENSSL_CONF:path.join(temp,'ek.conf')},encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:30000});}
 const ek=key(),ak=key(),device=key(),nonce=crypto.randomBytes(32);fs.writeFileSync(path.join(temp,'ek.key'),ek.privateKey.export({format:'pem',type:'pkcs8'}));
 // OpenSSL 3.5 includes these TPM OIDs. Older releases need the aliases
 // for the same numeric certificate subject attributes.
 const builtInOids = new Set(execFileSync('openssl', ['list', '-objects'], {
   encoding: 'utf8', timeout: 10000,
 }).split(/\r?\n/).map(line => line.match(/(?:^|[,=])\s*(\d+(?:\.\d+)+)$/)?.[1]));
 const missingOids = [
   ['tpmManufacturer', '2.23.133.2.1'], ['tpmModel', '2.23.133.2.2'],
   ['tpmVersion', '2.23.133.2.3'],
 ].filter(([, oid]) => !builtInOids.has(oid));
 const oidConfig = missingOids.length ? 'oid_section = oids\n[oids]\n' +
   missingOids.map(([name, oid]) => name + '=' + oid + '\n').join('') : '';
 fs.writeFileSync(path.join(temp,'ek.conf'),oidConfig+'[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=SYNTHETIC TEST EK\n[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\nextendedKeyUsage=2.23.133.8.1\nsubjectAltName=critical,dirName:tpm\n[tpm]\n1.2.23.133.2.1=id:49424d00\n1.2.23.133.2.2=SYNTHETIC TEST ONLY\n1.2.23.133.2.3=id:00010000\n');
 openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','root.key','-out','root.pem','-subj','/CN=GAME SYNTHETIC TEST ROOT','-days','2','-sha256','-addext','basicConstraints=critical,CA:TRUE,pathlen:1','-addext','keyUsage=critical,keyCertSign,cRLSign']);
 openssl(['req','-new','-key','ek.key','-out','ek.csr','-config','ek.conf']);openssl(['x509','-req','-in','ek.csr','-CA','root.pem','-CAkey','root.key','-CAcreateserial','-out','ek.pem','-days','1','-sha256','-extfile','ek.conf','-extensions','ext']);
 const cert=new crypto.X509Certificate(fs.readFileSync(path.join(temp,'ek.pem'))),trust={roots:[fs.readFileSync(path.join(temp,'root.pem'),'utf8')],intermediates:[],revokedCertificateSha256:[],validUntil:Date.now()+3600000};
 function activate(packed,ekPrivate,akName){const r=new tpm.Reader(packed),id=r.sized(),enc=r.sized();r.end();const seed=crypto.privateDecrypt({key:ekPrivate,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256',oaepLabel:Buffer.from('IDENTITY\0')},enc);function kdf(label,u,bits){return crypto.createHmac('sha256',seed).update(b32(1)).update(label+'\0').update(u).update(b32(bits)).digest().subarray(0,bits/8);}const ir=new tpm.Reader(id),hmac=ir.sized(),cipher=id.subarray(ir.p);assert.deepEqual(hmac,crypto.createHmac('sha256',kdf('INTEGRITY',Buffer.alloc(0),256)).update(cipher).update(akName).digest());const aes=crypto.createDecipheriv('aes-128-cfb',kdf('STORAGE',akName,128),Buffer.alloc(16)),clear=Buffer.concat([aes.update(cipher),aes.final()]),cr=new tpm.Reader(clear),secret=Buffer.from(cr.sized());cr.end();seed.fill(0);clear.fill(0);return secret;}

 function quote(frame, pcrs=crypto.randomBytes(256), clockSafe=1) {
  const qualifying=require('../../../services/security/peace.nhw-tpm-quote').QualifyingDigest(frame);
  const signer=Buffer.concat([b16(11),hash(pub(ak,true))]);
  const attest=Buffer.concat([b32(0xff544347),b16(0x8018),size(signer),size(qualifying),
   Buffer.alloc(8),b32(0),b32(0),Buffer.from([clockSafe]),Buffer.alloc(8),
   b32(1),b16(11),Buffer.from([3,0xff,0,0]),size(hash(pcrs))]);
  const signature=Buffer.concat([b16(20),b16(11),size(crypto.sign('sha256',attest,ak.privateKey))]);
  return {version:1,attest:attest.toString('base64'),signature:signature.toString('base64'),pcrs:pcrs.toString('base64')};
 }
 return {trust,quote,evidence(publicKey,nonce){return {version:1,ekCertificate:cert.raw.toString('base64'),...certify(ak,{publicKey:require('../../../services/licensing/peace.desktop-licenses').ParseKey(publicKey).key},nonce)};},
 activate(response){return activate(Buffer.from(response.activationBlob,'base64'),ek.privateKey,Buffer.concat([b16(11),hash(pub(ak,true))]));}};
};
