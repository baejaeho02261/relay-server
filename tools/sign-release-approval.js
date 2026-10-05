'use strict';
// Offline operator tool. The private key stays on the operator's signing host.
// This is detached release approval, NOT Microsoft Authenticode.
const fs = require('node:fs'), crypto = require('node:crypto');
const { ReleaseCanonical, PeCapabilities } = require('../services/desktopSecurityAuthority');
function SignRelease(component, version, file, keyFile) {
  if (!['A','B','O'].includes(component) || typeof version !== 'string' || version.length > 40 || !/^\d+(?:\.\d+){0,3}$/.test(version)) throw Error('RELEASE_ARGUMENT_INVALID');
  const stat = fs.statSync(file), keyStat = fs.statSync(keyFile);
  if (!stat.isFile() || stat.size < 64 || stat.size > 64*1024*1024 || !keyStat.isFile() || keyStat.size > 16384) throw Error('RELEASE_FILE_INVALID');
  const bytes = fs.readFileSync(file), keyBytes = fs.readFileSync(keyFile);
  let key;
  try { key = crypto.createPrivateKey(keyBytes); } finally { keyBytes.fill(0); }
  if (key.asymmetricKeyType !== 'ed25519') throw Error('ED25519_KEY_REQUIRED');
  require('../services/desktopIntegrity').CodeImage(bytes);
  const publicKey = crypto.createPublicKey(key), keyId = crypto.createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const signature = crypto.sign(null, Buffer.from(ReleaseCanonical(component,version,sha256)), key).toString('base64');
  return {component,version,sha256,...PeCapabilities(bytes),
    trustedKey:{keyId,publicKey:publicKey.export({type:'spki',format:'pem'}).toString()},
    approval:{keyId,signature},headers:{'x-game-release-key-id':keyId,'x-game-release-signature':signature}};
}
if (require.main === module) {
  const [component,version,file,flag,keyFile,...extra]=process.argv.slice(2);
  if (flag !== '--key' || !keyFile || extra.length) { console.error('Usage: node tools/sign-release-approval.js A|B|O VERSION FILE.exe --key PRIVATE_ED25519.pem'); process.exitCode=2; }
  else { try { process.stdout.write(JSON.stringify(SignRelease(component,version,file,keyFile),null,2)+'\n'); }
    catch (_) { console.error('RELEASE_SIGNING_FAILED: check component/version, PE input, and Ed25519 key. No key content was logged.'); process.exitCode=1; } }
}
module.exports={SignRelease};
