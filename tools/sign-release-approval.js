'use strict';
// Offline operator tool. The private key stays on the operator's signing host.
// This is detached release approval, NOT Microsoft Authenticode.
const fs = require('node:fs'), crypto = require('node:crypto');
const { ReleaseCanonical, PeCapabilities } = require('../services/desktopSecurityAuthority');
function SignRelease(component, version, file, keyFile) {
  if (!['A','B','O'].includes(component) || typeof version !== 'string' || version.length > 40 || !/^\d+(?:\.\d+){0,3}$/.test(version)) throw Error('RELEASE_ARGUMENT_INVALID');
  const stat = fs.statSync(file), keyStat = fs.statSync(keyFile);
  if (!stat.isFile() || stat.size < (component === 'O' ? 512 : 64) || stat.size > (component === 'O' ? 16 : 64)*1024*1024 || !keyStat.isFile() || keyStat.size > 16384) throw Error('RELEASE_FILE_INVALID');
  const bytes = fs.readFileSync(file), keyBytes = fs.readFileSync(keyFile);
  if (component === 'O' && (bytes.length < 512 || bytes.length > 16*1024*1024)) { keyBytes.fill(0); throw Error('RELEASE_FILE_INVALID'); }
  let key;
  try { key = crypto.createPrivateKey(keyBytes); } finally { keyBytes.fill(0); }
  if (key.asymmetricKeyType !== 'ed25519') throw Error('ED25519_KEY_REQUIRED');
  require('../services/desktopIntegrity').CodeImage(bytes);
  if (component === 'O') {
    const pe = bytes.readUInt32LE(0x3c);
    const exports = require('../services/desktopPeExports').ExportTable(bytes, 'GameOverlayRunV1');
    if ((bytes.readUInt16LE(pe + 22) & 0x2002) !== 0x2002 || exports.status !== 'MEASURED' || !exports.requiredExportRva) throw Error('OVERLAY_PLUGIN_PE_INVALID');
  }
  const publicKey = crypto.createPublicKey(key), keyId = crypto.createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const signature = crypto.sign(null, Buffer.from(ReleaseCanonical(component,version,sha256)), key).toString('base64');
  return {component,version,sha256,...PeCapabilities(bytes),
    trustedKey:{keyId,publicKey:publicKey.export({type:'spki',format:'pem'}).toString()},
    approval:{keyId,signature},headers:{'x-game-release-key-id':keyId,'x-game-release-signature':signature}};
}
if (require.main === module) {
  const [component,version,file,flag,keyFile,...extra]=process.argv.slice(2);
  if (flag !== '--key' || !keyFile || extra.length) { console.error('Usage: node tools/sign-release-approval.js A|B|O VERSION FILE.exe|FILE.bin --key PRIVATE_ED25519.pem'); process.exitCode=2; }
  else { try { process.stdout.write(JSON.stringify(SignRelease(component,version,file,keyFile),null,2)+'\n'); }
    catch (_) { console.error('RELEASE_SIGNING_FAILED: check component/version, PE input, and Ed25519 key. No key content was logged.'); process.exitCode=1; } }
}
module.exports={SignRelease};
