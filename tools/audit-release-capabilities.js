'use strict';
// Read-only PE metadata audit. Does not patch flags or manufacture CFG support.
const fs=require('node:fs'),crypto=require('node:crypto');
const {PeCapabilities}=require('../services/desktopSecurityAuthority');
function Audit(file){const stat=fs.statSync(file);if(!stat.isFile()||stat.size>64*1024*1024)throw Error('INVALID_RELEASE');const bytes=fs.readFileSync(file);const code=require('../services/desktopIntegrity').CodeImage(bytes);return {sha256:crypto.createHash('sha256').update(bytes).digest('hex'),codeSha256:code.sha256,...PeCapabilities(bytes),attested:false,notice:'CFG metadata is not proof that every indirect call is instrumented.'};}
if(require.main===module){try{if(process.argv.length!==3)throw Error();console.log(JSON.stringify(Audit(process.argv[2]),null,2));}catch(_){console.error('Usage: node tools/audit-release-capabilities.js FILE.exe (bounded PE64 input)');process.exitCode=1;}}
module.exports={Audit};
