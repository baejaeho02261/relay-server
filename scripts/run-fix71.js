'use strict';
const {spawnSync}=require('node:child_process'),path=require('node:path');
const checks=[
 ['check-modules.js'],['check-native-source.js'],['check-web-ui.js'],
 ['test-fix71-auth-layout.js'],['test-fix71-oauth-identity.js'],['test-member-test-access.js'],
 ['test-fix71-biometric-durability.js'],['test-fix71-device-credential.js'],
 ['test-fix71-home-receipts.js'],['test-fix71-catalog-download.js'],['test-fix70-catalog.js'],
 ['test-fix71-social-profile.js'],['test-fix70-feed-channels.js'],
 ['test-fix71-chat-gamewindow.js'],['test-fix59-direct-messages.js'],['test-fix70-chat-shares.js'],
 ['test-fix71-payments.js'],['test-fix71-payments.js','--sqlite'],['test-fix58-withdrawals.js'],
 ['test-fix70-retired-games.js'],['test-fix70-retirement-refunds.js'],
 ['test-web-ui-cache.js'],['test-web-dom.js']
];
let failures=0;
for(const [name,...args]of checks){
 const r=spawnSync(process.execPath,[path.join(__dirname,name),...args],{cwd:path.resolve(__dirname,'..'),encoding:'utf8',timeout:60000});
 const ok=r.status===0;console.log(`${ok?'PASS':'FAIL'} ${name} ${args.join(' ')}`.trim());
 if(!ok){failures++;console.error(r.error||(r.stdout||'')+(r.stderr||''));}
}
console.log(`${checks.length-failures}/${checks.length} FIX71 checks passed. Delphi/Android execution is not included.`);
process.exitCode=failures?1:0;
