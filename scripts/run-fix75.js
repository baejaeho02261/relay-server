'use strict';
const {spawnSync}=require('node:child_process'),path=require('node:path');
// Current product contract. Older FIX runners describe intentionally retired UIs.
const checks=[
 ['check-modules.js'],['check-native-source.js'],['check-web-ui.js'],
 ['test-fix74-single-use.js'],['test-fix74-single-use.js','--sqlite'],
 ['test-fix74-charge-retirement.js'],['test-fix74-reward-settings.js'],
 ['test-fix74-native-commerce.js'],['test-fix74-feed.js'],['test-fix75-profile-layout.js'],
 ['test-fix74-auth-ui.js'],['test-fix74-oauth-profile.js'],
 ['test-fix71-home-receipts.js'],['test-fix71-oauth-identity.js'],['test-fix71-biometric-durability.js'],
 ['test-fix72-oauth-revocation.js'],['test-fix72-native-auth.js'],
 ['test-fix72-admin-accounts-wallet.js'],['test-fix72-admin-dom.js'],
 ['test-build-sessions.js'],['test-member-test-access.js'],
 ['test-fix59-direct-messages.js'],['test-fix70-chat-shares.js'],
 ['test-fix58-withdrawals.js'],['test-fix70-retired-games.js'],['test-fix70-retirement-refunds.js'],
 ['test-web-ui-cache.js'],['test-web-dom.js'],
 ['test-fix75-home-attendance.js'],['test-fix75-home-payload.js'],['test-fix75-catalog-feed.js'],
 ['test-fix75-gallery-media.js'],['test-fix75-gallery-upload.js'],
 ['test-fix75-cosmetic-retirement.js'],['test-fix75-cosmetic-retirement.js','--sqlite'],
 ['test-fix75-support-livechat.js'],['test-fix75-support-native.js'],
 ['test-fix60-message-rendering.js'],['test-support-center.js'],['test-support-persistence.js'],
 ['test-fix75-auth-resume.js'],['test-fix75-auth-resume.js','--sqlite'],
 ['test-fix75-native-auth-flow.js']
];
let failures=0;
for(const [name,...args]of checks){
 const r=spawnSync(process.execPath,[path.join(__dirname,name),...args],{cwd:path.resolve(__dirname,'..'),encoding:'utf8',timeout:name==='check-modules.js'?180000:60000,env:{...process.env,...(args.includes('--sqlite')?{STORAGE_ENGINE:'sqlite'}:{})}});
 const ok=r.status===0;console.log(`${ok?'PASS':'FAIL'} ${name} ${args.join(' ')}`.trim());
 if(!ok){failures++;console.error(r.error||(r.stdout||'')+(r.stderr||''));}
}
console.log(`${checks.length-failures}/${checks.length} FIX75 checks passed. Delphi/Android execution is not included.`);
process.exitCode=failures?1:0;
