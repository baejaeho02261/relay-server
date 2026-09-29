'use strict';
const {spawnSync}=require('node:child_process'),path=require('node:path');
// Current product regression suite. Historical, retired contracts are not runtime dependencies.
const checks=[
 ['check-modules.js'],['check-native-source.js'],['check-web-ui.js'],
 ['test-single-use.js'],['test-single-use.js','--sqlite'],
 ['test-charge-retirement.js'],['test-reward-settings.js'],
 ['test-native-commerce.js'],['test-feed.js'],['test-profile-restoration.js'],
 ['test-auth-provider-ui.js'],['test-oauth-profile.js'],
 ['test-home-receipts.js'],['test-oauth-identity.js'],['test-biometric-durability.js'],
 ['test-oauth-revocation.js'],['test-native-auth.js'],
 ['test-admin-accounts-wallet.js'],['test-admin-oauth-wallet.js'],
 ['test-build-sessions.js'],['test-member-test-access.js'],
 ['test-direct-messages.js'],['test-chat-shares.js'],
 ['test-withdrawals.js'],['test-retired-games.js'],['test-retirement-refunds.js'],
 ['test-web-ui-cache.js'],['test-web-dom.js'],
 ['test-home-attendance.js'],['test-home-payload.js'],['test-catalog-feed.js'],
 ['test-gallery-media.js'],['test-gallery-upload.js'],
 ['test-cosmetic-retirement.js'],['test-cosmetic-retirement.js','--sqlite'],
 ['test-support-livechat.js'],['test-support-native.js'],
 ['test-message-rendering.js'],['test-support-center.js'],['test-support-persistence.js'],
 ['test-auth-resume.js'],['test-auth-resume.js','--sqlite'],
 ['test-native-auth-flow.js'],
 ['test-member-entry.js'],['test-member-entry.js','--sqlite'],
 ['test-single-use.js','--member-entry'],['test-toast.js'],
 ['test-home-catalog.js'],['test-feed-shop-ui.js'],
 ['test-social-action-entitlements.js'],['test-social-action-entitlements.js','--sqlite'],
 ['test-wheel-retirement.js'],['test-wheel-retirement.js','--sqlite'],
 ['test-admin-workspace.js'],['test-web-rewards.js']
];
let failures=0;
for(const [name,...args]of checks){
 const r=spawnSync(process.execPath,[path.join(__dirname,name),...args],{cwd:path.resolve(__dirname,'..'),encoding:'utf8',timeout:name==='check-modules.js'?180000:60000,env:{...process.env,...(args.includes('--sqlite')?{STORAGE_ENGINE:'sqlite'}:{})}});
 const ok=r.status===0;console.log(`${ok?'PASS':'FAIL'} ${name} ${args.join(' ')}`.trim());
 if(!ok){failures++;console.error(r.error||(r.stdout||'')+(r.stderr||''));}
}
console.log(`${checks.length-failures}/${checks.length} current product checks passed. Delphi/Android execution is not included.`);
process.exitCode=failures?1:0;
