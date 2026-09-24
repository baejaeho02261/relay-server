'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix70-retirement-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),service=require('../services/member/service'),rewards=require('../services/member/rewards'),badges=require('../services/member/badges');
function client(){const id='0000000000007070',key='FIX70-RETIREMENT',c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
let serial=0;const run=(c,action,body={})=>service.Execute(c,'FIX70-RETIRE-'+(++serial),action,body);
try{
 const c=client();run(c,'me');const p=s.Account(c);
 s.Atomic(()=>{
  p.balance=76543;p.points=1234;p.eventSpins=3;
  p.arcade={BACCARAT:{played:99,lastResult:{id:'OLD-HAND'}}};p.casino={CRASH:{played:50,active:{id:'OLD-ROUND',betAmount:1000}}};
  p.skillEvents={games:{DINO:{played:2,bestScore:50}},sessions:[{id:'OLD-SESSION',status:'ACTIVE'}]};
  s.DB().ledger['OLD-LEDGER']={id:'OLD-LEDGER',accountId:p.id,kind:'ARCADE_WIN',amount:2000,at:1};
  s.DB().pointLedger['OLD-POINTS']={id:'OLD-POINTS',accountId:p.id,kind:'EVENT_DINO',amount:50,at:1};
  badges.Capture(p);p.badgeProgress.awards.BACCARAT_1={at:1,rewardPaid:true,rewardPoints:50};
 });
 const before=JSON.stringify(s.DB());
 for(const action of ['arcade','arcade.play','casino','casino.play','casino.start','casino.action','event.start','event.finish','event.play']){
  assert.throws(()=>run(c,action,{game:'CRASH',revision:1}),/UNKNOWN_ACTION/,action+' must no longer execute');
  assert.equal(JSON.stringify(s.DB()),before,action+' rejection must not mutate balances, records, awards or pending legacy states');
 }
 const wallet=require('../services/member/wallet').Read(p);assert.equal(wallet.balance,76543);assert.equal(wallet.points,1234);assert.equal(wallet.eventSpins,3);
 assert.deepEqual(require('../services/member/withdrawals').Read(p).wallet,wallet,'normal wallet/withdrawal survives engine deletion');
 const visible=badges.Read(p).items||badges.Read(p).badges||[];
 assert.ok(!JSON.stringify(visible).includes('BACCARAT_1'),'retired missions are not available for new earning or selection');
 const services=require('../services/member/history').SERVICES;
 for(const key of ['events','playground','casino','original','baccarat','roulette','slots','blackjack','crash','dice','mines','plinko','limbo','hilo','tower','event.dino','event.flappy','event.whack','event.dodge','event.rhythm'])assert.ok(!Object.hasOwn(services,key),key+' is not a visitable service');
 assert.ok(Object.hasOwn(services,'wheel'),'reward wheel keeps its own route');
 const prior={arcade:structuredClone(p.arcade),casino:structuredClone(p.casino),skillEvents:structuredClone(p.skillEvents),ledger:structuredClone(s.DB().ledger['OLD-LEDGER']),point:structuredClone(s.DB().pointLedger['OLD-POINTS']),award:structuredClone(p.badgeProgress.awards.BACCARAT_1)};
 const spin=run(c,'event.spin',{revision:rewards.Rules().revision});assert.ok(spin.spin.points>0);assert.equal(p.eventSpins,2);assert.equal(p.balance,76543);assert.ok(p.points>=1234+spin.spin.points);assert.ok(!Object.hasOwn(spin,'eventGames'));
 for(const key of ['arcade','casino','skillEvents'])assert.deepEqual(p[key],prior[key],'retirement preserves opaque legacy '+key);
 assert.deepEqual(s.DB().ledger['OLD-LEDGER'],prior.ledger);assert.deepEqual(s.DB().pointLedger['OLD-POINTS'],prior.point);assert.deepEqual(p.badgeProgress.awards.BACCARAT_1,prior.award);
 assert.ok(rewards.History(p).items.some(row=>row.id==='OLD-POINTS'),'earned historical points remain visible');
 const once=JSON.stringify(s.DB());assert.throws(()=>run({...c,biometricVerified:false},'event.spin',{revision:rewards.Rules().revision}),/MEMBER_AUTH_REQUIRED/);assert.equal(JSON.stringify(s.DB()),once,'wheel still requires authorized membership');
 const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
 for(const file of ['MoaPlayCasinoBoard.pas','MoaPlayCasinoAmount.pas','MoaPlayCasinoIndicators.pas','MoaPlaySkillGames.pas','MoaPlayApp.Member.Events.inc','MoaPlayApp.Member.EventGames.inc','MoaPlayApp.Member.Playground.inc','MoaPlayApp.Member.Casino.inc','MoaPlayApp.Member.Blackjack.inc','MoaPlayApp.Member.Indicators.inc'])assert.ok(!fs.existsSync(path.join(native,file)),file+' source removed');
 for(const file of ['arcade.js','casino.js','eventEngine.js','eventGames.js','indicators.js'])assert.ok(!fs.existsSync(path.resolve(__dirname,'../services/member',file)),file+' engine removed');
 if(!process.argv.includes('--backend-only')){
  const read=name=>fs.readFileSync(path.join(native,name),'utf8');
  for(const file of ['MoaPlayApp.pas','MoaPlayApp.Fields.inc','MoaPlayApp.Methods.inc','MoaPlayApp.Member.Flow.inc','MoaPlayApp.Member.Actions.inc'])assert.doesNotMatch(read(file),/MoaPlay(?:Casino|SkillGames)|Hub(?:Casino|Blackjack|Arcade|EventGame)|FHub(?:Casino|Arcade|EventBoards)/,file+' no disconnected feature hooks');
  const wheel=read('MoaPlayApp.Member.Rewards.inc');assert.match(wheel,/procedure TMoaPlayForm.HubWheelStop/);assert.match(wheel,/CancelAnimation/);assert.match(wheel,/CountText:=' · '/);assert.doesNotMatch(wheel,/최근 당첨|참여 가능 %d회/);
  assert.match(read('MoaPlayApp.Member.Flow.inc'),/AndroidToast\(MemberFormat\('돌림판 당첨 · %s P'/,'wheel win appears as a toast on confirmed acknowledgement');
 }
 console.log('FIX70 retirement PASS: removed engine routes cannot mutate, original balances/ledgers/awards retained, standalone wallet survives, wheel remains authorized and rewards server-side, obsolete native code removed.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
