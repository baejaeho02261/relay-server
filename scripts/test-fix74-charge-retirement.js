'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-charge-retired-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.NODE_ENV='test';process.env.QR_APPROVAL_SECRET='test-only-entry-qr-signing-secret';
require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),state=require('../core/state'),admin=require('../services/member/admin'),center=require('../services/qrCenter');
const root=path.resolve(__dirname,'..');let webServer;
(async()=>{try{
 const p=s.Account({installationDeviceKey:'RETIRED-CHARGE-OWNER'});
 const oldId='CHG-123456789012345678901234';
 s.Atomic(()=>{const payment=s.Ledger(p,7500,'PAYMENT_TOPUP','HISTORICAL-PAYMENT');s.DB().chargeRequests[oldId]={id:oldId,accountId:p.id,status:'APPROVED',amount:7500,paymentId:payment.id,at:Date.now()-86400000};s.DB().settings.paymentOrders={old:{id:'old',accountId:p.id,status:'READY',amount:1000}};});
 s.Import({memberHub:structuredClone(s.DB())});
 const before=JSON.stringify(s.DB());
 for(const action of ['charge.scan','charge.approve','charge.reject','payment.start'])assert.throws(()=>admin.Write(action,{id:oldId,amount:1000},'TEST'),/TOPUP_UNAVAILABLE/);
 assert.throws(()=>admin.Read({view:'charges'}),/TOPUP_UNAVAILABLE/);
 assert.throws(()=>require('../services/member/identity').Read(s.ProfileById(p.id),{section:'charges'},true),/INPUT_INVALID/);
 for(const purpose of ['WALLET','ENTRY'])for(const method of ['Approve','Reject'])assert.throws(()=>center[method]({purpose,requestId:oldId,approvalToken:'OLD'},'TEST'),/QR_PURPOSE_MISMATCH/);
 assert.equal(JSON.stringify(s.DB()),before,'removed flows cannot mutate existing balances, ledgers or pending legacy records');
 assert.equal(center.List().some(x=>x.requestId===oldId),false,'legacy charge requests do not appear in entry approvals');
 assert.equal(Object.hasOwn(admin.Read({view:'integrations'}),'payments'),false);
 assert.equal(admin.Read({view:'ledger'}).items[0].kind,'PAYMENT_TOPUP','historical financial records remain available');
 const body={accountId:p.id,confirmedAccountId:p.id,confirmed:true,amount:1234,reason:'관리자 잔액 지급 테스트',requestId:'FIX74-ADMIN-GRANT-RETIRED'};
 const grant=admin.Write('wallet.grant',body,'TEST');assert.equal(s.ProfileById(p.id).balance,8734);assert.deepEqual(admin.Write('wallet.grant',body,'TEST'),grant);assert.equal(s.ProfileById(p.id).balance,8734);
 assert.equal(s.ProfileById(p.id).eventSpins||0,0,'administrator grants cannot trigger retired charge rewards');
 // The real image decoder and signed entry scanner still accept entry passes.
 const qr=require('../services/qrApproval'),QRCode=require('qrcode'),clientId='1234567890123456',requestId='QRA-123456789012345678901234',token=crypto.randomBytes(32).toString('base64url'),expiresAt=Date.now()+60000;
 state.qrAuthRequests.set(requestId,{requestId,clientId,deviceKey:'RETIRED-ENTRY',tokenHash:crypto.createHash('sha256').update(token).digest('hex'),issuedAt:Date.now(),expiresAt,status:'PENDING',scanCount:0});
 const scanned=center.Scan(await QRCode.toDataURL(qr.BuildPayload(requestId,clientId,expiresAt,token),{errorCorrectionLevel:'H',scale:6}));
 assert.equal(scanned.purpose,'ENTRY');assert.equal(scanned.request.requestId,requestId);assert.ok(scanned.approvalToken);
 const legacyImage=await QRCode.toDataURL('QRC1.'+oldId+'.'+token,{errorCorrectionLevel:'H',scale:6});
 assert.throws(()=>center.Scan(legacyImage),/QR_/,'old charging QR must never turn into a device approval');
 assert.equal(center.List().length,1);assert.equal(center.Summary().pending,1);
 // Old browser checkout / return / webhook URLs have no settlement handler.
 const reservation=net.createServer();await new Promise(resolve=>reservation.listen(0,'127.0.0.1',resolve));const port=reservation.address().port;await new Promise(resolve=>reservation.close(resolve));
 const config=require('../config/config');config.HOST='127.0.0.1';config.WEB_ADMIN_PORT=port;
 webServer=require('../web/webServer').StartWebAdmin();await new Promise(resolve=>webServer.listening?resolve():webServer.once('listening',resolve));
 const preserved=JSON.stringify(s.DB());
 for(const [method,url]of [['GET','/pay/start/old/token'],['GET','/pay/return/old/token/complete?paymentKey=old'],['POST','/pay/webhook/kakao'],['POST','/pay/webhook/toss']]){
  const response=await fetch('http://127.0.0.1:'+port+url,{method});assert.equal(response.status,410);assert.equal((await response.json()).code,'TOPUP_UNAVAILABLE');
 }
 assert.equal(JSON.stringify(s.DB()),preserved,'old callbacks cannot mint money or change legacy records');
 for(const name of ['payments.js','payment-provider.js','payment-http.js','charges.js'])assert.equal(fs.existsSync(path.join(root,'services/member',name)),false);
 for(const name of ['admin-member-accounts.js','admin-pages-qr.js','admin-actions-access.js']){
  const ui=fs.readFileSync(path.join(root,'public',name),'utf8');assert.doesNotMatch(ui,/카카오페이|토스페이|KAKAOPAY|TOSSPAYMENTS|charge\.approve|잔액 충전/);
 }
 console.log('FIX74 CHARGE RETIREMENT PASS: no checkout/provider/QR-credit paths, HTTP 410 callbacks, preserved balance/ledger, idempotent admin grants, signed entry QR still works.');
}finally{if(webServer)await new Promise(resolve=>webServer.close(resolve));fs.rmSync(temp,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
