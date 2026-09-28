'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(base,name),'utf8');
const catalog=read('MoaPlayApp.Member.NewsShop.inc'),tap=read('MoaPlayCatalogCard.pas');
const download=read('MoaPlayApp.Member.Download.inc'),store=read('MoaPlayGameDownloads.pas');
const window=read('MoaPlayApp.Member.GameWindow.inc'),pass=read('MoaPlayPassWindow.pas');
// One game has one visible single-use card. Only the explicit button spends money.
assert.doesNotMatch(catalog,/for Days in \[1,7,15,30\]|HubOpenPurchaseConfirm|OnBuy|HubCatalogCardLongPress/);
assert.match(catalog,/HubButton\(C,MemberCaption\('구매하기'\),'product\.purchase\|'/);
assert.match(catalog,/FMember\.HasPending[\s\S]*Body\.AddPair\('productId'[\s\S]*Body\.AddPair\('price'[\s\S]*Body\.AddPair\('revision'[\s\S]*FMember\.Request\('purchase',Body\.ToJSON,True\)/);
assert.doesNotMatch(catalog,/Body\.AddPair\('days'/);
assert.doesNotMatch(tap,/FHoldTimer|BuyNow|OnBuy/);
assert.match(tap,/MouseUp[\s\S]*StopPending;inherited/);
// Real game photos form a horizontal rounded carousel with a next-card preview.
assert.match(catalog,/THorzScrollBox\.Create/);assert.match(catalog,/InfoW\*0\.84/);
assert.match(catalog,/Picture\.Corners:=\[TCorner.TopLeft,TCorner.TopRight\]/);
assert.match(catalog,/Footer\.Corners:=\[TCorner.BottomLeft,TCorner.BottomRight\]/);
assert.match(catalog,/Canvas\.DrawBitmap\(Source,Crop/);
// The Android public destination is random, with no original name, date or prefix.
const name=store.match(/function OpaqueDownloadName:string;([\s\S]*?)constructor TMoaPlayGameDownloads/)[1];
assert.match(name,/CreateGUID\(ID\)/);assert.match(name,/LowerCase\(GUIDToString\(ID\)\)/);
for(const ch of ['{','}','-'])assert.ok(name.includes("'"+ch+"',''"));
assert.match(name,/\+'\.exe'/);
assert.match(store,/LocalName:=OpaqueDownloadName;[\s\S]*setDestinationInExternalPublicDir\(StringToJString\('Download'\),StringToJString\(LocalName\)\)/);
assert.doesNotMatch(store,/MoaPlay-'\+FormatDateTime|FileName\)\)\s*;/);
assert.match(store,/Total<>ExpectedBytes[\s\S]*SameText\(Hash,ExpectedHash\)/);
// PC readiness is server-issued and requires the independently verified local build proof.
assert.match(download,/HubBool\(Item,'connectionReady'\)[\s\S]*FState\.BiometricAuthenticated[\s\S]*FState\.BuildSessionID<>''[\s\S]*FState\.BuildSessionExpiresAt>FState\.CurrentUnixMilliseconds/);
assert.match(download,/if Verified then RequestAction:='order.start'/);
assert.match(download,/RequestAction:='order.activate'/);
assert.match(download,/if Action='order.start'[\s\S]*HubText\(Data,'accountId'\)<>AccountID[\s\S]*HubText\(Order,'status'\)<>'ACTIVE'[\s\S]*not HubBool\(Order,'connectionReady'\)/);
const prepared=download.slice(download.indexOf('procedure TMoaPlayForm.HubGameDownloadActivated'));
assert.doesNotMatch(prepared,/HubOpenGameWindow/,'biometric/preparation callbacks must not consume or auto-open');
assert.match(window,/HubText\(Item,'status'\)='ACTIVE'[\s\S]*HubBool\(Item,'connectionReady'\)[\s\S]*HubNumber\(Item,'sessionExpiresAt'\)>NowAt/);
assert.doesNotMatch(pass,/남은 이용 시간|일 이용|PassNumber\(Game,'days'\)|PassNumber\(Game,'expiresAt'\)/);
assert.match(pass,/1회 이용 중/);
console.log('FIX74 native commerce source checks PASS: one-use, explicit purchase, phone-only opaque downloads, verified PC start, carousel.');
