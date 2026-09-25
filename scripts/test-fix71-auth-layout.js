'use strict';
// Production-derived native geometry and source security contracts; no Delphi runtime claim.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(native,n),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const source=read('MoaPlayApp.AuthSteps.inc'),ui=read('MoaPlayApp.Ui.inc'),dashboard=read('MoaPlayApp.Dashboard.inc'),client=read('MoaPlayMemberClient.pas');
function routine(text,name){const all=[...text.matchAll(/^(?:function|procedure|constructor|destructor)\s+([\w.]+)/gm)],at=all.findIndex(m=>m[1]===name);assert.ok(at>=0,name);return text.slice(all[at].index,all[at+1]?.index??text.length).replace(/\{[\s\S]*?\}/g,'');}
const build=routine(source,'TMoaPlayForm.BuildAuthStepsUI'),resize=routine(source,'TMoaPlayForm.ResizeAuthStepsUI'),rootResize=routine(ui,'TMoaPlayForm.ResizeQrLayout');
function calc(expr,values){const js=expr.replace(/\bMin\(/g,'Math.min(').replace(/\bMax\(/g,'Math.max(');assert.match(js,/^[\w\s.()+*/,-]+$/);return Function('ctx','with(ctx){return ('+js+')}')(values);}
function args(s){let depth=0,start=0;const out=[];for(let i=0;i<s.length;i++){if(s[i]==='(')depth++;else if(s[i]===')')depth--;else if(s[i]===','&&depth===0){out.push(s.slice(start,i));start=i+1;}}out.push(s.slice(start));assert.equal(depth,0);return out;}
const parents={};for(const m of build.matchAll(/(FAuth\w+)\s*:=\s*Ui(?:Rect|Label)\(Self,\s*(FAuth\w+|FRoot),/g))parents[m[1]]=m[2];
for(const m of build.matchAll(/(FAuth\w+)\.Parent\s*:=\s*(FAuth\w+|FRoot)/g))parents[m[1]]=m[2];
const calls=[...resize.matchAll(/(FAuth\w+)\.SetBounds\(([^;]+)\);/g)];assert.ok(calls.length>=14);
let cases=0,scrollCases=0;
for(const ClientWidth of [240,280,320,360,390,412,480,600,800,1024])for(const ClientHeight of [320,480,640,780,960]){
 const ctx={ClientWidth,ClientHeight};
 ctx.RootWidth=calc(/RootWidth\s*:=\s*([^;]+);/.exec(rootResize)[1],ctx);ctx.RootHeight=calc(/RootHeight\s*:=\s*([^;]+);/.exec(rootResize)[1],ctx);
 assert.equal(ctx.RootWidth,Math.min(480,ClientWidth));assert.equal(ctx.RootHeight,ClientHeight);
 const rootArgs=args(/FRoot.SetBounds\(([^;]+)\);/.exec(rootResize)[1]).map(x=>calc(x,ctx));
 assert.equal(rootArgs[0],(ClientWidth-ctx.RootWidth)/2,'center the restored narrow viewport');
 ctx.FRoot={Width:ctx.RootWidth,Height:ctx.RootHeight};ctx.W=calc(/W:=([^;]+);/.exec(resize)[1],ctx);
 const controls={};for(const call of calls){const [x,y,w,h]=args(call[2]).map(x=>calc(x,ctx));controls[call[1]]={x,y,w,h};assert.ok(w>0&&h>0,call[1]+' has positive bounds');}
 for(const m of resize.matchAll(/(FAuth\w+)\.Height:=([^;]+);/g))controls[m[1]].h=calc(m[2],ctx);
 const card=controls.FAuthStepsCard;assert.ok(card.x>=0&&card.x+card.w<=ctx.RootWidth);
 for(const [name,r] of Object.entries(controls)){
  if(name==='FAuthStepsCard')continue;
  const parent=controls[parents[name]];assert.ok(parent,name+' parent is present');
  assert.ok(r.x>=0&&r.y>=0&&r.x+r.w<=parent.w&&r.y+r.h<=parent.h,name+' remains inside '+parents[name]);
 }
 for(const names of [
  ['FAuthStepsTitle','FAuthHero','FAuthStepsHint','FAuthFeatures','FAuthSocialPanel','FAuthContinue','FAuthFooter'],
  ['FAuthSocialTitle','FAuthKakaoButton','FAuthGoogleButton','FAuthSocialHint']
 ])for(let i=1;i<names.length;i++){const a=controls[names[i-1]],b=controls[names[i]];assert.ok(a.y+a.h<=b.y,names[i-1]+' cannot overlap '+names[i]);}
 for(const brand of ['Kakao','Google']){const icon=controls['FAuth'+brand+'Icon'],label=controls['FAuth'+brand+'Label'];assert.ok(icon.x+icon.w<=label.x,'brand glyph does not overlap button text');assert.equal(icon.y+icon.h/2,label.y+label.h/2,'brand label/glyph vertical center');}
 if(card.y+card.h>ctx.RootHeight){assert.equal(parents.FAuthStepsCard,'FAuthStepsScroll');assert.match(build,/FAuthStepsScroll.Align:=TAlignLayout.Client/);scrollCases++;}
 cases++;
}
assert.doesNotMatch(source,/TFloatAnimation|FAuthStepRows|FAuthStepCircles|FAuthStepLines|\.Start;/,'step indicators and slide/fade animation removed');
assert.match(build,/FAuthStepsScroll.AniCalculations.Animation:=False/);
assert.match(build,/\$FFFEE500/);assert.match(build,/FAuthGoogleButton := UiRect\(Self, FAuthSocialPanel, \$FFFFFFFF/);
const {JSDOM}=require('jsdom');for(const name of ['Kakao','Google']){const m=source.match(new RegExp('FAuth'+name+'Icon.Svg.Source := ([\\s\\S]*?);'));assert.ok(m);const svg=[...m[1].matchAll(/'([^']*)'/g)].map(x=>x[1]).join('');const doc=new JSDOM(svg,{contentType:'image/svg+xml'}).window.document;assert.equal(doc.querySelectorAll('parsererror,image,script,foreignObject,a').length,0);assert.ok(doc.querySelector('path'));if(name==='Google')assert.equal(new Set([...doc.querySelectorAll('path')].map(p=>p.getAttribute('fill'))).size,4);}
const provider=routine(source,'TMoaPlayForm.AuthProviderClick'),reply=routine(source,'TMoaPlayForm.HubIdentityReply'),request=routine(source,'TMoaPlayForm.HubIdentityRequest');
assert.match(provider,/HubIdentityRequest\('identity.start',Body.ToJSON\)/);assert.doesNotMatch(provider,/FIdentityLinked:=True|Authenticated\s*:=\s*True|ShowFinalPage/);
assert.match(request,/FMember.SetSession\(FState.ClientID,FPermissionAuthID,FSecurity\)/);
assert.ok(reply.indexOf('FIdentityRequestChallenge<>FPermissionAuthID')<reply.indexOf('FIdentityLinked:=True'),'reject prior challenge before accepting identity');
assert.ok(reply.indexOf("if not HubBool(Obj,'ok')")<reply.indexOf('FIdentityLinked:=True'));
assert.ok(reply.indexOf("if HubBool(Identity,'linked')")<reply.indexOf('RequestQrAuthorization'),'QR follows the verified server-linked account');
assert.match(reply,/if FState.LicenseAuthenticated then begin ShowRestoredBiometricPage;QueueBiometricAuthentication;end/);
assert.doesNotMatch(source,/(?:LicenseAuthenticated|BiometricAuthenticated|FMemberTestGranted|FPermissionsServerGranted)\s*:=\s*True/i,'provider clicks cannot locally grant protected state');
const wire=routine(client,'TMoaPlayMemberClient.HandleLine');assert.ok(wire.indexOf('if Difference <> 0 then Exit')<wire.indexOf('Deliver(P[1],P[2],Decoded)'),'HMAC verified before identity callbacks');assert.match(wire,/FChallengeID/);
const qr=routine(read('MoaPlayApp.QrAuth.inc'),'TMoaPlayForm.RequestQrAuthorization');assert.ok(qr.indexOf('not HubIdentityReady')<qr.indexOf('BuildQrAuthResumeLine'));
const bio=read('MoaPlayApp.BiometricBuild.inc'),credential=routine(bio,'TMoaPlayForm.CredentialResult');
assert.match(credential,/FCredentialClientID<>FState.ClientID/);assert.match(credential,/FCredentialChallengeID<>FPermissionAuthID/);assert.match(credential,/FBiometricPromptNonce<>FBiometricNonce/);assert.match(credential,/BiometricAuthenticateSuccess\(Self\)/);
assert.doesNotMatch(bio,/BiometricAuthenticated\s*:=\s*True/,'platform success sends proof, never local access grant');
const back=routine(dashboard,'TMoaPlayForm.SystemBackKey'),branches=[...back.matchAll(/\(FHubExitAt=0\) or \(HubAuthTick-FHubExitAt>(\d+)\) then begin\s*FHubExitAt:=HubAuthTick;Key:=0;AndroidToast\(MemberCaption\('([^']+)'\)\);\s*end else FHubExitAt:=0;/g)];
assert.equal(branches.length,2,'both account screen and main root require a second back press');
for(const branch of branches){const limit=Number(branch[1]);assert.equal(limit,2000);assert.match(branch[2],/한 번 더/);let at=0;function press(now){const intercepted=at===0||now-at>limit;if(intercepted)at=now;else at=0;return intercepted;}
 assert.equal(press(1000),true);assert.equal(press(1800),false);assert.equal(press(2400),true);assert.equal(press(4601),true);assert.equal(press(4700),false);}
assert.ok(back.indexOf('FHubOverlay.Visible')<back.indexOf('FHubExitAt=0'),'overlays consume back before the exit gate');
for(const file of ['MoaPlayApp.AuthSteps.inc','MoaPlayApp.Ui.inc']){const b=fs.readFileSync(path.join(native,file));assert.equal(b.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(b.toString('utf8'),/(?<!\r)\n/);}
console.log(`FIX71 AUTH LAYOUT PASS: ${cases} production-derived viewports (${scrollCases} scrollable), no footer/brand overlap, restored narrow root, no step animations, actual signed account→QR→system credential guards, and both double-back exit gates. Native runtime not executed.`);
