'use strict';
// Production-source geometry and authorization boundaries; no native runtime claim.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(native,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
function routine(text,name){const all=[...text.matchAll(/^(?:function|procedure|constructor|destructor)\s+([\w.]+)/gm)],at=all.findIndex(x=>x[1]===name);assert.ok(at>=0,name);return text.slice(all[at].index,all[at+1]?.index??text.length).replace(/\{[\s\S]*?\}/g,'');}
function before(text,a,b){assert.ok(text.indexOf(a)>=0&&text.indexOf(b)>text.indexOf(a),a+' precedes '+b);}
const source=read('MoaPlayApp.AuthSteps.inc'),ui=read('MoaPlayApp.Ui.inc'),bio=read('MoaPlayApp.BiometricBuild.inc'),wire=read('MoaPlayApp.Protocol.Biometric.inc');
const build=routine(source,'TMoaPlayForm.BuildAuthStepsUI'),resize=routine(source,'TMoaPlayForm.ResizeAuthStepsUI');
function calc(expr,ctx){const js=expr.replace(/\bMin\(/g,'Math.min(').replace(/\bMax\(/g,'Math.max(');assert.match(js,/^[\w\s.()+*/,-]+$/);return Function('ctx','with(ctx){return ('+js+')}')(ctx);}
function args(s){let d=0,start=0;const out=[];for(let i=0;i<s.length;i++){if(s[i]==='(')d++;else if(s[i]===')')d--;else if(s[i]===','&&!d){out.push(s.slice(start,i));start=i+1;}}out.push(s.slice(start));return out;}
const parents={};for(const m of build.matchAll(/(FAuth\w+)\s*:=\s*Ui(?:Rect|Label)\(Self,\s*(FAuth\w+|FRoot),/g))parents[m[1]]=m[2];for(const m of build.matchAll(/(FAuth\w+)\.Parent\s*:=\s*(FAuth\w+|FRoot)/g))parents[m[1]]=m[2];
let count=0;
for(const width of [240,280,320,360,390,412,480,600,800,1024])for(const height of [320,480,640,780,960]){
 const ctx={FRoot:{Width:Math.min(480,width),Height:height}};
 for(const variable of ['W','H','SocialY'])ctx[variable]=calc(new RegExp('\\b'+variable+':=([^;]+);').exec(resize)[1],ctx);
 const boxes={};for(const m of resize.matchAll(/(FAuth\w+)\.SetBounds\(([^;]+)\);/g)){const [x,y,w,h]=args(m[2]).map(v=>calc(v,ctx));boxes[m[1]]={x,y,w,h};assert.ok(w>0&&h>0,m[1]);}
 for(const [name,b]of Object.entries(boxes)){const parent=name==='FAuthStepsCard'?{w:ctx.FRoot.Width,h:ctx.H}:boxes[parents[name]];assert.ok(parent,name);assert.ok(b.x>=0&&b.y>=0&&b.x+b.w<=parent.w+0.001&&b.y+b.h<=parent.h+0.001,name+' stays within its parent');}
 for(const pair of [['FAuthStepsTitle','FAuthHero'],['FAuthHero','FAuthSocialPanel'],['FAuthSocialTitle','FAuthKakaoButton'],['FAuthKakaoButton','FAuthGoogleButton'],['FAuthGoogleButton','FAuthSocialHint']]){const a=boxes[pair[0]],b=boxes[pair[1]];assert.ok(a.y+a.h<=b.y,pair.join(' cannot overlap '));}
 for(const brand of ['Kakao','Google']){const icon=boxes['FAuth'+brand+'Icon'],label=boxes['FAuth'+brand+'Label'];assert.equal(icon.y+icon.h/2,label.y+label.h/2);assert.ok(icon.x+icon.w<=label.x);}
 if(ctx.H>height)assert.equal(parents.FAuthStepsCard,'FAuthStepsScroll');count++;
}
assert.match(build,/Bitmap.LoadFromFile/);assert.ok(fs.statSync(path.join(native,'Brand/auth-background.png')).size>100000);
assert.match(read('MoaPlay.dproj'),/Brand\\auth-background.png[\s\S]*?<RemoteDir>assets\\internal\\?<\/RemoteDir>/);
assert.match(routine(source,'TMoaPlayForm.AuthMotionTick'),/not FForeground/);assert.match(routine(source,'TMoaPlayForm.UpdateAuthSteps'),/FAuthMotion.Enabled:=ShowAccount and FForeground/);
const lifecycle=read('MoaPlayApp.Lifecycle.Construction.inc');assert.match(routine(lifecycle,'TMoaPlayForm.FormDeactivated'),/FAuthMotion.Enabled:=False/);assert.match(routine(lifecycle,'TMoaPlayForm.FormActivated'),/UpdateAuthSteps/);assert.match(routine(lifecycle,'TMoaPlayForm.Destroy'),/FAuthMotion.Enabled:=False/);
assert.doesNotMatch(source,/FAuthContinue|연결 상태 다시 확인/);
assert.match(read('MoaPlayMemberTouch.pas'),/FHighlight:=True/);assert.match(ui,/Result := TActionRectangle.Create/,'social buttons retain shared held press feedback');
for(const filename of fs.readdirSync(native).filter(n=>/\.(pas|inc|dpr)$/.test(n))){const value=read(filename);assert.doesNotMatch(value,/TMoaPlayDeviceCredential|CredentialClick|CredentialResult|createConfirmDeviceCredentialIntent/,filename+' contains no password fallback');}
const click=routine(bio,'TMoaPlayForm.BiometricContinueClick');
for(const guard of ['not PermissionsReady','not HubIdentityReady','not FState.Connected','not FState.LicenseAuthenticated','if not FState.BiometricAuthenticated'])before(click,guard,'SetAuthorizedUI');
assert.doesNotMatch(click,/Authenticated\s*:=\s*True|BuildBiometricHmac|BuildBiometricProofLine/);
assert.match(routine(bio,'TMoaPlayForm.StartBiometricAuthentication'),/FBiometricAuth.Authenticate/);
assert.match(routine(bio,'TMoaPlayForm.BiometricAuthenticateSuccess'),/BuildBiometricProofLine/);
const automatic=routine(bio,'TMoaPlayForm.TryAutomaticBuild');
for(const guard of ['not PermissionsReady','not HubIdentityReady','not FDeviceAuthVerified','not FState.LicenseAuthenticated','not FState.BiometricAuthenticated'])before(automatic,guard,'FRuntime.SendLine');
const access=read('MoaPlayApp.Member.Access.inc');assert.match(access,/FState.BiometricAuthenticated/);assert.doesNotMatch(access,/not FBiometricContinuePending/,'a second continuation tap no longer gates verified entry');
const authorized=routine(read('MoaPlayApp.QrAuth.inc'),'TMoaPlayForm.SetAuthorizedUI');
for(const guard of ['not PermissionsReady','not FDeviceAuthVerified','not FState.LicenseAuthenticated','not FState.BiometricAuthenticated','not HubIdentityReady'])before(authorized,guard,'EndAuthResume');
assert.doesNotMatch(authorized,/if FBiometricContinuePending then/);
const ok=wire.slice(wire.indexOf("if ALine.StartsWith('BIOMETRIC_OK|')"),wire.indexOf("if ALine.StartsWith('BIOMETRIC_ERROR|')"));
before(ok,'not FBiometricProofPending','FState.BiometricAuthenticated := True');
before(ok,'FState.BiometricAuthenticated := True','FBiometricContinuePending:=False');
before(ok,'FBiometricContinuePending:=False',"FUserProfile.MarkStage('MAIN')");before(ok,"FUserProfile.MarkStage('MAIN')",'SetAuthorizedUI');
assert.doesNotMatch(ok,/FBiometricContinuePending:=True|if FBiometricReturnToMain then begin/,'current server proof enters the main page without a continuation screen');
assert.match(routine(source,'TMoaPlayForm.HubIdentityReset'),/FBiometricContinuePending:=False;FBiometricReturnToMain:=False/);
assert.match(ui,/MoaBiometricArt/);assert.match(routine(ui,'TMoaPlayForm.ShowBiometricPanel'),/if Verified then begin SetAuthorizedUI;Exit;end/);assert.doesNotMatch(routine(ui,'TMoaPlayForm.ShowBiometricPanel'),/메인으로 이동/);
for(const filename of ['MoaPlayApp.AuthSteps.inc','MoaPlayApp.Ui.inc','MoaPlayApp.BiometricBuild.inc','MoaPlayApp.Protocol.Biometric.inc']){const bytes=fs.readFileSync(path.join(native,filename));assert.equal(bytes.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(bytes.toString(),/(?<!\r)\n/);}
console.log(`FIX74 AUTH UI PASS: ${count} source-derived viewport layouts; bundled photo/background motion lifecycle; provider button feedback; password fallback removal; current server proof enters main immediately; Build and native action guards remain. Delphi/Android runtime not executed.`);
