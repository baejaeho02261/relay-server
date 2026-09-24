'use strict';
// Native-source geometry and lifecycle guards; this is not a Delphi execution test.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(native,n),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const source=read('MoaPlayApp.AuthSteps.inc'),ui=read('MoaPlayApp.Ui.inc');
function part(s,a,b){const i=s.indexOf(a),j=s.indexOf(b,i+a.length);assert.ok(i>=0&&j>i,a);return s.slice(i,j);}
function calc(expr,values){const js=expr.replace(/\bMin\b/g,'Math.min').replace(/\bMax\b/g,'Math.max').replace(/FRoot\.(Width|Height)/g,(_,x)=>'Root'+x);assert.match(js,/^[\w\s.()+*/,-]+$/);return Function(...Object.keys(values),`return (${js})`)(...Object.values(values));}
const build=part(source,'procedure TMoaPlayForm.BuildAuthStepsUI','procedure TMoaPlayForm.ResizeAuthStepsUI');
const resize=part(source,'procedure TMoaPlayForm.ResizeAuthStepsUI','procedure TMoaPlayForm.UpdateAuthSteps');
const update=part(source,'procedure TMoaPlayForm.UpdateAuthSteps','procedure TMoaPlayForm.AuthStepClick');
const provider=source.slice(source.indexOf('procedure TMoaPlayForm.AuthProviderClick'));
const rootResize=part(ui,'procedure TMoaPlayForm.ResizeQrLayout','procedure TMoaPlayForm.ShowBiometricPanel');
const rootW=rootResize.match(/RootWidth := ([^;]+);/)[1],rootH=rootResize.match(/RootHeight := ([^;]+);/)[1];
const rootX=rootResize.match(/FRoot.SetBounds\((Max\(0,\(ClientWidth-RootWidth\)\/2\)),0,RootWidth,RootHeight\)/)[1];
const expressions=Object.fromEntries([...resize.matchAll(/^  (W|HeaderHeight|RowHeight|H|Y) := ([^;]+);/gm)].map(x=>[x[1],x[2]]));
let cases=0;
for(const ClientWidth of [240,280,320,360,390,412,480,600,800,1024])for(const ClientHeight of [320,480,640,780,960]){
 const vars={ClientWidth,ClientHeight};vars.RootWidth=calc(rootW,vars);vars.RootHeight=calc(rootH,vars);
 const left=calc(rootX,vars);assert.equal(vars.RootWidth,Math.min(480,ClientWidth));assert.equal(left,(ClientWidth-vars.RootWidth)/2);
 assert.equal(vars.RootHeight,ClientHeight);assert.ok(left+vars.RootWidth<=ClientWidth);
 for(const name of ['W','HeaderHeight','RowHeight','H','Y'])vars[name]=calc(expressions[name],vars);
 const {W,HeaderHeight,RowHeight,H,Y,RootWidth,RootHeight}=vars;
 assert.ok(W>0&&W<=RootWidth-40);assert.ok(H>=600);
 let previousBottom=0;
 for(let I=0;I<3;I++){
  const RowTop=HeaderHeight+I*RowHeight;assert.ok(RowTop>=previousBottom);previousBottom=RowTop+RowHeight;
  const titleW=calc(resize.match(/FAuthStepTitles\[I\].SetBounds\(52,0,(Max\(1,W - 104\)),24\)/)[1],vars);
  assert.ok(titleW>0&&52+titleW<=W-44);assert.ok(25+Math.max(24,RowHeight-32)<=RowHeight);
  if(I<2)assert.ok(RowTop+45+Math.max(1,RowHeight-50)<RowTop+RowHeight+3);
 }
 assert.ok(Y>=previousBottom);assert.ok(Y+48<Y+72);assert.equal(Y+72+166,H,'social footer fits the actual scrollable card');
 for(const [top,height] of [[30,48],[88,48],[144,22]])assert.ok(top+height<=166);
 assert.ok(16+22<=44);assert.ok(44+Math.max(1,W-60)<=W,'brand text and vector icon cannot overlap');
 const cardY=Math.max(16,(RootHeight-H)/2);
 if(cardY+H>RootHeight)assert.match(build,/FAuthStepsCard.Parent := FAuthStepsScroll/,'short windows can scroll to both branded actions');
 cases++;
}
assert.match(build,/FAuthStepsScroll.Align := TAlignLayout.Client/);
assert.match(build,/FAuthStepVisualState\[I\] := -1/);
assert.equal((build.match(/TFloatAnimation.Create/g)||[]).length,2,'one retained slide/fade pair per row');
assert.equal((build.match(/\.Loop := False/g)||[]).length,2);
assert.doesNotMatch(update,/TFloatAnimation.Create|TTimer.Create/,'polls must not allocate animations/timers');
const transitions=part(update,'if FAuthStepVisualState[I] <> VisualState then','    FAuthStepCircles[I].Stroke.Color := MemberBorder;');
assert.match(transitions,/FAuthStepVisualState\[I\] := VisualState/);
assert.equal((transitions.match(/\.Start;/g)||[]).length,2);assert.equal((update.match(/\.Start;/g)||[]).length,2,'only state transitions start animations');
assert.doesNotMatch(resize,/FAuthStepRows\[I\]\.Position\.X\s*:=|FAuthStepRows\[I\]\.Opacity\s*:=/,'periodic layout cannot interrupt in-flight motion');
assert.match(update,/if Completed\[I\] then FAuthStepLines\[I\].Fill.Color := MemberLink/);
assert.match(update,/if FAuthStepIcons\[I\].TagString <> ColorText then/,'SVG rebuilding is theme-dependent, not every auth poll');
assert.match(update,/Granted := Connected and LicenseOK and FPermissionsServerGranted and/);
assert.match(update,/FMemberTestGranted and \(FMemberTestChallenge = FPermissionAuthID\)/);
assert.doesNotMatch(source,/(?:LicenseAuthenticated|BiometricAuthenticated|FMemberTestGranted|FPermissionsServerGranted)\s*:=\s*True/i);
assert.match(build,/\$FFFEE500/);assert.match(build,/FAuthGoogleButton := UiRect\(Self, FAuthSocialPanel, \$FFFFFFFF/);
assert.match(provider,/Provider = 'kakao'/);assert.match(provider,/Provider = 'google'/);
assert.equal((provider.match(/AndroidToast/g)||[]).length,2);
assert.doesNotMatch(provider,/Request\(|MemberTest|AuthID|License|Biometric|ShowFinalPage|ShellExecute|OpenURL/,'deferred provider buttons cannot create sign-in success or replace device approval');
const {JSDOM}=require('jsdom');
for(const name of ['Kakao','Google']){
 const match=source.match(new RegExp('FAuth'+name+'Icon.Svg.Source := ([\\s\\S]*?);'));assert.ok(match);
 const svg=[...match[1].matchAll(/'([^']*)'/g)].map(x=>x[1]).join('');
 const document=new JSDOM(svg,{contentType:'image/svg+xml'}).window.document;
 assert.equal(document.querySelectorAll('parsererror,image,script,foreignObject,a').length,0);
 assert.ok(document.querySelectorAll('path').length>=1);
 if(name==='Google')assert.equal(new Set([...document.querySelectorAll('path')].map(n=>n.getAttribute('fill'))).size,4);
}
for(const file of ['MoaPlayApp.AuthSteps.inc','MoaPlayApp.Ui.inc']){const b=fs.readFileSync(path.join(native,file));assert.equal(b.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(b.toString('utf8'),/(?<!\r)\n/);}
console.log(`FIX70 AUTH LAYOUT PASS: ${cases} source-derived viewport/scroll layouts, retained state-only slide/fade, theme-cached vectors, branded pending sign-in actions and preserved server grants.`);
