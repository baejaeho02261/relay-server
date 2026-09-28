'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const file=path.resolve(__dirname,'../../MoaPlayApp_Android64/MoaPlayApp.Member.MyPage.inc');
const bytes=fs.readFileSync(file),source=bytes.toString('utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
function section(a,b){const at=source.indexOf(a),end=source.indexOf(b,at+a.length);assert.ok(at>=0&&end>at);return source.slice(at,end);}
const own=section('procedure TMoaPlayForm.HubRenderMe','procedure TMoaPlayForm.HubRenderMember');
const peer=section('procedure TMoaPlayForm.HubRenderMember','procedure TMoaPlayForm.HubRenderInfo');
assert.doesNotMatch(own,/HubProfileStat\(|HubProfileSuggestions\(|HubProfileTabs\(|HubRenderOwnComments\(|HubRenderProfileGallery\(/,'the owner page cannot mount removed social counters or content');
assert.match(peer,/if Own then begin HubRenderMe\(Data\);Exit;end;/,'opening my profile through a public profile link uses the same owner page');
assert.match(peer,/HubBool\(Data,'profilePostsHidden'\)/,'public member privacy guard remains');
assert.match(peer,/HubProfileTabs\(FHubPage,False,ID,FHubY\)/,'other members retain their public content');
assert.doesNotMatch(peer,/accountEmail|providerAccountEmail/,'private provider email has no peer renderer');
assert.match(own,/Email:=Trim\(HubText\(Profile,'accountEmail'\)\)/);
assert.match(own,/if Email<>'' then begin/,'missing or unconsented email is not invented');
assert.match(own,/OrbitAction\('edit','profile','프로필 편집'/);
assert.match(own,/OrbitAction\('share','profile.share','프로필 공유'/);
assert.doesNotMatch(own,/profile\.people|profile\.create|HubButton\(/,'owner actions are icons and account addition opens the account picker');
assert.equal((own.match(/HubTextAction\(Hero,'','profile.account'/g)||[]).length,2);
assert.match(own,/Provider='kakao'/);assert.match(own,/Provider='google'/);
assert.match(own,/BrandFill:=\$FFFEE500/);assert.match(own,/BrandFill:=\$FFE8F0FE/);
function expression(name){const match=own.match(new RegExp('\\b'+name+':=([^;]+);'));assert.ok(match,`missing ${name}`);return match[1];}
function evaluate(expr,scope){const js=expr.replace(/\bMin\b/g,'Math.min').replace(/\bMax\b/g,'Math.max');assert.match(js,/^[\w\s.()+*/,-]+$/);return Function(...Object.keys(scope),`return (${js})`)(...Object.values(scope));}
const geometry=['GroupW','GroupX','AvatarSize','AvatarX','ActionX','InfoX','InfoW'];
let checked=0;
for(const width of [240,280,320,360,390,412,480,600,800,1024])for(const provider of ['kakao','google',''])for(const hasEmail of [true,false]){
 const C={Width:width},Hero={Width:width-32};const values={C,Hero};
 for(const name of geometry)values[name]=evaluate(expression(name),values);
 const {GroupW,GroupX,AvatarSize,AvatarX,ActionX,InfoX,InfoW}=values;
 const ProviderW=provider==='google'?60:provider==='kakao'?54:0;
 let AccountY=evaluate(expression('AccountY'),values),EmailY=evaluate(expression('EmailY'),values),AccountW=InfoW;
 if(provider){if(InfoW>=150)AccountW=InfoW-ProviderW-6;else EmailY=127;}
 const AddY=EmailY+(hasEmail?43:0),InfoBottom=AddY+28;
 Hero.Height=Math.max(190,InfoBottom+22);values.InfoBottom=InfoBottom;
 const AvatarY=evaluate(expression('AvatarY'),values);
 assert.ok(Math.abs(GroupX-(Hero.Width-GroupW)/2)<1e-6,'whole identity group stays centered');
 assert.ok(AvatarX>=0&&AvatarX+AvatarSize<InfoX,'portrait remains separate from the identity');
 assert.ok(InfoW>=68,'small phones retain usable identity space');
 assert.ok(AccountW>=54,'account chip never collapses beneath its text inset');
 assert.ok(InfoX+InfoW<=Hero.Width-12+1e-6,'identity has a trailing gutter');
 for(const [x,y]of [[ActionX,AvatarY-22],[ActionX+2,AvatarY+AvatarSize-18]]){
  assert.ok(x>=0&&x+40<=InfoX-2,'orbit hit targets cannot intercept identity inputs');
  assert.ok(y>=0&&y+40<=Hero.Height,'both action targets remain fully inside the hero');
 }
 if(provider&&InfoW<150)assert.ok(ProviderW<=InfoW&&AccountY+34+28<=EmailY,'stacked provider badge clears the email');
 if(provider&&InfoW>=150)assert.ok(AccountW+6+ProviderW<=InfoW+1e-6,'inline provider badge fits');
 assert.ok(AddY>=AccountY+28+6,'add-account chip never overlaps the account chip');
 assert.ok(AddY+28<=Hero.Height-20,'last chip is not clipped by the card');
 checked++;
}
assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);
assert.equal(bytes.toString().replace(/\r\n/g,'').includes('\n'),false,'Delphi source uses CRLF and UTF-8 BOM');
console.log(`FIX74 profile PASS: ${checked} responsive provider/email layouts, functional owner actions, no removed owner social UI, preserved peer privacy.`);
