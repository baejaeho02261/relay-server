'use strict';
// Source-derived layout/dispatch regression, not a replacement for Delphi or
// native GPU/IME verification. Existing crop and quote tests cover shared paths.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const dir=path.join(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(dir,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const feed=read('MoaPlayApp.Member.Feed.inc'),news=read('MoaPlayApp.Member.NewsShop.inc');
const section=(s,a,b)=>{const from=s.indexOf(a),to=s.indexOf(b,from+a.length);assert.ok(from>=0&&to>from);return s.slice(from,to);};
// FIX66 deliberately restores compact feed/news cards. The newer contract
// keeps their actions/quotes, glass rendering and narrow-width geometry covered.
require('./test-fix66-feed-news');
const catalog=section(news,'procedure TMoaPlayForm.HubRenderCatalog','procedure TMoaPlayForm.HubRenderArticle');
assert.match(catalog,/AddMemberSvg\(Search,Search,'search'/,'search icon is inside its field');
assert.match(catalog,/ReturnKeyType:=TReturnKeyType.Search/);assert.match(catalog,/MaxLength:=80/);
assert.match(catalog,/HubCatalogSearchKeyDown/);assert.match(catalog,/HubCatalogSearchChanged/);
const search=section(news,'procedure TMoaPlayForm.HubCatalogSearchKeyDown','procedure TMoaPlayForm.HubRenderCatalog');
assert.match(search,/Key:=0;KeyChar:=#0/);assert.match(search,/FHubSearchText:=Trim\(FHubSearchEdit.Text\)/);
assert.match(search,/FHubSearchEdit.ResetFocus;FMember.CancelReads;FHubLoading:=False;HubFetch;HubRender/);
assert.doesNotMatch(search,/HubRenderNow|FreeAndNil/,'IME return never frees its editor synchronously');
const detail=news.slice(news.indexOf('procedure TMoaPlayForm.HubRenderGame;'));
assert.match(detail,/Hero.Configure\(Encoded/);assert.match(detail,/Hero.HitTest:=False/);
assert.match(detail,/HubArray\(FHubSelected,'plans'\)/);assert.match(detail,/FHubPlanCombo.OnChange:=HubComboChanged/,'purchase confirmation retains the validated plan flow');
assert.doesNotMatch(detail,/HubContentIcon/,'game details use the photo itself');
for(const name of ['MoaPlayApp.Member.Feed.inc','MoaPlayApp.Member.NewsShop.inc','MoaPlayDiscoverCard.pas']){
 const bytes=fs.readFileSync(path.join(dir,name));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);
 assert.doesNotMatch(bytes.toString('utf8'),/(?<!\r)\n/,'Delphi source CRLF');
}
console.log('FIX65 CONTENT COMPATIBILITY PASS: FIX66 compact cards/glass plus retained discover search, safe keyboard submit and validated purchase flow.');
