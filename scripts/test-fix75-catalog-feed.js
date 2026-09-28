"use strict";
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(__dirname,'../../MoaPlayApp_Android64'),read=name=>fs.readFileSync(path.join(base,name),'utf8');
const shop=read('MoaPlayApp.Member.NewsShop.inc'),feed=read('MoaPlayApp.Member.Feed.inc');
const card=shop.split('function TMoaPlayForm.HubFillGameCard')[1].split('procedure TMoaPlayForm.HubRenderNews')[0];
const body=feed.split('function TMoaPlayForm.HubFillPostCard')[1].split('function TMoaPlayForm.HubQuoteCard')[0];
assert.match(card,/Value:=HubText\(Photo,'image'\)/,'gallery render prefers actual display/original image');
assert.match(card,/if not MemberLoadBitmap\(Source,Value\) then\s+if not MemberLoadBitmap\(Source,HubText\(Photo,'thumb'\)\) then Continue/);
assert.match(card,/RasterScale:=Min\(MemberDisplayScale\(C\),Min\(CropW\/PhotoW,CropH\/PhotoH\)\)/);
assert.match(card,/BitmapScale:=1/);assert.match(card,/Canvas.DrawBitmap\(Source,Crop,[^;]+,1,False\)/);
assert.doesNotMatch(card,/PhotoW\*2|PhotoH\*2|HubMoney|HubLabel\(Footer|IntToStr\(I\+1\)/);
assert.doesNotMatch(card,/FHubView='home'/,'Home and Discovery have the same renderer');
const expanded=card.slice(card.lastIndexOf('if Expanded then begin'));
assert.equal((card.match(/MemberCaption\('구매하기'\)/g)||[]).length,1);
assert.match(expanded,/HubText\(Item,'description'\)[\s\S]*HubButton\(C,MemberCaption\('구매하기'\),'product.purchase\|'\+ID,16,Y,InfoW,42\)/);
assert.match(expanded,/Buy.Fill.Kind:=TBrushKind.None[\s\S]*Buy.Stroke.Kind:=TBrushKind.Solid/);
assert.match(expanded,/Buy.Enabled:=\(Price>0\) and HubBool\(Item,'available'\)/,'unavailable/zero-priced offers cannot spend money');
assert.doesNotMatch(body,/Expanded|chevron.down|HubReaction|more\|post\||post.menu/);
assert.match(body,/HubMentionBody\(C,Body/);assert.match(body,/HubPostPhoto/);assert.match(body,/HubQuoteCard/);
assert.doesNotMatch(feed,/HubPostToggle|feed.expanded|HubTitleBadge/);
assert.match(feed,/C.OnOpen:=nil;C.OnHold:=HubPostHold/);
assert.match(feed,/HubSendSocial\('repost.set',Body\)/);
const decoder=read('MoaPlayMemberImages.pas');assert.match(decoder,/Bitmap.LoadFromStream\(Stream\)/);assert.match(decoder,/Bitmap.BitmapScale:=1;Target.Assign\(Bitmap\);Target.BitmapScale:=1/);
// Physical raster dimensions never exceed the cropped source, including fallback
// thumbnails, while a normal 1280px image retains enough pixels at phone densities.
let checked=0;
for(const [sourceW,sourceH]of [[1280,720],[1024,576],[960,480],[720,1280],[160,90],[2,2]])for(const width of [240,280,320,360,390,412,480])for(const density of [1,1.5,2,3,4]){
 const photoW=(width-32)*.84,photoH=photoW*.57;let cropW=sourceW,cropH=cropW*photoH/photoW;
 if(cropH>sourceH){cropH=sourceH;cropW=cropH*photoW/photoH;}
 const scale=Math.min(density,cropW/photoW,cropH/photoH),outW=Math.max(1,Math.floor(photoW*scale)),outH=Math.max(1,Math.floor(photoH*scale));
 assert.ok(outW<=Math.ceil(cropW)&&outH<=Math.ceil(cropH),'resampling never fabricates source detail');
 assert.ok(outW<=Math.ceil(photoW*density)&&outH<=Math.ceil(photoH*density),'raster allocation follows scene density');
 checked++;
}
for(const name of ['MoaPlayApp.Member.NewsShop.inc','MoaPlayApp.Member.Feed.inc','MoaPlayFeedCard.pas']){
 const bytes=fs.readFileSync(path.join(base,name));assert.equal(bytes.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(bytes.toString('utf8'),/(?<!\r)\n/);
}
console.log(`FIX75 catalog/feed PASS: ${checked} density/source combinations, image-first decoding, bounded crop raster, expanded-body transparent purchase, always-visible feed and immediate hold repost.`);
