'use strict';
const channels=[
 ['steam','Steam','https://store.steampowered.com/search/?category1=998'],
 ['epic-games','Epic Games Store','https://store.epicgames.com/browse'],
 ['nexon','Nexon','https://www.nexon.com/Home/Game/'],
 ['kakao-games','Kakao Games','https://pubg.kakaogames.com/pubg/index'],
 ['raon-entertainment','Raon Entertainment','https://www.rhaone.com/page/sub02_1'],
 ['valofe','VALOFE','https://lostsaga-ko.valofe.com/main/main.asp'],
 ['ea-app','EA app','https://www.ea.com/games/library/pc-games'],
 ['battle-net','Battle.net','https://www.blizzard.com/ko-kr/games']
].map(([id,name,url])=>Object.freeze({id,name,url}));
const channelById=new Map(channels.map(channel=>[channel.id,channel]));

// Stable identifiers still match the stored licenses and native O views. The
// first verified Windows distribution channel is the default picker selection.
// Provider directories never add products to this explicit authorization list.
const rows=[
 ['cleaner.pubg','PUBG: BATTLEGROUNDS',['steam','epic-games','kakao-games']],
 ['cleaner.talesrunner','TalesRunner',['raon-entertainment']],
 ['cleaner.lost-saga','Lost Saga',['valofe']],
 ['cleaner.apex','Apex Legends',['ea-app','steam','epic-games']],
 ['cleaner.overwatch','Overwatch',['battle-net','steam']],
 ['cleaner.counter-strike','Counter-Strike 2',['steam']]
].map(([id,name,channels])=>Object.freeze({id,name,category:channels[0],channels:Object.freeze(channels)}));
const catalog=new Map(rows.map(row=>[row.id,row]));
// Legacy journal/receipt identifiers survive for storage validation and audit
// only. They are neither available products nor equivalents of another product.
const retired=new Set([
 'spoofer.battleye','spoofer.xigncode3','spoofer.easy-anti-cheat',
 'spoofer.vanguard','spoofer.ricochet','spoofer.ace',
 'mobile.roblox','mobile.brawl-stars','mobile.pubg-mobile',
 'mobile.genshin-impact','mobile.pokemon-go','mobile.clash-royale'
]);
function Find(value){return typeof value==='string'?catalog.get(value)||null:null;}
function Retired(value){return retired.has(value);}
function IsStoredProduct(value){return Find(value)!==null||Retired(value);}
function Require(value){
 const product=Find(value);if(product)return product;
 const error=Error(value===undefined||value===null||value===''?'DESKTOP_PRODUCT_REQUIRED':'DESKTOP_PRODUCT_INVALID');
 error.desktopError=true;error.status=400;throw error;
}
function List(){return rows.map(row=>({...row,channels:[...row.channels]}));}
function ListChannels(){return channels.map(channel=>({...channel}));}
function Id(row){return Find(row?.productId)?.id||'';}
function Projection(row){
 const product=Find(row?.productId);
 if(!product)return {productId:'',productName:'',productCategory:'',productAssigned:false};
 return {productId:product.id,productName:product.name,productCategory:product.category,productAssigned:true,productChannelNames:product.channels.map(id=>channelById.get(id).name)};
}
module.exports=Object.freeze({List,ListChannels,Find,Retired,IsStoredProduct,Require,Id,Projection});
