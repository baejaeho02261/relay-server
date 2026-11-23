'use strict';
// Stable identifiers are authorization data. Labels and card order may change;
// neither an unknown identifier nor a legacy unassigned license grants access.
const rows=[
 ['cleaner.pubg','PUBG: BATTLEGROUNDS','cleaner'],
 ['cleaner.talesrunner','TalesRunner','cleaner'],
 ['cleaner.lost-saga','Lost Saga','cleaner'],
 ['cleaner.apex','Apex Legends','cleaner'],
 ['cleaner.overwatch','Overwatch','cleaner'],
 ['cleaner.counter-strike','Counter-Strike 2','cleaner'],
 ['mobile.roblox','Roblox','mobile'],
 ['mobile.brawl-stars','Brawl Stars','mobile'],
 ['mobile.pubg-mobile','PUBG MOBILE','mobile'],
 ['mobile.genshin-impact','Genshin Impact','mobile'],
 ['mobile.pokemon-go','Pokémon GO','mobile'],
 ['mobile.clash-royale','Clash Royale','mobile']
].map(([id,name,category])=>Object.freeze({id,name,category}));
const catalog=new Map(rows.map(row=>[row.id,row]));
// Legacy journal/receipt identifiers survive for storage validation and audit
// only. They are neither available products nor equivalents of another product.
const retired=new Set([
 'spoofer.battleye','spoofer.xigncode3','spoofer.easy-anti-cheat',
 'spoofer.vanguard','spoofer.ricochet','spoofer.ace'
]);
function Find(value){return typeof value==='string'?catalog.get(value)||null:null;}
function Retired(value){return retired.has(value);}
function IsStoredProduct(value){return Find(value)!==null||Retired(value);}
function Require(value){
 const product=Find(value);if(product)return product;
 const error=Error(value===undefined||value===null||value===''?'DESKTOP_PRODUCT_REQUIRED':'DESKTOP_PRODUCT_INVALID');
 error.desktopError=true;error.status=400;throw error;
}
function List(){return rows.map(row=>({...row}));}
function Id(row){return Find(row?.productId)?.id||'';}
function Projection(row){const product=Find(row?.productId),retired=!product&&(Retired(row?.productId)||row?.productRetired===true);return {productId:product?.id||'',productName:product?.name||'',productCategory:product?.category||'',productAssigned:!!product,...(retired?{productRetired:true}:{})};}
module.exports=Object.freeze({List,Find,Retired,IsStoredProduct,Require,Id,Projection});
