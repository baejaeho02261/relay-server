'use strict';
const s=require('./store');
// One purchase is one start. Legacy duration prices only seed the new single price.
function Price(product){
 if(product?.singleUse===true&&Number.isSafeInteger(product.price))return product.price;
 const rows=Array.isArray(product?.plans)?product.plans:[];
 const first=rows.filter(x=>Number.isSafeInteger(x.price)&&x.price>0).sort((a,b)=>(a.days||0)-(b.days||0))[0];
 return first?.price||(Number.isSafeInteger(product?.price)?product.price:0);
}
function Plans(product){const price=Price(product);return [{uses:1,price,available:Number.isSafeInteger(price)&&price>0&&price<=10000000}];}
function Validate(value,previous){
 if(value===undefined)return Plans(previous).map(({uses,price})=>({uses,price}));
 if(!Array.isArray(value)||value.length!==1||value[0]?.days!==undefined)s.Fail('GAME_PLAN_INVALID');
 return [{uses:1,price:s.Money(value[0].price,0)}];
}
module.exports={Price,Plans,Validate};
